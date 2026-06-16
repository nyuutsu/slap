{-# LANGUAGE OverloadedStrings #-}

-- | What a parsed VCDIFF patch has to say about itself, in the two
-- registers slap reads it through: 'vcdiffMeta' for the cross-cutting
-- facts @slap info@ shows in a glance, and 'analyzeVCDIFF' for the
-- per-window walk @slap explain@ unfolds.
--
-- The decoders already found the whole story — the flavor, every
-- window's target size and source segment, every instruction, the
-- per-window checksum, the application header. This module is where the
-- patch finally gets to tell it. Nothing here re-derives; it only reads
-- the decoded form and chooses words for it.
--
-- The division of labor mirrors 'Slap.BPS.Describe': the meta side is
-- cheap single passes (it rides every @slap info@ and @slap apply@), the
-- analysis side is the per-instruction walk only @slap explain@ forces.
module Slap.VCDIFF.Describe
  ( vcdiffMeta
  , analyzeVCDIFF
  , makeVCDIFFRegion
  ) where

import Slap.VCDIFF.Types
  ( VCDIFFPatch(..), Window(..), XDelta3Header(..), XDelta3Window(..)
  , VCDIFFInstruction(..), SourceSegment(..), SegmentOrigin(..)
  , xdelta3WindowBody, xdelta3WindowAdler32, patchWindowsWithChecksums )
import Slap.VCDIFF.SecondaryCompression (XDelta3SecondaryCompressor(..))
import Slap.Display.Analysis
  ( PatchAnalysis(..), AnalysisSection(..), AnalysisRegion(..)
  , AnalysisPayload(..), CopySource(..), AnalysisSummary(..)
  , SummaryInfo(..)
  , Annotation(..), OffsetKind(..), AnnotDetail(..) )
import Slap.Display.Common
  ( InfoLine(..), Tally(..), CountUnit(..), ByteCount(..), renderAsText )
import Slap.Display.Primitives (renderEscapingNonPrintable, padHex)
import Slap.Checksum (Adler32, showAdler32)
import Slap.Text (EncodingName(..), EncodedText(..), decodeTextLenient)
import Slap.Measure (Offset(..), Length(..), FileSize(..), Cursor(..), byteLength)

import Data.Maybe (isJust)
import Data.List (mapAccumL)
import Data.Text (Text)
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.Vector as Vector

----------------------------------------------------------------------------
-- Info — the cross-cutting glance
----------------------------------------------------------------------------

-- | The facts @slap info@ surfaces that the format header's flavor
-- qualifier does not already carry. What there is to say depends on the
-- flavor: a core-only patch holds nothing but its windows, so it speaks
-- only of how those windows divide between source-backed and
-- self-contained; an xdelta3 patch adds the three things only its arc
-- can carry — the application header, the declared secondary
-- compressor, and the per-window checksums.
--
-- 'PatchRFC' is unconstructable today (the parser refuses the RFC arc
-- before building one), but its arm is written rather than wildcarded,
-- so the arc's eventual landing arrives here as a decision to make, not
-- a silent fall-through.
vcdiffMeta :: VCDIFFPatch -> [InfoLine]
vcdiffMeta patch = case patch of
  PatchCoreOnly windows -> sourceRollup (Vector.toList windows)
  PatchRFC _ windows    -> sourceRollup (Vector.toList windows)
  PatchXDelta3 header xdelta3Windows ->
    let windowList = Vector.toList xdelta3Windows
    in  InfoLine "app header" (renderAppHeaderLine (classifyAppHeader (xdelta3AppHeader header)))
      : compressorLines (xdelta3SecondaryCompressor header)
     ++ sourceRollup (map xdelta3WindowBody windowList)
     ++ adlerRollup windowList

-- | What slap can say about an xdelta3 application header, read through
-- a UTF-8 lens. VCD_APPHEADER bytes are opaque — the format fixes them
-- no meaning — so this is the same read-only glance
-- 'Slap.BPS.Types.classifyBPSMetadata' takes at the BPS metadata blob,
-- with one distinction the header's presence bit affords and the BPS
-- blob cannot: 'AppHeaderAbsent' (the bit was never set) is a different
-- fact from 'AppHeaderEmpty' (the bit was set over zero bytes), where
-- BPS, having no such bit, reads an empty blob as simply absent.
data AppHeaderShape
  = AppHeaderAbsent
    -- ^ No VCD_APPHEADER: the patch declared none.
  | AppHeaderEmpty
    -- ^ Declared, but carrying zero bytes.
  | AppHeaderText !Length !Text
    -- ^ Bytes that decode cleanly as UTF-8: their byte count and the
    -- decoded text (shown with every non-printable codepoint escaped).
  | AppHeaderBinary !Length
    -- ^ Bytes that are not UTF-8 at all — the "literally anything" an
    -- opaque field admits. Only the byte count is shown.
  deriving (Eq, Show)

-- | Classify an application header through the UTF-8 lens. Total and
-- pure — the one place the judgment lives, leaving 'renderAppHeaderLine'
-- to only fold it. Bytes the lenient decoder accepted with no
-- substitution are text; bytes that needed even one substitution are
-- not UTF-8, the same all-or-nothing reading 'classifyBPSMetadata'
-- makes.
classifyAppHeader :: Maybe ByteString -> AppHeaderShape
classifyAppHeader Nothing = AppHeaderAbsent
classifyAppHeader (Just headerBytes)
  | ByteString.null headerBytes = AppHeaderEmpty
  | otherwise = case decodeTextLenient EncodingUtf8 headerBytes of
      (EncodedText _encoding text, []) -> AppHeaderText (byteLength headerBytes) text
      (_decoded, _substitutionNotices) -> AppHeaderBinary (byteLength headerBytes)

-- | The @app header@ line: fold an 'AppHeaderShape' to its display. The
-- two byte-bearing shapes share the @"N bytes"@ phrasing; the text shape
-- carries it on to the escaped content.
renderAppHeaderLine :: AppHeaderShape -> Text
renderAppHeaderLine AppHeaderAbsent = "(none)"
renderAppHeaderLine AppHeaderEmpty  = "(empty)"
renderAppHeaderLine (AppHeaderText byteCount text) =
  byteCountPhrase byteCount <> ": " <> renderEscapingNonPrintable text
renderAppHeaderLine (AppHeaderBinary byteCount) =
  byteCountPhrase byteCount <> " (not valid UTF-8)"

-- | An application header's size as the @"N bytes"@ phrase its two
-- byte-bearing shapes wear.
byteCountPhrase :: Length -> Text
byteCountPhrase byteCount = renderAsText (unLength byteCount) <> " bytes"

-- | The @compression@ line, when a secondary compressor was declared.
-- Named, and named as a /declaration/ — the decoded form has long since
-- turned the compressed sections back into plain bytes, so the patch can
-- attest which compressor it announced but not, from here, which windows
-- leaned on it. Omitted entirely when no compressor was declared.
compressorLines :: Maybe XDelta3SecondaryCompressor -> [InfoLine]
compressorLines Nothing           = []
compressorLines (Just compressor) =
  [InfoLine "compression" (compressorName compressor <> " (declared)")]

compressorName :: XDelta3SecondaryCompressor -> Text
compressorName SecondaryDJW  = "DJW"
compressorName SecondaryLZMA = "LZMA"
compressorName SecondaryFGK  = "FGK"

-- | How many of a patch's windows draw a copy-source segment from the
-- source file, against the total. The rest are self-contained — pure
-- ADD\/RUN and target-internal copies — so the one fraction tells the
-- whole division.
sourceRollup :: [Window] -> [InfoLine]
sourceRollup windows =
  [InfoLine "source" (windowFraction sourceBackedCount (length windows))]
  where
    sourceBackedCount = length (filter (isJust . windowSourceSegment) windows)

-- | How many of a patch's windows carry a per-window Adler32, against
-- the total. Zero is the honest reading of an xdelta3 patch whose
-- creator omitted the checksums — the patch's only integrity mechanism,
-- left off.
adlerRollup :: [XDelta3Window] -> [InfoLine]
adlerRollup windowList =
  [InfoLine "adler32" (windowFraction checksummedCount (length windowList))]
  where
    checksummedCount = length (filter (isJust . xdelta3WindowAdler32) windowList)

-- | A @"k of n windows"@ fraction, the shared phrasing of the source
-- and adler rollups.
windowFraction :: Int -> Int -> Text
windowFraction part whole =
  renderAsText part <> " of " <> renderAsText whole <> " windows"

----------------------------------------------------------------------------
-- Explain — the per-window walk
----------------------------------------------------------------------------

-- | The full structural story: one labeled header per window, each
-- followed by that window's instructions as a region list, plus the
-- aggregate summary. Only @slap explain@ forces this.
--
-- The output cursor threads through every window's instructions
-- unbroken: a window's instructions produce exactly its declared target
-- size (the decoder guaranteed it), so where one window's last
-- instruction leaves the cursor is precisely where the next window
-- begins. Each region's offset is therefore the absolute output
-- position, the same @AtOutput@ frame 'Slap.BPS.Describe' walks.
analyzeVCDIFF :: VCDIFFPatch -> PatchAnalysis
analyzeVCDIFF patch = PatchAnalysis
  { analysisSections = concat (snd (mapAccumL describeWindow (Offset 0) numberedWindows))
  , analysisSummary  = Summary (SummaryInfo (Tally (length windows)) Windows
                                            (Just (TotalOutputBytes totalOutput)))
  }
  where
    windows         = Vector.toList (patchWindowsWithChecksums patch)
    numberedWindows = zip [1 ..] windows
    totalOutput     = FileSize (sum [ unFileSize (windowTargetSize window)
                                    | (window, _adler) <- windows ])

-- | One window described: its labeled header, then its instructions as
-- a region list, with the output cursor carried across so the next
-- window picks up exactly where this one ended.
describeWindow
  :: Offset -> (Int, (Window, Maybe Adler32)) -> (Offset, [AnalysisSection])
describeWindow outputCursor (windowNumber, (window, maybeAdler)) =
  (cursorAfterWindow, [windowHeader windowNumber window maybeAdler, SectionRegions regions])
  where
    (cursorAfterWindow, regions) =
      mapAccumL (makeVCDIFFRegion (windowSourceSegment window))
                outputCursor
                (Vector.toList (windowInstructions window))

-- | A window's header block: the roomy key-value shape 'SectionLabeled'
-- exists for, since VCDIFF is the one format with repeated structured
-- sub-units to head. Target size, where its copies draw from (or
-- "self-contained"), and its checksum when it carries one. Summary-mode
-- explain drops 'SectionLabeled', so this is a @--records@-only detail.
windowHeader :: Int -> Window -> Maybe Adler32 -> AnalysisSection
windowHeader windowNumber window maybeAdler =
  SectionLabeled ("window " <> renderAsText windowNumber <> ":") $
       [ InfoLine "target size" (renderAsText (unFileSize (windowTargetSize window)))
       , InfoLine "source"      (renderSourceSegment (windowSourceSegment window)) ]
    ++ [ InfoLine "adler32" (showAdler32 adler) | Just adler <- [maybeAdler] ]

-- | A window's copy-source segment as a line, or its absence as
-- "self-contained". Names the side the segment is cut from, where it
-- begins, and how long it is.
renderSourceSegment :: Maybe SourceSegment -> Text
renderSourceSegment Nothing = "self-contained"
renderSourceSegment (Just (SourceSegment origin (Offset position) segmentLength)) =
  originLabel origin
  <> " @ 0x" <> padHex 6 position
  <> ", " <> renderAsText (unLength segmentLength) <> " bytes"
  where
    originLabel FromSourceFile     = "source file"
    originLabel FromProducedTarget = "produced target"

-- | One instruction as an 'AnalysisRegion' at its absolute output
-- position, advancing the output cursor by what it writes. The three
-- instructions fall straight onto the shared payload vocabulary: ADD is
-- a literal write, RUN a fill, COPY a copy whose source — the source
-- file or the produced target — is read off where its address lands
-- relative to the window's segment.
makeVCDIFFRegion
  :: Maybe SourceSegment -> Offset -> VCDIFFInstruction -> (Offset, AnalysisRegion)
makeVCDIFFRegion maybeSegment outputPosition instruction = case instruction of
  Add literal ->
    let literalLength = byteLength literal
    in ( advance outputPosition literalLength
       , AnalysisRegion outputPosition literalLength "Add  " (PayloadWrite literal)
           (AnnotationAt AtOutput outputPosition []) )
  Run count fillByte ->
    ( advance outputPosition count
    , AnalysisRegion outputPosition count "Run  " (PayloadFill fillByte count)
        (AnnotationAt AtOutput outputPosition []) )
  Copy count address ->
    let (copySource, details) = describeCopyAddress maybeSegment address
    in ( advance outputPosition count
       , AnalysisRegion outputPosition count "Copy " (PayloadCopy copySource)
           (AnnotationAt AtOutput outputPosition details) )

-- | Where a COPY's bytes come from, read off its decoded superstring
-- address: a source-file read when the address lands inside a
-- source-file segment (then 'DetailSource' carries the absolute source
-- offset, which is what @--records --source@ resolves the real bytes
-- through), a produced-target read otherwise. A window with no segment,
-- a target-backed segment, or an address past the segment all read from
-- the produced target — the one source-file case is the guarded arm,
-- and everything else falls through to it.
describeCopyAddress :: Maybe SourceSegment -> Offset -> (CopySource, [AnnotDetail])
describeCopyAddress maybeSegment (Offset address) = case maybeSegment of
  Just (SourceSegment FromSourceFile (Offset segmentPosition) segmentLength)
    | address < unLength segmentLength ->
        (FromSource, [DetailSource (Offset (segmentPosition + address))])
  _ -> (FromTarget, [])
