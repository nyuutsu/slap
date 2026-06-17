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
  , xdelta3WindowBody, xdelta3WindowAdler32
  , patchWindowsWithChecksums, WindowWithChecksum(..) )
import Slap.VCDIFF.SecondaryCompression (XDelta3SecondaryCompressor(..))
import Slap.Display.Analysis
  ( PatchAnalysis(..), AnalysisSection(..), AnalysisRegion(..)
  , AnalysisPayload(..), CopySource(..), AnalysisSummary(..)
  , SummaryInfo(..)
  , Annotation(..), OffsetKind(..), AnnotDetail(..) )
import Slap.Display.Common
  ( InfoLine(..), Tally(..), CountUnit(..), ByteCount(..), renderAsText )
import Slap.Display.OpaqueField (renderOpaqueFieldBytes)
import Slap.Display.Primitives (padHex)
import Slap.Checksum (Adler32, showAdler32)
import Slap.Text (EncodingName)
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
-- flavor: a core-only or RFC patch holds nothing but its windows, so it
-- speaks only of where those windows draw their copies from (the source
-- file, the produced target, or nowhere); an xdelta3 patch adds the
-- three things only its arc can carry — the application header, the
-- declared secondary compressor, and the per-window checksums.
--
-- Exhaustive over the three flavors, no wildcard.
vcdiffMeta :: EncodingName -> VCDIFFPatch -> [InfoLine]
vcdiffMeta metadataEncoding patch = case patch of
  PatchCoreOnly windows -> originRollup (Vector.toList windows)
  PatchRFC _ windows    -> originRollup (Vector.toList windows)
  PatchXDelta3 header xdelta3Windows ->
    let windowList = Vector.toList xdelta3Windows
    in  InfoLine "app header"
          (renderAppHeaderLine metadataEncoding (classifyAppHeader (xdelta3AppHeader header)))
      : compressorLines (xdelta3SecondaryCompressor header)
     ++ originRollup (map xdelta3WindowBody windowList)
     ++ adlerRollup windowList

-- | The presence framing of an xdelta3 application header — the only
-- part of "what this opaque field is" VCDIFF itself decides, before any
-- viewing lens is chosen. VCD_APPHEADER bytes are opaque (the format
-- fixes them no meaning), so reading them as text is the shared lens's
-- job, deferred to display where the @--metadata-encoding@ choice lives;
-- what stays here is the one distinction the header's presence bit
-- affords and the BPS blob cannot: 'AppHeaderAbsent' (the bit was never
-- set) is a different fact from 'AppHeaderEmpty' (the bit was set over
-- zero bytes), where BPS, having no such bit, reads an empty blob as
-- simply absent.
data AppHeaderShape
  = AppHeaderAbsent
    -- ^ No VCD_APPHEADER: the patch declared none.
  | AppHeaderEmpty
    -- ^ Declared, but carrying zero bytes.
  | AppHeaderPresent !ByteString
    -- ^ Declared, carrying these bytes — read through the lens at
    -- display.
  deriving (Eq, Show)

-- | Frame an application header by presence alone. Flag-free and pure;
-- the encoding-dependent reading of its bytes belongs to
-- 'renderAppHeaderLine' and the shared lens beneath it.
classifyAppHeader :: Maybe ByteString -> AppHeaderShape
classifyAppHeader Nothing = AppHeaderAbsent
classifyAppHeader (Just headerBytes)
  | ByteString.null headerBytes = AppHeaderEmpty
  | otherwise                   = AppHeaderPresent headerBytes

-- | The @app header@ line: the absent and empty framings render
-- verbatim, and present bytes go through the shared
-- @--metadata-encoding@ lens — shown as text where they read as text
-- under the chosen encoding, as a byte count where they don't.
renderAppHeaderLine :: EncodingName -> AppHeaderShape -> Text
renderAppHeaderLine _        AppHeaderAbsent          = "(none)"
renderAppHeaderLine _        AppHeaderEmpty           = "(empty)"
renderAppHeaderLine encoding (AppHeaderPresent bytes) = renderOpaqueFieldBytes encoding bytes

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

-- | How a patch's windows divide by where their copies draw from. The
-- @source@ line — windows whose segment is cut from the source file —
-- always shows. The @produced target@ line — windows drawing on earlier
-- output through VCD_TARGET — shows only when at least one window does,
-- so it is absent on a patch with no VCD_TARGET window. A window in
-- neither count is self-contained: pure ADD\/RUN and copies of its own
-- output.
originRollup :: [Window] -> [InfoLine]
originRollup windows =
     [ InfoLine "source" (windowFraction (countOrigin FromSourceFile) total) ]
  ++ [ InfoLine "produced target" (windowFraction producedTargetCount total)
     | producedTargetCount > 0 ]
  where
    total               = length windows
    producedTargetCount = countOrigin FromProducedTarget
    countOrigin origin  = length
      [ () | window  <- windows
           , Just segment <- [windowSourceSegment window]
           , sourceSegmentOrigin segment == origin ]

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
    totalOutput     = FileSize (sum [ unFileSize (windowTargetSize (windowWithChecksumBody pairedWindow))
                                    | pairedWindow <- windows ])

-- | One window described: its labeled header, then its instructions as
-- a region list, with the output cursor carried across so the next
-- window picks up exactly where this one ended.
describeWindow
  :: Offset -> (Int, WindowWithChecksum) -> (Offset, [AnalysisSection])
describeWindow outputCursor (windowNumber, pairedWindow) =
  (cursorAfterWindow, [windowHeader windowNumber window maybeAdler, SectionRegions regions])
  where
    window     = windowWithChecksumBody pairedWindow
    maybeAdler = windowWithChecksumAdler32 pairedWindow
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
