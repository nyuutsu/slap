{-# LANGUAGE OverloadedStrings #-}

-- | What a parsed VCDIFF patch has to say about itself, in the two registers slap reads it through: 'vcdiffMeta' for the cross-cutting facts @slap info@ shows in a glance, and 'analyzeVCDIFF' for the per-window walk @slap explain@ unfolds.
--
-- The decoders already found everything (the flavor, every window's target size and source segment, every instruction, the per-window checksum, the application header), so nothing here re-derives; it only reads the decoded form and renders it.
--
-- The division of labor mirrors 'Slap.BPS.Describe': the meta side is cheap single passes (it rides every @slap info@ and @slap apply@), the analysis side the per-instruction walk only @slap explain@ forces.
module Slap.VCDIFF.Describe
  ( vcdiffMeta
  , vcdiffEmbeddedContent
  , analyzeVCDIFF
  , makeVCDIFFRegion
  ) where

import Slap.VCDIFF.Types
  ( VCDIFFPatch(..), Window(..), XDelta3Header(..), XDelta3Window(..)
  , RFCHeader(..), CustomCodeTable(..)
  , VCDIFFInstruction(..), SourceSegment(..), SegmentOrigin(..)
  , xdelta3WindowBody, xdelta3WindowAdler32
  , patchWindowsWithChecksums, WindowWithChecksum(..) )
import Slap.VCDIFF.SecondaryCompression (XDelta3SecondaryCompressor(..))
import Slap.VCDIFF.AddressCache
  ( AddressCacheConfig, nearSlotCount, sameBlockCount
  , unNearSlotCount, unSameBlockCount )
import Slap.Display.Analysis
  ( PatchAnalysis(..), AnalysisSection(..), AnalysisRegion(..)
  , AnalysisPayload(..), CopySource(..), AnalysisSummary(..)
  , SummaryInfo(..)
  , Annotation(..), OffsetKind(..), AnnotDetail(..) )
import Slap.Display.Common
  ( InfoLine(..), Tally(..), CountUnit(..), ByteCount(..), renderAsText )
import Slap.Display.EmbeddedContent (EmbeddedContent(..), EmbeddedField(..))
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
-- Info: the cross-cutting glance
----------------------------------------------------------------------------

-- | The facts @slap info@ surfaces that the format header's flavor qualifier does not already carry.
-- What there is to say depends on the flavor: a core-only patch speaks only of where its windows draw their copies from (the source file, the produced target, or nowhere); an RFC patch adds the custom code table when it carries one; an xdelta3 patch adds the declared secondary compressor and the per-window checksums.
-- The application header is embedded content, surfaced through 'vcdiffEmbeddedContent'.
vcdiffMeta :: VCDIFFPatch -> [InfoLine]
vcdiffMeta patch = case patch of
  PatchCoreOnly windows  -> originRollup (Vector.toList windows)
  PatchRFC header windows ->
    codeTableLines (rfcCustomCodeTable header) ++ originRollup (Vector.toList windows)
  PatchXDelta3 header xdelta3Windows ->
    let windowList = Vector.toList xdelta3Windows
    in  compressorLines (xdelta3SecondaryCompressor header)
     ++ originRollup (map xdelta3WindowBody windowList)
     ++ adlerRollup windowList

-- | The @code table@ and @address cache@ lines, when a patch supplied its own table (RFC 3284 §7).
-- The table line attests only that the patch decoded against a table of its own, not the default; the entries themselves were consumed at parse.
-- The cache line shows the geometry that table declared: the one place a VCDIFF patch's cache sizes depart from the default four-near\/three-same, since only a custom table can change them (xdelta3 and core-only patches always run the default geometry).
-- Both omitted for a patch on the default table, whose geometry is that implicit default.
codeTableLines :: Maybe CustomCodeTable -> [InfoLine]
codeTableLines Nothing            = []
codeTableLines (Just customTable) =
  [ InfoLine "code table"    "custom (RFC 3284 §7)"
  , InfoLine "address cache" (renderCacheGeometry (customCodeTableCacheConfig customTable)) ]

-- | The near-slot and same-block counts a custom table declares (RFC 3284
-- §5, §7), as the line @info@ \/ @explain@ shows for the address cache.
renderCacheGeometry :: AddressCacheConfig -> Text
renderCacheGeometry config =
     renderAsText (unNearSlotCount  (nearSlotCount  config)) <> " near, "
  <> renderAsText (unSameBlockCount (sameBlockCount config)) <> " same"

-- | An xdelta3 application header by presence alone, the one distinction VCDIFF's presence bit affords that the BPS blob cannot: 'AppHeaderAbsent' (the bit never set) is a different fact from 'AppHeaderEmpty' (the bit set over zero bytes), where BPS, having no such bit, reads an empty blob as simply absent.
-- The bytes are opaque, so reading them as text is the shared @--metadata-encoding@ lens's job at display.
data AppHeaderShape
  = AppHeaderAbsent
    -- ^ No VCD_APPHEADER: the patch declared none.
  | AppHeaderEmpty
    -- ^ Declared, but carrying zero bytes.
  | AppHeaderPresent !ByteString
    -- ^ Declared, carrying these bytes, read through the lens at display.
  deriving (Eq, Show)

-- | Frame an application header by presence alone. Flag-free and pure; 'vcdiffEmbeddedContent' turns the framing into the displayed field.
classifyAppHeader :: Maybe ByteString -> AppHeaderShape
classifyAppHeader Nothing = AppHeaderAbsent
classifyAppHeader (Just headerBytes)
  | ByteString.null headerBytes = AppHeaderEmpty
  | otherwise                   = AppHeaderPresent headerBytes

-- | The application header as embedded content: only the xdelta3 flavor carries one; RFC and core-only patches have none to show.
vcdiffEmbeddedContent :: EncodingName -> VCDIFFPatch -> [EmbeddedContent]
vcdiffEmbeddedContent metadataEncoding patch = case patch of
  PatchXDelta3 header _ ->
    [ EmbeddedContent "app header" (appHeaderField (classifyAppHeader (xdelta3AppHeader header))) ]
  _ -> []
  where
    appHeaderField AppHeaderAbsent          = FieldAbsent
    appHeaderField AppHeaderEmpty           = FieldEmpty
    appHeaderField (AppHeaderPresent bytes) = FieldOpaque metadataEncoding bytes

-- | The @compression@ line, when a secondary compressor was declared, named as a /declaration/: the decoded form has turned the compressed sections back into plain bytes, so the patch can attest which compressor it announced but not which windows leaned on it. Omitted when none was declared.
compressorLines :: Maybe XDelta3SecondaryCompressor -> [InfoLine]
compressorLines Nothing           = []
compressorLines (Just compressor) =
  [InfoLine "compression" (compressorName compressor <> " (declared)")]

compressorName :: XDelta3SecondaryCompressor -> Text
compressorName SecondaryDJW  = "DJW"
compressorName SecondaryLZMA = "LZMA"
compressorName SecondaryFGK  = "FGK"

-- | How a patch's windows divide by where their copies draw from.
-- A window in neither count is self-contained: pure ADD\/RUN and copies of its own output.
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

-- | How many of a patch's windows carry a per-window Adler32, against the total. Zero is a valid count: an xdelta3 patch whose creator omitted the checksums.
adlerRollup :: [XDelta3Window] -> [InfoLine]
adlerRollup windowList =
  [InfoLine "adler32" (windowFraction checksummedCount (length windowList))]
  where
    checksummedCount = length (filter (isJust . xdelta3WindowAdler32) windowList)

-- | A @"k of n windows"@ fraction, the shared phrasing of the source and adler rollups.
windowFraction :: Int -> Int -> Text
windowFraction part whole =
  renderAsText part <> " of " <> renderAsText whole <> " windows"

----------------------------------------------------------------------------
-- Analyze
----------------------------------------------------------------------------

-- | The full structural story: one labeled header per window, each followed by that window's instructions as a region list, plus the aggregate summary. Only @slap explain@ forces this.
--
-- The output cursor threads through every window's instructions unbroken: a window produces exactly its declared target size (the decoder guaranteed it), so where one window's last instruction leaves the cursor is where the next begins.
-- Each region's offset is therefore the absolute output position, the same @AtOutput@ frame 'Slap.BPS.Describe' walks.
analyzeVCDIFF :: VCDIFFPatch -> PatchAnalysis
analyzeVCDIFF patch = PatchAnalysis
  { analysisSections = concat (snd (mapAccumL describeWindow (Offset 0) numberedWindows))
  , analysisSummary  = Summary (SummaryInfo (Tally (length windows)) Windows
                                            (Just (TotalOutputBytes totalOutput)))
  }
  where
    windows         = Vector.toList (patchWindowsWithChecksums patch)
    windowNumbers   = [1 ..]
    numberedWindows = zip windowNumbers windows
    totalOutput     = FileSize (sum [ unFileSize (windowTargetSize (windowWithChecksumBody pairedWindow))
                                    | pairedWindow <- windows ])

-- | One window described: its labeled header, then its instructions as a region list, the output cursor carried across so the next window picks up where this one ended.
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

-- | A window's header block: the roomy key-value shape 'SectionLabeled' exists for, VCDIFF being the one format with repeated structured sub-units to head.
-- Target size, where its copies draw from (or "self-contained"), and its checksum when it carries one. Summary-mode explain drops 'SectionLabeled', so this is a @--records@-only detail.
windowHeader :: Int -> Window -> Maybe Adler32 -> AnalysisSection
windowHeader windowNumber window maybeAdler =
  SectionLabeled ("window " <> renderAsText windowNumber <> ":") $
       [ InfoLine "target size" (renderAsText (unFileSize (windowTargetSize window)))
       , InfoLine "source"      (renderSourceSegment (windowSourceSegment window)) ]
    ++ [ InfoLine "adler32" (showAdler32 adler) | Just adler <- [maybeAdler] ]

-- | A window's copy-source segment as a line, or its absence as "self-contained". Names the side it is cut from, where it begins, and how long it is.
renderSourceSegment :: Maybe SourceSegment -> Text
renderSourceSegment Nothing = "self-contained"
renderSourceSegment (Just (SourceSegment origin (Offset position) segmentLength)) =
  originLabel origin
  <> " @ 0x" <> padHex 6 position
  <> ", " <> renderAsText (unLength segmentLength) <> " bytes"
  where
    originLabel FromSourceFile     = "source file"
    originLabel FromProducedTarget = "produced target"

-- | One instruction as an 'AnalysisRegion' at its absolute output position, advancing the output cursor by what it writes.
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

-- | Where a COPY's bytes come from, read off its decoded superstring address: a source-file read when the address lands inside a source-file segment (then 'DetailSource' carries the absolute source offset @--records --source@ resolves the real bytes through), a produced-target read otherwise.
-- A window with no segment, a target-backed segment, or an address past the segment all read from the produced target: the one source-file case is the guarded arm, everything else falls through to it.
describeCopyAddress :: Maybe SourceSegment -> Offset -> (CopySource, [AnnotDetail])
describeCopyAddress maybeSegment (Offset address) = case maybeSegment of
  Just (SourceSegment FromSourceFile (Offset segmentPosition) segmentLength)
    | address < unLength segmentLength ->
        (FromSource, [DetailSource (Offset (segmentPosition + address))])
  _ -> (FromTarget, [])
