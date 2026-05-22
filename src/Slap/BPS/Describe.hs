module Slap.BPS.Describe
  ( bpsMeta
  , analyzeBPS
  , BPSRegionState(..)
  , initialBPSRegionState
  , makeBPSRegion
  ) where

import Slap.BPS.Types (BPSPatch(..), BPSAction(..), BPSMetadata(..))
import Slap.Display.Analysis
    ( PatchAnalysis(..), AnalysisSection(..), AnalysisRegion(..)
    , AnalysisPayload(..), CopySource(..), AnalysisSummary(..)
    , SummaryInfo(..)
    , Annotation(..), OffsetKind(..), AnnotDetail(..)
    )
import Slap.Checksum (showCRC32)
import Slap.Status (CursorKind(SourceCursor))
import Slap.Display.Common (InfoLine(..), Tally(..), CountUnit(..), ByteCount(..))
import Slap.Measure (Offset(..), FileSize(..),
                     SignedOffset(SignedOffset),
                     SignedOffsetSign(..), Cursor(..),
                     examineSignedOffset, byteLength)

import Slap.Text (EncodingName(..), encodedTextContent, decodeTextLenient)

import qualified Data.ByteString as ByteString
import Data.Char (isControl)
import Data.List (mapAccumL)
import qualified Data.Text as Text
import qualified Data.Vector as Vector

bpsMeta :: BPSPatch -> [InfoLine]
bpsMeta patch = concat
  [ [InfoLine "source size" (show (unFileSize (bpsSourceSize patch)))]
  , [InfoLine "target size" (show (unFileSize (bpsTargetSize patch)))]
  , [InfoLine "metadata" metadataDisplay]
  , [InfoLine "source CRC" (showCRC32 (bpsSourceCRC patch))]
  , [InfoLine "target CRC" (showCRC32 (bpsTargetCRC patch))]
  , [InfoLine "patch CRC" (showCRC32 (bpsPatchCRC patch))]
  ]
  where
    metadata = unBPSMetadata (bpsMetadata patch)
    metadataDisplay
      | ByteString.null metadata = "(none)"
      | otherwise =
          let (decodedMetadata, _lossNotices) = decodeTextLenient EncodingLocale metadata
              previewSafeCodepoints = Text.filter isPreviewSafe
                                        (encodedTextContent decodedMetadata)
          in show (ByteString.length metadata) ++ " bytes: " ++ Text.unpack previewSafeCodepoints
    isPreviewSafe character = not (isControl character) || character == '\t'

analyzeBPS :: BPSPatch -> PatchAnalysis
analyzeBPS patch = PatchAnalysis
    -- 'mapAccumL' is list-shaped; 'Data.Vector' has no direct equivalent.
    -- 'analyze' runs once per @slap explain@ invocation, not per byte,
    -- so the toList round-trip here is not in the hot path and the
    -- straightforward expression is preferable to a manual unfold.
  { analysisSections = [SectionRegions (snd (mapAccumL makeBPSRegion initialBPSRegionState (Vector.toList (bpsActions patch))))]
  , analysisSummary  = Summary (SummaryInfo (Tally actionCount) Actions (Just (TotalOutputBytes (bpsTargetSize patch))))
  }
  where
    actionCount = Vector.length (bpsActions patch)

-- | The accumulator state threaded through 'makeBPSRegion' as the
-- BPS action stream is walked for explain output. 'regionSourceRelative'
-- is a 'SignedOffset' for the same reason 'BPS.Apply' uses one: a
-- 'SourceCopy' delta can drive the cursor briefly negative.
data BPSRegionState = BPSRegionState
  { regionOutputPosition :: !Offset
  , regionSourceRelative :: !SignedOffset
  } deriving (Show)

-- | Initial state for walking the BPS action stream in 'makeBPSRegion'.
initialBPSRegionState :: BPSRegionState
initialBPSRegionState = BPSRegionState (Offset 0) (SignedOffset 0)

makeBPSRegion :: BPSRegionState -> BPSAction -> (BPSRegionState, AnalysisRegion)
makeBPSRegion state action = case action of
  SourceRead actionLength ->
    ( state { regionOutputPosition = advance (regionOutputPosition state) actionLength }
    , AnalysisRegion (regionOutputPosition state) actionLength "SourceRead " (PayloadCopy FromSource)
        (AnnotationAt AtOutput (regionOutputPosition state) [DetailSource (regionOutputPosition state)])
    )
  TargetRead payload ->
    let payloadLength = byteLength payload
    in ( state { regionOutputPosition = advance (regionOutputPosition state) payloadLength }
       , AnalysisRegion (regionOutputPosition state) payloadLength "TargetRead " (PayloadWrite payload)
           (AnnotationAt AtOutput (regionOutputPosition state) [])
       )
  SourceCopy actionLength actionDelta ->
    let nextSourceRelative = displace (regionSourceRelative state) actionDelta
        nextOutputPosition = advance (regionOutputPosition state) actionLength
        advancedSourceRelative = advance nextSourceRelative actionLength
        annotationDetails = case examineSignedOffset nextSourceRelative of
          NonNegativeCursor safeSourceStart ->
            [DetailSource safeSourceStart, DetailDelta actionDelta]
          NegativeCursor underflowedCursor ->
            [DetailCursorUnderflow SourceCursor underflowedCursor, DetailDelta actionDelta]
    in ( BPSRegionState nextOutputPosition advancedSourceRelative
       , AnalysisRegion (regionOutputPosition state) actionLength "SourceCopy " (PayloadCopy FromSource)
           (AnnotationAt AtOutput (regionOutputPosition state) annotationDetails)
       )
  TargetCopy actionLength actionDelta ->
    ( state { regionOutputPosition = advance (regionOutputPosition state) actionLength }
    , AnalysisRegion (regionOutputPosition state) actionLength "TargetCopy " (PayloadCopy FromTarget)
        (AnnotationAt AtOutput (regionOutputPosition state) [DetailDelta actionDelta])
    )
