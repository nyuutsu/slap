{-# LANGUAGE OverloadedStrings #-}

module Slap.BPS.Describe
  ( bpsMeta
  , bpsEmbeddedContent
  , bpsMetadataNotes
  , analyzeBPS
  , BPSRegionState(..)
  , initialBPSRegionState
  , makeBPSRegion
  ) where

import Slap.BPS.Types (BPSPatch(..), BPSAction(..), BPSMetadata(..))
import Slap.Display.Analysis
    ( PatchAnalysis(..), AnalysisSection(..), AnalysisRegion(..)
    , AnalysisPayload(..), LiteralWriteBytes(..), CopySource(..), AnalysisSummary(..)
    , SummaryInfo(..)
    , Annotation(..), OffsetKind(..), AnnotDetail(..)
    )
import Slap.Checksum (showCRC32)
import Slap.FormatLabel (FormatLabel)
import Slap.Status (SlapAdvisory(..), BPSMetadataDivergence(..),
                   CursorKind(SourceCursor))
import Slap.Display.Common (InfoLine(..), Tally(..), CountUnit(..), ByteCount(..), renderAsText)
import Slap.Display.EmbeddedContent (EmbeddedContent(..), EmbeddedField(..), readEmbeddedContent)
import Slap.Text (EncodingName(EncodingUtf8), encodedTextContent, decodeTextLenient, substitutionCount)
import Slap.Measure (Offset(..), FileSize(..),
                     SignedOffset(SignedOffset),
                     SignedOffsetSign(..), Cursor(..), SubstitutionCount(..),
                     examineSignedOffset, byteLength)

import qualified Data.ByteString as ByteString
import Data.Char (isControl, isSpace)
import Data.List (mapAccumL)
import qualified Data.Text as Text
import qualified Data.Vector as Vector

bpsMeta :: BPSPatch -> [InfoLine]
bpsMeta patch = concat
  [ [InfoLine "source size" (renderAsText (unFileSize (bpsSourceSize patch)))]
  , [InfoLine "target size" (renderAsText (unFileSize (bpsTargetSize patch)))]
  , [InfoLine "source CRC" (showCRC32 (bpsSourceCRC patch))]
  , [InfoLine "target CRC" (showCRC32 (bpsTargetCRC patch))]
  , [InfoLine "patch CRC" (showCRC32 (bpsPatchCRC patch))]
  ]

-- | The metadata blob as content, read under the viewing encoding. BPS always carries the field,
-- so an empty blob is 'FieldAbsent' — absence is emptiness, not omission.
bpsEmbeddedContent :: EncodingName -> BPSPatch -> [EmbeddedContent]
bpsEmbeddedContent metadataEncoding patch
  | ByteString.null metadataBytes = [EmbeddedContent "embedded data" FieldAbsent]
  | otherwise = [EmbeddedContent "embedded data" (readEmbeddedContent metadataEncoding metadataBytes)]
  where
    metadataBytes = unBPSMetadata (bpsMetadata patch)

-- | The remark on the metadata blob, measured against UTF-8 — the encoding the BPS spec recommends.
-- Conformance is a fact about the format, so the @--metadata-encoding@ viewing preference does not move it:
-- a blob viewed as Shift-JIS still earns the note when it is not UTF-8. Silent for an absent or ordinary-text field;
-- it fires through 'patchAdvisories', so the remark surfaces on apply and convert as well as info.
--
-- The non-text trigger is "a control that isn't whitespace": a pretty-printed XML blob is full of newlines and tabs,
-- which are controls but exactly what the field holds, so they do not count; NUL, ESC, the C1 range do.
bpsMetadataNotes :: FormatLabel -> BPSPatch -> [SlapAdvisory]
bpsMetadataNotes label patch
  | ByteString.null bytes                    = []
  | unSubstitutionCount substituted > 0      = [BPSMetadataNonConformant label (MetadataBytesSubstituted substituted) blobLength]
  | Text.any isNonTextControl readingContent = [BPSMetadataNonConformant label MetadataDecodedButNonText blobLength]
  | otherwise                                = []
  where
    bytes              = unBPSMetadata (bpsMetadata patch)
    blobLength         = byteLength bytes
    (reading, notices) = decodeTextLenient EncodingUtf8 bytes
    readingContent     = encodedTextContent reading
    substituted        = substitutionCount notices
    isNonTextControl c = isControl c && not (isSpace c)

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
       , AnalysisRegion (regionOutputPosition state) payloadLength "TargetRead " (PayloadWrite (LiteralWriteBytes payload))
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
