{-# LANGUAGE OverloadedStrings #-}

module Slap.BPS.Describe
  ( bpsMeta
  , bpsMetadataNotes
  , analyzeBPS
  , BPSRegionState(..)
  , initialBPSRegionState
  , makeBPSRegion
  ) where

import Slap.BPS.Types (BPSPatch(..), BPSAction(..), BPSMetadata(..),
                       BPSMetadataShape(..), classifyBPSMetadata)
import Slap.Display.Analysis
    ( PatchAnalysis(..), AnalysisSection(..), AnalysisRegion(..)
    , AnalysisPayload(..), CopySource(..), AnalysisSummary(..)
    , SummaryInfo(..)
    , Annotation(..), OffsetKind(..), AnnotDetail(..)
    )
import Slap.Checksum (showCRC32)
import Slap.FormatLabel (FormatLabel(LabelBPS))
import Slap.Status (SlapAdvisory(..), BPSMetadataDivergence(..),
                   CursorKind(SourceCursor))
import Slap.Display.Common (InfoLine(..), Tally(..), CountUnit(..), ByteCount(..), renderAsText)
import Slap.Display.OpaqueField (renderOpaqueFieldBytes)
import Slap.Text (EncodingName)
import Slap.Measure (Offset(..), FileSize(..),
                     SignedOffset(SignedOffset),
                     SignedOffsetSign(..), Cursor(..),
                     examineSignedOffset, byteLength)

import Data.Text (Text)

import qualified Data.ByteString as ByteString
import Data.Char (isControl, isSpace)
import Data.List (mapAccumL)
import qualified Data.Text as Text
import qualified Data.Vector as Vector

bpsMeta :: EncodingName -> BPSPatch -> [InfoLine]
bpsMeta metadataEncoding patch = concat
  [ [InfoLine "source size" (renderAsText (unFileSize (bpsSourceSize patch)))]
  , [InfoLine "target size" (renderAsText (unFileSize (bpsTargetSize patch)))]
  , [InfoLine "metadata" (renderMetadataLine metadataEncoding (bpsMetadata patch))]
  , [InfoLine "source CRC" (showCRC32 (bpsSourceCRC patch))]
  , [InfoLine "target CRC" (showCRC32 (bpsTargetCRC patch))]
  , [InfoLine "patch CRC" (showCRC32 (bpsPatchCRC patch))]
  ]

-- | The @metadata@ info line: a glance at the BPS metadata blob, read
-- through the @--metadata-encoding@ lens. An absent field reads
-- "(none)"; present bytes go to the shared 'renderOpaqueFieldBytes',
-- which shows them as text where they decode under the chosen encoding
-- and as a byte count where they don't. The blob itself is never
-- altered; this is a read-only view.
--
-- The viewing lens is deliberately separate from the spec-conformance
-- judgment 'bpsMetadataNotes' raises: the BPS spec recommends UTF-8 XML,
-- so the @BPSMetadataNonConformant@ remark stays anchored to UTF-8
-- through 'classifyBPSMetadata' regardless of how the user asks to view
-- the bytes. Showing a cp1252 blob as readable text and noting that it
-- diverges from the spec's UTF-8 are both true at once.
renderMetadataLine :: EncodingName -> BPSMetadata -> Text
renderMetadataLine metadataEncoding (BPSMetadata bytes)
  | ByteString.null bytes = "(none)"
  | otherwise             = renderOpaqueFieldBytes metadataEncoding bytes

-- | The remark companion to 'renderMetadataLine': a note-severity
-- 'SlapAdvisory' when the BPS metadata blob isn't the spec-recommended
-- UTF-8 text. Silent for an absent field and for ordinary UTF-8 text
-- (the field used exactly as recommended); it fires once, through
-- 'patchAdvisories', for the two divergent shapes, so the remark
-- surfaces on apply and convert as well as info.
--
-- Note the deliberate asymmetry from 'renderMetadataLine''s escaping.
-- The display escapes every non-printable codepoint, newlines
-- included, because the question there is "what is safe to render raw
-- in a terminal." The question here is "is the content surprising,"
-- and the answer for whitespace is no — a pretty-printed XML blob is
-- full of newlines and tabs, and that's exactly what the field is
-- meant to hold. So the trigger is "a control that isn't whitespace"
-- ('isControl' and 'not' . 'isSpace', two stdlib category predicates
-- composed — no codepoint privileged by hand): NUL, BEL, ESC, the C1
-- range, and the like, the codepoints that mean the field holds
-- something other than text.
bpsMetadataNotes :: BPSPatch -> [SlapAdvisory]
bpsMetadataNotes patch = case classifyBPSMetadata metadata of
  MetadataAbsent  -> []
  MetadataNotUTF8 -> [BPSMetadataNonConformant LabelBPS MetadataIsNotUTF8 blobLength]
  MetadataUTF8Text text
    | Text.any isNonTextControl text ->
        [BPSMetadataNonConformant LabelBPS MetadataIsValidUTF8ButNonText blobLength]
    | otherwise -> []
  where
    metadata           = bpsMetadata patch
    blobLength         = byteLength (unBPSMetadata metadata)
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
