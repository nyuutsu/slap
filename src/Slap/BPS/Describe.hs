module Slap.BPS.Describe
  ( bpsInfo
  , bpsMeta
  , explainBPS
  , BPSRegionState(..)
  , initialBPSRegionState
  , makeBPSRegion
  ) where

import Slap.BPS.Types (BPSPatch(..), BPSAction(..))
import Slap.Explain
    ( ExplainData(..), ExplainSection(..), ExplainRegion(..)
    , ExplainPayload(..), CopySource(..), ExplainSummary(..)
    , SummaryInfo(..), SummaryByteInfo(..), SummaryBytes(..)
    , Annotation(..), OffsetKind(..), AnnotDetail(..)
    )
import Slap.Checksum (showCRC32)
import Slap.Format (MetaField(..), renderField)
import Slap.Measure (Offset(..), Length(..), FileSize(..),
                     SignedOffset(..), Cursor(..))

import Slap.TextEncoding (decodeLocaleField)

import qualified Data.ByteString as ByteString
import Data.List (mapAccumL)
import qualified Data.Vector as Vector

bpsMeta :: BPSPatch -> [MetaField]
bpsMeta patch = concat
  [ [MetaField "source size" (show (unFileSize (bpsSourceSize patch)))]
  , [MetaField "target size" (show (unFileSize (bpsTargetSize patch)))]
  , [MetaField "metadata" metadataDisplay]
  , [MetaField "source CRC" (showCRC32 (bpsSourceCRC patch))]
  , [MetaField "target CRC" (showCRC32 (bpsTargetCRC patch))]
  , [MetaField "patch CRC" (showCRC32 (bpsPatchCRC patch))]
  ]
  where
    metadata = bpsMetadata patch
    metadataDisplay
      | ByteString.null metadata = "(none)"
      | otherwise        = show (ByteString.length metadata) ++ " bytes: "
                        ++ map sanitize (decodeLocaleField (ByteString.take metadataPreviewBytes metadata))
                        ++ if ByteString.length metadata > metadataPreviewBytes then "..." else ""
    sanitize character
      | character >= ' ' && character <= '~' = character
      | otherwise                            = '.'

bpsInfo :: BPSPatch -> String
bpsInfo patch = unlines $ filter (not . null) $
  [ "format:      BPS" ]
  ++ map renderField (bpsMeta patch)
  ++ [ "actions:     " ++ show (Vector.length (bpsActions patch)) ]

explainBPS :: BPSPatch -> ExplainData
explainBPS patch = ExplainData
  { explainFormat   = "BPS"
  , explainHeader   = bpsMeta patch
    -- 'mapAccumL' is list-shaped; 'Data.Vector' has no direct equivalent.
    -- 'explain' runs once per @slap explain@ invocation, not per byte,
    -- so the toList round-trip here is not in the hot path and the
    -- straightforward expression is preferable to a manual unfold.
  , explainSections = [SectionRegions (snd (mapAccumL makeBPSRegion initialBPSRegionState (Vector.toList (bpsActions patch))))]
  , explainSummary  = Summary (SummaryInfo actionCount "actions" (Just (SummaryByteInfo (unFileSize (bpsTargetSize patch)) BytesTotalOutput)))
  , explainNotes    = []
  }
  where
    actionCount = Vector.length (bpsActions patch)

-- | Maximum number of metadata bytes shown in 'bpsInfo' output before
-- truncation. Larger metadata blobs are truncated with an ellipsis.
metadataPreviewBytes :: Int
metadataPreviewBytes = 200

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

makeBPSRegion :: BPSRegionState -> BPSAction -> (BPSRegionState, ExplainRegion)
makeBPSRegion state action = case action of
  SourceRead actionLength ->
    ( state { regionOutputPosition = advance (regionOutputPosition state) actionLength }
    , ExplainRegion (regionOutputPosition state) actionLength "SourceRead " (PayloadCopy FromSource)
        (AnnotAt AtOutput (regionOutputPosition state) [DetailSource (regionOutputPosition state)])
    )
  TargetRead payload ->
    let payloadLength = Length (ByteString.length payload)
    in ( state { regionOutputPosition = advance (regionOutputPosition state) payloadLength }
       , ExplainRegion (regionOutputPosition state) payloadLength "TargetRead " (PayloadWrite payload)
           (AnnotAt AtOutput (regionOutputPosition state) [])
       )
  SourceCopy actionLength actionDelta ->
    let nextSourceRelative = displace (regionSourceRelative state) actionDelta
        nextOutputPosition = advance (regionOutputPosition state) actionLength
        advancedSourceRelative = advance nextSourceRelative actionLength
    in ( BPSRegionState nextOutputPosition advancedSourceRelative
       , ExplainRegion (regionOutputPosition state) actionLength "SourceCopy " (PayloadCopy FromSource)
           (AnnotAt AtOutput (regionOutputPosition state)
             [ DetailSource (Offset (unSignedOffset nextSourceRelative))
             , DetailDelta actionDelta
             ])
       )
  TargetCopy actionLength actionDelta ->
    ( state { regionOutputPosition = advance (regionOutputPosition state) actionLength }
    , ExplainRegion (regionOutputPosition state) actionLength "TargetCopy " (PayloadCopy FromTarget)
        (AnnotAt AtOutput (regionOutputPosition state) [DetailDelta actionDelta])
    )
