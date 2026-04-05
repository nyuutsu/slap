module Slap.BPS.Describe
  ( bpsInfo
  , bpsMeta
  , explainBPS
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
import Slap.Measure (Offset(..), Length(..), FileSize(..), Delta(..))

import Slap.TextEncoding (decodeLocaleField)

import qualified Data.ByteString as ByteString
import Data.List (mapAccumL)

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
                        ++ map sanitize (decodeLocaleField (ByteString.take 200 metadata))
                        ++ if ByteString.length metadata > 200 then "..." else ""
    sanitize character
      | character >= ' ' && character <= '~' = character
      | otherwise                            = '.'

bpsInfo :: BPSPatch -> String
bpsInfo patch = unlines $ filter (not . null) $
  [ "format:      BPS" ]
  ++ map renderField (bpsMeta patch)
  ++ [ "actions:     " ++ show (length (bpsActions patch)) ]

explainBPS :: BPSPatch -> ExplainData
explainBPS patch = ExplainData
  { explainFormat   = "BPS"
  , explainHeader   = bpsMeta patch
  , explainSections = [SectionRegions (snd (mapAccumL makeBPSRegion (0, 0) (bpsActions patch)))]
  , explainSummary  = Summary (SummaryInfo actionCount "actions" (Just (SummaryByteInfo (unFileSize (bpsTargetSize patch)) BytesTotalOutput)))
  , explainNotes    = []
  }
  where
    actionCount = length (bpsActions patch)

makeBPSRegion :: (Int, Int) -> BPSAction -> ((Int, Int), ExplainRegion)
makeBPSRegion (outputPosition, sourceRelative) action = case action of
  SourceRead actionLength ->
    let dataLength = unLength actionLength
    in ( (outputPosition + dataLength, sourceRelative)
       , ExplainRegion (Offset outputPosition) actionLength "SourceRead " (PayloadCopy FromSource)
           (AnnotAt AtOutput (Offset outputPosition) [DetailSource (Offset outputPosition)])
       )
  TargetRead payload ->
    let dataLength = ByteString.length payload
    in ( (outputPosition + dataLength, sourceRelative)
       , ExplainRegion (Offset outputPosition) (Length dataLength) "TargetRead " (PayloadWrite payload)
           (AnnotAt AtOutput (Offset outputPosition) [])
       )
  SourceCopy actionLength actionDelta ->
    let dataLength = unLength actionLength
        nextSourceRelative = sourceRelative + unDelta actionDelta
    in ( (outputPosition + dataLength, nextSourceRelative + dataLength)
       , ExplainRegion (Offset outputPosition) actionLength "SourceCopy " (PayloadCopy FromSource)
           (AnnotAt AtOutput (Offset outputPosition) [DetailSource (Offset nextSourceRelative), DetailDelta actionDelta])
       )
  TargetCopy actionLength actionDelta ->
    let dataLength = unLength actionLength
    in ( (outputPosition + dataLength, sourceRelative)
       , ExplainRegion (Offset outputPosition) actionLength "TargetCopy " (PayloadCopy FromTarget)
           (AnnotAt AtOutput (Offset outputPosition) [DetailDelta actionDelta])
       )
