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
import Slap.Format (renderField)
import Slap.Measure (Offset(..), Length(..), FileSize(..), Delta(..))

import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Char8 as ByteString8
import Data.Int (Int64)
import Data.List (mapAccumL)

bpsMeta :: BPSPatch -> [(String, String)]
bpsMeta patch = concat
  [ [("source size", show (unFileSize (bpsSourceSize patch)))]
  , [("target size", show (unFileSize (bpsTargetSize patch)))]
  , [("metadata", metadataDisplay)]
  , [("source CRC", showCRC32 (bpsSourceCRC patch))]
  , [("target CRC", showCRC32 (bpsTargetCRC patch))]
  , [("patch CRC", showCRC32 (bpsPatchCRC patch))]
  ]
  where
    metadata = bpsMetadata patch
    metadataDisplay
      | ByteString.null metadata = "(none)"
      | otherwise        = show (ByteString.length metadata) ++ " bytes: "
                        ++ map sanitize (ByteString8.unpack (ByteString.take 200 metadata))
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
  , explainSummary  = Summary (SummaryInfo actionCount "actions" (Just (SummaryByteInfo (fromIntegral (unFileSize (bpsTargetSize patch))) BytesTotalOutput)))
  , explainNotes    = []
  }
  where
    actionCount = length (bpsActions patch)

makeBPSRegion :: (Int64, Int64) -> BPSAction -> ((Int64, Int64), ExplainRegion)
makeBPSRegion (outputPosition, sourceRelative) action = case action of
  SourceRead actionLength ->
    let dataLength = unLength actionLength
    in ( (outputPosition + fromIntegral dataLength, sourceRelative)
       , ExplainRegion (Offset outputPosition) actionLength "SourceRead " (PayloadCopy FromSource)
           (AnnotAt AtOutput (Offset outputPosition) [DetailSource (Offset outputPosition)])
       )
  TargetRead payload ->
    let dataLength = ByteString.length payload
    in ( (outputPosition + fromIntegral dataLength, sourceRelative)
       , ExplainRegion (Offset outputPosition) (Length dataLength) "TargetRead " (PayloadWrite payload)
           (AnnotAt AtOutput (Offset outputPosition) [])
       )
  SourceCopy actionLength actionDelta ->
    let dataLength = unLength actionLength
        nextSourceRelative = sourceRelative + unDelta actionDelta
    in ( (outputPosition + fromIntegral dataLength, nextSourceRelative + fromIntegral dataLength)
       , ExplainRegion (Offset outputPosition) actionLength "SourceCopy " (PayloadCopy FromSource)
           (AnnotAt AtOutput (Offset outputPosition) [DetailSource (Offset nextSourceRelative), DetailDelta actionDelta])
       )
  TargetCopy actionLength actionDelta ->
    let dataLength = unLength actionLength
    in ( (outputPosition + fromIntegral dataLength, sourceRelative)
       , ExplainRegion (Offset outputPosition) actionLength "TargetCopy " (PayloadCopy FromTarget)
           (AnnotAt AtOutput (Offset outputPosition) [DetailDelta actionDelta])
       )
