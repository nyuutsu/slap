module Slap.PMSR.Describe
  ( pmsrInfo
  , pmsrMeta
  , explainPMSR
  , makePMSRRegion
  ) where

import Slap.PMSR.Types (PMSRPatch(..), PMSRRecord(..))
import Slap.Explain
    ( ExplainData(..), ExplainSection(..), ExplainRegion(..)
    , ExplainPayload(..), ExplainSummary(..)
    , SummaryBytes(..), Annotation(..), OffsetKind(..)
    )
import Slap.Measure (Offset(..), Length(..))

import qualified Data.ByteString as ByteString
import Data.Word (Word64)
import Numeric (showHex)

----------------------------------------------------------------------------
-- Info
----------------------------------------------------------------------------

-- | PMSR carries no header metadata; this returns an empty list.
pmsrMeta :: PMSRPatch -> [(String, String)]
pmsrMeta _ = []

pmsrInfo :: PMSRPatch -> String
pmsrInfo patch = unlines $ filter (not . null)
  [ "format:      PMSR (Paper Mario Star Rod)"
  , "records:     " ++ show recordCount
  , "total bytes: " ++ show totalBytes
  , rangeString
  ]
  where
    recordCount = length (pmsrRecords patch)
    totalBytes = sum (map (ByteString.length . pmsrData) (pmsrRecords patch))

    rangeString
      | null (pmsrRecords patch) = "range:       (empty patch)"
      | otherwise =
          let records = pmsrRecords patch
              lowest = minimum (map (unOffset . pmsrOffset) records)
              highest = maximum (map (\record -> unOffset (pmsrOffset record) + fromIntegral (ByteString.length (pmsrData record))) records)
          in "range:       0x" ++ showHex (fromIntegral lowest :: Word64) ""
             ++ " - 0x" ++ showHex (fromIntegral highest :: Word64) ""

----------------------------------------------------------------------------
-- Explain
----------------------------------------------------------------------------

explainPMSR :: PMSRPatch -> ExplainData
explainPMSR patch = ExplainData
  { explainFormat   = "PMSR (Paper Mario Star Rod)"
  , explainHeader   = pmsrMeta patch
  , explainSections = [SectionRegions (map makePMSRRegion (pmsrRecords patch))]
  , explainSummary  = Summary recordCount "records" (Just (totalBytes, BytesTotal))
  , explainNotes    = []
  }
  where
    recordCount = length (pmsrRecords patch)
    totalBytes = sum (map (ByteString.length . pmsrData) (pmsrRecords patch))

makePMSRRegion :: PMSRRecord -> ExplainRegion
makePMSRRegion record = ExplainRegion
  { regionOffset     = pmsrOffset record
  , regionSize       = Length (ByteString.length (pmsrData record))
  , regionLabel      = "Write  "
  , regionPayload    = PayloadWrite (pmsrData record)
  , regionAnnotation = AnnotAt AtOffset (pmsrOffset record) []
  }
