module Slap.DPS.Describe
  ( dpsInfo
  , dpsMeta
  , explainDPS
  , makeDPSRegion
  ) where

import Slap.DPS.Types (DPSPatch(..), DPSRecord(..), DPSMode(..), DPSStability(..))
import qualified Slap.DPS.Types as DPS
import Slap.Explain
    ( ExplainData(..), ExplainSection(..), ExplainRegion(..)
    , ExplainPayload(..), CopySource(..), ExplainSummary(..)
    , SummaryBytes(..), Annotation(..), OffsetKind(..), AnnotDetail(..)
    )
import Slap.Format (renderField)
import Slap.Measure (Offset(..), Length(..), FileSize(..))

import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Char8 as ByteString8

----------------------------------------------------------------------------
-- Info
----------------------------------------------------------------------------

dpsMeta :: DPSPatch -> [(String, String)]
dpsMeta patch = concat
  [ fieldPair "name"    (dpsName patch)
  , fieldPair "author"  (dpsAuthor patch)
  , fieldPair "version" (dpsVersion patch)
  , [("orig size", show (unFileSize (dpsOriginalSize patch)))]
  , [("flag", "unstable") | dpsStability patch == DPSUnstable]
  ]
  where
    fieldPair _ value | ByteString.null value = []
    fieldPair label value = [(label, ByteString8.unpack value)]

dpsInfo :: DPSPatch -> String
dpsInfo patch = unlines $ filter (not . null) $
  [ "format:      DPS (Deufeufeu Patching System)" ]
  ++ map renderField (dpsMeta patch)
  ++ [ "records:     " ++ show (length (dpsRecords patch))
     , "  copy:      " ++ show copyCount
     , "  enclosed:  " ++ show enclosedCount
     ]
  where
    copyCount = length [() | DPSRecord CopyFromROM _ _ <- dpsRecords patch]
    enclosedCount = length [() | DPSRecord EnclosedData _ _ <- dpsRecords patch]

----------------------------------------------------------------------------
-- Explain
----------------------------------------------------------------------------

explainDPS :: DPSPatch -> ExplainData
explainDPS patch = ExplainData
  { explainFormat   = "DPS (Deufeufeu Patching System)"
  , explainHeader   = dpsMeta patch
  , explainSections = [SectionRegions (map makeDPSRegion (dpsRecords patch))]
  , explainSummary  = Summary recordCount "records" (Just (totalBytes, BytesTotal))
  , explainNotes    = []
  }
  where
    recordCount = length (dpsRecords patch)
    totalBytes = sum (map recordBytes (dpsRecords patch))
    recordBytes record = case dpsRecordPayload record of
      DPS.PayloadData payload     -> ByteString.length payload
      DPS.PayloadCopy _ copyLength -> fromIntegral copyLength

makeDPSRegion :: DPSRecord -> ExplainRegion
makeDPSRegion record = case dpsRecordPayload record of
  DPS.PayloadData payload -> ExplainRegion
    { regionOffset     = dpsRecordOutputOffset record
    , regionSize       = Length (ByteString.length payload)
    , regionLabel      = "Data   "
    , regionPayload    = PayloadWrite payload
    , regionAnnotation = AnnotAt AtOffset (dpsRecordOutputOffset record) []
    }
  DPS.PayloadCopy sourceOffset copyLength -> ExplainRegion
    { regionOffset     = dpsRecordOutputOffset record
    , regionSize       = Length (fromIntegral copyLength)
    , regionLabel      = "Copy   "
    , regionPayload    = PayloadCopy FromSource
    , regionAnnotation = AnnotAt AtOffset (dpsRecordOutputOffset record) [DetailSource (Offset sourceOffset)]
    }
