module Slap.DPS.Describe
  ( dpsInfo
  , dpsMeta
  , explainDPS
  , makeDPSRegion
  ) where

import Slap.DPS.Types (DPSPatch(..), DPSRecord(..), DPSStability(..))
import Slap.Explain
    ( ExplainData(..), ExplainSection(..), ExplainRegion(..)
    , ExplainPayload(..), CopySource(..), ExplainSummary(..)
    , SummaryInfo(..), SummaryByteInfo(..), SummaryBytes(..)
    , Annotation(..), OffsetKind(..), AnnotDetail(..)
    )
import Slap.Format (MetaField(..), renderField)
import Slap.Measure (Length(..), FileSize(..))

import Slap.TextEncoding (decodeLocaleField)

import qualified Data.ByteString as ByteString

----------------------------------------------------------------------------
-- Info
----------------------------------------------------------------------------

dpsMeta :: DPSPatch -> [MetaField]
dpsMeta patch = concat
  [ fieldPair "name"    (dpsName patch)
  , fieldPair "author"  (dpsAuthor patch)
  , fieldPair "version" (dpsVersion patch)
  , [MetaField "orig size" (show (unFileSize (dpsOriginalSize patch)))]
  , [MetaField "flag" "unstable" | dpsStability patch == DPSUnstable]
  ]
  where
    fieldPair _ value | ByteString.null value = []
    fieldPair label value = [MetaField label (decodeLocaleField value)]

dpsInfo :: DPSPatch -> String
dpsInfo patch = unlines $ filter (not . null) $
  [ "format:      DPS (Deufeufeu Patching System)" ]
  ++ map renderField (dpsMeta patch)
  ++ [ "records:     " ++ show (length (dpsRecords patch))
     , "  copy:      " ++ show copyCount
     , "  enclosed:  " ++ show enclosedCount
     ]
  where
    copyCount = length [() | DPSCopyFromROM {} <- dpsRecords patch]
    enclosedCount = length [() | DPSEnclosedData {} <- dpsRecords patch]

----------------------------------------------------------------------------
-- Explain
----------------------------------------------------------------------------

explainDPS :: DPSPatch -> ExplainData
explainDPS patch = ExplainData
  { explainFormat   = "DPS (Deufeufeu Patching System)"
  , explainHeader   = dpsMeta patch
  , explainSections = [SectionRegions (map makeDPSRegion (dpsRecords patch))]
  , explainSummary  = Summary (SummaryInfo recordCount "records" (Just (SummaryByteInfo totalBytes BytesTotal)))
  , explainNotes    = []
  }
  where
    recordCount = length (dpsRecords patch)
    totalBytes = sum (map recordBytes (dpsRecords patch))
    recordBytes (DPSEnclosedData _ payload)       = ByteString.length payload
    recordBytes (DPSCopyFromROM _ _ copyLength) = unLength copyLength

makeDPSRegion :: DPSRecord -> ExplainRegion
makeDPSRegion (DPSEnclosedData outputOffset payload) = ExplainRegion
  { regionOffset     = outputOffset
  , regionSize       = Length (ByteString.length payload)
  , regionLabel      = "Data   "
  , regionPayload    = PayloadWrite payload
  , regionAnnotation = AnnotAt AtOffset outputOffset []
  }
makeDPSRegion (DPSCopyFromROM outputOffset sourceOffset copyLength) = ExplainRegion
  { regionOffset     = outputOffset
  , regionSize       = copyLength
  , regionLabel      = "Copy   "
  , regionPayload    = PayloadCopy FromSource
  , regionAnnotation = AnnotAt AtOffset outputOffset [DetailSource sourceOffset]
  }
