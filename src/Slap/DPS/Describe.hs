module Slap.DPS.Describe
  ( dpsInfo
  , dpsMeta
  , analyzeDPS
  , makeDPSRegion
  ) where

import Slap.DPS.Types (DPSPatch(..), DPSRecord(..), DPSStability(..))
import Slap.Explain
    ( PatchAnalysis(..), AnalysisSection(..), AnalysisRegion(..)
    , AnalysisPayload(..), CopySource(..), AnalysisSummary(..)
    , SummaryInfo(..), SummaryByteInfo(..), SummaryBytes(..)
    , Annotation(..), OffsetKind(..), AnnotDetail(..)
    )
import Slap.Display (InfoLine(..), renderInfoLine)
import Slap.Measure (Length(..), FileSize(..))

import Slap.TextEncoding (decodeLocaleField)

import qualified Data.ByteString as ByteString

----------------------------------------------------------------------------
-- Info
----------------------------------------------------------------------------

dpsMeta :: DPSPatch -> [InfoLine]
dpsMeta patch = concat
  [ fieldPair "name"    (dpsName patch)
  , fieldPair "author"  (dpsAuthor patch)
  , fieldPair "version" (dpsVersion patch)
  , [InfoLine "orig size" (show (unFileSize (dpsOriginalSize patch)))]
  , [InfoLine "flag" "unstable" | dpsStability patch == DPSUnstable]
  ]
  where
    fieldPair _ value | ByteString.null value = []
    fieldPair label value = [InfoLine label (decodeLocaleField value)]

dpsInfo :: DPSPatch -> String
dpsInfo patch = unlines $ filter (not . null) $
  [ "format:      DPS" ]
  ++ map renderInfoLine (dpsMeta patch)
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

analyzeDPS :: DPSPatch -> PatchAnalysis
analyzeDPS patch = PatchAnalysis
  { analysisSections = [SectionRegions (map makeDPSRegion (dpsRecords patch))]
  , analysisSummary  = Summary (SummaryInfo recordCount "records" (Just (SummaryByteInfo totalBytes BytesTotal)))
  }
  where
    recordCount = length (dpsRecords patch)
    totalBytes = sum (map recordBytes (dpsRecords patch))
    recordBytes (DPSEnclosedData _ payload)       = ByteString.length payload
    recordBytes (DPSCopyFromROM _ _ copyLength) = unLength copyLength

makeDPSRegion :: DPSRecord -> AnalysisRegion
makeDPSRegion (DPSEnclosedData outputOffset payload) = AnalysisRegion
  { regionOffset     = outputOffset
  , regionSize       = Length (ByteString.length payload)
  , regionLabel      = "Data   "
  , regionPayload    = PayloadWrite payload
  , regionAnnotation = AnnotAt AtOffset outputOffset []
  }
makeDPSRegion (DPSCopyFromROM outputOffset sourceOffset copyLength) = AnalysisRegion
  { regionOffset     = outputOffset
  , regionSize       = copyLength
  , regionLabel      = "Copy   "
  , regionPayload    = PayloadCopy FromSource
  , regionAnnotation = AnnotAt AtOffset outputOffset [DetailSource sourceOffset]
  }
