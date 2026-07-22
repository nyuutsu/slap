{-# LANGUAGE OverloadedStrings #-}

module Slap.PMSR.Describe
  ( pmsrMeta
  , analyzePMSR
  , pmsrRecordRegion
  , pmsrRecordsRange
  ) where

import Slap.PMSR.Types (PMSRPatch(..), PMSRRecord(..))
import Slap.Display.Analysis
    ( PatchAnalysis(..), AnalysisSection(..), AnalysisRegion(..)
    , AnalysisPayload(..), LiteralWriteBytes(..), AnalysisSummary(..)
    , SummaryInfo(..)
    , Annotation(..), OffsetKind(..)
    )
import Slap.Display.Common (InfoLine, Tally(..), CountUnit(..), ByteCount(..))
import Slap.Measure (OffsetRange, byteLength, writtenOffsetRange)
import Data.Vector (Vector)

import qualified Data.Vector as Vector

----------------------------------------------------------------------------
-- Info
----------------------------------------------------------------------------

-- | PMSR carries no header metadata.
pmsrMeta :: PMSRPatch -> [InfoLine]
pmsrMeta _ = []

----------------------------------------------------------------------------
-- Analyze
----------------------------------------------------------------------------

analyzePMSR :: PMSRPatch -> PatchAnalysis
analyzePMSR patch = PatchAnalysis
  { analysisSections = [SectionRegions (map pmsrRecordRegion (Vector.toList records))]
  , analysisSummary  = Summary (SummaryInfo (Tally recordCount) Records (Just (TotalPayloadBytes totalBytes)))
  }
  where
    records      = pmsrRecords patch
    recordCount  = Vector.length records
    totalBytes   = foldMap (byteLength . pmsrData) records

pmsrRecordRegion :: PMSRRecord -> AnalysisRegion
pmsrRecordRegion record = AnalysisRegion
  { regionOffset     = pmsrOffset record
  , regionSize       = byteLength (pmsrData record)
  , regionLabel      = "Write  "
  , regionPayload    = PayloadWrite (LiteralWriteBytes (pmsrData record))
  , regionAnnotation = AnnotationAt AtOffset (pmsrOffset record) []
  }

----------------------------------------------------------------------------
-- Display range
----------------------------------------------------------------------------

-- | Consumed by the cheap display path's 'Slap.Display.Info.PatchInfo' construction;
-- 'Nothing' on an empty stream so the display layer suppresses the range line.
pmsrRecordsRange :: Vector PMSRRecord -> Maybe OffsetRange
pmsrRecordsRange records =
  writtenOffsetRange (Vector.map (\record -> (pmsrOffset record, byteLength (pmsrData record))) records)
