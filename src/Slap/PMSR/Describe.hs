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
    , AnalysisPayload(..), AnalysisSummary(..)
    , SummaryInfo(..)
    , Annotation(..), OffsetKind(..)
    )
import Slap.Display.Common (InfoLine, Tally(..), CountUnit(..), ByteCount(..))
import Slap.Measure (Length(..),
                     OffsetRange(..), advance, byteLength, distance)
import Data.Vector (Vector)

import qualified Data.ByteString as ByteString
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
  , analysisSummary  = Summary (SummaryInfo (Tally recordCount) Records (Just (TotalPayloadBytes (Length totalBytes))))
  }
  where
    records      = pmsrRecords patch
    recordCount  = Vector.length records
    totalBytes   = Vector.foldl' addPayloadBytes 0 records

    addPayloadBytes runningTotal record =
      runningTotal + ByteString.length (pmsrData record)

pmsrRecordRegion :: PMSRRecord -> AnalysisRegion
pmsrRecordRegion record = AnalysisRegion
  { regionOffset     = pmsrOffset record
  , regionSize       = byteLength (pmsrData record)
  , regionLabel      = "Write  "
  , regionPayload    = PayloadWrite (pmsrData record)
  , regionAnnotation = AnnotationAt AtOffset (pmsrOffset record) []
  }

----------------------------------------------------------------------------
-- Display range
----------------------------------------------------------------------------

-- | Consumed by the cheap display path's 'Slap.Display.Info.PatchInfo' construction;
-- 'Nothing' on an empty stream so the display layer suppresses the range line.
pmsrRecordsRange :: Vector PMSRRecord -> Maybe OffsetRange
pmsrRecordsRange records
  | Vector.null records = Nothing
  | otherwise =
      let firstAffectedOffset = Vector.minimum (Vector.map pmsrOffset records)
          endOfLastRecord     = Vector.maximum (Vector.map recordEndOffset records)
      in Just OffsetRange
          { rangeStart  = firstAffectedOffset
          , rangeLength = distance firstAffectedOffset endOfLastRecord
          }
  where
    recordEndOffset record =
      advance (pmsrOffset record) (byteLength (pmsrData record))
