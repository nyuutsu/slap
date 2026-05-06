module Slap.PMSR.Describe
  ( pmsrMeta
  , analyzePMSR
  , makePMSRRegion
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
import Slap.Measure (Offset(..), Length(..),
                     OffsetRange(..), advance, byteLength)
import Data.Vector (Vector)

import qualified Data.ByteString as ByteString
import qualified Data.Vector as Vector

----------------------------------------------------------------------------
-- Info
----------------------------------------------------------------------------

-- | PMSR carries no header metadata; this returns an empty list.
pmsrMeta :: PMSRPatch -> [InfoLine]
pmsrMeta _ = []

----------------------------------------------------------------------------
-- Explain
----------------------------------------------------------------------------

analyzePMSR :: PMSRPatch -> PatchAnalysis
analyzePMSR patch = PatchAnalysis
  { analysisSections = [SectionRegions (map makePMSRRegion (Vector.toList records))]
  , analysisSummary  = Summary (SummaryInfo (Tally recordCount) Records (Just (TotalPayloadBytes (Length totalBytes))))
  }
  where
    records      = pmsrRecords patch
    recordCount  = Vector.length records
    totalBytes   = Vector.foldl' addPayloadBytes 0 records

    addPayloadBytes runningTotal record =
      runningTotal + ByteString.length (pmsrData record)

makePMSRRegion :: PMSRRecord -> AnalysisRegion
makePMSRRegion record = AnalysisRegion
  { regionOffset     = pmsrOffset record
  , regionSize       = Length (ByteString.length (pmsrData record))
  , regionLabel      = "Write  "
  , regionPayload    = PayloadWrite (pmsrData record)
  , regionAnnotation = AnnotationAt AtOffset (pmsrOffset record) []
  }

----------------------------------------------------------------------------
-- Display range
----------------------------------------------------------------------------

-- | The 'OffsetRange' spanning a non-empty PMSR record stream,
-- consumed by the cheap display path's 'Slap.Display.Info.PatchInfo'
-- construction. Returns 'Nothing' on an empty stream so the display
-- layer suppresses the range line.
pmsrRecordsRange :: Vector PMSRRecord -> Maybe OffsetRange
pmsrRecordsRange records
  | Vector.null records = Nothing
  | otherwise =
      let firstAffectedOffset = Vector.minimum (Vector.map pmsrOffset records)
          endOfLastRecord     = Vector.maximum (Vector.map recordEndOffset records)
      in Just OffsetRange
          { rangeStart  = firstAffectedOffset
          , rangeLength = Length (unOffset endOfLastRecord - unOffset firstAffectedOffset)
          }
  where
    recordEndOffset record =
      advance (pmsrOffset record) (byteLength (pmsrData record))
