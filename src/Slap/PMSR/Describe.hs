module Slap.PMSR.Describe
  ( pmsrInfo
  , pmsrMeta
  , explainPMSR
  , makePMSRRegion
  , pmsrRecordsRange
  ) where

import Slap.PMSR.Types (PMSRPatch(..), PMSRRecord(..))
import Slap.Explain
    ( ExplainData(..), ExplainSection(..), ExplainRegion(..)
    , ExplainPayload(..), ExplainSummary(..)
    , SummaryInfo(..), SummaryByteInfo(..), SummaryBytes(..)
    , Annotation(..), OffsetKind(..)
    )
import Slap.Display (InfoLine)
import Slap.Measure (Offset(..), Length(..),
                     OffsetRange(..), advance, byteLength)
import Data.Vector (Vector)

import qualified Data.ByteString as ByteString
import qualified Data.Vector as Vector
import Data.Word (Word64)
import Numeric (showHex)

----------------------------------------------------------------------------
-- Info
----------------------------------------------------------------------------

-- | PMSR carries no header metadata; this returns an empty list.
pmsrMeta :: PMSRPatch -> [InfoLine]
pmsrMeta _ = []

pmsrInfo :: PMSRPatch -> String
pmsrInfo patch = unlines $ filter (not . null)
  [ "format:      PMSR (Paper Mario Star Rod)"
  , "records:     " ++ show recordCount
  , "total bytes: " ++ show totalBytes
  , rangeLine
  ]
  where
    records      = pmsrRecords patch
    recordCount  = Vector.length records
    totalBytes   = Vector.foldl' addPayloadBytes 0 records

    addPayloadBytes runningTotal record =
      runningTotal + ByteString.length (pmsrData record)

    rangeLine
      | Vector.null records = "range:       (empty patch)"
      | otherwise =
          "range:       0x" ++ showHex (fromIntegral firstAffectedByte :: Word64) ""
          ++ " - 0x" ++ showHex (fromIntegral endAffectedByte :: Word64) ""

    firstAffectedByte =
      Vector.minimum (Vector.map (unOffset . pmsrOffset) records)
    endAffectedByte =
      unOffset (Vector.maximum (Vector.map recordEndOffset records))

    recordEndOffset record =
      advance (pmsrOffset record) (byteLength (pmsrData record))

----------------------------------------------------------------------------
-- Explain
----------------------------------------------------------------------------

explainPMSR :: PMSRPatch -> ExplainData
explainPMSR patch = ExplainData
  { explainFormat   = "PMSR (Paper Mario Star Rod)"
  , explainHeader   = pmsrMeta patch
  , explainSections = [SectionRegions (map makePMSRRegion (Vector.toList records))]
  , explainSummary  = Summary (SummaryInfo recordCount "records" (Just (SummaryByteInfo totalBytes BytesTotal)))
  , explainNotes    = []
  }
  where
    records      = pmsrRecords patch
    recordCount  = Vector.length records
    totalBytes   = Vector.foldl' addPayloadBytes 0 records

    addPayloadBytes runningTotal record =
      runningTotal + ByteString.length (pmsrData record)

makePMSRRegion :: PMSRRecord -> ExplainRegion
makePMSRRegion record = ExplainRegion
  { regionOffset     = pmsrOffset record
  , regionSize       = Length (ByteString.length (pmsrData record))
  , regionLabel      = "Write  "
  , regionPayload    = PayloadWrite (pmsrData record)
  , regionAnnotation = AnnotAt AtOffset (pmsrOffset record) []
  }

----------------------------------------------------------------------------
-- Display range
----------------------------------------------------------------------------

-- | The 'OffsetRange' spanning a non-empty PMSR record stream,
-- consumed by the cheap display path's 'Slap.Display.PatchHeader'
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
