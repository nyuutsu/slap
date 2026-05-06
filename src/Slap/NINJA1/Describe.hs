module Slap.NINJA1.Describe
  ( ninja1Meta
  , analyzeNINJA1
  , makeNINJA1Region
  , ninja1RecordsRange
  ) where

import Slap.NINJA1.Types (NINJA1Patch(..), NINJA1Record(..),
                           romTypeName)
import Slap.Display.Analysis (PatchAnalysis(..), AnalysisSection(..), AnalysisRegion(..),
                      AnalysisPayload(..), AnalysisSummary(..), SummaryInfo(..),
                      Annotation(..), OffsetKind(..))
import Slap.Checksum (showCRC32, MD5Hash(..), SHA1Hash(..))
import Slap.Display.Common (InfoLine(..),
                     Tally(..), CountUnit(..), ByteCount(..))
import Slap.Display.Primitives (padHex)
import Slap.Measure (Offset(..), Length(..),
                     OffsetRange(..), advance, byteLength)

import qualified Data.ByteString as ByteString

----------------------------------------------------------------------------
-- Info
----------------------------------------------------------------------------

ninja1Meta :: NINJA1Patch -> [InfoLine]
ninja1Meta patch = concat
  [ [InfoLine "ROM type" (romTypeName (ninja1RomType patch))]
  , case ninja1SourceCRC patch of
      Nothing  -> []
      Just crc -> [InfoLine "source CRC" ("0x" ++ showCRC32 crc)]
  , case ninja1SourceMD5 patch of
      Nothing              -> []
      Just (MD5Hash hash)  -> [InfoLine "source MD5" (concatMap (\byte -> padHex 2 byte) (ByteString.unpack hash))]
  , case ninja1SourceSHA1 patch of
      Nothing              -> []
      Just (SHA1Hash hash) -> [InfoLine "source SHA1" (concatMap (\byte -> padHex 2 byte) (ByteString.unpack hash))]
  ]

----------------------------------------------------------------------------
-- Analyze
----------------------------------------------------------------------------

analyzeNINJA1 :: NINJA1Patch -> PatchAnalysis
analyzeNINJA1 patch = PatchAnalysis
  { analysisSections = [SectionRegions (map makeNINJA1Region (ninja1Records patch))]
  , analysisSummary  = Summary (SummaryInfo (Tally recordCount) Records (Just (TotalPayloadBytes (Length totalBytes))))
  }
  where
    recordCount = length (ninja1Records patch)
    totalBytes = sum (map (ByteString.length . ninja1RecordData) (ninja1Records patch))

makeNINJA1Region :: NINJA1Record -> AnalysisRegion
makeNINJA1Region (NINJA1Record recordOffset recordPayload) = AnalysisRegion
  { regionOffset     = recordOffset
  , regionSize       = Length (ByteString.length recordPayload)
  , regionLabel      = "Write  "
  , regionPayload    = PayloadWrite recordPayload
  , regionAnnotation = AnnotationAt AtOffset recordOffset []
  }

----------------------------------------------------------------------------
-- Display range
----------------------------------------------------------------------------

-- | The 'OffsetRange' spanning a non-empty NINJA1 record stream,
-- consumed by the cheap display path's 'Slap.Display.Info.PatchInfo'
-- construction. Returns 'Nothing' on an empty stream so the display
-- layer suppresses the range line.
ninja1RecordsRange :: [NINJA1Record] -> Maybe OffsetRange
ninja1RecordsRange [] = Nothing
ninja1RecordsRange records =
  let firstAffectedOffset = minimum (map ninja1RecordOffset records)
      endOfLastRecord     = maximum (map recordEndOffset records)
  in Just OffsetRange
      { rangeStart  = firstAffectedOffset
      , rangeLength = Length (unOffset endOfLastRecord - unOffset firstAffectedOffset)
      }
  where
    recordEndOffset record =
      advance (ninja1RecordOffset record) (byteLength (ninja1RecordData record))
