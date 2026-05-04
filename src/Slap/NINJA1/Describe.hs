module Slap.NINJA1.Describe
  ( ninja1Info
  , ninja1Meta
  , explainNINJA1
  , makeNINJA1Region
  , ninja1RecordsRange
  ) where

import Slap.NINJA1.Types (NINJA1Patch(..), NINJA1Record(..),
                           romTypeName, subFormatName)
import Slap.Explain (ExplainData(..), ExplainSection(..), ExplainRegion(..),
                      ExplainPayload(..), ExplainSummary(..), SummaryInfo(..),
                      SummaryByteInfo(..), SummaryBytes(..),
                      Annotation(..), OffsetKind(..))
import Slap.Checksum (showCRC32, MD5Hash(..), SHA1Hash(..))
import Slap.Display (InfoLine(..), renderInfoLine)
import Slap.Format (padHex)
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

ninja1Info :: NINJA1Patch -> String
ninja1Info patch = unlines $ filter (not . null) $
  [ "format:      NINJA1 (" ++ subFormatString ++ ")" ]
  ++ map renderInfoLine (ninja1Meta patch)
  ++ [ "records:     " ++ show (length (ninja1Records patch))
     , "total bytes: " ++ show totalBytes
     ]
  where
    subFormatString = subFormatName (ninja1SubFormat patch)
    totalBytes = sum (map (ByteString.length . ninja1RecordData) (ninja1Records patch))

----------------------------------------------------------------------------
-- Explain
----------------------------------------------------------------------------

explainNINJA1 :: NINJA1Patch -> ExplainData
explainNINJA1 patch = ExplainData
  { explainFormat   = "NINJA1 (" ++ subFormatString ++ ")"
  , explainHeader   = ninja1Meta patch
  , explainSections = [SectionRegions (map makeNINJA1Region (ninja1Records patch))]
  , explainSummary  = Summary (SummaryInfo recordCount "records" (Just (SummaryByteInfo totalBytes BytesTotal)))
  , explainNotes    = []
  }
  where
    recordCount = length (ninja1Records patch)
    subFormatString = subFormatName (ninja1SubFormat patch)
    totalBytes = sum (map (ByteString.length . ninja1RecordData) (ninja1Records patch))

makeNINJA1Region :: NINJA1Record -> ExplainRegion
makeNINJA1Region (NINJA1Record recordOffset recordPayload) = ExplainRegion
  { regionOffset     = recordOffset
  , regionSize       = Length (ByteString.length recordPayload)
  , regionLabel      = "Write  "
  , regionPayload    = PayloadWrite recordPayload
  , regionAnnotation = AnnotAt AtOffset recordOffset []
  }

----------------------------------------------------------------------------
-- Display range
----------------------------------------------------------------------------

-- | The 'OffsetRange' spanning a non-empty NINJA1 record stream,
-- consumed by the cheap display path's 'Slap.Display.PatchHeader'
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
