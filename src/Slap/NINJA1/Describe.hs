module Slap.NINJA1.Describe
  ( ninja1Info
  , ninja1Meta
  , explainNINJA1
  , makeNINJA1Region
  ) where

import Slap.NINJA1.Types (NINJA1Patch(..), NINJA1Record(..), NINJA1SubFormat(..),
                           romTypeName, subFormatName)
import Slap.Explain (ExplainData(..), ExplainSection(..), ExplainRegion(..),
                      ExplainPayload(..), ExplainSummary(..), SummaryInfo(..),
                      SummaryByteInfo(..), SummaryBytes(..),
                      Annotation(..), OffsetKind(..))
import Slap.Checksum (showCRC32, MD5Hash(..), SHA1Hash(..))
import Slap.Format (MetaField(..), padHex, renderField)
import Slap.Measure (Length(..))

import qualified Data.ByteString as ByteString

----------------------------------------------------------------------------
-- Info
----------------------------------------------------------------------------

ninja1Meta :: NINJA1Patch -> [MetaField]
ninja1Meta patch = concat
  [ [MetaField "ROM type" (romTypeName (ninja1RomType patch))]
  , case ninja1SourceCRC patch of
      Nothing  -> []
      Just crc -> [MetaField "source CRC" ("0x" ++ showCRC32 crc)]
  , case ninja1SourceMD5 patch of
      Nothing              -> []
      Just (MD5Hash hash)  -> [MetaField "source MD5" (concatMap (\byte -> padHex 2 (fromIntegral byte)) (ByteString.unpack hash))]
  , case ninja1SourceSHA1 patch of
      Nothing              -> []
      Just (SHA1Hash hash) -> [MetaField "source SHA1" (concatMap (\byte -> padHex 2 (fromIntegral byte)) (ByteString.unpack hash))]
  ]

ninja1Info :: NINJA1Patch -> String
ninja1Info patch = unlines $ filter (not . null) $
  [ "format:      NINJA1 (" ++ subFormatString ++ ")" ]
  ++ map renderField (ninja1Meta patch)
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
