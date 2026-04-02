module Slap.NINJA1.Describe
  ( ninja1Info
  , ninja1Meta
  , explainNINJA1
  , makeNINJA1Region
  ) where

import Slap.NINJA1.Types (NINJA1Patch(..), NINJA1Record(..), NINJA1SubFormat(..),
                           romTypeName)
import Slap.Explain (ExplainData(..), ExplainSection(..), ExplainRegion(..),
                      ExplainPayload(..), ExplainSummary(..), SummaryInfo(..),
                      SummaryByteInfo(..), SummaryBytes(..),
                      Annotation(..), OffsetKind(..))
import Slap.Checksum (showCRC32)
import Slap.Format (padHex, renderField)
import Slap.Measure (Length(..))

import qualified Data.ByteString as ByteString

----------------------------------------------------------------------------
-- Info
----------------------------------------------------------------------------

ninja1Meta :: NINJA1Patch -> [(String, String)]
ninja1Meta patch = concat
  [ [("ROM type", romTypeName (ninja1RomType patch))]
  , case ninja1SourceCRC patch of
      Nothing  -> []
      Just crc -> [("source CRC", "0x" ++ showCRC32 crc)]
  , case ninja1SourceMD5 patch of
      Nothing   -> []
      Just hash -> [("source MD5", concatMap (\byte -> padHex 2 (fromIntegral byte)) (ByteString.unpack hash))]
  , case ninja1SourceSHA1 patch of
      Nothing   -> []
      Just hash -> [("source SHA1", concatMap (\byte -> padHex 2 (fromIntegral byte)) (ByteString.unpack hash))]
  ]

ninja1Info :: NINJA1Patch -> String
ninja1Info patch = unlines $ filter (not . null) $
  [ "format:      NINJA1 (" ++ subFormatString ++ ")" ]
  ++ map renderField (ninja1Meta patch)
  ++ [ "records:     " ++ show (length (ninja1Records patch))
     , "total bytes: " ++ show totalBytes
     ]
  where
    subFormatString = case ninja1SubFormat patch of
      Ninja1Binary  -> "binary"
      Ninja1BinaryCompressed -> "binary, compressed"
      Ninja1Text    -> "text"
      Ninja1TextCompressed   -> "text, compressed"
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
    subFormatString = case ninja1SubFormat patch of
      Ninja1Binary -> "binary"
      Ninja1BinaryCompressed -> "binary, compressed"
      Ninja1Text   -> "text"
      Ninja1TextCompressed   -> "text, compressed"
    totalBytes = sum (map (ByteString.length . ninja1RecordData) (ninja1Records patch))

makeNINJA1Region :: NINJA1Record -> ExplainRegion
makeNINJA1Region (NINJA1Record recordOffset recordPayload) = ExplainRegion
  { regionOffset     = recordOffset
  , regionSize       = Length (ByteString.length recordPayload)
  , regionLabel      = "Write  "
  , regionPayload    = PayloadWrite recordPayload
  , regionAnnotation = AnnotAt AtOffset recordOffset []
  }
