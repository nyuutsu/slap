module Slap.APSN64.Describe
  ( apsN64Info
  , apsN64Meta
  , explainAPSN64
  , makeN64Region
  ) where

import Slap.APSN64.Types
import Slap.Explain (ExplainData(..), ExplainSection(..), ExplainRegion(..),
                     ExplainPayload(..), ExplainSummary(..), SummaryInfo(..),
                     Annotation(..), OffsetKind(..), AnnotDetail(..))
import Slap.Format (padHex, renderField)
import Slap.Measure (Length(..), FileSize(..))

import qualified Data.ByteString as ByteString

apsN64Meta :: APSN64Patch -> [(String, String)]
apsN64Meta (APSN64Patch header _) = concat
  [ [("patch type", patchTypeName (apsN64PatchType header))]
  , [("encoding", show (apsN64Encoding header)) | apsN64Encoding header /= 0]
  , descriptionField (apsN64Description header)
  , formatField (apsN64ImageFormat header)
  , cartField (apsN64CartId header)
  , countryField (apsN64Country header)
  , [("dest size", show (unFileSize (apsN64DestinationSize header)))]
  ]
  where
    descriptionField description
      | ByteString.all (\byte -> byte == 0x20 || byte == 0) description = []
      | otherwise = [("description", show (ByteString.takeWhile (/= 0) description))]
    patchTypeName APSSimple      = "simple"
    patchTypeName APSN64Specific = "N64-specific"
    formatField Nothing                       = []
    formatField (Just V64Format)              = [("image", "V64 (byteswapped)")]
    formatField (Just Z64Format)              = [("image", "Z64 (big-endian)")]
    formatField (Just (UnknownImageFormat format)) = [("image", "unknown (" ++ show format ++ ")")]
    cartField Nothing      = []
    cartField (Just cartId) = [("cart ID", concatMap (\byte -> padHex 2 (fromIntegral byte)) (ByteString.unpack cartId))]
    countryField Nothing        = []
    countryField (Just country) = [("country", "0x" ++ padHex 2 (fromIntegral country))]

apsN64Info :: APSN64Patch -> String
apsN64Info patch@(APSN64Patch _ records) = unlines $ filter (not . null) $
  [ "format:      APS (N64)" ]
  ++ map renderField (apsN64Meta patch)
  ++ [ "records:     " ++ show (length records) ]

explainAPSN64 :: APSN64Patch -> ExplainData
explainAPSN64 patch@(APSN64Patch _header records) = ExplainData
  { explainFormat   = "APS (N64)"
  , explainHeader   = apsN64Meta patch
  , explainSections = [SectionRegions (map makeN64Region records)]
  , explainSummary  = Summary (SummaryInfo (length records) "records" Nothing)
  , explainNotes    = []
  }

makeN64Region :: APSN64Record -> ExplainRegion
makeN64Region (APSN64Normal recordOffset recordPayload) = ExplainRegion
  { regionOffset     = recordOffset
  , regionSize       = Length (ByteString.length recordPayload)
  , regionLabel      = "Write  "
  , regionPayload    = PayloadWrite recordPayload
  , regionAnnotation = AnnotAt AtOffset recordOffset []
  }
makeN64Region (APSN64RLE rle) = ExplainRegion
  { regionOffset     = apsN64RLEOffset rle
  , regionSize       = Length (fromIntegral (apsN64RLERepeatCount rle))
  , regionLabel      = "Fill "
  , regionPayload    = PayloadFill (apsN64RLEFillValue rle) (Length (fromIntegral (apsN64RLERepeatCount rle)))
  , regionAnnotation = AnnotAt AtOffset (apsN64RLEOffset rle) [DetailRLE]
  }
