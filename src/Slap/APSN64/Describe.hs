module Slap.APSN64.Describe
  ( apsN64Meta
  , explainAPSN64
  , makeN64Region
  ) where

import Slap.APSN64.Types
import Slap.Explain (ExplainData(..), ExplainSection(..), ExplainRegion(..),
                     ExplainPayload(..), ExplainSummary(..), SummaryInfo(..),
                     Annotation(..), OffsetKind(..), AnnotDetail(..))
import Slap.Display (InfoLine(..))
import Slap.Format (padHex)
import Slap.Measure (Length(..), FileSize(..))

import qualified Data.ByteString as ByteString
import qualified Data.Vector as Vector

apsN64Meta :: APSN64Patch -> [InfoLine]
apsN64Meta (APSN64Patch header _) = concat
  [ [InfoLine "patch type" (patchTypeName (apsN64PatchType header))]
  , [InfoLine "encoding" (show (fromAPSRecordEncoding (apsN64Encoding header)))
    | apsN64Encoding header /= APSDefaultRecordEncoding]
  , descriptionField (apsN64Description header)
  , formatField (apsN64ImageFormat header)
  , cartField (apsN64CartId header)
  , countryField (apsN64Country header)
  , [InfoLine "dest size" (show (unFileSize (apsN64DestinationSize header)))]
  ]
  where
    descriptionField description
      | ByteString.all (\byte -> byte == 0x20 || byte == 0) description = []
      | otherwise = [InfoLine "description" (show (ByteString.takeWhile (/= 0) description))]
    patchTypeName APSSimple      = "simple"
    patchTypeName APSN64Specific = "N64-specific"
    formatField Nothing                       = []
    formatField (Just V64Format)              = [InfoLine "image" "V64 (byteswapped)"]
    formatField (Just Z64Format)              = [InfoLine "image" "Z64 (big-endian)"]
    formatField (Just (UnknownImageFormat format)) = [InfoLine "image" ("unknown (" ++ show format ++ ")")]
    cartField Nothing                   = []
    cartField (Just (N64CartId cartId)) = [InfoLine "cart ID" (concatMap (\byte -> padHex 2 byte) (ByteString.unpack cartId))]
    countryField Nothing        = []
    countryField (Just country) = [InfoLine "country" (renderAPSN64Country country)]
    renderAPSN64Country APSN64CountryBeta            = "Beta"
    renderAPSN64Country APSN64CountryAsian           = "Asian (NTSC)"
    renderAPSN64Country APSN64CountryBrazil          = "Brazil"
    renderAPSN64Country APSN64CountryChina           = "China"
    renderAPSN64Country APSN64CountryGermany         = "Germany"
    renderAPSN64Country APSN64CountryUSA             = "USA"
    renderAPSN64Country APSN64CountryFrance          = "France"
    renderAPSN64Country APSN64CountryGateway64NTSC   = "Gateway 64 (NTSC)"
    renderAPSN64Country APSN64CountryNetherlands     = "Netherlands"
    renderAPSN64Country APSN64CountryItaly           = "Italy"
    renderAPSN64Country APSN64CountryJapan           = "Japan"
    renderAPSN64Country APSN64CountryKorea           = "Korea"
    renderAPSN64Country APSN64CountryGateway64PAL    = "Gateway 64 (PAL)"
    renderAPSN64Country APSN64CountryCanada          = "Canada"
    renderAPSN64Country APSN64CountryPAL             = "PAL"
    renderAPSN64Country APSN64CountrySpain           = "Spain"
    renderAPSN64Country APSN64CountryAustralia       = "Australia"
    renderAPSN64Country APSN64CountryScandinavia     = "Scandinavia"
    renderAPSN64Country APSN64CountryEuropeX         = "Europe (X)"
    renderAPSN64Country APSN64CountryEuropeY         = "Europe (Y)"
    renderAPSN64Country (APSN64CountryUnrecognised byte) =
      "unrecognised (0x" ++ padHex 2 byte ++ ")"

explainAPSN64 :: APSN64Patch -> ExplainData
explainAPSN64 patch@(APSN64Patch _header records) = ExplainData
  { explainFormat   = "APS (N64)"
  , explainHeader   = apsN64Meta patch
  , explainSections = [SectionRegions (Vector.toList (Vector.map makeN64Region records))]
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
makeN64Region (APSN64RLE recordOffset fillValue fillCount) = ExplainRegion
  { regionOffset     = recordOffset
  , regionSize       = Length (fromIntegral fillCount)
  , regionLabel      = "Fill "
  , regionPayload    = PayloadFill fillValue (Length (fromIntegral fillCount))
  , regionAnnotation = AnnotAt AtOffset recordOffset [DetailRLE]
  }
