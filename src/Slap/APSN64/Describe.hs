{-# LANGUAGE OverloadedStrings #-}

module Slap.APSN64.Describe
  ( apsN64Meta
  , analyzeAPSN64
  , makeN64Region
  ) where

import Slap.APSN64.Types
import Slap.Display.Analysis (PatchAnalysis(..), AnalysisSection(..), AnalysisRegion(..),
                     AnalysisPayload(..), AnalysisSummary(..), SummaryInfo(..),
                     Annotation(..), OffsetKind(..), AnnotDetail(..))
import Slap.Display.Common (InfoLine(..), Tally(..), CountUnit(..), renderAsText)
import Slap.Display.Primitives (hexByteString)
import Slap.Measure (Length(..), FileSize(..), byteLength)
import Slap.Text (encodedTextContent)

import qualified Data.Text as Text
import qualified Data.Vector as Vector

apsN64Meta :: APSN64Patch -> [InfoLine]
apsN64Meta (APSN64Patch header _) = concat
  [ [InfoLine "patch type" (patchTypeName (apsN64PatchType header))]
  , descriptionField (apsN64Description header)
  , formatField (apsN64ImageFormat header)
  , cartField (apsN64CartId header)
  , countryField (apsN64Country header)
  , [InfoLine "dest size" (renderAsText (unFileSize (apsN64DestinationSizeAsFileSize (apsN64DestinationSize header))))]
  ]
  where
    -- The field is trimmed to its content at parse time.
    descriptionField description
      | Text.null text = []
      | otherwise      = [InfoLine "description" text]
      where text = encodedTextContent description
    patchTypeName APSSimple      = "simple"
    patchTypeName APSN64Specific = "N64-specific"
    formatField Nothing                       = []
    formatField (Just V64Format)              = [InfoLine "image" "V64 (byteswapped)"]
    formatField (Just Z64Format)              = [InfoLine "image" "Z64 (big-endian)"]
    formatField (Just (UnknownImageFormat format)) = [InfoLine "image" ("unknown (" <> renderAsText format <> ")")]
    cartField Nothing                   = []
    cartField (Just (N64CartId cartId)) = [InfoLine "cart ID" (hexByteString cartId)]
    countryField Nothing        = []
    countryField (Just country) = [InfoLine "country" (apsN64CountryName country)]

analyzeAPSN64 :: APSN64Patch -> PatchAnalysis
analyzeAPSN64 (APSN64Patch _header records) = PatchAnalysis
  { analysisSections = [SectionRegions (Vector.toList (Vector.map makeN64Region records))]
  , analysisSummary  = Summary (SummaryInfo (Tally (length records)) Records Nothing)
  }

makeN64Region :: APSN64Record -> AnalysisRegion
makeN64Region (APSN64Normal recordOffset recordPayload) = AnalysisRegion
  { regionOffset     = recordOffset
  , regionSize       = byteLength recordPayload
  , regionLabel      = "Write  "
  , regionPayload    = PayloadWrite recordPayload
  , regionAnnotation = AnnotationAt AtOffset recordOffset []
  }
makeN64Region (APSN64RLE recordOffset fillValue fillCount) = AnalysisRegion
  { regionOffset     = recordOffset
  , regionSize       = Length (fromIntegral fillCount)
  , regionLabel      = "Fill "
  , regionPayload    = PayloadFill fillValue (Length (fromIntegral fillCount))
  , regionAnnotation = AnnotationAt AtOffset recordOffset [DetailRLE]
  }
