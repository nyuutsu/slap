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
  , [InfoLine "encoding" (renderAsText (fromAPSRecordEncoding (apsN64Encoding header)))
    | apsN64Encoding header /= APSDefaultRecordEncoding]
  , descriptionField (apsN64Description header)
  , formatField (apsN64ImageFormat header)
  , cartField (apsN64CartId header)
  , countryField (apsN64Country header)
  , [InfoLine "dest size" (renderAsText (unFileSize (apsN64DestinationSizeAsFileSize (apsN64DestinationSize header))))]
  ]
  where
    -- Read the decoded text directly off the typed field. The
    -- pre-migration code rendered @show (ByteString.takeWhile (/= 0) bytes)@,
    -- which emitted the Haskell-escape-quoted bytestring (literal
    -- @"abc"@ including the quotes) — a pre-existing bug that the
    -- migration fixes as a side effect: callers now see plain text.
    -- The empty-padding guard moves from the byte-level
    -- @0x20 \/ 0x00@ predicate to a codepoint-level check on the
    -- decoded 'Text'; the intent ("don't show a description line if
    -- the wire field was blank padding") is preserved.
    descriptionField description
      | Text.all (\c -> c == ' ' || c == '\NUL') text = []
      | otherwise = [InfoLine "description" (Text.takeWhile (/= '\NUL') text)]
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
