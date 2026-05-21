module Slap.NINJA2.Describe
  ( ninja2Meta
  , analyzeNINJA2
  , makeNINJA2Region
  ) where

import Slap.NINJA2.Types
import Slap.Checksum (MD5Hash(..))
import Slap.Display.Common (InfoLine(..), Tally(..), CountUnit(..))
import Slap.Display.Primitives (padHex)
import Slap.Measure (FileSize(..), byteLength)
import Slap.Display.Analysis (PatchAnalysis(..), AnalysisSection(..), AnalysisRegion(..),
                     AnalysisPayload(..), AnalysisSummary(..), SummaryInfo(..),
                     Annotation(..), OffsetKind(..))
import Slap.Text (encodedTextContent)

import qualified Data.ByteString as ByteString
import qualified Data.Text as Text

----------------------------------------------------------------------------
-- Info
----------------------------------------------------------------------------

ninja2Meta :: NINJA2Patch -> [InfoLine]
ninja2Meta patch = concat
  [ optionalField "title"       (ninja2Title       header)
  , optionalField "author"      (ninja2Author      header)
  , optionalField "version"     (ninja2Version     header)
  , optionalField "date"        (ninja2Date        header)
  , optionalField "genre"       (ninja2Genre       header)
  , optionalField "language"    (ninja2Language    header)
  , optionalField "website"     (ninja2Website     header)
  , optionalField "description" (ninja2Description header)
  , openNewFileFields
  , overflowField
  ]
  where
    header = ninja2Header patch

    optionalField _     Nothing      = []
    optionalField label (Just value) =
      [InfoLine label (Text.unpack (encodedTextContent value))]

    openNewFileFields = case ninja2OpenNewFile patch of
      Nothing -> []
      Just openNewFile ->
        let romTypeField = case openNewFileRomType openNewFile of
              NINJA2Raw -> []
              romType   -> [InfoLine "ROM type" (ninja2RomTypeName romType)]
            sizeFields =
              [ InfoLine "source size" (show (unFileSize (openNewFileSourceSize openNewFile)))
              , InfoLine "target size" (show (unFileSize (openNewFileTargetSize openNewFile)))
              ]
            sourceMD5Field = md5Field "source MD5" (openNewFileSourceMD5 openNewFile)
            targetMD5Field = md5Field "target MD5" (openNewFileTargetMD5 openNewFile)
        in concat [romTypeField, sizeFields, sourceMD5Field, targetMD5Field]

    md5Field label (MD5Hash hash) =
      [InfoLine label (concatMap (\byte -> padHex 2 byte) (ByteString.unpack hash))]

    overflowField = case (ninja2OverflowType patch, ninja2Overflow patch) of
      (Just OverflowAppend,   Just payload) -> [InfoLine "overflow" ("append " ++ show (ByteString.length payload) ++ " bytes")]
      (Just OverflowTruncate, Just payload) -> [InfoLine "overflow" ("truncate " ++ show (ByteString.length payload) ++ " bytes")]
      (_, Just payload)                     -> [InfoLine "overflow" (show (ByteString.length payload) ++ " bytes")]
      _                                     -> []

----------------------------------------------------------------------------
-- Explain
----------------------------------------------------------------------------

analyzeNINJA2 :: NINJA2Patch -> PatchAnalysis
analyzeNINJA2 patch = PatchAnalysis
  { analysisSections = [SectionRegions (map makeNINJA2Region (ninja2Records patch))]
  , analysisSummary  = Summary (SummaryInfo (Tally recordCount) Records Nothing)
  }
  where
    recordCount = length (ninja2Records patch)

makeNINJA2Region :: NINJA2Record -> AnalysisRegion
makeNINJA2Region (NINJA2Record recordOffset deltaBytes) = AnalysisRegion
  { regionOffset     = recordOffset
  , regionSize       = byteLength deltaBytes
  , regionLabel      = "XOR  "
  , regionPayload    = PayloadXOR (Just deltaBytes)
  , regionAnnotation = AnnotationAt AtOffset recordOffset []
  }
