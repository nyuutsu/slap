module Slap.NINJA2.Describe
  ( ninja2Meta
  , explainNINJA2
  , makeNINJA2Region
  ) where

import Slap.NINJA2.Types
import Slap.Checksum (MD5Hash(..))
import Slap.Display (InfoLine(..))
import Slap.Format (padHex)
import Slap.Measure (Length(..), FileSize(..))
import Slap.Explain (ExplainData(..), ExplainSection(..), ExplainRegion(..),
                     ExplainPayload(..), ExplainSummary(..), SummaryInfo(..),
                     Annotation(..), OffsetKind(..))

import qualified Data.ByteString as ByteString

----------------------------------------------------------------------------
-- Info
----------------------------------------------------------------------------

ninja2Meta :: NINJA2Patch -> [InfoLine]
ninja2Meta patch = concat
  [ optionalField "title"       (ninja2Title (ninja2Header patch))
  , optionalField "author"      (ninja2Author (ninja2Header patch))
  , optionalField "version"     (ninja2Version (ninja2Header patch))
  , optionalField "date"        (ninja2Date (ninja2Header patch))
  , optionalField "genre"       (ninja2Genre (ninja2Header patch))
  , optionalField "language"    (ninja2Language (ninja2Header patch))
  , optionalField "website"     (ninja2Website (ninja2Header patch))
  , optionalField "description" (ninja2Description (ninja2Header patch))
  , openNewFileFields
  , overflowField
  ]
  where
    encoding = ninja2PatchEncoding patch
    optionalField _ Nothing = []
    optionalField label (Just value) = [InfoLine label (decodeNINJA2Field encoding value)]

    openNewFileFields = case ninja2OpenNewFile patch of
      Nothing -> []
      Just openNewFile ->
        let romTypeField = case openNewFileRomType openNewFile of
              Ninja2Raw -> []
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

explainNINJA2 :: NINJA2Patch -> ExplainData
explainNINJA2 patch = ExplainData
  { explainFormat   = "NINJA2"
  , explainHeader   = ninja2Meta patch
  , explainSections = [SectionRegions (map makeNINJA2Region (ninja2Records patch))]
  , explainSummary  = Summary (SummaryInfo recordCount "records" Nothing)
  , explainNotes    = []
  }
  where
    recordCount = length (ninja2Records patch)

makeNINJA2Region :: NINJA2Record -> ExplainRegion
makeNINJA2Region (NINJA2Record recordOffset deltaBytes) = ExplainRegion
  { regionOffset     = recordOffset
  , regionSize       = Length (ByteString.length deltaBytes)
  , regionLabel      = "XOR  "
  , regionPayload    = PayloadXOR (Just deltaBytes)
  , regionAnnotation = AnnotAt AtOffset recordOffset []
  }
