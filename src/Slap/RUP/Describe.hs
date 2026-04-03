module Slap.RUP.Describe
  ( rupInfo
  , rupMeta
  , explainRUP
  , makeRUPRegion
  ) where

import Slap.RUP.Types
import Slap.Format (MetaField(..), padHex, renderField)
import Slap.Measure (Length(..), FileSize(..))
import Slap.Explain (ExplainData(..), ExplainSection(..), ExplainRegion(..),
                     ExplainPayload(..), ExplainSummary(..), SummaryInfo(..),
                     Annotation(..), OffsetKind(..))

import qualified Data.ByteString as ByteString

----------------------------------------------------------------------------
-- Info
----------------------------------------------------------------------------

rupMeta :: RUPPatch -> [MetaField]
rupMeta patch = concat
  [ optionalField "title"       (rupTitle (rupHeader patch))
  , optionalField "author"      (rupAuthor (rupHeader patch))
  , optionalField "version"     (rupVersion (rupHeader patch))
  , optionalField "date"        (rupDate (rupHeader patch))
  , optionalField "genre"       (rupGenre (rupHeader patch))
  , optionalField "language"    (rupLanguage (rupHeader patch))
  , optionalField "website"     (rupWebsite (rupHeader patch))
  , optionalField "description" (rupDescription (rupHeader patch))
  , romTypeField
  , sizeFields
  , md5Field "source MD5" (rupSourceMD5 patch)
  , md5Field "target MD5" (rupTargetMD5 patch)
  , overflowField
  ]
  where
    patchEncoding = rupPatchEncoding patch
    optionalField _ Nothing = []
    optionalField label (Just value) = [MetaField label (decodeRUPField patchEncoding value)]

    romTypeField
      | rupRomType patch == 0 = []
      | otherwise = [MetaField "ROM type" (show (rupRomType patch))]

    sizeFields
      | unFileSize (rupSourceSize patch) == 0 && unFileSize (rupTargetSize patch) == 0 = []
      | otherwise = [ MetaField "source size" (show (unFileSize (rupSourceSize patch)))
                     , MetaField "target size" (show (unFileSize (rupTargetSize patch))) ]

    md5Field _ Nothing = []
    md5Field label (Just hash) =
      [MetaField label (concatMap (\byte -> padHex 2 (fromIntegral byte)) (ByteString.unpack hash))]

    overflowField = case (rupOverflowType patch, rupOverflow patch) of
      (Just OverflowAppend,   Just payload) -> [MetaField "overflow" ("append " ++ show (ByteString.length payload) ++ " bytes")]
      (Just OverflowTruncate, Just payload) -> [MetaField "overflow" ("truncate " ++ show (ByteString.length payload) ++ " bytes")]
      (_, Just payload)                     -> [MetaField "overflow" (show (ByteString.length payload) ++ " bytes")]
      _                                     -> []

rupInfo :: RUPPatch -> String
rupInfo patch = unlines $ filter (not . null) $
  [ "format:      RUP (NINJA2)" ]
  ++ map renderField (rupMeta patch)
  ++ [ "records:     " ++ show (length (rupRecords patch)) ]

----------------------------------------------------------------------------
-- Explain
----------------------------------------------------------------------------

explainRUP :: RUPPatch -> ExplainData
explainRUP patch = ExplainData
  { explainFormat   = "RUP (NINJA2)"
  , explainHeader   = rupMeta patch
  , explainSections = [SectionRegions (map makeRUPRegion (rupRecords patch))]
  , explainSummary  = Summary (SummaryInfo recordCount "records" Nothing)
  , explainNotes    = []
  }
  where
    recordCount = length (rupRecords patch)

makeRUPRegion :: RUPRecord -> ExplainRegion
makeRUPRegion (RUPRecord recordOffset deltaBytes) = ExplainRegion
  { regionOffset     = recordOffset
  , regionSize       = Length (ByteString.length deltaBytes)
  , regionLabel      = "XOR  "
  , regionPayload    = PayloadXOR (Just deltaBytes)
  , regionAnnotation = AnnotAt AtOffset recordOffset []
  }
