{-# LANGUAGE OverloadedStrings #-}

module Slap.NINJA2.Describe
  ( ninja2Meta
  , ninja2UndeclaredTextFields
  , analyzeNINJA2
  , makeNINJA2Region
  ) where

import Slap.NINJA2.Types
import Slap.Checksum (MD5Hash(..))
import Slap.Display.Common (InfoLine(..), Tally(..), CountUnit(..), renderAsText)
import Slap.Display.Glyph (spacePaddedRightwardsArrow)
import Slap.Display.Primitives (hexByteString)
import Slap.Measure (FileSize(..), byteLength)
import Slap.Display.Analysis (PatchAnalysis(..), AnalysisSection(..), AnalysisRegion(..),
                     AnalysisPayload(..), XORDeltaBytes(..), AnalysisSummary(..), SummaryInfo(..),
                     Annotation(..), OffsetKind(..))
import Slap.Text (encodedTextContent)

import Data.Maybe (isJust)
import Data.Text (Text)

import qualified Data.ByteString as ByteString

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
  , [InfoLine "text mode" (ninja2TextModeName (ninja2TextMode patch))]
  , fileCountField
  , openNewFileFields
  , overflowField
  , furtherFileFields
  ]
  where
    header = ninja2Header patch

    -- In a bundle, the size and MD5 lines above describe the first file; each further file gets a row of its own.
    fileCountField = case ninja2FurtherFiles patch of
      [] -> []
      further -> [InfoLine "files" (renderAsText (1 + length further))]

    furtherFileFields =
      [ InfoLine ("file " <> renderAsText fileNumber) (furtherFileGlance furtherFile)
      | (fileNumber, furtherFile) <- zip [2 :: Int ..] (ninja2FurtherFiles patch) ]

    furtherFileGlance furtherFile =
      renderAsText (unFileSize (openNewFileSourceSize opened))
        <> spacePaddedRightwardsArrow <> renderAsText (unFileSize (openNewFileTargetSize opened))
        <> " bytes, " <> renderAsText (furtherFileRecordCount furtherFile) <> " records"
      where
        opened = furtherFileOpen furtherFile

    optionalField _     Nothing      = []
    optionalField label (Just value) =
      [InfoLine label (encodedTextContent value)]

    openNewFileFields = case ninja2OpenNewFile patch of
      Nothing -> []
      Just openNewFile ->
        let romTypeField = case openNewFileRomType openNewFile of
              NINJA2Raw -> []
              romType   -> [InfoLine "ROM type" (ninja2RomTypeName romType)]
            sizeFields =
              [ InfoLine "source size" (renderAsText (unFileSize (openNewFileSourceSize openNewFile)))
              , InfoLine "target size" (renderAsText (unFileSize (openNewFileTargetSize openNewFile)))
              ]
            sourceMD5Field = md5Field "source MD5" (openNewFileSourceMD5 openNewFile)
            targetMD5Field = md5Field "target MD5" (openNewFileTargetMD5 openNewFile)
        in concat [romTypeField, sizeFields, sourceMD5Field, targetMD5Field]

    md5Field label (MD5Hash hash) =
      [InfoLine label (hexByteString hash)]

    overflowField = case (ninja2OverflowType patch, ninja2Overflow patch) of
      (Just OverflowAppend,   Just payload) -> [InfoLine "overflow" ("append " <> renderAsText (ByteString.length payload) <> " bytes")]
      (Just OverflowTruncate, Just payload) -> [InfoLine "overflow" ("truncate " <> renderAsText (ByteString.length payload) <> " bytes")]
      (_, Just payload)                     -> [InfoLine "overflow" (renderAsText (ByteString.length payload) <> " bytes")]
      _                                     -> []

----------------------------------------------------------------------------
-- Analyze
----------------------------------------------------------------------------

-- | Mode-0 text arrives with no declared codepage, so only there does the viewing encoding govern a reading;
-- a UTF-8-mode patch reads the same under every @--metadata-encoding@.
ninja2UndeclaredTextFields :: NINJA2Patch -> [Text]
ninja2UndeclaredTextFields patch = case ninja2TextMode patch of
  TextModeUTF8       -> []
  TextModeUndeclared ->
    [ label
    | (label, field) <- [ ("title", ninja2Title), ("author", ninja2Author), ("version", ninja2Version)
                        , ("date", ninja2Date), ("genre", ninja2Genre), ("language", ninja2Language)
                        , ("website", ninja2Website), ("description", ninja2Description) ]
    , isJust (field (ninja2Header patch)) ]

-- | A multi-file bundle's records name offsets in several files' address spaces, so no single walk describes them;
-- its analysis carries the record total and no regions.
analyzeNINJA2 :: NINJA2Patch -> PatchAnalysis
analyzeNINJA2 patch = PatchAnalysis
  { analysisSections = [SectionRegions (map makeNINJA2Region (ninja2Records patch)) | null (ninja2FurtherFiles patch)]
  , analysisSummary  = Summary (SummaryInfo (Tally recordTotal) Records Nothing)
  }
  where
    recordTotal = length (ninja2Records patch)
                + sum (map furtherFileRecordCount (ninja2FurtherFiles patch))

makeNINJA2Region :: NINJA2Record -> AnalysisRegion
makeNINJA2Region (NINJA2Record recordOffset deltaBytes) = AnalysisRegion
  { regionOffset     = recordOffset
  , regionSize       = byteLength deltaBytes
  , regionLabel      = "XOR  "
  , regionPayload    = PayloadXOR (XORDeltaBytes deltaBytes)
  , regionAnnotation = AnnotationAt AtOffset recordOffset []
  }
