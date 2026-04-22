{-# LANGUAGE OverloadedStrings #-}

module Slap.NINJA2.Create
  ( createNINJA2
  , encodeFixedHeader
  , encodeXorRecord
  ) where

import Slap.NINJA2.Types
import Slap.Binary (diffHunks, md5)
import Slap.Checksum (MD5Hash(..))
import Slap.Measure (Offset(..), Length(..), Hunk(..),
                     OriginalLength(..), TruncatedLength(..))
import Slap.Error (SlapError, SlapWarning(..), CreateResult(..), FieldName(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.Platform (platformToNinja2)
import Slap.TextEncoding (truncateUtf8, truncateLocale)

import Slap.FileContents (SourceFileContents(..), TargetFileContents(..), PatchFileContents(..))

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Lazy as LazyByteString
import Data.ByteString.Builder (Builder, word8, byteString, toLazyByteString)
import Data.Bits (xor)


-- | Create a NINJA2 patch from original and modified ByteStrings.
-- XOR-based records with VLV encoding; handles size changes via overflow.
-- Field-truncation warnings (from fields too long to fit the fixed
-- header) and platform warnings (from 'PlatformType' values NINJA2
-- can't express) are both folded into 'CreateResult.resultWarnings'
-- so the caller doesn't have to remember to collect them separately.
createNINJA2 :: SourceFileContents -> TargetFileContents -> NINJA2Metadata
             -> Either SlapError CreateResult
createNINJA2 (SourceFileContents original) (TargetFileContents modified) metadata =
    Right (CreateResult (PatchFileContents patchBytes)
                        (ninja2TruncationNotes info ++ platformWarnings))
  where
    encoding = ninja2MetadataEncoding metadata
    encodeField = encodeNINJA2String encoding
    info = NINJA2Info
      { ninja2Author      = fmap encodeField (ninja2MetadataAuthor      metadata)
      , ninja2Version     = fmap encodeField (ninja2MetadataVersion     metadata)
      , ninja2Title       = fmap encodeField (ninja2MetadataTitle       metadata)
      , ninja2Genre       = fmap encodeField (ninja2MetadataGenre       metadata)
      , ninja2Language    = fmap encodeField (ninja2MetadataLanguage    metadata)
      , ninja2Date        = fmap encodeField (ninja2MetadataDate        metadata)
      , ninja2Website     = fmap encodeField (ninja2MetadataWebsite     metadata)
      , ninja2Description = fmap encodeField (ninja2MetadataDescription metadata)
      }
    (romType, platformWarnings) =
      maybe (Ninja2Raw, []) platformToNinja2 (ninja2MetadataPlatform metadata)
    patchBytes = LazyByteString.toStrict $ toLazyByteString $
      byteString ninja2MagicBytes              -- magic (6 bytes)
      <> word8 (fromPatchEncoding encoding)   -- text encoding
      <> byteString (encodeFixedHeader encoding info)  -- rest of 2048-byte header
      <> word8 0x01                           -- OPEN_NEW_FILE command
      <> encodeVariableLengthValue 0          -- filename length (empty)
      <> word8 (fromNINJA2RomType romType)    -- ROM type byte
      <> encodeVariableLengthValue (fromIntegral (ByteString.length original))   -- source size
      <> encodeVariableLengthValue (fromIntegral (ByteString.length modified))   -- target size
      <> byteString (unMD5Hash (md5 original))  -- source MD5
      <> byteString (unMD5Hash (md5 modified))  -- target MD5
      <> overflowPart
      <> foldMap encodeXorRecord xorHunks
      <> word8 0x00                           -- END command
    -- XOR hunks over the shared region
    minimumLength = min (ByteString.length original) (ByteString.length modified)
    sourceTrimmed = ByteString.take minimumLength original
    targetTrimmed = ByteString.take minimumLength modified
    -- diffHunks finds changed regions; we then XOR old and new at those positions
    xorHunks = map computeXorHunk (diffHunks sourceTrimmed targetTrimmed)
    computeXorHunk (Hunk hunkOffset newData) =
      let intOffset = unOffset hunkOffset
          oldData = ByteString.take (ByteString.length newData) (ByteString.drop intOffset sourceTrimmed)
      in XorRecord hunkOffset (ByteString.packZipWith xor oldData newData)

    -- Overflow section: emitted whenever sizes differ (parser expects it).
    -- Type byte: 'A' (0x41) = append, 'M' (0x4D) = truncate/minify.
    -- Data is XOR'd with 0xFF on disk (RomPatcher.js convention).
    overflowPart
      | ByteString.length modified > ByteString.length original =
          let extra = ByteString.drop (ByteString.length original) modified
          in word8 (fromOverflowMode OverflowAppend)
             <> encodeVariableLengthValue (fromIntegral (ByteString.length extra))
             <> byteString (ByteString.map (xor 0xFF) extra)
      | ByteString.length modified < ByteString.length original =
          let extra = ByteString.drop (ByteString.length modified) original
          in word8 (fromOverflowMode OverflowTruncate)
             <> encodeVariableLengthValue (fromIntegral (ByteString.length extra))
             <> byteString (ByteString.map (xor 0xFF) extra)
      | otherwise = mempty

-- | Encode a NINJA2Info into the fixed header region (bytes 7..2047).
-- Mirrors parseFixedHeader layout: author@0x007/84, version@0x05B/11,
-- title@0x066/256, genre@0x166/48, language@0x196/48, date@0x1C6/8,
-- website@0x1CE/512, description@0x3CE/1074.
-- Fields that exceed their byte width are truncated at the last complete
-- codepoint boundary (UTF-8) or byte boundary (system encoding).
encodeFixedHeader :: PatchEncoding -> NINJA2Info -> ByteString
encodeFixedHeader encoding info =
    ByteString.pack $ map byteAt [0 .. headerSize - 8]
  where
    byteAt index = case lookup index fieldBytes of
      Just byte -> byte
      Nothing   -> 0
    fieldBytes = concatMap expandField fields
    expandField (fieldOffset, fieldLength, maybeValue) = case maybeValue of
      Nothing    -> []
      Just value ->
        let truncated = truncateField encoding fieldLength value
        in zip [fieldOffset..fieldOffset+fieldLength-1] (ByteString.unpack (zeroPadTo fieldLength truncated))
    zeroPadTo count input = ByteString.take count input <> ByteString.replicate (max 0 (count - ByteString.length input)) 0
    fields =
      [ (0x007 - 7, ninja2AuthorWidth,      ninja2Author info)
      , (0x05B - 7, ninja2VersionWidth,     ninja2Version info)
      , (0x066 - 7, ninja2TitleWidth,       ninja2Title info)
      , (0x166 - 7, ninja2GenreWidth,       ninja2Genre info)
      , (0x196 - 7, ninja2LanguageWidth,    ninja2Language info)
      , (0x1C6 - 7, ninja2DateWidth,        ninja2Date info)
      , (0x1CE - 7, ninja2WebsiteWidth,     ninja2Website info)
      , (0x3CE - 7, ninja2DescriptionWidth, ninja2Description info)
      ]

-- | Truncate a field value to fit within the given byte width.
-- For UTF-8: cuts at the last complete codepoint boundary.
-- For system encoding: truncates at the byte boundary.
truncateField :: PatchEncoding -> Int -> ByteString -> ByteString
truncateField PatchEncodingUTF8 = truncateUtf8
truncateField _                 = truncateLocale

-- | Check which NINJA2Info fields would be truncated by encodeFixedHeader,
-- and return a warning for each one.
ninja2TruncationNotes :: NINJA2Info -> [SlapWarning]
ninja2TruncationNotes info = concatMap checkField fields
  where
    checkField (fieldLength, name, maybeValue) = case maybeValue of
      Just value | ByteString.length value > fieldLength ->
        [FieldTruncated LabelNINJA2 name
          (OriginalLength (Length (ByteString.length value)))
          (TruncatedLength (Length fieldLength))]
      _ -> []
    fields =
      [ (ninja2AuthorWidth,      FieldAuthor,      ninja2Author info)
      , (ninja2VersionWidth,     FieldVersion,     ninja2Version info)
      , (ninja2TitleWidth,       FieldTitle,        ninja2Title info)
      , (ninja2GenreWidth,       FieldGenre,       ninja2Genre info)
      , (ninja2LanguageWidth,    FieldLanguage,    ninja2Language info)
      , (ninja2DateWidth,        FieldDate,        ninja2Date info)
      , (ninja2WebsiteWidth,     FieldWebsite,     ninja2Website info)
      , (ninja2DescriptionWidth, FieldDescription, ninja2Description info)
      ]

encodeXorRecord :: XorRecord -> Builder
encodeXorRecord record =
    word8 0x02                                    -- XOR command
    <> encodeVariableLengthValue (fromIntegral (unOffset (xorRecordOffset record)))   -- offset
    <> encodeVariableLengthValue (fromIntegral (ByteString.length (xorRecordPayload record)))  -- length
    <> byteString (xorRecordPayload record)       -- XOR data
