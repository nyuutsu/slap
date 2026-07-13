{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}

-- | NINJA2 patch creation. XOR-based records, packed-integer (VLV)
-- header sizes and per-record lengths.
module Slap.NINJA2.Create
  ( createNINJA2
  , encodeXorRecord
  ) where

import Slap.NINJA2.Types
import Slap.Binary (diffHunks, md5, replicateLength, viewBytesInRange)
import Slap.Normalize (normalizeCreatePair)
import Slap.Checksum (MD5Hash(..))
import Slap.Measure (Offset(..), Length, Hunk(..), byteLength, minLength, subtractLength)
import Slap.Status (SlapError, SlapAdvisory, CreateResult(..))
import Slap.FieldName (FieldName(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.Platform (platformToNINJA2)
import Slap.Text (EncodedText, EncodingName(..), encodedTextContent,
                  encodeTextBounded, encodeLossAdvisories)

import Slap.FileContents (InputFileContents(..), OutputFileContents(..), PatchFileContents(..))

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Lazy as LazyByteString
import Data.ByteString.Builder (Builder, word8, byteString, toLazyByteString)
import Data.Bits (xor)


-- | The actually-stored value (not the requested codepoint count) is what 'parseFixedHeader' reads back from the same patch;
-- the @0x00@ padding matches NINJA2's reference encoder.
-- The @PATCH_ENC@ byte slap writes is an independent choice ('fromTextMode'),
-- so the field bytes are always UTF-8 while the declared byte is whatever the target 'TextMode' is.
encodeBoundedField :: FieldName -> Length -> Maybe EncodedText
                   -> (ByteString, [SlapAdvisory])
encodeBoundedField fieldName fieldWidth = \case
  Nothing -> (replicateLength fieldWidth 0, [])
  Just inputText ->
    let (encodedBytes, notices) =
          encodeTextBounded EncodingUtf8
                            fieldWidth
                            (encodedTextContent inputText)
        padded     = encodedBytes
                  <> replicateLength
                       (subtractLength fieldWidth (minLength fieldWidth (byteLength encodedBytes)))
                       0x00
        advisories = encodeLossAdvisories LabelNINJA2 fieldName notices
    in (padded, advisories)


-- | XOR-based records with VLV encoding; size changes go through the overflow section.
-- Field advisories (truncation and substitution from the fixed header's bounded text), platform advisories (a 'PlatformType' NINJA2 can't express),
-- and normalization advisories all fold into 'CreateResult.resultAdvisories', so the caller collects them from one place.
-- When the ROM type has a normalization procedure, both files are canonicalized before the diff and the hashes.
createNINJA2 :: InputFileContents -> OutputFileContents -> NINJA2CreateMetadata
             -> Either SlapError CreateResult
createNINJA2 handedOriginal handedModified metadata =
    Right (CreateResult (PatchFileContents patchBytes)
                        (normalizationAdvisories ++ fieldAdvisories ++ platformAdvisories))
  where
    (InputFileContents original, OutputFileContents modified, normalizationAdvisories) =
      case ninja2CreateMetadataPlatform metadata of
        Just platform | ninja2RomTypeNeedsNormalization romType ->
          normalizeCreatePair LabelNINJA2 platform handedOriginal handedModified
        _ -> (handedOriginal, handedModified, [])
    textMode              = ninja2CreateTextMode metadata
    -- The fixed header's bounded text fields, in wire order. Each
    -- encodes to its padded bytes paired with any truncation or
    -- substitution advisories; 'mconcat' over the
    -- @(ByteString, [SlapAdvisory])@ tuple monoid concatenates both
    -- streams in one pass, so the field order is stated once and the
    -- bytes and the advisories cannot fall out of step.
    (fixedHeaderBytes, fieldAdvisories) = mconcat
      [ encodeBoundedField FieldAuthor      ninja2AuthorWidth      (ninja2CreateMetadataAuthor      metadata)
      , encodeBoundedField FieldVersion     ninja2VersionWidth     (ninja2CreateMetadataVersion     metadata)
      , encodeBoundedField FieldTitle       ninja2TitleWidth       (ninja2CreateMetadataTitle       metadata)
      , encodeBoundedField FieldGenre       ninja2GenreWidth       (ninja2CreateMetadataGenre       metadata)
      , encodeBoundedField FieldLanguage    ninja2LanguageWidth    (ninja2CreateMetadataLanguage    metadata)
      , encodeBoundedField FieldDate        ninja2DateWidth        (ninja2CreateMetadataDate        metadata)
      , encodeBoundedField FieldWebsite     ninja2WebsiteWidth     (ninja2CreateMetadataWebsite     metadata)
      , encodeBoundedField FieldDescription ninja2DescriptionWidth (ninja2CreateMetadataDescription metadata)
      ]
    (romType, platformAdvisories) =
      maybe (NINJA2Raw, []) platformToNINJA2 (ninja2CreateMetadataPlatform metadata)
    patchBytes = LazyByteString.toStrict $ toLazyByteString $
      byteString ninja2MagicBytes              -- magic (6 bytes)
      <> word8 (fromTextMode textMode)         -- text mode (1 byte)
      <> byteString fixedHeaderBytes           -- fixed-header region (2041 bytes)
      <> word8 0x01                            -- OPEN_NEW_FILE command
      <> word8 0                               -- FILE_N_MUL=0: single-file sentinel
                                               -- (spec §FILE block: 0 in this slot
                                               -- signals single-file, with no
                                               -- FILE_N_LEN/FILE_NAME bytes to
                                               -- follow — distinct from a length-1
                                               -- VLV holding the value 0)
      <> word8 (fromNINJA2RomType romType)
      <> encodeVariableLengthValue (fromIntegral (ByteString.length original))
      <> encodeVariableLengthValue (fromIntegral (ByteString.length modified))
      <> byteString (unMD5Hash (md5 original))
      <> byteString (unMD5Hash (md5 modified))
      <> overflowPart
      <> foldMap encodeXorRecord xorHunks
      <> word8 0x00                            -- END command
    minimumLength = min (ByteString.length original) (ByteString.length modified)
    sourceTrimmed = ByteString.take minimumLength original
    targetTrimmed = ByteString.take minimumLength modified
    xorHunks = map computeXorHunk
                   (diffHunks (InputFileContents sourceTrimmed)
                              (OutputFileContents targetTrimmed))
    computeXorHunk (Hunk hunkOffset newData) =
      let oldData = viewBytesInRange hunkOffset (byteLength newData) sourceTrimmed
      in XorRecord hunkOffset (ByteString.packZipWith xor oldData newData)

    -- Overflow section: emitted whenever sizes differ (parser expects it).
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

encodeXorRecord :: XorRecord -> Builder
encodeXorRecord record =
    word8 0x02                                    -- XOR command
    <> encodeVariableLengthValue (unOffset (xorRecordOffset record))
    <> encodeVariableLengthValue (fromIntegral (ByteString.length (xorRecordPayload record)))
    <> byteString (xorRecordPayload record)
