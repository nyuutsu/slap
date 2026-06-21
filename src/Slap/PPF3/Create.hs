{-# LANGUAGE OverloadedStrings #-}

-- | Wire encoder for PPF3 patches. Records use 8-byte LE offsets,
-- a 1-byte payload-length count, and (when the patch's undo flag
-- is set) an equal-length undo payload after each write payload.
-- Optional FILE_ID.DIZ trailer is appended verbatim by the caller
-- after this function returns its bytes.
--
-- Same-size patches only. PPF3's wire format has no command for
-- declaring growth or shrinkage; see
-- 'Slap.PPF3.Types.ppf3RejectIncompatibleSizeChange' for slap's
-- enforcement and @docs\/ppf\/spec.md@ for the upstream picture.
-- The convert layer's 'Slap.Convert.rejectIncompatibleSizeChange'
-- runs the check before reaching this encoder.
module Slap.PPF3.Create
  ( encodePPF3
  , encodeFileIdDiz
  ) where

import Slap.PPF3.Types (PPF3ImageType(..),
                        PPF3FileId, unPPF3FileId,
                        PPF3ValidationBlock(..),
                        fromImageType,
                        ppf3DescriptionLength)
import Slap.Measure (Length(..), Offset(..))
import Slap.Narrow (EncodedHunk, encodedOffset, encodedPayload,
                    EncodedUndoHunk, encodedUndoOffset, encodedUndoPayload,
                    encodedUndoOriginal)
import Slap.Status (SlapAdvisory, CreateResult(..))
import Slap.Text (EncodedText, EncodingName(..),
                  encodedTextContent, encodeTextBounded, encodeTextLenient,
                  encodeLossAdvisories)
import Slap.FieldName (FieldName(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.FileContents (PatchFileContents(..))

import qualified Data.ByteString as ByteString
import Data.ByteString (ByteString)
import Data.ByteString.Builder
import qualified Data.ByteString.Lazy as LazyByteString
import Data.Maybe (isJust)

-- | Codepoint-aware bounded encode of the description into PPF3's
-- 50-byte field, space-padded on the right with @0x20@ to match the
-- reference maker, which fills the field with spaces
-- (@memset(description,0x20,50)@). Padding is applied here, local to
-- PPF3, so the shared bounded primitive stays padding-agnostic.
padDescription :: EncodedText -> (ByteString, [SlapAdvisory])
padDescription description =
  let width = unLength ppf3DescriptionLength
      (truncatedBytes, notices) =
        encodeTextBounded EncodingUtf8 width (encodedTextContent description)
      padded = truncatedBytes <> ByteString.replicate
                 (max 0 (width - ByteString.length truncatedBytes)) 0x20
      advisories = encodeLossAdvisories LabelPPF3 FieldDescription notices
  in (padded, advisories)

buildHeader :: ByteString -> Bool -> Bool -> ByteString -> PPF3ImageType -> Builder
buildHeader description blockCheck hasUndo validationBlock imageType =
  byteString "PPF30"                                    -- magic + version
  <> word8 0x02                                          -- encoding method
  <> byteString description                              -- 50-byte description
  <> word8 (fromImageType imageType)                     -- image type
  <> word8 (if blockCheck then 0x01 else 0x00)           -- block-check flag
  <> word8 (if hasUndo then 0x01 else 0x00)              -- undo flag
  <> word8 0x00                                          -- dummy
  <> if blockCheck then byteString validationBlock else mempty

encodeUndoRecord :: EncodedUndoHunk -> Builder
encodeUndoRecord ehunk =
  int64LE (fromIntegral (unOffset (encodedUndoOffset ehunk)))
  <> word8 (fromIntegral (ByteString.length (encodedUndoPayload ehunk)))
  <> byteString (encodedUndoPayload ehunk)
  <> byteString (encodedUndoOriginal ehunk)

encodeWriteRecord :: EncodedHunk -> Builder
encodeWriteRecord ehunk =
  int64LE (fromIntegral (unOffset (encodedOffset ehunk)))
  <> word8 (fromIntegral (ByteString.length (encodedPayload ehunk)))
  <> byteString (encodedPayload ehunk)

-- | Encode a PPF3 patch from pre-split, pre-narrowed records.
-- Write records: @[EncodedHunk]@, each payload ≤ @ppf3MaxRecordPayload@
-- (offset is unbounded — Int64-shaped on the wire — so the convert
-- pipeline narrows via 'Slap.Narrow.narrowHunksUnbounded').
-- Undo hunks (if provided): @[EncodedUndoHunk]@, each payload
-- ≤ @ppf3MaxRecordPayload@; the parallel undo pipeline
-- 'Slap.Measure.splitUndoHunks' →
-- 'Slap.Narrow.narrowUndoHunksUnbounded' enforces this.
encodePPF3 :: [EncodedHunk]
           -> EncodedText
           -> Maybe [EncodedUndoHunk]
           -> Maybe PPF3ValidationBlock
           -> PPF3ImageType
           -> CreateResult
encodePPF3 records description undoHunks validationBlock imageType =
  let (descriptionBytes, descriptionAdvisories) = padDescription description
      hasValidate = isJust validationBlock
      hasUndo     = isJust undoHunks
      validationBytes = maybe ByteString.empty unPPF3ValidationBlock validationBlock
      header = buildHeader descriptionBytes hasValidate hasUndo
                 validationBytes imageType
      body = case undoHunks of
        Just hunks -> foldMap encodeUndoRecord hunks
        Nothing    -> foldMap encodeWriteRecord records
  in CreateResult
       (PatchFileContents (LazyByteString.toStrict (toLazyByteString (header <> body))))
       descriptionAdvisories

-- | Encode a FILE_ID.DIZ trailer in PPF3 format (2-byte LE length).
-- Returns the trailer bytes plus any substitution advisories from
-- encoding the typed-text content as UTF-8.
encodeFileIdDiz :: PPF3FileId -> (ByteString, [SlapAdvisory])
encodeFileIdDiz fid =
  let description = unPPF3FileId fid
      (content, notices) =
        encodeTextLenient EncodingUtf8 (encodedTextContent description)
      advisories = encodeLossAdvisories LabelPPF3 FieldFileIdDiz notices
      trailer = LazyByteString.toStrict $ toLazyByteString $
                  byteString "@BEGIN_FILE_ID.DIZ"
                  <> byteString content
                  <> byteString "@END_FILE_ID.DIZ"
                  -- 'narrowPPF3FileId' validated the encoded byte count fits
                  -- 'Word16', so this 'fromIntegral' cannot truncate.
                  <> word16LE (fromIntegral (ByteString.length content))
  in (trailer, advisories)
