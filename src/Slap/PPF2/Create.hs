{-# LANGUAGE OverloadedStrings #-}

-- | Wire encoder for PPF2 patches. PPF2 extends PPF1's record stream
-- (4-byte LE offset + 1-byte count + payload) with a header that
-- declares the source ROM's expected size and embeds a 1024-byte
-- block sampled from source offset 0x9320 for at-apply verification.
-- An optional FILE_ID.DIZ trailer follows the record stream.
--
-- Caller responsibilities (enforced upstream in 'Slap.Convert'):
--
-- * Same-size or growing target. PPF2 can shrink nothing — records
--   only overwrite or add bytes — but growth is allowed, since PPF2's
--   source-size header is an advisory identity check rather than an
--   integrity rule. The convert layer's
--   'Slap.Convert.rejectIncompatibleSizeChange' dispatches to
--   'Slap.PPF2.Types.ppf2RejectIncompatibleSizeChange', which refuses
--   only shrinkage. See @docs\/ppf\/spec.md@, "Size-changing patches"
--   under PPF2.
--
-- * Source size ≥ 0x9720 bytes. Smaller sources can't supply a
--   1024-byte validation block at offset 0x9320; the convert layer
--   refuses with 'SourceTooSmallForPPF2Validation'.
--
-- * Per-record payload ≤ 'Slap.PPF2.Types.ppf2MaxRecordPayload'
--   (255 bytes). The convert layer calls @splitHunks@ before
--   reaching this encoder.
module Slap.PPF2.Create
  ( encodePPF2
  , encodeFileIdDiz
  ) where

import Slap.PPF2.Types (PPF2ValidationBlock(..),
                        PPF2FileId, unPPF2FileId,
                        PPF2SourceSize, unPPF2SourceSize,
                        ppf2DescriptionLength)
import Slap.Measure (Length(..), Offset(..))
import Slap.Narrow (EncodedHunk, encodedOffset, encodedPayload)
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

-- | Encode a PPF2 patch from pre-split, pre-narrowed records.
-- 'EncodedHunk' is the typed proof that each record's offset fits the
-- 4-byte LE field ('Slap.PPF2.Types.ppf2Limits') and each payload
-- fits the single-byte count field
-- ('Slap.PPF2.Types.ppf2MaxRecordPayload') — the convert-layer
-- pipeline runs @splitHunks ppf2MaxRecordPayload@ and
-- @narrowHunks ppf2Limits@ before reaching this encoder.
encodePPF2
  :: [EncodedHunk]         -- ^ pre-split, pre-narrowed records
  -> EncodedText           -- ^ description (truncated and space-padded to 50 bytes)
  -> PPF2SourceSize        -- ^ source ROM size (written into the header for verification)
  -> PPF2ValidationBlock   -- ^ 1024-byte block sampled from source[0x9320]
  -> CreateResult
encodePPF2 records description sourceSize (PPF2ValidationBlock validationBytes) =
  let (descriptionBytes, descriptionAdvisories) = padDescription description
      header = buildHeader descriptionBytes sourceSize validationBytes
      body   = foldMap encodeRecord records
  in CreateResult
       (PatchFileContents (LazyByteString.toStrict (toLazyByteString (header <> body))))
       descriptionAdvisories

-- | Space-pad the description to 50 bytes. Same shape as PPF1.Create's
-- helper — see that module for the rationale (matches the reference
-- @memset(buf,' ',50)@ + @strcpy@ + @space-overwrite@ idiom).
padDescription :: EncodedText -> (ByteString, [SlapAdvisory])
padDescription description =
  let (truncatedBytes, notices) =
        encodeTextBounded EncodingUtf8 ppf2DescriptionLength (encodedTextContent description)
      padded = truncatedBytes <> ByteString.replicate
                 (max 0 (unLength ppf2DescriptionLength - ByteString.length truncatedBytes)) 0x20
      advisories = encodeLossAdvisories LabelPPF2 FieldDescription notices
  in (padded, advisories)

buildHeader :: ByteString -> PPF2SourceSize -> ByteString -> Builder
buildHeader description sourceSize validationBytes =
  byteString "PPF20"                            -- 5-byte magic
  <> word8 0x01                                  -- encoding method 1 (PPF2)
  <> byteString description                      -- 50-byte padded description
  <> word32LE (unPPF2SourceSize sourceSize)      -- 4-byte LE source-file size
  <> byteString validationBytes                  -- 1024-byte validation block

encodeRecord :: EncodedHunk -> Builder
encodeRecord ehunk =
  word32LE (fromIntegral (unOffset (encodedOffset ehunk)))
  <> word8 (fromIntegral (ByteString.length (encodedPayload ehunk)))
  <> byteString (encodedPayload ehunk)

-- | Encode a FILE_ID.DIZ trailer in PPF2 format (4-byte LE length).
-- The PPF2 trailer wire shape is:
--
-- @"\@BEGIN_FILE_ID.DIZ" <content> "\@END_FILE_ID.DIZ" <length:LE32>@
--
-- Differs from PPF3's trailer only in the length field width
-- (PPF2: 4 bytes; PPF3: 2 bytes). Returns the trailer bytes plus any
-- substitution advisories from encoding the typed-text content
-- as UTF-8.
encodeFileIdDiz :: PPF2FileId -> (ByteString, [SlapAdvisory])
encodeFileIdDiz fid =
  let description = unPPF2FileId fid
      (content, notices) =
        encodeTextLenient EncodingUtf8 (encodedTextContent description)
      advisories = encodeLossAdvisories LabelPPF2 FieldFileIdDiz notices
      trailer = LazyByteString.toStrict $ toLazyByteString $
                  byteString "@BEGIN_FILE_ID.DIZ"
                  <> byteString content
                  <> byteString "@END_FILE_ID.DIZ"
                  -- 'narrowPPF2FileId' validated the encoded byte count fits
                  -- 'Word32', so this 'fromIntegral' cannot truncate.
                  <> word32LE (fromIntegral (ByteString.length content))
  in (trailer, advisories)
