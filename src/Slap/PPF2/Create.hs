{-# LANGUAGE OverloadedStrings #-}

-- | Wire encoder for PPF2 patches. PPF2 extends PPF1's record stream
-- (4-byte LE offset + 1-byte count + payload) with a header that
-- declares the source ROM's expected size and embeds a 1024-byte
-- block sampled from source offset 0x9320 for at-apply verification.
-- An optional FILE_ID.DIZ trailer follows the record stream.
--
-- Caller responsibilities (enforced upstream in 'Slap.Convert'):
--
-- * Same-size or growing target. PPF2 cannot express truncation —
--   no truncation marker exists in the wire format. The convert
--   layer's 'rejectTruncation' refuses shrinking-target inputs
--   with 'CannotExpressTargetShrinkage'.
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

import Slap.PPF2.Types (PPF2ValidationBlock(..), PPF2FileId(..),
                        ppf2DescriptionLength)
import Slap.Measure (Length(..), Offset(..), FileSize(..),
                     Hunk(..),
                     OriginalLength(..), TruncatedLength(..))
import Slap.TextEncoding (encodeLocaleField, truncateLocale)
import Slap.Error (SlapWarning(..), CreateResult(..), FieldName(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.FileContents (PatchFileContents(..))

import qualified Data.ByteString as ByteString
import Data.ByteString (ByteString)
import Data.ByteString.Builder
import qualified Data.ByteString.Lazy as LazyByteString

-- | Encode a PPF2 patch.
encodePPF2
  :: [Hunk]                -- ^ records, each payload ≤ 'ppf2MaxRecordPayload'
  -> String                -- ^ description (truncated and space-padded to 50 bytes)
  -> FileSize              -- ^ source ROM size (written into the header for verification)
  -> PPF2ValidationBlock   -- ^ 1024-byte block sampled from source[0x9320]
  -> CreateResult
encodePPF2 records description sourceFileSize (PPF2ValidationBlock validationBytes) =
  let (descriptionBytes, descriptionWarnings) = padDescription description
      header = buildHeader descriptionBytes sourceFileSize validationBytes
      body   = foldMap encodeRecord records
  in CreateResult
       (PatchFileContents (LazyByteString.toStrict (toLazyByteString (header <> body))))
       descriptionWarnings

-- | Space-pad the description to 50 bytes. Same shape as PPF1.Create's
-- helper — see that module for the rationale (matches the reference
-- @memset(buf,' ',50)@ + @strcpy@ + @space-overwrite@ idiom).
padDescription :: String -> (ByteString, [SlapWarning])
padDescription text =
  let encoded   = encodeLocaleField text
      width     = unLength ppf2DescriptionLength
      truncated = truncateLocale width encoded
      padded    = truncated <> ByteString.replicate
                    (max 0 (width - ByteString.length truncated)) 0x20
      warnings = if ByteString.length encoded > width
                   then [FieldTruncated LabelPPF2 FieldDescription
                           (OriginalLength (Length (ByteString.length encoded)))
                           (TruncatedLength (Length (ByteString.length truncated)))]
                   else []
  in (padded, warnings)

buildHeader :: ByteString -> FileSize -> ByteString -> Builder
buildHeader description (FileSize sourceSize) validationBytes =
  byteString "PPF20"                            -- 5-byte magic
  <> word8 0x01                                  -- encoding method 1 (PPF2)
  <> byteString description                      -- 50-byte padded description
  <> word32LE (fromIntegral sourceSize)          -- 4-byte LE source-file size
  <> byteString validationBytes                  -- 1024-byte validation block

encodeRecord :: Hunk -> Builder
encodeRecord (Hunk recordOffset recordPayload) =
  word32LE (fromIntegral (unOffset recordOffset))
  <> word8 (fromIntegral (ByteString.length recordPayload))
  <> byteString recordPayload

-- | Encode a FILE_ID.DIZ trailer in PPF2 format (4-byte LE length).
-- The PPF2 trailer wire shape is:
--
-- @\"\@BEGIN_FILE_ID.DIZ\" <content> \"\@END_FILE_ID.DIZ\" <length:LE32>@
--
-- Differs from PPF3's trailer only in the length field width
-- (PPF2: 4 bytes; PPF3: 2 bytes).
encodeFileIdDiz :: PPF2FileId -> ByteString
encodeFileIdDiz (PPF2FileId content) = LazyByteString.toStrict $ toLazyByteString $
  byteString "@BEGIN_FILE_ID.DIZ"
  <> byteString content
  <> byteString "@END_FILE_ID.DIZ"
  <> word32LE (fromIntegral (ByteString.length content))
