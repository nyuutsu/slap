{-# LANGUAGE OverloadedStrings #-}

-- | Wire encoder for PPF1 patches. PPF1's record format is a 4-byte
-- LE offset + 1-byte count + @count@ payload bytes (literal mode);
-- the count=0 RLE mode in the spec is honored on parse but never
-- emitted on create — the reference @makeppf.c@ doesn't emit RLE
-- either, and matching that gives byte-equivalent output for the
-- common case.
--
-- Same-size and growing-target patches are expressible. Truncating
-- patches are not (PPF1 has no size field, and the wire format
-- offers no way to declare that the target is shorter than the
-- source); the convert-layer caller refuses those before reaching
-- this encoder.
module Slap.PPF1.Create
  ( encodePPF1
  ) where

import Slap.PPF1.Types (PPF1Origin(..), ppf1DescriptionLength)
import Slap.Measure (Length(..), Offset(..))
import Slap.Narrow (EncodedHunk, encodedOffset, encodedPayload)
import Slap.Status (SlapAdvisory, CreateResult(..))
import Slap.Text (EncodedText, EncodingName(..),
                  encodedTextContent, encodeTextBounded, encodeLossAdvisories)
import Slap.FieldName (FieldName(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.FileContents (PatchFileContents(..))

import qualified Data.ByteString as ByteString
import Data.ByteString (ByteString)
import Data.ByteString.Builder
import qualified Data.ByteString.Lazy as LazyByteString
import Data.Word (Word32)

-- | Encode a PPF1 patch from pre-split, pre-narrowed records.
-- 'EncodedHunk' is the typed proof that each record's offset fits the
-- 4-byte field ('Slap.PPF1.Types.ppf1Limits') and each payload fits
-- the single-byte count field ('Slap.PPF1.Types.ppf1MaxRecordPayload')
-- — the convert-layer pipeline runs @splitHunks ppf1MaxRecordPayload@
-- and @narrowHunks ppf1Limits@ before reaching this encoder, so the
-- @fromIntegral@ casts at the offset and length sites are
-- safe-by-construction.
encodePPF1 :: PPF1Origin -> [EncodedHunk] -> EncodedText -> CreateResult
encodePPF1 origin records description =
  let writeOffsetWord = case origin of
        PPF1OriginPC    -> word32LE
        PPF1OriginAmiga -> word32BE
      (descriptionBytes, descriptionAdvisories) = padDescription description
      header = buildHeader descriptionBytes
      body   = foldMap (encodeRecord writeOffsetWord) records
  in CreateResult
       (PatchFileContents (LazyByteString.toStrict (toLazyByteString (header <> body))))
       descriptionAdvisories

-- | Encode the description as exactly 'ppf1DescriptionLength' bytes,
-- space-padded on the right per the PPF1 spec doc and matching the
-- reference @makeppf.c@ exactly: that source @memset@s the buffer to
-- @' '@, @strcpy@s the text in, then writes a space over the
-- @strcpy@'s NUL terminator — so the on-wire bytes are
-- @text ++ replicate (50 - length text) 0x20@, no NULs anywhere.
--
-- Codepoint-aware truncation via 'encodeTextBounded' fits the bytes
-- under the 50-byte cap without splitting codepoints; the @0x20@
-- right-pad happens here, locally to PPF1, because PPF3 fills the
-- same field with @0x00@ — the padding byte is format-faithful and
-- does not belong inside the shared bounded-encode primitive.
padDescription :: EncodedText -> (ByteString, [SlapAdvisory])
padDescription description =
  let width = unLength ppf1DescriptionLength
      (truncatedBytes, notices) =
        encodeTextBounded EncodingLocale width (encodedTextContent description)
      padded = truncatedBytes <> ByteString.replicate
                 (max 0 (width - ByteString.length truncatedBytes)) 0x20
      advisories = encodeLossAdvisories LabelPPF1 FieldDescription notices
  in (padded, advisories)

buildHeader :: ByteString -> Builder
buildHeader description =
  byteString "PPF10"          -- magic + version (5 bytes)
  <> word8 0x00                -- encoding method
  <> byteString description    -- 50-byte padded description

encodeRecord :: (Word32 -> Builder) -> EncodedHunk -> Builder
encodeRecord writeOffsetWord ehunk =
  writeOffsetWord (fromIntegral (unOffset (encodedOffset ehunk)))
  <> word8 (fromIntegral (ByteString.length (encodedPayload ehunk)))
  <> byteString (encodedPayload ehunk)
