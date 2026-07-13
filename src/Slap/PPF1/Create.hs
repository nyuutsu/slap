{-# LANGUAGE OverloadedStrings #-}

-- | Wire encoder for PPF1 patches. PPF1's record format is a 4-byte
-- LE offset + 1-byte count + @count@ payload bytes (literal mode);
-- the count=0 RLE mode in the spec is parsed but never emitted on
-- create, as the reference @makeppf.c@ doesn't emit RLE either.
--
-- Same-size patches only. PPF1's wire format has no command for
-- declaring growth or shrinkage; see 'Slap.PPF1.Types.ppf1RejectIncompatibleSizeChange'
-- for slap's enforcement and @docs\/ppf\/spec.md@ for the upstream
-- picture. The convert layer's 'Slap.Convert.rejectIncompatibleSizeChange'
-- runs the check before reaching this encoder.
module Slap.PPF1.Create
  ( encodePPF1
  ) where

import Slap.PPF1.Types (PPF1Origin(..), ppf1DescriptionLength)
import Slap.Binary (replicateLength)
import Slap.Measure (Offset(..), byteLength, minLength, subtractLength)
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
-- @fromIntegral@ casts at the offset and length sites cannot truncate.
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
-- space-padded on the right. The reference @makeppf.c@ @memset@s the
-- buffer to @' '@, @strcpy@s the text in, then writes a space over
-- the NUL terminator, so the on-wire bytes are
-- @text ++ replicate (50 - length text) 0x20@ with no NULs anywhere.
-- 'encodeTextBounded' does the codepoint-aware truncation under the
-- 50-byte cap; the @0x20@ pad lives here rather than in that shared
-- primitive because PPF3 pads the same field with @0x00@.
padDescription :: EncodedText -> (ByteString, [SlapAdvisory])
padDescription description =
  let (truncatedBytes, notices) =
        encodeTextBounded EncodingUtf8 ppf1DescriptionLength (encodedTextContent description)
      padded = truncatedBytes <> replicateLength
                 (subtractLength ppf1DescriptionLength (minLength ppf1DescriptionLength (byteLength truncatedBytes))) 0x20
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
