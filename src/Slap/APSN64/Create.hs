{-# LANGUAGE OverloadedStrings #-}

module Slap.APSN64.Create
  ( encodeAPSN64
  ) where

import Slap.APSN64.Types (fromAPSPatchType, APSPatchType(..), fromAPSRecordEncoding, APSRecordEncoding(..), apsN64MagicBytes, apsN64DescriptionWidth, APSN64DestinationSize, unAPSN64DestinationSize)
import Slap.Binary (putWord32LE)
import Slap.Measure (Offset(..))
import Slap.Narrow (EncodedHunk, encodedOffset, encodedPayload)
import Slap.Text (EncodedText, EncodingName(..),
                  encodedTextContent, encodeTextBounded, encodeLossAdvisories)
import Slap.Status (SlapAdvisory, CreateResult(..))
import Slap.FieldName (FieldName(..))
import Slap.FormatLabel (FormatLabel(..))

import Slap.FileContents (PatchFileContents(..))

import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Lazy as LazyByteString
import Data.ByteString.Builder (Builder, word8, byteString, toLazyByteString)
import Data.Word (Word32)

-- | Encode pre-diffed records as an APS N64 patch.
-- Patch type: APSSimple matches the simple-record structure we emit.
-- N64-specific (type 1) would require image format, cart ID, country.
-- Encoding byte: 0 is the canonical/default encoding; we emit APSDefaultRecordEncoding.
encodeAPSN64 :: [EncodedHunk] -> APSN64DestinationSize -> EncodedText -> CreateResult
encodeAPSN64 records destinationSize description =
    let (descriptionBytes, descriptionAdvisories) = padDescription description
        patchBytes = LazyByteString.toStrict $ toLazyByteString $
            byteString apsN64MagicBytes
            <> word8 (fromAPSPatchType APSSimple)
            <> word8 (fromAPSRecordEncoding APSDefaultRecordEncoding)
            <> byteString descriptionBytes
            <> putWord32LE (unAPSN64DestinationSize destinationSize)
            <> foldMap encodeAPSN64Record records
    in CreateResult (PatchFileContents patchBytes) descriptionAdvisories

-- | Codepoint-aware bounded encode of the description into APS-N64's
-- 50-byte field, space-padded on the right with @0x20@ to match the
-- format spec ("Space padded free text") and the original maker, which
-- fills the field with spaces (n64caps.c's @memset(Description,' ',50)@).
-- Substitution and truncation notices both surface as 'SlapAdvisory'
-- values tagged 'LabelAPSN64' \/ 'FieldDescription'.
padDescription :: EncodedText -> (ByteString.ByteString, [SlapAdvisory])
padDescription description =
  let (truncatedBytes, notices) =
        encodeTextBounded EncodingUtf8 apsN64DescriptionWidth
                          (encodedTextContent description)
      padded = truncatedBytes
            <> ByteString.replicate
                 (max 0 (apsN64DescriptionWidth - ByteString.length truncatedBytes))
                 0x20
      advisories = encodeLossAdvisories LabelAPSN64 FieldDescription notices
  in (padded, advisories)

-- | Encode one APS-N64 record. Caller must ensure the payload's length
-- is at most 'Slap.APSN64.Types.apsN64MaxChunkSize' (255 bytes); the
-- wire format reserves one byte for the length field.
encodeAPSN64Record :: EncodedHunk -> Builder
encodeAPSN64Record ehunk =
    let recordOffset  = encodedOffset ehunk
        recordPayload = encodedPayload ehunk
    in putWord32LE (fromIntegral (unOffset recordOffset) :: Word32)
       <> word8 (fromIntegral (ByteString.length recordPayload))
       <> byteString recordPayload
