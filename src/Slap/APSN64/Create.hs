{-# LANGUAGE OverloadedStrings #-}

module Slap.APSN64.Create
  ( encodeAPSN64
  ) where

import Slap.APSN64.Types (fromAPSPatchType, APSPatchType(..), fromAPSRecordEncoding, APSRecordEncoding(..), APSN64Description(..), apsN64MagicBytes, apsN64DescriptionWidth)
import Slap.Binary (putWord32LE)
import Slap.Measure (Offset(..), OriginalLength(..), TruncatedLength(..))
import Slap.Narrow (EncodedHunk, encodedOffset, encodedPayload)
import Slap.TextEncoding (BoundedResult(..), TruncationInfo(..), encodeBoundedLocale)
import Slap.Error (SlapWarning(..), CreateResult(..))
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
-- Encoding byte: genuinely unused by all known implementations; 0 is canonical.
encodeAPSN64 :: [EncodedHunk] -> Word32 -> APSN64Description -> CreateResult
encodeAPSN64 records destinationSize description =
    let bounded = encodeBoundedLocale apsN64DescriptionWidth (unAPSN64Description description)
        descriptionWarnings = case boundedTruncation bounded of
          Nothing -> []
          Just info -> [FieldTruncated LabelAPSN64 FieldDescription
                         (OriginalLength (truncatedFrom info)) (TruncatedLength (truncatedTo info))]
        patchBytes = LazyByteString.toStrict $ toLazyByteString $
            byteString apsN64MagicBytes
            <> word8 (fromAPSPatchType APSSimple)
            <> word8 (fromAPSRecordEncoding APSDefaultRecordEncoding)
            <> byteString (boundedField bounded)
            <> putWord32LE destinationSize
            <> foldMap encodeAPSN64Record records
    in CreateResult (PatchFileContents patchBytes) descriptionWarnings

-- | Encode one APS-N64 record. Caller must ensure the payload's length
-- is at most 'Slap.APSN64.Types.apsN64MaxChunkSize' (255 bytes); the
-- wire format reserves one byte for the length field. 'Slap.Convert'
-- splits at 'splitHunks apsN64MaxChunkSize' before narrow, so all
-- 'EncodedHunk's reaching this function have payload length within
-- bounds.
encodeAPSN64Record :: EncodedHunk -> Builder
encodeAPSN64Record ehunk =
    let recordOffset  = encodedOffset ehunk
        recordPayload = encodedPayload ehunk
    in putWord32LE (fromIntegral (unOffset recordOffset) :: Word32)
       <> word8 (fromIntegral (ByteString.length recordPayload))
       <> byteString recordPayload
