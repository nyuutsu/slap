{-# LANGUAGE OverloadedStrings #-}

module Slap.APSN64.Create
  ( encodeAPSN64
  , splitLong
  , encodeN64Record
  ) where

import Slap.APSN64.Types (fromAPSPatchType, APSPatchType(..), fromAPSRecordEncoding, APSRecordEncoding(..), apsN64DescriptionWidth, apsN64MaxChunkSize)
import Slap.Binary (putWord32LE)
import Slap.Measure (Offset(..), Length(..), EncodedHunk(..), advance)
import Slap.TextEncoding (BoundedResult(..), TruncationInfo(..), encodeBoundedLocale)
import Slap.Error (SlapWarning(..), CreateResult(..), FieldName(..))
import Slap.FormatLabel (FormatLabel(..))

import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Lazy as LazyByteString
import Data.ByteString.Builder (Builder, word8, byteString, toLazyByteString)
import Data.Word (Word32)

-- | Encode pre-diffed records as an APS N64 patch.
-- Records are split at apsN64MaxChunkSize bytes internally.
-- Patch type: APSSimple matches the simple-record structure we emit.
-- N64-specific (type 1) would require image format, cart ID, country.
-- Encoding byte: genuinely unused by all known implementations; 0 is canonical.
encodeAPSN64 :: [EncodedHunk] -> Word32 -> String -> CreateResult
encodeAPSN64 records destinationSize description =
    let bounded = encodeBoundedLocale apsN64DescriptionWidth description
        descriptionWarnings = case boundedTruncation bounded of
          Nothing -> []
          Just info -> [FieldTruncated LabelAPSN64 FieldDescription
                         (Length (truncatedFrom info)) (Length (truncatedTo info))]
        patchBytes = LazyByteString.toStrict $ toLazyByteString $
            byteString "APS10"
            <> word8 (fromAPSPatchType APSSimple)
            <> word8 (fromAPSRecordEncoding APSDefaultRecordEncoding)
            <> byteString (boundedField bounded)
            <> putWord32LE destinationSize
            <> foldMap encodeN64Record (splitLong records)
    in CreateResult patchBytes descriptionWarnings

splitLong :: [EncodedHunk] -> [EncodedHunk]
splitLong = concatMap splitRecord
  where
    splitRecord (EncodedHunk hunkOffset hunkPayload)
      | ByteString.length hunkPayload <= apsN64MaxChunkSize = [EncodedHunk hunkOffset hunkPayload]
      | otherwise =
          let (chunk, rest) = ByteString.splitAt apsN64MaxChunkSize hunkPayload
          in EncodedHunk hunkOffset chunk : splitRecord (EncodedHunk (advance hunkOffset (Length apsN64MaxChunkSize)) rest)

encodeN64Record :: EncodedHunk -> Builder
encodeN64Record (EncodedHunk hunkOffset hunkPayload) =
    putWord32LE (fromIntegral (unOffset hunkOffset) :: Word32)
    <> word8 (fromIntegral (ByteString.length hunkPayload))
    <> byteString hunkPayload
