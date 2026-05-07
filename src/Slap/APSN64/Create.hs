{-# LANGUAGE OverloadedStrings #-}

module Slap.APSN64.Create
  ( encodeAPSN64
  ) where

import Slap.APSN64.Types (fromAPSPatchType, APSPatchType(..), fromAPSRecordEncoding, APSRecordEncoding(..), APSN64Description(..), apsN64MagicBytes, apsN64DescriptionWidth, apsN64MaxChunkSize)
import Slap.Binary (putWord32LE)
import Slap.Measure (Offset(..), Length(..), EncodedHunk(..), advance, byteLength,
                     OriginalLength(..), TruncatedLength(..))
import Slap.TextEncoding (BoundedResult(..), TruncationInfo(..), encodeBoundedLocale)
import Slap.Error (SlapWarning(..), CreateResult(..), FieldName(..))
import Slap.FormatLabel (FormatLabel(..))

import Slap.FileContents (PatchFileContents(..))

import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Lazy as LazyByteString
import Data.ByteString.Builder (Builder, word8, byteString, toLazyByteString)
import Data.Word (Word32)

-- | Encode pre-diffed records as an APS N64 patch.
-- Records are split at apsN64MaxChunkSize bytes internally.
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
            <> foldMap encodeHunkAsRecords records
    in CreateResult (PatchFileContents patchBytes) descriptionWarnings

-- | Encode a hunk as one or more APS-N64 records. A hunk whose
-- payload fits in 'apsN64MaxChunkSize' emits a single record;
-- larger hunks split into back-to-back records, each addressing
-- the appropriate continuation offset. Adjacency is wire-level
-- only — the parser sees N independent records, not a logical
-- group.
encodeHunkAsRecords :: EncodedHunk -> Builder
encodeHunkAsRecords (EncodedHunk hunkOffset hunkPayload)
  | byteLength hunkPayload <= apsN64MaxChunkSize =
      emitOneRecord hunkOffset hunkPayload
  | otherwise =
      let (chunk, leftover) = ByteString.splitAt (unLength apsN64MaxChunkSize) hunkPayload
          nextOffset        = advance hunkOffset apsN64MaxChunkSize
      in emitOneRecord hunkOffset chunk
         <> encodeHunkAsRecords (EncodedHunk nextOffset leftover)
  where
    -- emitOneRecord's recordPayload has byteLength at most
    -- apsN64MaxChunkSize (= 255) by construction at both call
    -- sites above: the guard on the small path, and
    -- ByteString.splitAt's contract on the chunked path. The
    -- fromIntegral on the payload length below is therefore a
    -- no-op narrowing rather than a silent truncation.
    emitOneRecord recordOffset recordPayload =
        putWord32LE (fromIntegral (unOffset recordOffset) :: Word32)
        <> word8 (fromIntegral (ByteString.length recordPayload))
        <> byteString recordPayload
