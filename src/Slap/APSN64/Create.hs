{-# LANGUAGE OverloadedStrings #-}

module Slap.APSN64.Create
  ( encodeAPSN64
  , splitLong
  , encodeN64Record
  ) where

import Slap.APSN64.Types (fromAPSPatchType, APSPatchType(..), apsN64DescriptionWidth)
import Slap.Binary (putWord32LE)
import Slap.Measure (Offset(..), EncodedHunk(..))

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Char8 as ByteString8
import qualified Data.ByteString.Lazy as LazyByteString
import Data.ByteString.Builder (Builder, word8, byteString, toLazyByteString)
import Data.Word (Word32)

-- | Encode pre-diffed records as an APS N64 patch.
-- Records are split at 255 bytes internally.
-- Patch type: APSSimple matches the simple-record structure we emit.
-- N64-specific (type 1) would require image format, cart ID, country.
-- Encoding byte: genuinely unused by all known implementations; 0 is canonical.
encodeAPSN64 :: [EncodedHunk] -> Word32 -> String -> ByteString
encodeAPSN64 records destinationSize description = LazyByteString.toStrict $ toLazyByteString $
    byteString "APS10"             -- magic
    <> word8 (fromAPSPatchType APSSimple)  -- patch type: simple
    <> word8 0                     -- encoding: not used
    <> byteString descriptionBytes        -- 50-byte description
    <> putWord32LE destinationSize -- dest size
    <> foldMap encodeN64Record (splitLong records)
  where
    descriptionBytes = let padded = ByteString8.pack (take apsN64DescriptionWidth description)
                in padded <> ByteString.replicate (apsN64DescriptionWidth - ByteString.length padded) 0

splitLong :: [EncodedHunk] -> [EncodedHunk]
splitLong = concatMap splitRecord
  where
    splitRecord (EncodedHunk hunkOffset hunkPayload)
      | ByteString.length hunkPayload <= 255 = [EncodedHunk hunkOffset hunkPayload]
      | otherwise =
          let (chunk, rest) = ByteString.splitAt 255 hunkPayload
          in EncodedHunk hunkOffset chunk : splitRecord (EncodedHunk (Offset (unOffset hunkOffset + 255)) rest)

encodeN64Record :: EncodedHunk -> Builder
encodeN64Record (EncodedHunk hunkOffset hunkPayload) =
    putWord32LE (fromIntegral (unOffset hunkOffset) :: Word32)
    <> word8 (fromIntegral (ByteString.length hunkPayload))
    <> byteString hunkPayload
