{-# LANGUAGE OverloadedStrings #-}

module Slap.NINJA1.Create
  ( encodeNINJA1
  , encodeRecordBuilder
  , encodeBigEndian
  , ninja1HashInput
  ) where

import Slap.NINJA1.Types (NINJA1RomType(..), fromNINJA1RomType)
import Slap.Binary (putWord32BE)
import Slap.Checksum (CRC32(..))
import Slap.Measure (Offset(..), EncodedHunk(..))
import Slap.Compress (zlibDeflate)

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Char8 as ByteString8
import qualified Data.ByteString.Lazy as LazyByteString
import Data.ByteString.Builder (Builder, word8, byteString, toLazyByteString)
import Data.Bits (shiftR, (.&.))
import Data.Int (Int64)

-- | Encode pre-diffed records as a NINJA1 Binary patch.
-- When compress is True, zlib-compresses the payload and emits BZ subformat.
encodeNINJA1 :: [EncodedHunk]
             -> CRC32           -- source CRC32
             -> ByteString      -- source MD5 (16 bytes)
             -> ByteString      -- source SHA1 (20 bytes)
             -> NINJA1RomType   -- ROM platform type
             -> Bool            -- compress (BZ subformat)
             -> ByteString
encodeNINJA1 records sourceCRC sourceMD5 sourceSHA1 romType doCompress
  | doCompress = "NINJA1BZ" <> zlibDeflate payload
  | otherwise  = "NINJA1B " <> payload
  where
    payload = LazyByteString.toStrict $ toLazyByteString $
        word8 (fromNINJA1RomType romType)
        <> putWord32BE (unCRC32 sourceCRC)
        <> byteString sourceMD5
        <> byteString sourceSHA1
        <> foldMap encodeRecordBuilder records
        <> word8 3 <> byteString "EOF"     -- EOF sentinel

encodeRecordBuilder :: EncodedHunk -> Builder
encodeRecordBuilder (EncodedHunk hunkOffset hunkPayload) =
    let offsetEncoded = encodeBigEndian (fromIntegral (unOffset hunkOffset) :: Int64)
        lengthEncoded = encodeBigEndian (fromIntegral (ByteString.length hunkPayload) :: Int64)
    in word8 (fromIntegral (ByteString.length offsetEncoded))
       <> byteString offsetEncoded
       <> word8 (fromIntegral (ByteString.length lengthEncoded))
       <> byteString lengthEncoded
       <> byteString hunkPayload

-- | Encode an Int64 as minimal big-endian bytes (at least 1 byte).
encodeBigEndian :: Int64 -> ByteString
encodeBigEndian 0 = ByteString.singleton 0
encodeBigEndian value = ByteString.pack (extractBytes [] value)
  where
    extractBytes accumulated 0 = accumulated
    extractBytes accumulated remainder = extractBytes (fromIntegral (remainder .&. 0xFF) : accumulated) (remainder `shiftR` 8)

----------------------------------------------------------------------------
-- Large-file hash sampling
--
-- Per the PHP reference (ninja-1.01php), files >0x1e00000 bytes use a
-- sample instead of the full file: first 20 MiB + last 10 MiB + decimal
-- file size string.  CRC32/MD5/SHA1 are computed on this sample.
----------------------------------------------------------------------------

-- | Prepare hash input for NINJA1 source verification.
-- Files >0x1e00000 (30 MiB) use the sampling algorithm from the PHP
-- reference: first 0x1400000 bytes, last 0xa00000 bytes, decimal size.
ninja1HashInput :: ByteString -> ByteString
ninja1HashInput input
  | ByteString.length input > 0x1e00000 =
      let headSample = ByteString.take 0x1400000 input
          tailSample  = ByteString.drop (ByteString.length input - 0xa00000) input
          sizeString  = ByteString8.pack (show (ByteString.length input))
      in headSample <> tailSample <> sizeString
  | otherwise = input
