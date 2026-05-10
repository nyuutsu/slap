{-# LANGUAGE OverloadedStrings #-}

module Slap.NINJA1.Create
  ( encodeNINJA1
  , encodeRecordBuilder
  , encodeBigEndian
  , ninja1HashInput
  , resolveSentinelCollisions
  ) where

import Slap.NINJA1.Types (NINJA1RomType(..), fromNINJA1RomType)
import Slap.Binary (putWord32BE)
import Slap.Checksum (CRC32(..), MD5Hash(..), SHA1Hash(..))
import Slap.Error (SlapError(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.Measure (Delta(..), Cursor(..), Offset(..),
                     Hunk(..),
                     SplitHunk, splitOffset, splitPayload,
                     SentinelOffset(..), offsetToInt)
import Slap.Narrow (EncodedHunk, encodedOffset, encodedPayload)
import Slap.Compression.Stream (zlibDeflate)

import Slap.FileContents (PatchFileContents(..), InputFileContents(..))

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Lazy as LazyByteString
import Data.ByteString.Builder (Builder, word8, byteString, intDec, toLazyByteString)
import Data.Bits (shiftR, (.&.))
import Data.Int (Int64)

-- | Encode pre-diffed records as a NINJA1 Binary patch.
-- When compress is True, zlib-compresses the payload and emits BZ subformat.
encodeNINJA1 :: [EncodedHunk]
             -> CRC32           -- source CRC32
             -> MD5Hash         -- source MD5 (16 bytes)
             -> SHA1Hash        -- source SHA1 (20 bytes)
             -> NINJA1RomType   -- ROM platform type
             -> Bool            -- compress (BZ subformat)
             -> PatchFileContents
encodeNINJA1 records sourceCRC sourceMD5 sourceSHA1 romType doCompress
  | doCompress = PatchFileContents $ "NINJA1BZ" <> zlibDeflate payload
  | otherwise  = PatchFileContents $ "NINJA1B " <> payload
  where
    payload = LazyByteString.toStrict $ toLazyByteString $
        word8 (fromNINJA1RomType romType)
        <> putWord32BE (unCRC32 sourceCRC)
        <> byteString (unMD5Hash sourceMD5)
        <> byteString (unSHA1Hash sourceSHA1)
        <> foldMap encodeRecordBuilder records
        <> word8 3 <> byteString "EOF"     -- EOF sentinel

encodeRecordBuilder :: EncodedHunk -> Builder
encodeRecordBuilder ehunk =
    let recordOffset  = encodedOffset ehunk
        recordPayload = encodedPayload ehunk
        offsetEncoded = encodeBigEndian (fromIntegral (unOffset recordOffset) :: Int64)
        lengthEncoded = encodeBigEndian (fromIntegral (ByteString.length recordPayload) :: Int64)
    in word8 (fromIntegral (ByteString.length offsetEncoded))
       <> byteString offsetEncoded
       <> word8 (fromIntegral (ByteString.length lengthEncoded))
       <> byteString lengthEncoded
       <> byteString recordPayload

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
          sizeString  = LazyByteString.toStrict (toLazyByteString (intDec (ByteString.length input)))
      in headSample <> tailSample <> sizeString
  | otherwise = input

----------------------------------------------------------------------------
-- Sentinel-collision resolution
----------------------------------------------------------------------------

-- | Resolve every record that sits on the NINJA1 binary trailer
-- sentinel ('ninja1SentinelOffset' = @0x454F46@). NINJA1's footer is a
-- width prefix of @3@ followed by the bytes @"EOF"@; an offset value of
-- @0x454F46@ minimally encodes to exactly those three bytes, so its
-- record header collides with the trailer and the parser stops early,
-- silently dropping every record after the colliding one.
--
-- Two outcomes per record:
--
-- * "Fixable": the record's offset equals the sentinel, offset \> 0,
--   and the source contains the byte at @sentinel - 1@. The record
--   is rewritten to begin one byte earlier with that preceding byte
--   prepended to its payload. The prepended byte overwrites itself
--   (a no-op write) and the original payload lands at the original
--   offset; the wire bytes no longer trigger the trailer check.
--
-- * "Unfixable": the record's offset equals the sentinel but the
--   source has no byte to prepend — either because the source is
--   empty (source-less direct conversion), the source is shorter
--   than @sentinel@, or the sentinel sits at offset @0@ so there is
--   no preceding position. The whole call returns
--   'Left' 'SentinelCollisionUnfixable' with the format label and
--   the colliding offset, and the conversion aborts rather than
--   emitting bytes a parser could not faithfully round-trip.
--
-- Records whose offset is not the sentinel pass through unchanged —
-- the explicit "not a collision" branch, not a silent catch-all.
--
-- This function is a deliberate structural duplicate of
-- 'Slap.IPS.Create.resolveSentinelCollisions'. The two formats share
-- exactly this logic but format modules do not import each other; the
-- copy lives here so NINJA1's pipeline does not depend on IPS, and
-- the parameterized signature keeps both copies pin-compatible so
-- future drift is easy to spot.
--
-- The function operates on already-split records ('SplitHunk') and
-- unwraps them to raw 'Hunk's on output, parallel to
-- 'Slap.IPS.Create.resolveSentinelCollisions'. NINJA1's wire format
-- uses a variable-width length-of-length encoding with no per-record
-- cap, so the second 'splitHunksUnbounded' pass that the convert
-- pipeline runs after this function is a no-op for NINJA1 — present
-- for type uniformity with the IPS variants where the same pass
-- closes a real overflow hazard.
resolveSentinelCollisions
  :: FormatLabel
  -> SentinelOffset
  -> InputFileContents
  -> [SplitHunk]
  -> Either SlapError [Hunk]
resolveSentinelCollisions label sentinel (InputFileContents source) =
  traverse resolveOne
  where
    SentinelOffset sentinelPosition = sentinel
    sourceLength                    = ByteString.length source

    resolveOne record
      | recordOffset /= sentinelPosition = Right (Hunk recordOffset recordPayload)
      | offsetToInt recordOffset > 0
      , offsetToInt recordOffset - 1 < sourceLength =
          let precedingByteIndex = offsetToInt recordOffset - 1
              precedingByte      =
                ByteString.index source precedingByteIndex
              extendedPayload    =
                ByteString.cons precedingByte recordPayload
          in Right (Hunk (displace recordOffset (Delta (-1))) extendedPayload)
      | otherwise =
          Left (SentinelCollisionUnfixable label sentinel)
      where
        recordOffset  = splitOffset record
        recordPayload = splitPayload record
