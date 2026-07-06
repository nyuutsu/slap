{-# LANGUAGE OverloadedStrings #-}

-- | BSDiff patch creation: "Slap.BSDiff.Parse", reversed. The
-- decomposition into control triples and the diff and extra streams
-- is the Rust differ's ('Slap.BSDiff.FFI.bsdiffDiff'); this module
-- owns every wire byte — 'putSignMagnitude64' beside Parse's
-- 'getSignMagnitude64', 'bzip2Compress' where Parse decompresses,
-- and the 32-byte header written where 'parseBSDiff' splits it.
module Slap.BSDiff.Create
  ( createBSDiff
  , putSignMagnitude64
  ) where

import Slap.BSDiff.FFI (BSDiffDifferOutput(..), bsdiffDiff)
import Slap.BSDiff.Types (BSDiffInstruction(..), bsdiffMagicBytes)
import Slap.Compression.Stream (bzip2Compress)
import Slap.FileContents (InputFileContents, OutputFileContents(..), PatchFileContents(..))
import Slap.Measure (Length(..), Delta(..))
import Slap.Status (SlapError, CreateResult(..))

import Data.Bits ((.|.), bit)
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.ByteString.Builder (Builder, byteString, toLazyByteString, word64LE)
import qualified Data.ByteString.Lazy as LazyByteString
import Data.Int (Int64)
import Data.Word (Word64)

-- | Create a BSDIFF40 patch using the Rust diff engine. Every
-- (source, target) pair is encodeable — the format's 64-bit fields
-- outreach any input buffer — so the only 'Left' is the differ
-- surfacing an internal-invariant violation.
createBSDiff :: InputFileContents -> OutputFileContents
             -> Either SlapError CreateResult
createBSDiff inputContents outputContents@(OutputFileContents modified) = do
  differOutput <- bsdiffDiff inputContents outputContents
  let controlCompressed = bzip2Compress (encodeControlStream (bsdiffDifferInstructions differOutput))
      diffCompressed    = bzip2Compress (bsdiffDifferDiffStream  differOutput)
      extraCompressed   = bzip2Compress (bsdiffDifferExtraStream differOutput)
      -- The header names the two leading sections' compressed sizes
      -- and the target's size; the extra section's size is whatever
      -- remains, exactly how 'parseBSDiff' reads it back.
      patch = byteString bsdiffMagicBytes
              <> putSignMagnitude64 (fromIntegral (ByteString.length controlCompressed))
              <> putSignMagnitude64 (fromIntegral (ByteString.length diffCompressed))
              <> putSignMagnitude64 (fromIntegral (ByteString.length modified))
              <> byteString controlCompressed
              <> byteString diffCompressed
              <> byteString extraCompressed
  Right (CreateResult (PatchFileContents (LazyByteString.toStrict (toLazyByteString patch))) [])

-- | Serialize the control triples, 24 bytes each — the stream
-- 'Slap.BSDiff.Parse.parseInstructions' reads back.
encodeControlStream :: [BSDiffInstruction] -> ByteString
encodeControlStream instructions =
  LazyByteString.toStrict (toLazyByteString (foldMap encodeInstruction instructions))
  where
    encodeInstruction instruction =
      putSignMagnitude64 (fromIntegral (unLength (controlAdd  instruction)))
      <> putSignMagnitude64 (fromIntegral (unLength (controlCopy instruction)))
      <> putSignMagnitude64 (fromIntegral (unDelta  (controlSeek instruction)))

-- | Write a signed 64-bit LE value in bsdiff sign-magnitude form:
-- magnitude in the low 63 bits, the sign in bit 63. Round-trip
-- partner of 'Slap.BSDiff.Parse.getSignMagnitude64'. The one 'Int64'
-- with no sign-magnitude form, 'minBound', cannot reach here: every
-- value written is a length or displacement inside buffers whose
-- sizes fit the host 'Int'.
putSignMagnitude64 :: Int64 -> Builder
putSignMagnitude64 value
  | value < 0 = word64LE (fromIntegral (negate value) .|. signBit)
  | otherwise = word64LE (fromIntegral value)
  where
    signBit = bit 63 :: Word64
