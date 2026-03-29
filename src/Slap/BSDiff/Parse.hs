{-# LANGUAGE OverloadedStrings #-}

module Slap.BSDiff.Parse
  ( parseBSDiff
  , parseControls
  , getSignMagnitude64
  , safeDecompressBZip
  ) where

-- Canonical reference: bsdiff 4.3 source (Colin Percival)

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.Bits ((.&.), (.|.), shiftL, testBit)
import Data.Int (Int64)
import Slap.BSDiff.Types (BSDiffPatch(..), BSDiffControl(..))
import Slap.Compress (bz2Decompress)
import Slap.Measure (FileSize(..), Delta(..))

----------------------------------------------------------------------------
-- Signed LE64 (bsdiff sign-magnitude encoding)
----------------------------------------------------------------------------

-- | Read a signed 64-bit LE value in bsdiff format.
-- Bit 63 of byte 7 is the sign; lower 63 bits are the magnitude (LE).
getSignMagnitude64 :: Int -> ByteString -> Int64
getSignMagnitude64 offset input =
  let readByte index = fromIntegral (ByteString.index input (offset + index)) :: Int64
      magnitude = readByte 0 .|. (readByte 1 `shiftL` 8) .|. (readByte 2 `shiftL` 16) .|. (readByte 3 `shiftL` 24)
                  .|. (readByte 4 `shiftL` 32) .|. (readByte 5 `shiftL` 40) .|. (readByte 6 `shiftL` 48)
                  .|. ((readByte 7 .&. 0x7F) `shiftL` 56)
  in if testBit (ByteString.index input (offset + 7)) 7
     then negate magnitude
     else magnitude

----------------------------------------------------------------------------
-- Safe decompression
----------------------------------------------------------------------------

safeDecompressBZip :: String -> ByteString -> Either String ByteString
safeDecompressBZip _     compressed | ByteString.null compressed = Right ByteString.empty
safeDecompressBZip label compressed = case bz2Decompress compressed of
  Left _  -> Left ("BSDiff: " ++ label ++ " decompression failed")
  Right decompressed -> Right decompressed

----------------------------------------------------------------------------
-- Parsing
----------------------------------------------------------------------------

parseBSDiff :: ByteString -> Either String BSDiffPatch
parseBSDiff input
  | ByteString.length input < 32 = Left "BSDiff: input too short"
  | ByteString.take 8 input /= "BSDIFF40" = Left "not a BSDiff file (bad magic)"
  | rawControlSize < 0 || rawDiffSize < 0 || rawTargetSize < 0 = Left "BSDiff: invalid header (negative size)"
  | otherwise = do
      controlData  <- safeDecompressBZip "control" controlCompressed
      diffData  <- safeDecompressBZip "diff" diffCompressed
      extraData <- safeDecompressBZip "extra" extraCompressed
      let controls = parseControls controlData
          rawExtraSize = fromIntegral (ByteString.length input) - 32 - rawControlSize - rawDiffSize
      Right (BSDiffPatch (FileSize rawControlSize) (FileSize rawDiffSize) (FileSize rawExtraSize) (FileSize rawTargetSize) controls diffData extraData)
  where
    rawControlSize = getSignMagnitude64 8 input
    rawDiffSize = getSignMagnitude64 16 input
    rawTargetSize  = getSignMagnitude64 24 input
    controlOffset  = 32
    diffOffset  = 32 + fromIntegral rawControlSize
    extraOffset = diffOffset + fromIntegral rawDiffSize
    controlCompressed  = ByteString.take (fromIntegral rawControlSize) (ByteString.drop controlOffset input)
    diffCompressed  = ByteString.take (fromIntegral rawDiffSize) (ByteString.drop diffOffset input)
    extraCompressed = ByteString.drop extraOffset input

parseControls :: ByteString -> [BSDiffControl]
parseControls input
  | ByteString.length input < 24 = []
  | otherwise =
      BSDiffControl (getSignMagnitude64 0 input) (getSignMagnitude64 8 input) (Delta (getSignMagnitude64 16 input))
        : parseControls (ByteString.drop 24 input)
