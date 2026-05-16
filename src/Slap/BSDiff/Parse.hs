{-# LANGUAGE OverloadedStrings #-}

module Slap.BSDiff.Parse
  ( parseBSDiff
  , parseInstructions
  , getSignMagnitude64
  , safeDecompressBZip
  ) where

-- Canonical reference: bsdiff 4.3 source (Colin Percival)

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.Bits ((.&.), (.|.), shiftL, testBit)
import Data.Int (Int64)
import Slap.BSDiff.Types (BSDiffPatch(..), BSDiffInstruction(..), bsdiffMagicBytes, bsdiffInstructionSize)
import Slap.Compression.Stream (bzip2Decompress)
import Slap.Error (SlapError(..), DecompressionFailure(..), BSDiffSection(..), Parsed(..))
import Slap.FileContents (PatchFileContents(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.Measure (FileSize(..), Length(..), Delta(..),
                     RequiredLength(..), ActualLength(..), ActualMagic(..),
                     byteLength)

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

safeDecompressBZip :: BSDiffSection -> ByteString -> Either SlapError ByteString
safeDecompressBZip _       compressed | ByteString.null compressed = Right ByteString.empty
safeDecompressBZip section compressed = case bzip2Decompress compressed of
  Left cause         -> Left (DecompressionFailed (BSDiffSectionFailed section cause))
  Right decompressed -> Right decompressed

----------------------------------------------------------------------------
-- Parsing
----------------------------------------------------------------------------

parseBSDiff :: PatchFileContents -> Either SlapError (Parsed BSDiffPatch)
parseBSDiff (PatchFileContents input)
  | ByteString.length input < 32 = Left (InputTooShort LabelBSDiff (RequiredLength (Length 32)) (ActualLength (byteLength input)))
  | ByteString.take 8 input /= bsdiffMagicBytes = Left (BadMagic LabelBSDiff (ActualMagic (ByteString.take 8 input)))
  | rawControlSize < 0 || rawDiffSize < 0 || rawTargetSize < 0 = Left (ParseError LabelBSDiff "invalid header (negative size)")
  | otherwise = do
      controlData <- safeDecompressBZip BSDiffControl controlCompressed
      diffData    <- safeDecompressBZip BSDiffDiff    diffCompressed
      extraData   <- safeDecompressBZip BSDiffExtra   extraCompressed
      let instructions = parseInstructions controlData
          rawExtraSize = fromIntegral (ByteString.length input) - 32 - rawControlSize - rawDiffSize
      Right (Parsed (BSDiffPatch (FileSize (fromIntegral rawControlSize)) (FileSize (fromIntegral rawDiffSize)) (FileSize (fromIntegral rawExtraSize)) (FileSize (fromIntegral rawTargetSize)) instructions diffData extraData) [])
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

parseInstructions :: ByteString -> [BSDiffInstruction]
parseInstructions input
  | ByteString.length input < bsdiffInstructionSize = []
  | otherwise =
      BSDiffInstruction
        (Length (fromIntegral (getSignMagnitude64 0  input)))
        (Length (fromIntegral (getSignMagnitude64 8  input)))
        (Delta  (fromIntegral (getSignMagnitude64 16 input)))
        : parseInstructions (ByteString.drop bsdiffInstructionSize input)
