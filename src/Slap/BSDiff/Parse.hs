{-# LANGUAGE OverloadedStrings #-}

module Slap.BSDiff.Parse
  ( parseBSDiff
  , parseInstructions
  , getSignMagnitude64
  , safeDecompressBZip
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.Bits ((.&.), (.|.), shiftL, testBit)
import Data.Bifunctor (first)
import Data.Int (Int64)
import Slap.BSDiff.Types (BSDiffPatch(..), BSDiffInstruction(..), bsdiffMagicBytes, bsdiffInstructionSize)
import Slap.Compression.Stream (bzip2Decompress)
import Slap.Status (SlapError(..), SlapAdvisory(..), BSDiffHeaderMalformation(..),
                    ControlSectionSize(..), DiffSectionSize(..), TargetSectionSize(..),
                    DecompressionFailure(..), BSDiffSection(..), Parsed(..))
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
safeDecompressBZip section compressed =
  first (DecompressionFailed . BSDiffSectionFailed section) (bzip2Decompress compressed)

----------------------------------------------------------------------------
-- Parsing
----------------------------------------------------------------------------

-- | The declared-size fit checks run sequentially — control against the whole patch body, then diff against what control left —
-- so each step compares non-negative values and none can wrap.
-- A summed bound could: two hostile near-2^63 declared sizes drive @body - control - diff@ past the Int64 floor and back to positive,
-- slipping the guard and misreporting the malformed header as a decompression failure downstream.
parseBSDiff :: PatchFileContents -> Either SlapError (Parsed BSDiffPatch)
parseBSDiff (PatchFileContents input)
  | ByteString.length input < bsdiffHeaderSize = Left (InputTooShort LabelBSDiff (RequiredLength (Length bsdiffHeaderSize)) (ActualLength (byteLength input)))
  | ByteString.take 8 input /= bsdiffMagicBytes = Left (BadMagic LabelBSDiff (ActualMagic (ByteString.take 8 input)))
  | rawControlSize < 0 || rawDiffSize < 0 || rawTargetSize < 0 =
      Left (MalformedBSDiffHeader (BSDiffNegativeHeaderSizes (ControlSectionSize rawControlSize) (DiffSectionSize rawDiffSize) (TargetSectionSize rawTargetSize)))
  | rawControlSize > patchBodyLength =
      Left (MalformedBSDiffHeader (BSDiffControlOverrunsPatch (rawControlSize - patchBodyLength)))
  | rawDiffSize > patchBodyAfterControl =
      Left (MalformedBSDiffHeader (BSDiffDiffOverrunsPatch (rawDiffSize - patchBodyAfterControl)))
  | otherwise = do
      controlData <- safeDecompressBZip BSDiffControl controlCompressed
      diffData    <- safeDecompressBZip BSDiffDiff    diffCompressed
      extraData   <- safeDecompressBZip BSDiffExtra   extraCompressed
      let instructions   = parseInstructions controlData
          fragmentLength = ByteString.length controlData `mod` bsdiffInstructionSize
      Right (Parsed
              (BSDiffPatch (Length (fromIntegral rawControlSize))
                           (Length (fromIntegral rawDiffSize))
                           (Length (fromIntegral rawExtraSize))
                           (FileSize (fromIntegral rawTargetSize))
                           instructions diffData extraData)
              [BSDiffTrailingControlFragment (Length fragmentLength) | fragmentLength /= 0])
  where
    bsdiffHeaderSize, controlSizeFieldOffset, diffSizeFieldOffset, targetSizeFieldOffset :: Int
    bsdiffHeaderSize       = 32
    controlSizeFieldOffset = 8
    diffSizeFieldOffset    = 16
    targetSizeFieldOffset  = 24
    rawControlSize = getSignMagnitude64 controlSizeFieldOffset input
    rawDiffSize    = getSignMagnitude64 diffSizeFieldOffset input
    rawTargetSize  = getSignMagnitude64 targetSizeFieldOffset input
    patchBodyLength       = fromIntegral (ByteString.length input - bsdiffHeaderSize) :: Int64
    patchBodyAfterControl = patchBodyLength - rawControlSize
    rawExtraSize          = patchBodyAfterControl - rawDiffSize
    controlOffset  = bsdiffHeaderSize
    diffOffset     = bsdiffHeaderSize + fromIntegral rawControlSize
    extraOffset    = diffOffset + fromIntegral rawDiffSize
    controlCompressed = ByteString.take (fromIntegral rawControlSize) (ByteString.drop controlOffset input)
    diffCompressed    = ByteString.take (fromIntegral rawDiffSize) (ByteString.drop diffOffset input)
    extraCompressed   = ByteString.drop extraOffset input

-- | Decode the control stream, one 24-byte instruction at a time.
-- A trailing fragment shorter than one instruction is dropped here;
-- 'parseBSDiff' measures it and reports 'BSDiffTrailingControlFragment'.
parseInstructions :: ByteString -> [BSDiffInstruction]
parseInstructions input
  | ByteString.length input < bsdiffInstructionSize = []
  | otherwise =
      BSDiffInstruction
        (Length (fromIntegral (getSignMagnitude64 0  input)))
        (Length (fromIntegral (getSignMagnitude64 8  input)))
        (Delta  (fromIntegral (getSignMagnitude64 16 input)))
        : parseInstructions (ByteString.drop bsdiffInstructionSize input)
