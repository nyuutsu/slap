{-# LANGUAGE OverloadedStrings #-}

module Slap.APSGBA.Create
  ( createAPSGBA
  , encodeGBABlock
  ) where

import Slap.APSGBA.Apply (safeSlice)
import Slap.APSGBA.Types (apsGbaMagicBytes, apsGbaBlockSize)
import Slap.Binary (crc16, putWord32LE, putWord16LE)

import Slap.FileContents (SourceFileContents(..), TargetFileContents(..), PatchFileContents(..))

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Lazy as LazyByteString
import Data.ByteString.Builder (Builder, byteString, toLazyByteString)
import Data.Bits (xor)
import Data.Word (Word32)

createAPSGBA :: SourceFileContents -> TargetFileContents -> PatchFileContents
createAPSGBA (SourceFileContents original) (TargetFileContents modified) = PatchFileContents $ LazyByteString.toStrict $ toLazyByteString $
    byteString apsGbaMagicBytes
    <> putWord32LE (fromIntegral (ByteString.length original) :: Word32)
    <> putWord32LE (fromIntegral (ByteString.length modified) :: Word32)
    <> foldMap (encodeGBABlock original modified) changedBlocks
  where
    blockSize = apsGbaBlockSize
    blockCount = max (blocksOf original) (blocksOf modified)
    blocksOf input = (ByteString.length input + blockSize - 1) `div` blockSize
    changedBlocks = filter hasChanges [0 .. blockCount - 1]
    hasChanges blockIndex =
      let offset = blockIndex * blockSize
          sourceBlock = padBlock (safeSlice offset blockSize original)
          targetBlock = padBlock (safeSlice offset blockSize modified)
      in sourceBlock /= targetBlock
    padBlock input
      | ByteString.length input >= blockSize = ByteString.take blockSize input
      | otherwise = input <> ByteString.replicate (blockSize - ByteString.length input) 0

encodeGBABlock :: ByteString -> ByteString -> Int -> Builder
encodeGBABlock original modified blockIndex =
    putWord32LE (fromIntegral offset :: Word32)
    <> putWord16LE (crc16 sourceBlock)
    <> putWord16LE (crc16 targetBlock)
    <> byteString xorPayload
  where
    offset = blockIndex * apsGbaBlockSize
    sourceBlock = zeroPadTo apsGbaBlockSize (safeSlice offset apsGbaBlockSize original)
    targetBlock = zeroPadTo apsGbaBlockSize (safeSlice offset apsGbaBlockSize modified)
    xorPayload = ByteString.packZipWith xor sourceBlock targetBlock
    zeroPadTo size input
      | ByteString.length input >= size = ByteString.take size input
      | otherwise = input <> ByteString.replicate (size - ByteString.length input) 0
