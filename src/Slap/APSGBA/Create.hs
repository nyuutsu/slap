{-# LANGUAGE OverloadedStrings #-}

module Slap.APSGBA.Create
  ( createAPSGBA
  , encodeGBABlock
  ) where

import Slap.APSGBA.Types (apsGbaMagicBytes, apsGbaBlockSize,
                           narrowAPSGBASourceSize, narrowAPSGBATargetSize,
                           unAPSGBASourceSize, unAPSGBATargetSize)
import Slap.Binary (crc16, putWord32LE, putWord16LE, viewBytesInRange)
import Slap.Checksum (CRC16(..))
import Slap.Status (SlapError, CreateResult(..))
import Slap.Measure (Offset(..), Length(..), byteFileSize)

import Slap.FileContents (InputFileContents(..), OutputFileContents(..), PatchFileContents(..))

import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Lazy as LazyByteString
import Data.ByteString.Builder (Builder, byteString, toLazyByteString)
import Data.Bits (xor)
import Data.Word (Word32)

createAPSGBA :: InputFileContents -> OutputFileContents
             -> Either SlapError CreateResult
createAPSGBA inputContents@(InputFileContents original) outputContents@(OutputFileContents modified) = do
  sourceSize <- narrowAPSGBASourceSize (byteFileSize original)
  targetSize <- narrowAPSGBATargetSize (byteFileSize modified)
  Right (CreateResult (PatchFileContents (patchBytes sourceSize targetSize)) [])
  where
    patchBytes sourceSize targetSize = LazyByteString.toStrict $ toLazyByteString $
      byteString apsGbaMagicBytes
      <> putWord32LE (unAPSGBASourceSize sourceSize)
      <> putWord32LE (unAPSGBATargetSize targetSize)
      <> foldMap (encodeGBABlock inputContents outputContents) changedBlocks
    blockSize = apsGbaBlockSize
    blockCount = max (blocksOf original) (blocksOf modified)
    blocksOf input = (ByteString.length input + blockSize - 1) `div` blockSize
    changedBlocks = filter hasChanges [0 .. blockCount - 1]
    hasChanges blockIndex =
      let offset = blockIndex * blockSize
          sourceBlock = padBlock (viewBytesInRange (Offset offset) (Length blockSize) original)
          targetBlock = padBlock (viewBytesInRange (Offset offset) (Length blockSize) modified)
      in sourceBlock /= targetBlock
    padBlock input
      | ByteString.length input >= blockSize = ByteString.take blockSize input
      | otherwise = input <> ByteString.replicate (blockSize - ByteString.length input) 0

encodeGBABlock :: InputFileContents -> OutputFileContents -> Int -> Builder
encodeGBABlock (InputFileContents original) (OutputFileContents modified) blockIndex =
    -- Safe-by-construction: 'createAPSGBA' has narrowed both
    -- 'sourceSize' and 'targetSize' to 'Word32', and any reachable
    -- 'blockIndex' lies in @[0 .. blockCount)@ where
    -- @blockCount * apsGbaBlockSize@ does not exceed the larger of
    -- those two narrowed sizes. The @blockIndex * apsGbaBlockSize@
    -- product therefore fits 'Word32' without truncation.
    putWord32LE (fromIntegral offset :: Word32)
    <> putWord16LE (unCRC16 (crc16 sourceBlock))
    <> putWord16LE (unCRC16 (crc16 targetBlock))
    <> byteString xorPayload
  where
    offset = blockIndex * apsGbaBlockSize
    sourceBlock = zeroPadTo apsGbaBlockSize (viewBytesInRange (Offset offset) (Length apsGbaBlockSize) original)
    targetBlock = zeroPadTo apsGbaBlockSize (viewBytesInRange (Offset offset) (Length apsGbaBlockSize) modified)
    xorPayload = ByteString.packZipWith xor sourceBlock targetBlock
    zeroPadTo size input
      | ByteString.length input >= size = ByteString.take size input
      | otherwise = input <> ByteString.replicate (size - ByteString.length input) 0
