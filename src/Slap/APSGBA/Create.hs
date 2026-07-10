{-# LANGUAGE OverloadedStrings #-}

module Slap.APSGBA.Create
  ( createAPSGBA
  ) where

import Slap.APSGBA.Types (apsGbaMagicBytes, apsGbaBlockSize,
                           narrowAPSGBASourceSize, narrowAPSGBATargetSize,
                           unAPSGBASourceSize, unAPSGBATargetSize)
import Slap.Binary (crc16, putWord32LE, putWord16LE, zeroExtendedBlock)
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
          sourceBlock = zeroExtendedBlock (Offset offset) (Length blockSize) original
          targetBlock = zeroExtendedBlock (Offset offset) (Length blockSize) modified
      in sourceBlock /= targetBlock

encodeGBABlock :: InputFileContents -> OutputFileContents -> Int -> Builder
encodeGBABlock (InputFileContents original) (OutputFileContents modified) blockIndex =
    -- offset fits Word32: createAPSGBA narrowed both file sizes to
    -- Word32, and offset = blockIndex * apsGbaBlockSize stays below the
    -- larger size.
    putWord32LE (fromIntegral offset :: Word32)
    <> putWord16LE (unCRC16 (crc16 sourceBlock))
    <> putWord16LE (unCRC16 (crc16 targetBlock))
    <> byteString xorPayload
  where
    offset = blockIndex * apsGbaBlockSize
    sourceBlock = zeroExtendedBlock (Offset offset) (Length apsGbaBlockSize) original
    targetBlock = zeroExtendedBlock (Offset offset) (Length apsGbaBlockSize) modified
    xorPayload = ByteString.packZipWith xor sourceBlock targetBlock
