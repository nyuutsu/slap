{-# LANGUAGE OverloadedStrings #-}

module Slap.APSGBA.Create
  ( createAPSGBA
  , encodeGBABlock
  ) where

import Slap.APSGBA.Types (apsGbaMagicBytes, apsGbaBlockSize)
import Slap.Binary (crc16, putWord32LE, putWord16LE, viewBytesInRange)
import Slap.Checksum (CRC16(..))
import Slap.Error (SlapError(..), CreateResult(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.Measure (Offset(..), Length(..), FileSize(..),
                     ActualSize(..), MaxAddressableSize(..), byteFileSize)

import Slap.FileContents (SourceFileContents(..), TargetFileContents(..), PatchFileContents(..))

import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Lazy as LazyByteString
import Data.ByteString.Builder (Builder, byteString, toLazyByteString)
import Data.Bits (xor)
import Data.Word (Word32)

createAPSGBA :: SourceFileContents -> TargetFileContents
             -> Either SlapError CreateResult
createAPSGBA sourceContents@(SourceFileContents original) targetContents@(TargetFileContents modified) = do
  guardAPSGBASize (byteFileSize original)
  guardAPSGBASize (byteFileSize modified)
  Right (CreateResult (PatchFileContents patchBytes) [])
  where
    patchBytes = LazyByteString.toStrict $ toLazyByteString $
      byteString apsGbaMagicBytes
      <> putWord32LE (fromIntegral (ByteString.length original) :: Word32)
      <> putWord32LE (fromIntegral (ByteString.length modified) :: Word32)
      <> foldMap (encodeGBABlock sourceContents targetContents) changedBlocks
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

-- | APS-GBA encodes source and target sizes as little-endian 'Word32'
-- on the wire, so inputs over 4 GB would silently truncate. Reject at
-- the boundary. Unreachable in practice — GBA cartridges cap at 32 MB
-- — but the guard keeps the encoder honest about its wire-format limit.
guardAPSGBASize :: FileSize -> Either SlapError ()
guardAPSGBASize size
  | size <= maxAddressable = Right ()
  | otherwise = Left (FileExceedsAddressableRange LabelAPSGBA
                        (ActualSize size)
                        (MaxAddressableSize maxAddressable))
  where
    maxAddressable = FileSize (fromIntegral (maxBound :: Word32))

encodeGBABlock :: SourceFileContents -> TargetFileContents -> Int -> Builder
encodeGBABlock (SourceFileContents original) (TargetFileContents modified) blockIndex =
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
