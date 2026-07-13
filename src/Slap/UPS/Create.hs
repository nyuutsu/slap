{-# LANGUAGE OverloadedStrings #-}

-- | UPS patch creation. Builds an XOR-block stream over the
-- byuu-varint header/skip widths.
module Slap.UPS.Create
  ( createUPS
  ) where

import Slap.UPS.Types (UPSBlock(..), upsMagicBytes, upsTerminatorByte)
import Slap.Binary (putWord32LE, word32LEBytes, putByuuVarint, byteAtOffset, dropLength, zeroExtendedBlock)
import Slap.Checksum (CRC32(..))
import Slap.Status (SlapError(..), UnencodeabilityReason(..), CreateResult(..))
import Slap.FFI (crc32)
import Slap.FormatLabel (FormatLabel(..))
import Slap.Measure (Length(..), Offset(..), advance, distance,
                     byteLength, byteFileSize, fitsWithin, lengthToOffset)
import Slap.FileContents (InputFileContents(..), OutputFileContents(..), PatchFileContents(..))

import Data.Bits (xor)

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.ByteString.Builder
import qualified Data.ByteString.Lazy as LazyByteString
import Data.Word (Word8)

-- | Create a UPS patch from source and target bytestrings.
-- Returns 'Left (UnencodeablePair LabelUPS UPSSourceTailNonZero)' when @source@ extends past @target@ with non-zero bytes:
-- those bytes have nowhere to be encoded in the bi-directional XOR stream (the block stream only covers @[0, target_size)@),
-- and accepting the pair would silently break the spec's bi-directional guarantee on undo.
-- Diff runs that extend all the way to @target@ end are accepted;
-- 'diffToBlocks' documents that phantom-terminator shape and the tools that produce it.
createUPS :: InputFileContents -> OutputFileContents
          -> Either SlapError CreateResult
createUPS inputContents@(InputFileContents original) outputContents@(OutputFileContents modified) = do
  blocks <- diffToBlocks inputContents outputContents
  let sourceCRC = crc32 original
      targetCRC = crc32 modified
      body = byteString upsMagicBytes
             <> putByuuVarint (fromIntegral (ByteString.length original))
             <> putByuuVarint (fromIntegral (ByteString.length modified))
             <> foldMap encodeUPSBlock blocks
             <> putWord32LE (unCRC32 sourceCRC)
             <> putWord32LE (unCRC32 targetCRC)
      bodyBytes = LazyByteString.toStrict (toLazyByteString body)
      patchCRC = crc32 bodyBytes
      patchCRCBytes = word32LEBytes (unCRC32 patchCRC)
  Right (CreateResult (PatchFileContents (bodyBytes <> patchCRCBytes)) [])

encodeUPSBlock :: UPSBlock -> Builder
encodeUPSBlock (UPSBlock skipLength xorData) =
  putByuuVarint (unLength skipLength)
  <> byteString xorData
  <> word8 upsTerminatorByte

-- | Walk source and target in lockstep, emitting UPS diff blocks.
-- Returns 'Left' 'UPSSourceTailNonZero' for a source tail that can't be encoded; 'createUPS' has the why.
--
-- A diff run that extends all the way to @target@ end is /not/ a rejection:
-- it produces a block whose terminator's "phantom" position lands at @targetLength@, past the last written byte.
-- This matches what beat, NUPS, and Tsukuyomi produce in practice
-- (see @docs/ups/findings.md@: @crystalleaf@, @FE1+2_GBA@, @smbs-1.0~rc1@ all exhibit one such block at the tail).
-- The apply path in "Slap.UPS.Apply" already clips that terminator's write against the output buffer;
-- 'detectOOBBlocks' summarises it as a warning.
-- Forward apply and reverse apply both reconstruct the original bytes cleanly under this shape.
diffToBlocks :: InputFileContents -> OutputFileContents -> Either SlapError [UPSBlock]
diffToBlocks (InputFileContents source) (OutputFileContents target)
  | not sourceTailAllZero =
      Left (UnencodeablePair LabelUPS UPSSourceTailNonZero)
  | otherwise = Right (scan (Offset 0) (Length 0) [])
  where
    targetLength      = byteLength target
    targetEndPosition = lengthToOffset targetLength
    sourceTailAllZero = ByteString.all (== 0) (dropLength targetLength source)

    byteAt :: ByteString -> Offset -> Word8
    byteAt bytes position
      | fitsWithin position (Length 1) (byteFileSize bytes) = byteAtOffset position bytes
      | otherwise = 0

    -- Accumulates skip count while bytes match;
    -- on diff, collects the run and emits a block.
    scan :: Offset -> Length -> [UPSBlock] -> [UPSBlock]
    scan !position !skipCount !accumulatedBlocks
      | position >= targetEndPosition =
          reverse accumulatedBlocks
      | byteAt source position == byteAt target position =
          scan (advance position (Length 1))
               (skipCount <> Length 1)
               accumulatedBlocks
      | otherwise =
          let (runBytes, nextPosition) = collectRun position
              block = UPSBlock skipCount runBytes
          in scan nextPosition (Length 0) (block : accumulatedBlocks)

    -- Scan forward from 'start' while bytes differ, then consume the terminating matching byte.
    -- A run with no match in @[start, targetLength)@ extends to @targetLength@:
    -- the phantom-terminator shape covered in the header above.
    collectRun :: Offset -> (ByteString, Offset)
    collectRun start =
      let runEnd    = findFirstMatchPosition start
          runLength = distance start runEnd
          runBytes  = ByteString.packZipWith xor
                        (zeroExtendedBlock start runLength source)
                        (zeroExtendedBlock start runLength target)
      in (runBytes, advance runEnd (Length 1))

    -- | Return the first position p in [start, target end) where source[p] == target[p] (with virtual zero-padding past either end).
    -- If no such position exists, returns the target-end position as a sentinel.
    findFirstMatchPosition :: Offset -> Offset
    findFirstMatchPosition !position
      | position >= targetEndPosition = position
      | byteAt source position == byteAt target position = position
      | otherwise = findFirstMatchPosition (advance position (Length 1))
