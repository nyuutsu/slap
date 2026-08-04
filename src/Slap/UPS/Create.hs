{-# LANGUAGE OverloadedStrings #-}

-- | UPS patch creation. Builds an XOR-block stream over the
-- byuu-varint header/skip widths.
module Slap.UPS.Create
  ( createUPS
  ) where

import Slap.UPS.Types (UPSBlock(..), upsMagicBytes, upsTerminatorByte)
import Slap.UPS.FFI (nextDifference, nextAgreement)
import Slap.Binary (putWord32LE, word32LEBytes, putByuuVarint, dropLength, zeroExtendedBlock)
import Slap.Checksum (CRC32(..))
import Slap.Status (SlapError(..), UnencodeabilityReason(..), CreateResult(..))
import Slap.FFI (crc32)
import Slap.FormatLabel (FormatLabel(..))
import Slap.Measure (Length(..), Offset(..), advance, distance, byteLength, lengthToOffset)
import Slap.FileContents (InputFileContents(..), OutputFileContents(..), PatchFileContents(..))

import Data.Bits (xor)

import qualified Data.ByteString as ByteString
import Data.ByteString.Builder
import qualified Data.ByteString.Lazy as LazyByteString

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
  | otherwise = Right (blocksFrom (Offset 0))
  where
    targetLength      = byteLength target
    targetEndPosition = lengthToOffset targetLength
    sourceTailAllZero = ByteString.all (== 0) (dropLength targetLength source)

    blocksFrom :: Offset -> [UPSBlock]
    blocksFrom position
      | position >= targetEndPosition = []
      | runStart >= targetEndPosition = []
      -- the agreeing byte at runEnd is spent as the block's 0x00 terminator, so the next walk begins past it
      | otherwise = UPSBlock skipLength runBytes : blocksFrom (advance runEnd (Length 1))
      where
        runStart   = nextDifference source target position
        runEnd     = nextAgreement source target runStart
        skipLength = distance position runStart
        runLength  = distance runStart runEnd
        runBytes   = ByteString.packZipWith xor
                       (zeroExtendedBlock runStart runLength source)
                       (zeroExtendedBlock runStart runLength target)
