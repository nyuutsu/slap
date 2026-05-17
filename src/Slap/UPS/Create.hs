{-# LANGUAGE OverloadedStrings #-}

-- | UPS patch creation. Builds an XOR-block stream over the
-- byuu-varint header/skip widths.
--
-- Wire-format integer safety: the 'fromIntegral' calls in this
-- module convert 'Int' to 'Int64' as required by 'putByuuVarint'.
-- @Int → Int64@ is widening on 32-bit hosts and a no-op on 64-bit
-- (where GHC's 'Int' is 'Int64'); the conversion never shrinks, so
-- no truncation hazard exists at any of these sites.
module Slap.UPS.Create
  ( createUPS
  ) where

import Slap.UPS.Types (UPSBlock(..), upsMagicBytes)
import Slap.Binary (putWord32LE, word32LEBytes, putByuuVarint)
import Slap.Checksum (CRC32(..))
import Slap.Status (SlapError(..), UnencodeabilityReason(..), CreateResult(..))
import Slap.FFI (crc32)
import Slap.FormatLabel (FormatLabel(..))
import Slap.Measure (Length(..), Offset(..), advance, distance, offsetToInt)
import Slap.FileContents (InputFileContents(..), OutputFileContents(..), PatchFileContents(..))

import Data.Bits (xor)

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.ByteString.Builder
import Data.ByteString.Internal (unsafeCreate)
import qualified Data.ByteString.Lazy as LazyByteString
import Data.Word (Word8)
import Foreign.Storable (pokeByteOff)

-- | Create a UPS patch from source and target bytestrings. Returns
-- 'Left (UPSUnencodeablePair LabelUPS UPSSourceTailNonZero)' when
-- @source@ extends past @target@ with non-zero bytes: those bytes
-- have nowhere to be encoded in the bi-directional XOR stream
-- (the block stream only covers @[0, target_size)@), and accepting
-- the pair would silently break the spec's bi-directional guarantee
-- on undo. Diff runs that extend all the way to @target@ end are
-- accepted — the resulting block's terminator lands at
-- @target_size@, which is what byuu's beat and other real-world UPS
-- tools produce; the apply path's OOB-clipping handles it.
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
  putByuuVarint (fromIntegral (unLength skipLength))
  <> byteString xorData
  <> word8 0x00  -- terminator

-- | Walk source and target in lockstep, emitting UPS diff blocks.
-- Returns 'Left' if the pair is unencodeable: 'UPSSourceTailNonZero'
-- when @source@ extends past @target@ with non-zero bytes (those
-- bytes have nowhere to go in the bi-directional XOR encoding —
-- accepting would silently break undo).
--
-- A diff run that extends all the way to @target@ end is /not/ a
-- rejection: it produces a block whose terminator's "phantom"
-- position lands at @targetLength@, past the last written byte.
-- This matches what beat, NUPS, and Tsukuyomi produce in practice
-- (see @docs\/ups\/findings.md@: @crystalleaf@, @FE1+2_GBA@,
-- @smbs-1.0~rc1@ all exhibit one such block at the tail). The
-- apply path in "Slap.UPS.Apply" already clips that terminator's
-- write against the output buffer; 'detectOOBBlocks' summarises it
-- as a warning. Forward apply and reverse apply both reconstruct
-- the original bytes cleanly under this shape.
diffToBlocks :: InputFileContents -> OutputFileContents -> Either SlapError [UPSBlock]
diffToBlocks (InputFileContents source) (OutputFileContents target)
  | not sourceTailAllZero =
      Left (UPSUnencodeablePair LabelUPS UPSSourceTailNonZero)
  | otherwise = Right (scan (Offset 0) (Length 0) [])
  where
    targetLength = ByteString.length target
    sourceTailAllZero = ByteString.all (== 0) (ByteString.drop targetLength source)

    byteAt :: ByteString -> Int -> Word8
    byteAt bytes position
      | position < ByteString.length bytes = ByteString.index bytes position
      | otherwise = 0

    -- Tail-recursive scan. Accumulates skip count while bytes match;
    -- on diff, collects the run and emits a block.
    scan :: Offset -> Length -> [UPSBlock] -> [UPSBlock]
    scan !position !skipCount !accumulatedBlocks
      | offsetToInt position >= targetLength =
          reverse accumulatedBlocks
      | byteAt source (offsetToInt position) == byteAt target (offsetToInt position) =
          scan (advance position (Length 1))
               (skipCount <> Length 1)
               accumulatedBlocks
      | otherwise =
          let (runBytes, nextPosition) = collectRun position
              block = UPSBlock skipCount runBytes
          in scan nextPosition (Length 0) (block : accumulatedBlocks)

    -- Scan forward from 'start' while bytes differ, then consume the
    -- terminating matching byte. If no match is found within
    -- @[start, targetLength)@, the run extends to @targetLength@ and
    -- the implicit terminator's "phantom" position is @targetLength@
    -- itself — past the output buffer's last byte. The apply path
    -- handles that via the OOB-clipping branch in 'applyUPS'.
    collectRun :: Offset -> (ByteString, Offset)
    collectRun start =
      let runEnd = findFirstMatchPosition start
          runLength = distance start runEnd
          -- unsafeCreate (not create) is safe here because the
          -- buffer-fill callback writes only to the freshly-allocated
          -- local buffer with no observable effects beyond that write —
          -- no IORef, no shared state, deterministic output. The 'unsafe'
          -- refers to allowing the IO action to be duplicated by GHC,
          -- which is fine because duplication produces identical output.
          runByteCount    = unLength runLength
          startByteOffset = offsetToInt start
          runBytes = unsafeCreate runByteCount $ \outputPointer ->
            let writeLoop !byteOffset
                  | byteOffset >= runByteCount = pure ()
                  | otherwise = do
                      let sourceByte = byteAt source (startByteOffset + byteOffset)
                          targetByte = byteAt target (startByteOffset + byteOffset)
                      pokeByteOff outputPointer byteOffset
                        (sourceByte `xor` targetByte :: Word8)
                      writeLoop (byteOffset + 1)
            in writeLoop 0
      in (runBytes, advance runEnd (Length 1))

    -- | Return the first position p in [start, targetLength) where
    -- source[p] == target[p] (with virtual zero-padding past either
    -- end). If no such position exists, returns targetLength as a
    -- sentinel.
    findFirstMatchPosition :: Offset -> Offset
    findFirstMatchPosition !position
      | offsetToInt position >= targetLength = position
      | byteAt source (offsetToInt position) == byteAt target (offsetToInt position) = position
      | otherwise = findFirstMatchPosition (advance position (Length 1))
