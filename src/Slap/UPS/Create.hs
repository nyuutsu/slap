{-# LANGUAGE OverloadedStrings #-}

module Slap.UPS.Create
  ( createUPS
  , encodeUPSBlock
  , diffToBlocks
  ) where

import Slap.UPS.Types (UPSBlock(..))
import Slap.Binary (putWord32LE, putByuuVarint)
import Slap.Checksum (CRC32(..))
import Slap.Error (SlapError(..), UnencodeabilityReason(..))
import Slap.FFI (rustyCRC32)
import Slap.FormatLabel (FormatLabel(..))
import Slap.Measure (Delta(..))

import Data.Bits (xor)
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.ByteString.Builder
import Data.ByteString.Internal (unsafeCreate)
import qualified Data.ByteString.Lazy as LazyByteString
import Data.Word (Word8)
import Foreign.Storable (pokeByteOff)

-- | Create a UPS patch from source and target bytestrings. Returns
-- 'Left' if the pair is unencodeable per the UPS spec (diff run with
-- no valid terminator position within target bounds).
createUPS :: ByteString -> ByteString -> Either SlapError ByteString
createUPS original modified = do
  blocks <- diffToBlocks original modified
  let sourceCRC = rustyCRC32 original
      targetCRC = rustyCRC32 modified
      body = byteString "UPS1"
             <> putByuuVarint (fromIntegral (ByteString.length original))
             <> putByuuVarint (fromIntegral (ByteString.length modified))
             <> foldMap encodeUPSBlock blocks
             <> putWord32LE (unCRC32 sourceCRC)
             <> putWord32LE (unCRC32 targetCRC)
      bodyBytes = LazyByteString.toStrict (toLazyByteString body)
      patchCRC = rustyCRC32 bodyBytes
  let patchCRCBytes = LazyByteString.toStrict (toLazyByteString (putWord32LE (unCRC32 patchCRC)))
  Right (bodyBytes <> patchCRCBytes)

encodeUPSBlock :: UPSBlock -> Builder
encodeUPSBlock (UPSBlock skipDelta xorData) =
  putByuuVarint (fromIntegral (unDelta skipDelta))
  <> byteString xorData
  <> word8 0x00  -- terminator

-- | Walk source and target in lockstep, emitting UPS diff blocks.
-- Returns 'Left' if the pair is unencodeable (diff run whose
-- terminator would fall past target end, or source has non-zero
-- bytes past target size).
diffToBlocks :: ByteString -> ByteString -> Either SlapError [UPSBlock]
diffToBlocks source target
  | not sourceTailAllZero =
      Left (UPSUnencodeablePair LabelUPS UPSSourceTailNonZero)
  | otherwise = scan 0 0 []
  where
    targetLength = ByteString.length target
    sourceTailAllZero = ByteString.all (== 0) (ByteString.drop targetLength source)

    byteAt :: ByteString -> Int -> Word8
    byteAt bytes position
      | position < ByteString.length bytes = ByteString.index bytes position
      | otherwise = 0

    -- Tail-recursive scan. Accumulates skip count while bytes match;
    -- on diff, collects the run and emits a block.
    scan :: Int -> Int -> [UPSBlock] -> Either SlapError [UPSBlock]
    scan !position !skipCount !accumulatedBlocks
      | position >= targetLength =
          Right (reverse accumulatedBlocks)
      | byteAt source position == byteAt target position =
          scan (position + 1) (skipCount + 1) accumulatedBlocks
      | otherwise = do
          (runBytes, nextPosition) <- collectRun position
          let block = UPSBlock (Delta (fromIntegral skipCount)) runBytes
          scan nextPosition 0 (block : accumulatedBlocks)

    -- Scan forward from 'start' while bytes differ, then consume the
    -- terminating matching byte. Returns Left if no match is found
    -- within targetLength (terminator would fall past target end).
    collectRun :: Int -> Either SlapError (ByteString, Int)
    collectRun start =
      let runEnd = findFirstMatchPosition start
          runLength = runEnd - start
      in if runEnd >= targetLength
           then Left (UPSUnencodeablePair LabelUPS UPSLastByteDiffers)
           else
             -- unsafeCreate (not create) is safe here because the
             -- buffer-fill callback writes only to the freshly-allocated
             -- local buffer with no observable effects beyond that write —
             -- no IORef, no shared state, deterministic output. The 'unsafe'
             -- refers to allowing the IO action to be duplicated by GHC,
             -- which is fine because duplication produces identical output.
             let runBytes = unsafeCreate runLength $ \outputPointer ->
                   let writeLoop !byteOffset
                         | byteOffset >= runLength = pure ()
                         | otherwise = do
                             let sourceByte = byteAt source (start + byteOffset)
                                 targetByte = byteAt target (start + byteOffset)
                             pokeByteOff outputPointer byteOffset
                               (sourceByte `xor` targetByte :: Word8)
                             writeLoop (byteOffset + 1)
                   in writeLoop 0
             in Right (runBytes, runEnd + 1)

    -- | Return the first position p in [start, targetLength) where
    -- source[p] == target[p] (with virtual zero-padding past either
    -- end). If no such position exists, returns targetLength as a
    -- sentinel — the caller compares against targetLength to detect
    -- the no-match case.
    findFirstMatchPosition :: Int -> Int
    findFirstMatchPosition !position
      | position >= targetLength = position
      | byteAt source position == byteAt target position = position
      | otherwise = findFirstMatchPosition (position + 1)
