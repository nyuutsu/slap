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
import Slap.Error (SlapError(..), UnencodeabilityReason(..), CreateResult(..))
import Slap.FFI (rustyCRC32)
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
-- 'Left' if the pair is unencodeable per the UPS spec (diff run with
-- no valid terminator position within target bounds).
createUPS :: InputFileContents -> OutputFileContents
          -> Either SlapError CreateResult
createUPS inputContents@(InputFileContents original) outputContents@(OutputFileContents modified) = do
  blocks <- diffToBlocks inputContents outputContents
  let sourceCRC = rustyCRC32 original
      targetCRC = rustyCRC32 modified
      body = byteString upsMagicBytes
             <> putByuuVarint (fromIntegral (ByteString.length original))
             <> putByuuVarint (fromIntegral (ByteString.length modified))
             <> foldMap encodeUPSBlock blocks
             <> putWord32LE (unCRC32 sourceCRC)
             <> putWord32LE (unCRC32 targetCRC)
      bodyBytes = LazyByteString.toStrict (toLazyByteString body)
      patchCRC = rustyCRC32 bodyBytes
      patchCRCBytes = word32LEBytes (unCRC32 patchCRC)
  Right (CreateResult (PatchFileContents (bodyBytes <> patchCRCBytes)) [])

encodeUPSBlock :: UPSBlock -> Builder
encodeUPSBlock (UPSBlock skipLength xorData) =
  putByuuVarint (fromIntegral (unLength skipLength))
  <> byteString xorData
  <> word8 0x00  -- terminator

-- | Walk source and target in lockstep, emitting UPS diff blocks.
-- Returns 'Left' if the pair is unencodeable (diff run whose
-- terminator would fall past target end, or source has non-zero
-- bytes past target size).
diffToBlocks :: InputFileContents -> OutputFileContents -> Either SlapError [UPSBlock]
diffToBlocks (InputFileContents source) (OutputFileContents target)
  | not sourceTailAllZero =
      Left (UPSUnencodeablePair LabelUPS UPSSourceTailNonZero)
  | otherwise = scan (Offset 0) (Length 0) []
  where
    targetLength = ByteString.length target
    sourceTailAllZero = ByteString.all (== 0) (ByteString.drop targetLength source)

    byteAt :: ByteString -> Int -> Word8
    byteAt bytes position
      | position < ByteString.length bytes = ByteString.index bytes position
      | otherwise = 0

    -- Tail-recursive scan. Accumulates skip count while bytes match;
    -- on diff, collects the run and emits a block.
    scan :: Offset -> Length -> [UPSBlock] -> Either SlapError [UPSBlock]
    scan !position !skipCount !accumulatedBlocks
      | offsetToInt position >= targetLength =
          Right (reverse accumulatedBlocks)
      | byteAt source (offsetToInt position) == byteAt target (offsetToInt position) =
          scan (advance position (Length 1))
               (skipCount <> Length 1)
               accumulatedBlocks
      | otherwise = do
          (runBytes, nextPosition) <- collectRun position
          let block = UPSBlock skipCount runBytes
          scan nextPosition (Length 0) (block : accumulatedBlocks)

    -- Scan forward from 'start' while bytes differ, then consume the
    -- terminating matching byte. Returns Left if no match is found
    -- within targetLength (terminator would fall past target end).
    collectRun :: Offset -> Either SlapError (ByteString, Offset)
    collectRun start =
      let runEnd = findFirstMatchPosition start
          runLength = distance start runEnd
      in if offsetToInt runEnd >= targetLength
           then Left (UPSUnencodeablePair LabelUPS UPSLastByteDiffers)
           else
             -- unsafeCreate (not create) is safe here because the
             -- buffer-fill callback writes only to the freshly-allocated
             -- local buffer with no observable effects beyond that write —
             -- no IORef, no shared state, deterministic output. The 'unsafe'
             -- refers to allowing the IO action to be duplicated by GHC,
             -- which is fine because duplication produces identical output.
             let runByteCount    = unLength runLength
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
             in Right (runBytes, advance runEnd (Length 1))

    -- | Return the first position p in [start, targetLength) where
    -- source[p] == target[p] (with virtual zero-padding past either
    -- end). If no such position exists, returns targetLength as a
    -- sentinel — the caller compares against targetLength to detect
    -- the no-match case.
    findFirstMatchPosition :: Offset -> Offset
    findFirstMatchPosition !position
      | offsetToInt position >= targetLength = position
      | byteAt source (offsetToInt position) == byteAt target (offsetToInt position) = position
      | otherwise = findFirstMatchPosition (advance position (Length 1))
