{-# LANGUAGE OverloadedStrings #-}

module Slap.GDIFF.Create
  ( createGDIFF
  , encodeData
  , encodeCopy
  , CopyEncoding(..)
  , planCopy
  ) where

import Slap.Binary (diffHunks, putWord16BE, putWord32BE, putInt64BE)
import Slap.Error (SlapError, CreateResult(..))
import Slap.GDIFF.Types (gdiffMagicBytes, maxSingleCommandLength,
                         maximumTwoByteOffset, maximumFourByteOffset,
                         maximumOneByteLength, maximumTwoByteLength)
import Slap.Measure (Offset(..), Length(..), Hunk(..),
                     advance, byteLength, distance, hunkEnd,
                     lengthToOffset, minLength, subtractLength)

import Slap.FileContents (InputFileContents(..), OutputFileContents(..), PatchFileContents(..))

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Lazy as LazyByteString
import Data.ByteString.Builder (Builder, word8, byteString, toLazyByteString)
import Data.Int (Int64)
import Data.List (unfoldr)
import Data.Word (Word8, Word16, Word32)

-- | Unchanged regions become COPY commands; changed regions become DATA commands.
createGDIFF :: InputFileContents -> OutputFileContents
            -> Either SlapError CreateResult
createGDIFF inputContents@(InputFileContents original) outputContents@(OutputFileContents modified) =
    Right (CreateResult (PatchFileContents patchBytes) [])
  where
    patchBytes = LazyByteString.toStrict $ toLazyByteString $
      byteString gdiffMagicBytes       -- magic
      <> word8 4                       -- version
      <> buildCommands (Offset 0) (diffHunks inputContents outputContents)
      <> word8 0                       -- EOF command
    sharedRegionEnd = lengthToOffset (minLength (byteLength original) (byteLength modified))
    buildCommands position [] =
      -- trailing unchanged region
      if position < sharedRegionEnd
        then encodeCopy position (distance position sharedRegionEnd)
        else mempty
    buildCommands position (currentHunk : remaining) =
      let gap         = distance position (hunkOffset currentHunk)
          copyPart    = if gap > Length 0
                          then encodeCopy position gap
                          else mempty
          dataBuilder = encodeData (hunkPayload currentHunk)
      in copyPart <> dataBuilder
         <> buildCommands (hunkEnd currentHunk) remaining

-- | Encode a DATA command. Payloads larger than 'maxSingleCommandLength' bytes
-- are split into multiple DATA 248 commands. The W3C GDIFF spec defines int
-- as signed 32-bit, so a single DATA command can carry at most
-- @unLength maxSingleCommandLength@ bytes.
encodeData :: ByteString -> Builder
encodeData payload
  | ByteString.null payload                          = mempty
  | payloadLength <= 246                             = word8 (fromIntegral payloadLength) <> byteString payload
  | payloadLength <= 0xFFFF                          = word8 247 <> putWord16BE (fromIntegral payloadLength) <> byteString payload
  | payloadLength <= unLength maxSingleCommandLength = word8 248 <> putWord32BE (fromIntegral payloadLength) <> byteString payload
  | otherwise                                        = splitData payload
  where
    payloadLength = ByteString.length payload

-- | Split a large payload into multiple DATA 248 commands, each carrying
-- at most 'maxSingleCommandLength' bytes.
splitData :: ByteString -> Builder
splitData remaining
  | ByteString.null remaining = mempty
  | otherwise =
      let chunkLength    = min (unLength maxSingleCommandLength) (ByteString.length remaining)
          (chunk, leftover) = ByteString.splitAt chunkLength remaining
      in word8 248 <> putWord32BE (fromIntegral chunkLength) <> byteString chunk
         <> splitData leftover

-- | A single COPY command, opcode-tagged so the constructor field types
-- match the wire field widths exactly. Reads top-to-bottom as the W3C
-- GDIFF spec's COPY table:
--
-- > 249  ushort offset, ubyte  length
-- > 250  ushort offset, ushort length
-- > 251  ushort offset, int    length
-- > 252  int    offset, ubyte  length
-- > 253  int    offset, ushort length
-- > 254  int    offset, int    length
-- > 255  long   offset, int    length
--
-- 'Copy255' is the only opcode whose offset spans a full 'Int64'; all
-- length fields top out at 'maxSingleCommandLength' (the spec's signed
-- 32-bit @int@), and 'planCopy' is responsible for splitting longer
-- requests into a run of in-range chunks.
data CopyEncoding
  = Copy249 Word16 Word8   -- ^ ushort offset, ubyte  length
  | Copy250 Word16 Word16  -- ^ ushort offset, ushort length
  | Copy251 Word16 Word32  -- ^ ushort offset, int    length
  | Copy252 Word32 Word8   -- ^ int    offset, ubyte  length
  | Copy253 Word32 Word16  -- ^ int    offset, ushort length
  | Copy254 Word32 Word32  -- ^ int    offset, int    length
  | Copy255 Int64  Word32  -- ^ long   offset, int    length
  deriving (Show, Eq)

-- | Split a COPY request into a sequence of in-range 'CopyEncoding'
-- chunks. Implemented as an 'unfoldr' because the work is a corecursion:
-- one chunk per step, threading a @(cursor, remaining)@ state until
-- exhausted. Above 'maxSingleCommandLength' this yields a run of
-- 'Copy255' commands; below it, a singleton.
planCopy :: Offset -> Length -> [CopyEncoding]
planCopy initialOffset initialLength = unfoldr peelChunk (initialOffset, initialLength)
  where
    peelChunk (_, Length 0) = Nothing
    peelChunk (currentOffset, remainingLength) =
      let chunkLength    = minLength maxSingleCommandLength remainingLength
          nextOffset     = advance currentOffset chunkLength
          remainingAfter = subtractLength remainingLength chunkLength
      in Just (selectCopy currentOffset chunkLength, (nextOffset, remainingAfter))

-- | Choose the narrowest 'CopyEncoding' opcode whose offset and length
-- fields fit the inputs. Total over inputs whose length fits in
-- 'maxSingleCommandLength'; outside that range, 'planCopy' enforces the
-- precondition by chunking before each call. Reads top-to-bottom as the
-- W3C GDIFF spec's COPY table — same order as 'CopyEncoding'.
selectCopy :: Offset -> Length -> CopyEncoding
selectCopy offset copyLength
  | offset <= maximumTwoByteOffset  && copyLength <= maximumOneByteLength = Copy249 offsetAsTwoBytes  lengthAsOneByte
  | offset <= maximumTwoByteOffset  && copyLength <= maximumTwoByteLength = Copy250 offsetAsTwoBytes  lengthAsTwoBytes
  | offset <= maximumTwoByteOffset                                        = Copy251 offsetAsTwoBytes  lengthAsFourBytes
  | offset <= maximumFourByteOffset && copyLength <= maximumOneByteLength = Copy252 offsetAsFourBytes lengthAsOneByte
  | offset <= maximumFourByteOffset && copyLength <= maximumTwoByteLength = Copy253 offsetAsFourBytes lengthAsTwoBytes
  | offset <= maximumFourByteOffset                                       = Copy254 offsetAsFourBytes lengthAsFourBytes
  | otherwise                                                             = Copy255 offsetAsEightBytes lengthAsFourBytes
  where
    offsetAsTwoBytes   = fromIntegral (unOffset offset)
    offsetAsFourBytes  = fromIntegral (unOffset offset)
    offsetAsEightBytes = fromIntegral (unOffset offset)
    lengthAsOneByte    = fromIntegral (unLength copyLength)
    lengthAsTwoBytes   = fromIntegral (unLength copyLength)
    lengthAsFourBytes  = fromIntegral (unLength copyLength)

-- | Serialise a single 'CopyEncoding' to the wire — one line per opcode,
-- structured as a wire-format reference card.
renderCopy :: CopyEncoding -> Builder
renderCopy = \case
  Copy249 wireOffset wireLength -> word8 249 <> putWord16BE wireOffset <> word8       wireLength
  Copy250 wireOffset wireLength -> word8 250 <> putWord16BE wireOffset <> putWord16BE wireLength
  Copy251 wireOffset wireLength -> word8 251 <> putWord16BE wireOffset <> putWord32BE wireLength
  Copy252 wireOffset wireLength -> word8 252 <> putWord32BE wireOffset <> word8       wireLength
  Copy253 wireOffset wireLength -> word8 253 <> putWord32BE wireOffset <> putWord16BE wireLength
  Copy254 wireOffset wireLength -> word8 254 <> putWord32BE wireOffset <> putWord32BE wireLength
  Copy255 wireOffset wireLength -> word8 255 <> putInt64BE  wireOffset <> putWord32BE wireLength

-- | Encode a COPY command for a region of @regionLength@ bytes starting
-- at @regionOffset@ in source. Larger-than-spec regions are split into
-- a run of 'Copy255' commands by 'planCopy'.
encodeCopy :: Offset -> Length -> Builder
encodeCopy regionOffset regionLength = foldMap renderCopy (planCopy regionOffset regionLength)
