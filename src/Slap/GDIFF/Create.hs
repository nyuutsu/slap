-- | GDIFF patch creation. The commands are planned by the Rust differ behind "Slap.GDIFF.FFI";
-- this module spells them onto the wire.
{-# LANGUAGE OverloadedStrings #-}

module Slap.GDIFF.Create
  ( createGDIFF
  , encodeData
  , encodeCopy
  , CopyEncoding(..)
  , planCopy
  ) where

import Slap.Binary (putWord16BE, putWord32BE, putInt64BE, splitAtLength)
import Slap.Status (SlapError, CreateResult(..))
import Slap.GDIFF.FFI (gdiffDiff)
import Slap.GDIFF.Types (GDiffPatch(..), GDiffCommand(..),
                         gdiffMagicBytes, maxSingleCommandLength,
                         maximumTwoByteOffset, maximumFourByteOffset,
                         maximumOneByteLength, maximumTwoByteLength)
import Slap.Measure (Offset(..), Length(..), advance, byteLength, minLength, subtractLength)

import Slap.FileContents (InputFileContents(..), OutputFileContents(..), PatchFileContents(..))

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Lazy as LazyByteString
import Data.ByteString.Builder (Builder, word8, byteString, toLazyByteString)
import Data.Int (Int64)
import Data.List (unfoldr)
import Data.Word (Word8, Word16, Word32)

createGDIFF :: InputFileContents -> OutputFileContents
            -> Either SlapError CreateResult
createGDIFF inputContents outputContents = do
  GDiffPatch commands <- gdiffDiff inputContents outputContents
  let patchBytes = LazyByteString.toStrict $ toLazyByteString $
        byteString gdiffMagicBytes
        <> word8 4                       -- version
        <> foldMap encodeCommand commands
        <> word8 0                       -- EOF command
  pure (CreateResult (PatchFileContents patchBytes) [])

encodeCommand :: GDiffCommand -> Builder
encodeCommand (GDiffCommandData payload)               = encodeData payload
encodeCommand (GDiffCommandCopy copyOffset copyLength) = encodeCopy copyOffset copyLength

-- | Encode a DATA command.
-- Payloads larger than 'maxSingleCommandLength' bytes are split into multiple DATA 248 commands.
--
-- Each branch's guard establishes the bound the 'fromIntegral' relies on.
encodeData :: ByteString -> Builder
encodeData payload
  | ByteString.null payload                    = mempty
  | payloadLength <= Length 246                = word8 (fromIntegral (unLength payloadLength)) <> byteString payload
  | payloadLength <= Length 0xFFFF             = word8 247 <> putWord16BE (fromIntegral (unLength payloadLength)) <> byteString payload
  | payloadLength <= maxSingleCommandLength    = word8 248 <> putWord32BE (fromIntegral (unLength payloadLength)) <> byteString payload
  | otherwise                                  = splitData payload
  where
    payloadLength = byteLength payload

-- | Split a large payload into multiple DATA 248 commands, each carrying
-- at most 'maxSingleCommandLength' bytes.
splitData :: ByteString -> Builder
splitData remaining
  | ByteString.null remaining = mempty
  | otherwise =
      -- 'chunkLength' is bounded above by 'maxSingleCommandLength', so the 'fromIntegral' below fits 'Word32'.
      let chunkLength       = minLength maxSingleCommandLength (byteLength remaining)
          (chunk, leftover) = splitAtLength chunkLength remaining
      in word8 248 <> putWord32BE (fromIntegral (unLength chunkLength)) <> byteString chunk
         <> splitData leftover

-- | A single COPY command, opcode-tagged so the constructor field types match the wire field widths exactly.
-- Reads top-to-bottom as the W3C GDIFF spec's COPY table.
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

-- | The corecursion state 'planCopy' threads through 'unfoldr':
-- the source offset where the next chunk starts,
-- and how many bytes are still to be planned.
data CopyPlanCursor = CopyPlanCursor !Offset !Length

-- | Split a COPY request into a sequence of in-range 'CopyEncoding' chunks:
-- a singleton at or below 'maxSingleCommandLength', a run of capped chunks above it.
planCopy :: Offset -> Length -> [CopyEncoding]
planCopy initialOffset initialLength =
  unfoldr peelChunk (CopyPlanCursor initialOffset initialLength)
  where
    peelChunk (CopyPlanCursor _ (Length 0)) = Nothing
    peelChunk (CopyPlanCursor currentOffset remainingLength) =
      let chunkLength    = minLength maxSingleCommandLength remainingLength
          nextOffset     = advance currentOffset chunkLength
          remainingAfter = subtractLength remainingLength chunkLength
      in Just (selectCopy currentOffset chunkLength,
               CopyPlanCursor nextOffset remainingAfter)

-- | Choose the narrowest 'CopyEncoding' opcode whose offset and length
-- fields fit the inputs. Total over inputs whose length fits in
-- 'maxSingleCommandLength'; outside that range, 'planCopy' enforces the
-- precondition by chunking before each call. Reads top-to-bottom as the
-- W3C GDIFF spec's COPY table — same order as 'CopyEncoding'.
--
-- Each branch's guard establishes the bound the 'fromIntegral' calls rely on.
selectCopy :: Offset -> Length -> CopyEncoding
selectCopy offset copyLength
  | offset <= maximumTwoByteOffset  && copyLength <= maximumOneByteLength =
      Copy249 (fromIntegral (unOffset offset)) (fromIntegral (unLength copyLength))
  | offset <= maximumTwoByteOffset  && copyLength <= maximumTwoByteLength =
      Copy250 (fromIntegral (unOffset offset)) (fromIntegral (unLength copyLength))
  | offset <= maximumTwoByteOffset                                        =
      Copy251 (fromIntegral (unOffset offset)) (fromIntegral (unLength copyLength))
  | offset <= maximumFourByteOffset && copyLength <= maximumOneByteLength =
      Copy252 (fromIntegral (unOffset offset)) (fromIntegral (unLength copyLength))
  | offset <= maximumFourByteOffset && copyLength <= maximumTwoByteLength =
      Copy253 (fromIntegral (unOffset offset)) (fromIntegral (unLength copyLength))
  | offset <= maximumFourByteOffset                                       =
      Copy254 (fromIntegral (unOffset offset)) (fromIntegral (unLength copyLength))
  | otherwise                                                             =
      Copy255 (unOffset offset) (fromIntegral (unLength copyLength))

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

-- | Encode a COPY command for a region of @regionLength@ bytes starting at @regionOffset@ in source.
encodeCopy :: Offset -> Length -> Builder
encodeCopy regionOffset regionLength = foldMap renderCopy (planCopy regionOffset regionLength)
