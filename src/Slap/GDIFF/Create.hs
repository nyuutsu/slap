{-# LANGUAGE OverloadedStrings #-}

module Slap.GDIFF.Create
  ( createGDIFF
  , encodeData
  , encodeCopy
  ) where

import Slap.Binary (diffHunks, putWord16BE, putWord32BE, putInt64BE)
import Slap.Measure (Offset(..), Hunk(..))

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Lazy as LazyByteString
import Data.ByteString.Builder (Builder, word8, byteString, toLazyByteString)
import Data.Int (Int64)

-- | Unchanged regions become COPY commands; changed regions become DATA commands.
createGDIFF :: ByteString -> ByteString -> ByteString
createGDIFF original modified = LazyByteString.toStrict $ toLazyByteString $
    byteString "\xd1\xff\xd1\xff"   -- magic
    <> word8 4                       -- version
    <> buildCommands 0 (diffHunks original modified)
    <> word8 0                       -- EOF command
  where
    minLength = min (ByteString.length original) (ByteString.length modified)
    buildCommands position [] =
      -- trailing unchanged region
      if position < minLength then encodeCopy (fromIntegral position) (fromIntegral (minLength - position))
      else mempty
    buildCommands position (Hunk hunkOffset hunkPayload : remaining) =
      let intOffset = fromIntegral (unOffset hunkOffset) :: Int
          gap = intOffset - position
          copyPart = if gap > 0 then encodeCopy (fromIntegral position) (fromIntegral gap) else mempty
          dataBuilder = encodeData hunkPayload
      in copyPart <> dataBuilder <> buildCommands (intOffset + ByteString.length hunkPayload) remaining

-- | Encode a DATA command, splitting into chunks if > 2^31.
encodeData :: ByteString -> Builder
encodeData payload
  | ByteString.null payload = mempty
  | payloadLength <= 246  = word8 (fromIntegral payloadLength) <> byteString payload
  | payloadLength <= 0xFFFF = word8 247 <> putWord16BE payloadLength <> byteString payload
  | otherwise     = word8 248 <> putWord32BE (fromIntegral payloadLength) <> byteString payload
  where payloadLength = ByteString.length payload

-- | Encode a COPY command with optimal opcode selection.
encodeCopy :: Int64 -> Int64 -> Builder
encodeCopy offset copyLength
  -- COPY ushort,ubyte (249)
  | offset <= 0xFFFF && copyLength <= 0xFF =
      word8 249 <> putWord16BE (fromIntegral offset) <> word8 (fromIntegral copyLength)
  -- COPY ushort,ushort (250)
  | offset <= 0xFFFF && copyLength <= 0xFFFF =
      word8 250 <> putWord16BE (fromIntegral offset) <> putWord16BE (fromIntegral copyLength)
  -- COPY ushort,int (251)
  | offset <= 0xFFFF =
      word8 251 <> putWord16BE (fromIntegral offset) <> putWord32BE (fromIntegral copyLength)
  -- COPY int,ubyte (252)
  | offset <= 0xFFFFFFFF && copyLength <= 0xFF =
      word8 252 <> putWord32BE (fromIntegral offset) <> word8 (fromIntegral copyLength)
  -- COPY int,ushort (253)
  | offset <= 0xFFFFFFFF && copyLength <= 0xFFFF =
      word8 253 <> putWord32BE (fromIntegral offset) <> putWord16BE (fromIntegral copyLength)
  -- COPY int,int (254)
  | offset <= 0xFFFFFFFF =
      word8 254 <> putWord32BE (fromIntegral offset) <> putWord32BE (fromIntegral copyLength)
  -- COPY long,int (255)
  | otherwise =
      word8 255 <> putInt64BE offset <> putWord32BE (fromIntegral copyLength)
