{-# LANGUAGE OverloadedStrings #-}

module Slap.DPS.Create
  ( createDPS
  , dpsRecordsFromDiff
  , encodeRecord
  ) where

import Slap.DPS.Types (DPSStability, fromDPSStability)
import Slap.Binary (putWord32LE, diffHunks)
import Slap.Measure (Offset(..), Hunk(..))

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Char8 as ByteString8
import qualified Data.ByteString.Lazy as LazyByteString
import Data.ByteString.Builder (Builder, word8, byteString, toLazyByteString)
import Data.Word (Word8, Word32)

-- Encodes changed regions as EnclosedData records and unchanged regions
-- as CopyFromROM records.
createDPS :: ByteString -> ByteString -> String -> String -> String -> DPSStability -> ByteString
createDPS original modified name author version stability = LazyByteString.toStrict $ toLazyByteString $
    padField 64 name                    -- name
    <> padField 64 author               -- author
    <> padField 64 version              -- version
    <> word8 (fromDPSStability stability)  -- flag
    <> word8 1                          -- DPS version
    <> putWord32LE (fromIntegral (ByteString.length original) :: Word32)  -- orig size
    <> foldMap encodeRecord (dpsRecordsFromDiff original modified)
  where
    padField fieldLength fieldString =
      let fieldBytes = ByteString8.pack (take fieldLength fieldString)
      in byteString fieldBytes <> byteString (ByteString.replicate (fieldLength - ByteString.length fieldBytes) 0)

dpsRecordsFromDiff :: ByteString -> ByteString -> [(Word8, Int, ByteString)]
dpsRecordsFromDiff original modified = buildRecords 0 (diffHunks original modified)
  where
    buildRecords _ [] = []
    buildRecords position (Hunk rawOffset rawData : rest) =
      let intOffset = fromIntegral (unOffset rawOffset) :: Int
      in if intOffset > position
         then (0, position, encodeCopy position (intOffset - position))  -- CopyFromROM gap
              : (1, intOffset, rawData)                                  -- EnclosedData
              : buildRecords (intOffset + ByteString.length rawData) rest
         else (1, intOffset, rawData) : buildRecords (intOffset + ByteString.length rawData) rest
    encodeCopy sourceOffset copyLength = LazyByteString.toStrict $ toLazyByteString $
      putWord32LE (fromIntegral sourceOffset :: Word32)
      <> putWord32LE (fromIntegral copyLength :: Word32)

encodeRecord :: (Word8, Int, ByteString) -> Builder
encodeRecord (0, outputOffset, copyPayload) =  -- CopyFromROM: mode + outOff + srcOff + len (pre-encoded in copyPayload)
    word8 0
    <> putWord32LE (fromIntegral outputOffset :: Word32)
    <> byteString copyPayload
encodeRecord (_, outputOffset, payload) =      -- EnclosedData: mode + outOff + len + data
    word8 1
    <> putWord32LE (fromIntegral outputOffset :: Word32)
    <> putWord32LE (fromIntegral (ByteString.length payload) :: Word32)
    <> byteString payload
