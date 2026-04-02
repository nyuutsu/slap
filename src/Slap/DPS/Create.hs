{-# LANGUAGE OverloadedStrings #-}

module Slap.DPS.Create
  ( createDPS
  , dpsRecordsFromDiff
  , encodeRecord
  ) where

import Slap.DPS.Types (DPSStability, fromDPSStability, DPSRecord(..), DPSMode(..), DPSPayload(..),
                        dpsFieldWidth)
import Slap.Binary (putWord32LE, diffHunks)
import Slap.Measure (Offset(..), Length(..), Hunk(..))

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Char8 as ByteString8
import qualified Data.ByteString.Lazy as LazyByteString
import Data.ByteString.Builder (Builder, word8, byteString, toLazyByteString)
import Data.Word (Word32)

-- Encodes changed regions as EnclosedData records and unchanged regions
-- as CopyFromROM records.
createDPS :: ByteString -> ByteString -> String -> String -> String -> DPSStability -> ByteString
createDPS original modified name author version stability = LazyByteString.toStrict $ toLazyByteString $
    padField dpsFieldWidth name         -- name
    <> padField dpsFieldWidth author    -- author
    <> padField dpsFieldWidth version   -- version
    <> word8 (fromDPSStability stability)  -- flag
    <> word8 1                          -- DPS version
    <> putWord32LE (fromIntegral (ByteString.length original) :: Word32)  -- orig size
    <> foldMap encodeRecord (dpsRecordsFromDiff original modified)
  where
    padField fieldLength fieldString =
      let fieldBytes = ByteString8.pack (take fieldLength fieldString)
      in byteString fieldBytes <> byteString (ByteString.replicate (fieldLength - ByteString.length fieldBytes) 0)

dpsRecordsFromDiff :: ByteString -> ByteString -> [DPSRecord]
dpsRecordsFromDiff original modified = buildRecords 0 (diffHunks original modified)
  where
    buildRecords _ [] = []
    buildRecords position (Hunk rawOffset rawData : rest) =
      let intOffset = fromIntegral (unOffset rawOffset) :: Int
      in if intOffset > position
         then DPSRecord CopyFromROM (Offset (fromIntegral position))
                (PayloadCopy (Offset (fromIntegral position)) (Length (intOffset - position)))
              : DPSRecord EnclosedData rawOffset (PayloadData rawData)
              : buildRecords (intOffset + ByteString.length rawData) rest
         else DPSRecord EnclosedData rawOffset (PayloadData rawData)
              : buildRecords (intOffset + ByteString.length rawData) rest

encodeRecord :: DPSRecord -> Builder
encodeRecord (DPSRecord CopyFromROM outputOffset (PayloadCopy sourceOffset copyLength)) =
    word8 0
    <> putWord32LE (fromIntegral (unOffset outputOffset) :: Word32)
    <> putWord32LE (fromIntegral (unOffset sourceOffset) :: Word32)
    <> putWord32LE (fromIntegral (unLength copyLength) :: Word32)
encodeRecord (DPSRecord EnclosedData outputOffset (PayloadData payload)) =
    word8 1
    <> putWord32LE (fromIntegral (unOffset outputOffset) :: Word32)
    <> putWord32LE (fromIntegral (ByteString.length payload) :: Word32)
    <> byteString payload
encodeRecord (DPSRecord CopyFromROM outputOffset (PayloadData payload)) =
    -- Shouldn't happen in normal use; encode as EnclosedData
    encodeRecord (DPSRecord EnclosedData outputOffset (PayloadData payload))
encodeRecord (DPSRecord EnclosedData outputOffset (PayloadCopy sourceOffset copyLength)) =
    -- Shouldn't happen in normal use; encode as CopyFromROM
    encodeRecord (DPSRecord CopyFromROM outputOffset (PayloadCopy sourceOffset copyLength))
