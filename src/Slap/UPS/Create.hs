{-# LANGUAGE OverloadedStrings #-}

module Slap.UPS.Create
  ( createUPS
  , encodeUPSBlock
  , xorToBlocks
  ) where

import Slap.UPS.Types (UPSBlock(..))
import Slap.Binary (putWord32LE, putByuuVarint)
import Slap.Checksum (CRC32(..))
import Slap.FFI (rustyCRC32)
import Slap.Measure (Delta(..))

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.ByteString.Builder
import qualified Data.ByteString.Lazy as LazyByteString
import Data.Bits (xor)
import Data.Int (Int64)

createUPS :: ByteString -> ByteString -> ByteString
createUPS original modified =
  let sourceCRC = rustyCRC32 original
      targetCRC = rustyCRC32 modified
      maxLength = max (ByteString.length original) (ByteString.length modified)
      paddedSource = if ByteString.length original < maxLength
               then original <> ByteString.replicate (maxLength - ByteString.length original) 0
               else original
      paddedTarget = if ByteString.length modified < maxLength
               then modified <> ByteString.replicate (maxLength - ByteString.length modified) 0
               else modified
      xorBytes = ByteString.packZipWith xor paddedSource paddedTarget
      blocks = xorToBlocks xorBytes
      body = byteString "UPS1"
             <> putByuuVarint (fromIntegral (ByteString.length original))
             <> putByuuVarint (fromIntegral (ByteString.length modified))
             <> foldMap encodeUPSBlock blocks
             <> putWord32LE (unCRC32 sourceCRC)
             <> putWord32LE (unCRC32 targetCRC)
      bodyBytes = LazyByteString.toStrict (toLazyByteString body)
      patchCRC = rustyCRC32 bodyBytes
  in bodyBytes <> LazyByteString.toStrict (toLazyByteString (putWord32LE (unCRC32 patchCRC)))

encodeUPSBlock :: UPSBlock -> Builder
encodeUPSBlock (UPSBlock skipDelta xorData) =
  putByuuVarint (unDelta skipDelta)
  <> byteString xorData
  <> word8 0x00  -- terminator

-- | Convert XOR byte array into UPS blocks (skip + nonzero runs).
xorToBlocks :: ByteString -> [UPSBlock]
xorToBlocks input = scanLoop 0
  where
    inputLength = ByteString.length input

    scanLoop position
      | position >= inputLength = []
      | otherwise =
          let skip = countZeros position
              runStart = position + fromIntegral skip
          in if runStart >= inputLength
             then []
             else let (xorData, end) = collectNonzero runStart
                  in UPSBlock (Delta skip) xorData : scanLoop end

    countZeros :: Int -> Int64
    countZeros startPosition = countFrom startPosition
      where
        countFrom scanPosition
          | scanPosition >= inputLength = fromIntegral (scanPosition - startPosition)
          | ByteString.index input scanPosition == 0 = countFrom (scanPosition + 1)
          | otherwise = fromIntegral (scanPosition - startPosition)

    collectNonzero :: Int -> (ByteString, Int)
    collectNonzero start = collectFrom start []
      where
        collectFrom scanPosition accumulated
          | scanPosition >= inputLength = (ByteString.pack (reverse accumulated), scanPosition)
          | ByteString.index input scanPosition == 0 = (ByteString.pack (reverse accumulated), scanPosition + 1)  -- +1: consume terminator position
          | otherwise = collectFrom (scanPosition + 1) (ByteString.index input scanPosition : accumulated)
