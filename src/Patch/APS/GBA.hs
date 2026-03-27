{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StrictData #-}

module Patch.APS.GBA
  ( APSGBAPatch(..)
  , APSGBAHeader(..)
  , APSGBARecord(..)
  , parseAPSGBA
  , applyAPSGBA
  , applyAPSGBAMemory
  , createAPSGBA
  , apsGBAMeta
  , apsGBAInfo
  ) where

-- Canonical reference: https://github.com/btimofeev/UniPatcher/wiki/APS-(GBA)
-- Secondary: RomPatcher.js modules/RomPatcher.format.aps_gba.js

import Patch.Get (Get, runGet, getBytes, skip, remaining, word16LE, word32LE)
import Patch.Binary (crc16, copyByteStringRange, putWord32LE, putWord16LE)
import Patch.Format (renderField)

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.ByteString.Internal (unsafeCreate)
import qualified Data.ByteString.Lazy as LazyByteString
import Data.ByteString.Builder (Builder, byteString, toLazyByteString)
import Data.Bits (xor)
import Data.Word (Word8, Word16, Word32)
import Control.Monad (forM_, when)
import Foreign.Marshal.Utils (fillBytes)
import Foreign.Ptr (plusPtr)
import Foreign.Storable (peekByteOff, pokeByteOff)

----------------------------------------------------------------------------
-- Types
----------------------------------------------------------------------------

data APSGBAPatch = APSGBAPatch APSGBAHeader [APSGBARecord]
  deriving (Show)

data APSGBAHeader = APSGBAHeader
  { apsGbaSourceSize :: Word32
  , apsGbaTargetSize :: Word32
  } deriving (Show)

data APSGBARecord = APSGBARecord
  { apsGbaOffset    :: Word32
  , apsGbaSourceCRC :: Word16
  , apsGbaTargetCRC :: Word16
  , apsGbaXorData   :: ByteString  -- 65536 bytes
  } deriving (Show)

----------------------------------------------------------------------------
-- Parse
----------------------------------------------------------------------------

parseAPSGBA :: ByteString -> Either String APSGBAPatch
parseAPSGBA input
  | ByteString.length input < 4 = Left "APS-GBA: input too short"
  | ByteString.take 4 input /= "APS1" = Left "not an APS-GBA file (bad magic)"
  | otherwise = runGet parseGBA input

parseGBA :: Get APSGBAPatch
parseGBA = do
  skip 4  -- "APS1"
  sourceSize <- word32LE
  targetSize <- word32LE
  records <- parseGBARecords
  pure $ APSGBAPatch (APSGBAHeader sourceSize targetSize) records

parseGBARecords :: Get [APSGBARecord]
parseGBARecords = do
  avail <- remaining
  if avail < 65544 then pure []
  else do
    offset <- word32LE
    sourceCrc <- word16LE
    targetCrc <- word16LE
    xorPayload <- getBytes 65536
    rest <- parseGBARecords
    pure (APSGBARecord offset sourceCrc targetCrc xorPayload : rest)

----------------------------------------------------------------------------
-- Apply
----------------------------------------------------------------------------

applyAPSGBA :: APSGBAPatch -> FilePath -> IO Int
applyAPSGBA (APSGBAPatch header records) target = do
  source <- ByteString.readFile target
  let targetSize = fromIntegral (apsGbaTargetSize header) :: Int
      padded = if ByteString.length source < targetSize
               then source <> ByteString.replicate (targetSize - ByteString.length source) 0
               else source
  result <- applyGBARecords padded records
  ByteString.writeFile target (ByteString.take targetSize result)
  pure (length records)

applyGBARecords :: ByteString -> [APSGBARecord] -> IO ByteString
applyGBARecords source [] = pure source
applyGBARecords source (APSGBARecord offset _ _ xorPayload : rest) = do
  let blockOffset = fromIntegral offset :: Int
      blockSize = 65536
      before = ByteString.take blockOffset source
      sourceBlock = ByteString.take blockSize (ByteString.drop blockOffset source)
      paddedBlock = if ByteString.length sourceBlock < blockSize
                    then sourceBlock <> ByteString.replicate (blockSize - ByteString.length sourceBlock) 0
                    else sourceBlock
      patchedBlock = ByteString.packZipWith xor paddedBlock xorPayload
      after = ByteString.drop (blockOffset + blockSize) source
      result = before <> patchedBlock <> after
  applyGBARecords result rest

applyAPSGBAMemory :: APSGBAPatch -> ByteString -> ByteString
applyAPSGBAMemory (APSGBAPatch header records) source = unsafeCreate targetSize $ \targetPointer -> do
    copyByteStringRange targetPointer 0 source 0 (min sourceLength targetSize)
    when (targetSize > sourceLength) $
      fillBytes (targetPointer `plusPtr` sourceLength) (0 :: Word8) (targetSize - sourceLength)
    forM_ records $ \(APSGBARecord offset _ _ xorPayload) -> do
      let blockOffset = fromIntegral offset :: Int
      forM_ [0..65535] $ \index -> do
        let position = blockOffset + index
        when (position < targetSize) $ do
          original <- peekByteOff targetPointer position :: IO Word8
          pokeByteOff targetPointer position (original `xor` ByteString.index xorPayload index)
  where
    sourceLength = ByteString.length source
    targetSize = fromIntegral (apsGbaTargetSize header)

----------------------------------------------------------------------------
-- Info
----------------------------------------------------------------------------

apsGBAMeta :: APSGBAPatch -> [(String, String)]
apsGBAMeta (APSGBAPatch header _) =
  [ ("source size", show (apsGbaSourceSize header))
  , ("target size", show (apsGbaTargetSize header))
  ]

apsGBAInfo :: APSGBAPatch -> String
apsGBAInfo patch@(APSGBAPatch _ records) = unlines $ filter (not . null) $
  [ "format:      APS (GBA)" ]
  ++ map renderField (apsGBAMeta patch)
  ++ [ "blocks:      " ++ show (length records) ]

----------------------------------------------------------------------------
-- Create (64KB XOR blocks with CRC16)
----------------------------------------------------------------------------

createAPSGBA :: ByteString -> ByteString -> ByteString
createAPSGBA original modified = LazyByteString.toStrict $ toLazyByteString $
    byteString "APS1"
    <> putWord32LE (fromIntegral (ByteString.length original) :: Word32)
    <> putWord32LE (fromIntegral (ByteString.length modified) :: Word32)
    <> foldMap (encodeGBABlock original modified) changedBlocks
  where
    blockSize = 65536
    blockCount = max (blocksOf original) (blocksOf modified)
    blocksOf input = (ByteString.length input + blockSize - 1) `div` blockSize
    changedBlocks = filter hasChanges [0 .. blockCount - 1]
    hasChanges blockIndex =
      let offset = blockIndex * blockSize
          sourceBlock = padBlock (safeSlice offset blockSize original)
          targetBlock = padBlock (safeSlice offset blockSize modified)
      in sourceBlock /= targetBlock
    padBlock input
      | ByteString.length input >= blockSize = ByteString.take blockSize input
      | otherwise = input <> ByteString.replicate (blockSize - ByteString.length input) 0

encodeGBABlock :: ByteString -> ByteString -> Int -> Builder
encodeGBABlock original modified blockIndex =
    putWord32LE (fromIntegral offset :: Word32)
    <> putWord16LE (crc16 sourceBlock)
    <> putWord16LE (crc16 targetBlock)
    <> byteString xorPayload
  where
    offset = blockIndex * 65536
    sourceBlock = zeroPadTo 65536 (safeSlice offset 65536 original)
    targetBlock = zeroPadTo 65536 (safeSlice offset 65536 modified)
    xorPayload = ByteString.packZipWith xor sourceBlock targetBlock
    zeroPadTo size input
      | ByteString.length input >= size = ByteString.take size input
      | otherwise = input <> ByteString.replicate (size - ByteString.length input) 0

safeSlice :: Int -> Int -> ByteString -> ByteString
safeSlice offset sliceLength input
  | offset >= ByteString.length input = ByteString.empty
  | otherwise = ByteString.take sliceLength (ByteString.drop offset input)
