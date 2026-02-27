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
import Patch.Binary (crc16, copyBSRange, putWord32LE, putWord16LE)
import Patch.Format (renderField)

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.ByteString.Internal (unsafeCreate)
import qualified Data.ByteString.Lazy as BL
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
  { gbaSourceSize :: Word32
  , gbaTargetSize :: Word32
  } deriving (Show)

data APSGBARecord = APSGBARecord
  { gbaOffset    :: Word32
  , gbaSourceCRC :: Word16
  , gbaTargetCRC :: Word16
  , gbaXorData   :: ByteString  -- 65536 bytes
  } deriving (Show)

----------------------------------------------------------------------------
-- Parse
----------------------------------------------------------------------------

parseAPSGBA :: ByteString -> Either String APSGBAPatch
parseAPSGBA bs
  | BS.length bs < 4 = Left "APS-GBA: input too short"
  | BS.take 4 bs /= "APS1" = Left "not an APS-GBA file (bad magic)"
  | otherwise = runGet parseGBA bs

parseGBA :: Get APSGBAPatch
parseGBA = do
  skip 4  -- "APS1"
  srcSize <- word32LE
  tgtSize <- word32LE
  recs <- parseGBARecords
  pure $ APSGBAPatch (APSGBAHeader srcSize tgtSize) recs

parseGBARecords :: Get [APSGBARecord]
parseGBARecords = do
  avail <- remaining
  if avail < 65544 then pure []
  else do
    off    <- word32LE
    srcCrc <- word16LE
    tgtCrc <- word16LE
    xorDat <- getBytes 65536
    rest   <- parseGBARecords
    pure (APSGBARecord off srcCrc tgtCrc xorDat : rest)

----------------------------------------------------------------------------
-- Apply
----------------------------------------------------------------------------

applyAPSGBA :: APSGBAPatch -> FilePath -> IO Int
applyAPSGBA (APSGBAPatch hdr recs) target = do
  source <- BS.readFile target
  let tgtSize = fromIntegral (gbaTargetSize hdr) :: Int
      padded = if BS.length source < tgtSize
               then source <> BS.replicate (tgtSize - BS.length source) 0
               else source
  result <- applyGBARecs padded recs
  BS.writeFile target (BS.take tgtSize result)
  pure (length recs)

applyGBARecs :: ByteString -> [APSGBARecord] -> IO ByteString
applyGBARecs source [] = pure source
applyGBARecs source (APSGBARecord off _ _ xorDat : rest) = do
  let blockOff = fromIntegral off :: Int
      blockSize = 65536
      before = BS.take blockOff source
      srcBlock = BS.take blockSize (BS.drop blockOff source)
      padBlock = if BS.length srcBlock < blockSize
                 then srcBlock <> BS.replicate (blockSize - BS.length srcBlock) 0
                 else srcBlock
      newBlock = BS.packZipWith xor padBlock xorDat
      after = BS.drop (blockOff + blockSize) source
      result = before <> newBlock <> after
  applyGBARecs result rest

applyAPSGBAMemory :: APSGBAPatch -> ByteString -> ByteString
applyAPSGBAMemory (APSGBAPatch hdr recs) source = unsafeCreate tgtSize $ \ptr -> do
    copyBSRange ptr 0 source 0 (min srcLen tgtSize)
    when (tgtSize > srcLen) $
      fillBytes (ptr `plusPtr` srcLen) (0 :: Word8) (tgtSize - srcLen)
    forM_ recs $ \(APSGBARecord off _ _ xorDat) -> do
      let blockOff = fromIntegral off :: Int
      forM_ [0..65535] $ \i -> do
        let pos = blockOff + i
        when (pos < tgtSize) $ do
          old <- peekByteOff ptr pos :: IO Word8
          pokeByteOff ptr pos (old `xor` BS.index xorDat i)
  where
    srcLen = BS.length source
    tgtSize = fromIntegral (gbaTargetSize hdr)

----------------------------------------------------------------------------
-- Info
----------------------------------------------------------------------------

apsGBAMeta :: APSGBAPatch -> [(String, String)]
apsGBAMeta (APSGBAPatch hdr _) =
  [ ("source size", show (gbaSourceSize hdr))
  , ("target size", show (gbaTargetSize hdr))
  ]

apsGBAInfo :: APSGBAPatch -> String
apsGBAInfo p@(APSGBAPatch _ recs) = unlines $ filter (not . null) $
  [ "format:      APS (GBA)" ]
  ++ map renderField (apsGBAMeta p)
  ++ [ "blocks:      " ++ show (length recs) ]

----------------------------------------------------------------------------
-- Create (64KB XOR blocks with CRC16)
----------------------------------------------------------------------------

createAPSGBA :: ByteString -> ByteString -> ByteString
createAPSGBA old new = BL.toStrict $ toLazyByteString $
    byteString "APS1"
    <> putWord32LE (fromIntegral (BS.length old) :: Word32)
    <> putWord32LE (fromIntegral (BS.length new) :: Word32)
    <> foldMap (encodeGBABlock old new) changedBlocks
  where
    blockSize = 65536
    nBlocks = max (blocksOf old) (blocksOf new)
    blocksOf bs = (BS.length bs + blockSize - 1) `div` blockSize
    changedBlocks = filter hasChanges [0 .. nBlocks - 1]
    hasChanges i =
      let off = i * blockSize
          srcBlk = padBlock (safeSlice off blockSize old)
          tgtBlk = padBlock (safeSlice off blockSize new)
      in srcBlk /= tgtBlk
    padBlock bs
      | BS.length bs >= blockSize = BS.take blockSize bs
      | otherwise = bs <> BS.replicate (blockSize - BS.length bs) 0

encodeGBABlock :: ByteString -> ByteString -> Int -> Builder
encodeGBABlock old new i =
    putWord32LE (fromIntegral off :: Word32)
    <> putWord16LE (crc16 srcBlk)
    <> putWord16LE (crc16 tgtBlk)
    <> byteString xorDat
  where
    off = i * 65536
    srcBlk = padTo 65536 (safeSlice off 65536 old)
    tgtBlk = padTo 65536 (safeSlice off 65536 new)
    xorDat = BS.packZipWith xor srcBlk tgtBlk
    padTo n bs
      | BS.length bs >= n = BS.take n bs
      | otherwise = bs <> BS.replicate (n - BS.length bs) 0

safeSlice :: Int -> Int -> ByteString -> ByteString
safeSlice off len bs
  | off >= BS.length bs = BS.empty
  | otherwise = BS.take len (BS.drop off bs)
