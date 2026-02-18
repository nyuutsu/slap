{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StrictData #-}

module Patch.APS
  ( APSVariant(..)
  , APSPatch(..)
  , APSN64Header(..)
  , APSN64Record(..)
  , APSGBAHeader(..)
  , APSGBARecord(..)
  , parseAPS
  , applyAPS
  , apsInfo
  ) where

import Patch.Get (Get, runGet, getByte, getBytes, skip, atEnd, remaining, word16LE, word32LE)
import Patch.Format (padHex)

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Bits (xor)
import Data.Int (Int64)
import Data.Word (Word8, Word16, Word32)
import System.IO

----------------------------------------------------------------------------
-- Types
----------------------------------------------------------------------------

data APSVariant
  = APSN64 APSN64Header [APSN64Record]
  | APSGBA APSGBAHeader [APSGBARecord]
  deriving (Show)

data APSN64Header = APSN64Header
  { n64PatchType   :: Word8      -- 0 = simple, 1 = N64
  , n64Description :: ByteString -- 50 bytes
  , n64ImageFormat :: Maybe Word8  -- N64 only: 0=V64, 1=Z64
  , n64CartId      :: Maybe ByteString  -- N64 only: 2 bytes
  , n64Country     :: Maybe Word8       -- N64 only
  , n64Crc         :: Maybe ByteString  -- N64 only: 8 bytes
  , n64DestSize    :: Word32
  } deriving (Show)

data APSN64Record
  = APSN64Normal Int64 ByteString    -- offset, data
  | APSN64RLE    Int64 Word8 Word8   -- offset, value, count
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

data APSPatch = APSPatch APSVariant
  deriving (Show)

----------------------------------------------------------------------------
-- Parsing
----------------------------------------------------------------------------

parseAPS :: ByteString -> Either String APSPatch
parseAPS bs
  | BS.length bs < 5 = Left "too short for APS header"
  | BS.take 5 bs == "APS10" = runGet parseN64 bs
  | BS.take 4 bs == "APS1" = runGet parseGBA bs
  | otherwise = Left "not an APS file (bad magic)"

parseN64 :: Get APSPatch
parseN64 = do
  skip 5  -- "APS10"
  ptype <- getByte
  skip 1  -- encoding (always 0)
  desc <- getBytes 50
  case ptype of
    0 -> do  -- Simple patch
      destSize <- word32LE
      recs <- parseN64Records
      pure $ APSPatch $ APSN64
        (APSN64Header ptype desc Nothing Nothing Nothing Nothing destSize)
        recs
    1 -> do  -- N64-specific
      imgFmt  <- getByte
      cartId  <- getBytes 2
      country <- getByte
      crcVal  <- getBytes 8
      skip 5  -- padding (bytes 69-73)
      destSize <- word32LE
      recs <- parseN64Records
      pure $ APSPatch $ APSN64
        (APSN64Header ptype desc (Just imgFmt) (Just cartId)
                      (Just country) (Just crcVal) destSize)
        recs
    _ -> fail ("unknown APS N64 patch type: " ++ show ptype)

parseN64Records :: Get [APSN64Record]
parseN64Records = do
  done <- atEnd
  if done then pure []
  else do
    avail <- remaining
    if avail < 5 then pure []
    else do
      off <- fromIntegral <$> word32LE
      len <- getByte
      if len == 0
        then do  -- RLE record
          val   <- getByte
          count <- getByte
          rest <- parseN64Records
          pure (APSN64RLE off val count : rest)
        else do  -- Normal record
          dat <- getBytes (fromIntegral len)
          rest <- parseN64Records
          pure (APSN64Normal off dat : rest)

parseGBA :: Get APSPatch
parseGBA = do
  skip 4  -- "APS1"
  srcSize <- word32LE
  tgtSize <- word32LE
  recs <- parseGBARecords
  pure $ APSPatch $ APSGBA (APSGBAHeader srcSize tgtSize) recs

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

applyAPS :: APSPatch -> FilePath -> IO Int
applyAPS (APSPatch variant) target = case variant of
  APSN64 _ recs -> withBinaryFile target ReadWriteMode $ \h -> do
    mapM_ (applyN64Record h) recs
    pure (length recs)
  APSGBA hdr recs -> do
    source <- BS.readFile target
    let tgtSize = fromIntegral (gbaTargetSize hdr) :: Int
        padded = if BS.length source < tgtSize
                 then source <> BS.replicate (tgtSize - BS.length source) 0
                 else source
    result <- applyGBARecs padded recs
    BS.writeFile target (BS.take tgtSize result)
    pure (length recs)

applyN64Record :: Handle -> APSN64Record -> IO ()
applyN64Record h (APSN64Normal off dat) = do
  hSeek h AbsoluteSeek (fromIntegral off)
  BS.hPut h dat
applyN64Record h (APSN64RLE off val count) = do
  hSeek h AbsoluteSeek (fromIntegral off)
  BS.hPut h (BS.replicate (fromIntegral count) val)

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

----------------------------------------------------------------------------
-- Info
----------------------------------------------------------------------------

apsInfo :: APSPatch -> String
apsInfo (APSPatch variant) = case variant of
  APSN64 hdr recs -> unlines $ filter (not . null)
    [ "format:      APS (N64)"
    , "patch type:  " ++ if n64PatchType hdr == 1 then "N64-specific" else "simple"
    , descStr (n64Description hdr)
    , fmtStr (n64ImageFormat hdr)
    , cartStr (n64CartId hdr)
    , countryStr (n64Country hdr)
    , "dest size:   " ++ show (n64DestSize hdr)
    , "records:     " ++ show (length recs)
    ]
  APSGBA hdr recs -> unlines $ filter (not . null)
    [ "format:      APS (GBA)"
    , "source size: " ++ show (gbaSourceSize hdr)
    , "target size: " ++ show (gbaTargetSize hdr)
    , "blocks:      " ++ show (length recs)
    ]
  where
    descStr d
      | BS.all (\b -> b == 0x20 || b == 0) d = ""
      | otherwise = "description: " ++ show (BS.takeWhile (/= 0) d)
    fmtStr Nothing  = ""
    fmtStr (Just 0) = "image:       V64 (byteswapped)"
    fmtStr (Just 1) = "image:       Z64 (big-endian)"
    fmtStr (Just f) = "image:       unknown (" ++ show f ++ ")"
    cartStr Nothing  = ""
    cartStr (Just c) = "cart ID:     " ++ concatMap (\b -> padHex 2 (fromIntegral b)) (BS.unpack c)
    countryStr Nothing  = ""
    countryStr (Just c) = "country:     0x" ++ padHex 2 (fromIntegral c)
