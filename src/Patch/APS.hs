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

import Patch.Binary (getWord16LE, getWord32LE)

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Bits (xor)
import Data.Int (Int64)
import Data.Word (Word8, Word16, Word32)
import Numeric (showHex)
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
  | BS.take 5 bs == "APS10" = parseN64 bs
  | BS.take 4 bs == "APS1" = parseGBA bs
  | otherwise = Left "not an APS file (bad magic)"

parseN64 :: ByteString -> Either String APSPatch
parseN64 bs = do
  let ptype = BS.index bs 5
      -- encoding = BS.index bs 6  -- always 0
      desc = BS.take 50 (BS.drop 7 bs)
  case ptype of
    0 -> do  -- Simple patch
      if BS.length bs < 61
        then Left "truncated APS N64 simple header"
        else do
          let destSize = getWord32LE 57 bs
              recs = parseN64Records 61 bs
          Right $ APSPatch $ APSN64
            (APSN64Header ptype desc Nothing Nothing Nothing Nothing destSize)
            recs
    1 -> do  -- N64-specific
      if BS.length bs < 78
        then Left "truncated APS N64 header"
        else do
          let imgFmt   = BS.index bs 57
              cartId   = BS.take 2 (BS.drop 58 bs)
              country  = BS.index bs 60
              crcVal   = BS.take 8 (BS.drop 61 bs)
              destSize = getWord32LE 74 bs
              recs     = parseN64Records 78 bs
          Right $ APSPatch $ APSN64
            (APSN64Header ptype desc (Just imgFmt) (Just cartId)
                          (Just country) (Just crcVal) destSize)
            recs
    _ -> Left ("unknown APS N64 patch type: " ++ show ptype)

parseN64Records :: Int -> ByteString -> [APSN64Record]
parseN64Records pos bs
  | pos + 5 > BS.length bs = []
  | otherwise =
      let off = fromIntegral (getWord32LE pos bs) :: Int64
          len = BS.index bs (pos + 4)
      in if len == 0 && pos + 7 <= BS.length bs
         then -- RLE record
           let val   = BS.index bs (pos + 5)
               count = BS.index bs (pos + 6)
           in APSN64RLE off val count : parseN64Records (pos + 7) bs
         else -- Normal record
           let dat = BS.take (fromIntegral len) (BS.drop (pos + 5) bs)
           in APSN64Normal off dat : parseN64Records (pos + 5 + fromIntegral len) bs

parseGBA :: ByteString -> Either String APSPatch
parseGBA bs = do
  if BS.length bs < 12
    then Left "truncated APS GBA header"
    else do
      let srcSize = getWord32LE 4 bs
          tgtSize = getWord32LE 8 bs
          recs    = parseGBARecords 12 bs
      Right $ APSPatch $ APSGBA (APSGBAHeader srcSize tgtSize) recs

parseGBARecords :: Int -> ByteString -> [APSGBARecord]
parseGBARecords pos bs
  | pos + 65544 > BS.length bs = []
  | otherwise =
      let off    = getWord32LE pos bs
          srcCrc = getWord16LE (pos + 4) bs
          tgtCrc = getWord16LE (pos + 6) bs
          xorDat = BS.take 65536 (BS.drop (pos + 8) bs)
      in APSGBARecord off srcCrc tgtCrc xorDat : parseGBARecords (pos + 65544) bs

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
      newBlock = BS.pack (zipWith xor (BS.unpack padBlock) (BS.unpack xorDat))
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
    cartStr (Just c) = "cart ID:     " ++ concatMap (\b -> padH 2 (showHex b "")) (BS.unpack c)
    countryStr Nothing  = ""
    countryStr (Just c) = "country:     0x" ++ padH 2 (showHex c "")

padH :: Int -> String -> String
padH n s = replicate (n - length s) '0' ++ s
