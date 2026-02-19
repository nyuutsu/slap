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
  , createAPSN64
  , createAPSGBA
  , encodeAPSN64
  , apsInfo
  ) where

import Patch.Get (Get, runGet, getByte, getBytes, skip, atEnd, remaining, word16LE, word32LE)
import Patch.Binary (crc16, putWord32LE, putWord16LE, diffHunks)
import Patch.Format (padHex)

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BS8
import qualified Data.ByteString.Lazy as BL
import Data.ByteString.Builder (Builder, word8, byteString, toLazyByteString)
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
  -- APS N64 and APS GBA: two unrelated formats by different authors who both
  -- thought "APS" was a good name.  N64 magic is "APS10" (5 ASCII bytes, probably
  -- "version 1.0"); GBA magic is "APS1" (4 bytes) followed by a LE u32 source size.
  -- The '0' in "APS10" is ASCII 0x30, not a null byte — so a collision requires the
  -- source size's low byte to land on exactly 0x30 (size mod 256 == 48).  Unusual
  -- for stock ROMs, but trimmed/hacked ROMs can be any size, and without this guard
  -- the N64 parser happily eats the GBA data as variable-length records and applies
  -- garbage writes at arbitrary offsets.  No checksums, no sentinel, no diagnostic.
  -- Disambiguate via two structural properties unique to GBA:
  --   1. File is exactly 12 + N*65544 bytes (12-byte header, fixed-size records)
  --   2. Every record's offset is 64KB-aligned (low 2 bytes of each LE u32 are 0x00)
  -- An N64 file would need the right file size (~1/65544) AND every record-position
  -- offset to land on 00 00 (~1/65536 each).  For even one record that's ~1 in 4
  -- billion; for two or more it's beyond the heat death of the universe.
  | BS.take 5 bs == "APS10", not (gbaStructure bs) = runGet parseN64 bs
  | BS.take 4 bs == "APS1" = runGet parseGBA bs
  | otherwise = Left "not an APS file (bad magic)"
  where
    gbaStructure b =
      let payload = BS.length b - 12
          nRecs   = payload `div` 65544
      in payload >= 65544 && payload `mod` 65544 == 0
         && all (\i -> let pos = 12 + i * 65544
                       in BS.index b pos == 0 && BS.index b (pos + 1) == 0)
                [0 .. nRecs - 1]

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

----------------------------------------------------------------------------
-- Create APS N64 (simple type, raw overwrite records, max 255 bytes each)
----------------------------------------------------------------------------

createAPSN64 :: ByteString -> ByteString -> ByteString
createAPSN64 old new =
  encodeAPSN64 (diffHunks old new) (fromIntegral (BS.length new)) (replicate 50 ' ')

-- | Encode pre-diffed records as an APS N64 patch.
-- Records are split at 255 bytes internally.
encodeAPSN64 :: [(Int, ByteString)] -> Word32 -> String -> ByteString
encodeAPSN64 recs destSize desc = BL.toStrict $ toLazyByteString $
    byteString "APS10"             -- magic
    <> word8 0                     -- patch type: simple
    <> word8 0                     -- encoding: not used
    <> byteString descBytes        -- 50-byte description
    <> putWord32LE destSize        -- dest size
    <> foldMap encodeN64Rec (splitLong recs)
  where
    descBytes = let bs = BS8.pack (take 50 desc)
                in bs <> BS.replicate (50 - BS.length bs) 0x20

-- | Split hunks longer than 255 bytes into multiple records.
splitLong :: [(Int, ByteString)] -> [(Int, ByteString)]
splitLong = concatMap split1
  where
    split1 (off, dat)
      | BS.length dat <= 255 = [(off, dat)]
      | otherwise =
          let (chunk, rest) = BS.splitAt 255 dat
          in (off, chunk) : split1 (off + 255, rest)

encodeN64Rec :: (Int, ByteString) -> Builder
encodeN64Rec (off, dat) =
    putWord32LE (fromIntegral off :: Word32)
    <> word8 (fromIntegral (BS.length dat))
    <> byteString dat

----------------------------------------------------------------------------
-- Create APS GBA (64KB XOR blocks with CRC16)
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
