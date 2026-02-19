{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StrictData #-}

module Patch.NINJA1
  ( NINJA1Patch(..)
  , NINJA1SubFormat(..)
  , NINJA1Record(..)
  , parseNINJA1
  , applyNINJA1
  , createNINJA1
  , encodeNINJA1
  , ninja1Info
  ) where

import Patch.Get (Get, runGet, getByte, getBytes, remaining)
import Patch.Binary (diffHunks, putWord32BE)
import Patch.Format (showCRC, padHex)

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BS8
import qualified Data.ByteString.Lazy as BL
import Data.ByteString.Builder (Builder, word8, byteString, toLazyByteString)
import Data.Bits (shiftR, (.&.))
import Data.Char (toLower)
import Data.Int (Int64)
import Data.Word (Word8, Word32)
import Numeric (readHex)
import System.IO

import qualified Codec.Compression.Zlib as Zlib
import Control.Exception (SomeException, try, evaluate)
import System.IO.Unsafe (unsafePerformIO)

----------------------------------------------------------------------------
-- Types
----------------------------------------------------------------------------

data NINJA1SubFormat = N1Binary | N1BinaryZ | N1Text | N1TextZ
  deriving (Show, Eq)

data NINJA1Patch = NINJA1Patch
  { n1SubFormat  :: NINJA1SubFormat
  , n1RomType    :: Word8
  , n1SourceCRC  :: Maybe Word32
  , n1SourceMD5  :: Maybe ByteString  -- 16 bytes
  , n1SourceSHA1 :: Maybe ByteString  -- 20 bytes
  , n1Records    :: [NINJA1Record]
  , n1CleanEOF   :: Bool              -- binary: True if EOF sentinel found
  } deriving (Show)

data NINJA1Record = NINJA1Record
  { n1RecOffset :: Int64
  , n1RecData   :: ByteString
  } deriving (Show)

----------------------------------------------------------------------------
-- Parse
----------------------------------------------------------------------------

parseNINJA1 :: ByteString -> Either String NINJA1Patch
parseNINJA1 bs
  | BS.length bs < 8             = Left "too short for NINJA1 header"
  | BS.take 6 bs /= "NINJA1"    = Left "not a NINJA1 file (bad magic)"
  | subId == "B "                = parseBin N1Binary payload
  | subId == "BZ"                = zlibDecompress payload >>= parseBin N1BinaryZ
  | subId == BS.pack [0x54,0x0A] = parseTxt N1Text payload    -- "T\n"
  | subId == "TZ"                = zlibDecompress payload >>= parseTxt N1TextZ
  | otherwise                    = Left ("unknown NINJA1 subformat: " ++ show subId)
  where
    subId   = BS.take 2 (BS.drop 6 bs)
    payload = BS.drop 8 bs

-- | Zlib decompression (PHP gzcompress = RFC 1950 zlib format).
{-# NOINLINE zlibDecompress #-}
zlibDecompress :: ByteString -> Either String ByteString
zlibDecompress compressed = unsafePerformIO $ do
  result <- try $ evaluate $ BL.toStrict $ Zlib.decompress $ BL.fromStrict compressed
  pure $ case result of
    Left (e :: SomeException) -> Left ("zlib decompression failed: " ++ show e)
    Right r -> Right r

----------------------------------------------------------------------------
-- Binary format: 41-byte header + variable-length records + EOF sentinel
--
-- Header: 1B ROM type, 4B CRC32 BE, 16B MD5, 20B SHA1
-- Records: offlen(1B) offset(offlenB BE) lenlen(1B) length(lenlenB BE) data
-- EOF: offlen=3 offset="EOF"
-- All offsets/lengths are big-endian, width given by preceding byte.
-- Patch bytes are raw overwrites (NOT XOR like NINJA2).
----------------------------------------------------------------------------

parseBin :: NINJA1SubFormat -> ByteString -> Either String NINJA1Patch
parseBin fmt payload
  | BS.length payload < 41 = Left "NINJA1 binary payload too short"
  | otherwise = runGet (parseBinGet fmt) payload

parseBinGet :: NINJA1SubFormat -> Get NINJA1Patch
parseBinGet fmt = do
  romType   <- getByte
  crcBytes  <- getBytes 4
  md5Bytes  <- getBytes 16
  sha1Bytes <- getBytes 20
  (recs, clean) <- parseBinRecords
  let crc  = if BS.all (== 0) crcBytes then Nothing else Just (decodeBE32 crcBytes)
      md5  = if BS.all (== 0) md5Bytes then Nothing else Just md5Bytes
      sha1 = if BS.all (== 0) sha1Bytes then Nothing else Just sha1Bytes
  pure NINJA1Patch
    { n1SubFormat  = fmt
    , n1RomType    = romType
    , n1SourceCRC  = crc
    , n1SourceMD5  = md5
    , n1SourceSHA1 = sha1
    , n1Records    = recs
    , n1CleanEOF   = clean
    }

decodeBE32 :: ByteString -> Word32
decodeBE32 = BS.foldl' (\acc b -> acc * 256 + fromIntegral b) 0

decodeBE :: ByteString -> Int64
decodeBE = BS.foldl' (\acc b -> acc * 256 + fromIntegral b) 0

parseBinRecords :: Get ([NINJA1Record], Bool)
parseBinRecords = go []
  where
    go acc = do
      avail <- remaining
      if avail < 1 then pure (reverse acc, False)
      else do
        offLen <- fromIntegral <$> getByte :: Get Int
        if offLen == 0 then pure (reverse acc, False)
        else do
          offBytes <- getBytes offLen
          if offLen == 3 && offBytes == "EOF"
            then pure (reverse acc, True)
            else do
              let off = decodeBE offBytes
              lenLen <- fromIntegral <$> getByte :: Get Int
              lenBytes <- getBytes lenLen
              let len = fromIntegral (decodeBE lenBytes) :: Int
              dat <- getBytes len
              go (NINJA1Record off dat : acc)

----------------------------------------------------------------------------
-- Textual format: line-based, # comments, header + hex records
--
-- Header line: FORMAT CRC32 MD5 SHA1
--   FORMAT = rom type name (raw, snes, gba, etc.)
--   CRC32/MD5/SHA1 = hex string or "unk"/"unk." to skip
-- Record lines: OFFSET HEXDATA (both hex strings, no 0x prefix)
----------------------------------------------------------------------------

parseTxt :: NINJA1SubFormat -> ByteString -> Either String NINJA1Patch
parseTxt fmt payload = do
  let stripCR = BS8.takeWhile (/= '\r')
      contentLines = filter (not . isSkippable) (map stripCR (BS8.lines payload))
  case contentLines of
    [] -> Left "empty NINJA1 textual patch"
    (hdrLine : recLines) -> do
      let (romType, crc, md5, sha1) = parseTxtHeader hdrLine
      recs <- mapM parseTxtRecord recLines
      Right NINJA1Patch
        { n1SubFormat  = fmt
        , n1RomType    = romType
        , n1SourceCRC  = crc
        , n1SourceMD5  = md5
        , n1SourceSHA1 = sha1
        , n1Records    = recs
        , n1CleanEOF   = True  -- textual format has no EOF sentinel
        }
  where
    isSkippable line = BS.null line || BS8.head line == '#'

parseTxtHeader :: ByteString -> (Word8, Maybe Word32, Maybe ByteString, Maybe ByteString)
parseTxtHeader line = (romType, crc, md5, sha1)
  where
    ws = map BS8.unpack (BS8.words line)
    romType = case ws of
      (f:_) -> romTypeFromName f
      _     -> 0
    isUnk s = s == "unk" || s == "unk."
    crc = case ws of
      (_:c:_) | not (isUnk c) -> case (readHex c :: [(Word32, String)]) of
        [(n, "")] -> Just n
        _         -> Nothing
      _ -> Nothing
    nonEmpty bs = if BS.null bs then Nothing else Just bs
    md5 = case ws of
      (_:_:m:_) | not (isUnk m) -> nonEmpty (hexToBS m)
      _ -> Nothing
    sha1 = case ws of
      (_:_:_:s:_) | not (isUnk s) -> nonEmpty (hexToBS s)
      _ -> Nothing

parseTxtRecord :: ByteString -> Either String NINJA1Record
parseTxtRecord line = case BS8.words line of
  (offStr : datParts@(_:_)) ->
    case (readHex (BS8.unpack offStr) :: [(Int64, String)]) of
      [(off, "")] -> Right (NINJA1Record off (hexToBS (concatMap BS8.unpack datParts)))
      _ -> Left ("bad offset in NINJA1 text record: " ++ BS8.unpack offStr)
  _ -> Left ("malformed NINJA1 text record: " ++ BS8.unpack line)

hexToBS :: String -> ByteString
hexToBS s = BS.pack (go s)
  where
    go [] = []
    go [_] = []
    go (a:b:rest) = case (readHex [a,b] :: [(Word8, String)]) of
      [(n, "")] -> n : go rest
      _         -> []

romTypeFromName :: String -> Word8
romTypeFromName s = case map toLower s of
  "raw"  -> 0;  "nes"  -> 1;  "snes" -> 2;  "n64"  -> 3
  "gb"   -> 4;  "gbc"  -> 5;  "gba"  -> 6;  "ngp"  -> 7
  "ngpc" -> 8;  "sms"  -> 9;  "gg"   -> 10; "mega" -> 11
  "pce"  -> 12; "ws"   -> 13; "wsc"  -> 14; "lynx" -> 15
  "jag"  -> 16; "gp32" -> 17; _      -> 0

----------------------------------------------------------------------------
-- Apply (raw overwrite, like IPS)
----------------------------------------------------------------------------

applyNINJA1 :: NINJA1Patch -> FilePath -> IO Int
applyNINJA1 patch target = withBinaryFile target ReadWriteMode $ \h -> do
  mapM_ (applyRecord h) (n1Records patch)
  pure (length (n1Records patch))

applyRecord :: Handle -> NINJA1Record -> IO ()
applyRecord h (NINJA1Record off dat) = do
  hSeek h AbsoluteSeek (fromIntegral off)
  BS.hPut h dat

----------------------------------------------------------------------------
-- Info
----------------------------------------------------------------------------

ninja1Info :: NINJA1Patch -> String
ninja1Info p = unlines $ filter (not . null)
  [ "format:      NINJA1 (" ++ subFmtStr ++ ")"
  , "ROM type:    " ++ romTypeName' (n1RomType p)
  , crcStr
  , md5Str
  , sha1Str
  , "records:     " ++ show (length (n1Records p))
  , "total bytes: " ++ show totalBytes
  ]
  where
    subFmtStr = case n1SubFormat p of
      N1Binary  -> "binary"
      N1BinaryZ -> "binary, compressed"
      N1Text    -> "text"
      N1TextZ   -> "text, compressed"
    crcStr = case n1SourceCRC p of
      Nothing -> ""
      Just c  -> "source CRC:  0x" ++ showCRC c
    md5Str = case n1SourceMD5 p of
      Nothing  -> ""
      Just md5 -> "source MD5:  " ++ concatMap (\b -> padHex 2 (fromIntegral b)) (BS.unpack md5)
    sha1Str = case n1SourceSHA1 p of
      Nothing   -> ""
      Just sha1 -> "source SHA1: " ++ concatMap (\b -> padHex 2 (fromIntegral b)) (BS.unpack sha1)
    totalBytes = sum (map (BS.length . n1RecData) (n1Records p))

romTypeName' :: Word8 -> String
romTypeName' 0  = "RAW"
romTypeName' 1  = "NES"
romTypeName' 2  = "SNES"
romTypeName' 3  = "N64"
romTypeName' 4  = "GB"
romTypeName' 5  = "GBC"
romTypeName' 6  = "GBA"
romTypeName' 7  = "NGP"
romTypeName' 8  = "NGPC"
romTypeName' 9  = "SMS"
romTypeName' 10 = "Game Gear"
romTypeName' 11 = "Genesis"
romTypeName' 12 = "PC Engine"
romTypeName' 13 = "WonderSwan"
romTypeName' 14 = "WonderSwan Color"
romTypeName' 15 = "Lynx"
romTypeName' 16 = "Jaguar"
romTypeName' 17 = "GP32"
romTypeName' n  = "unknown (" ++ show n ++ ")"

----------------------------------------------------------------------------
-- Create (binary subformat, no hashes)
----------------------------------------------------------------------------

-- | Create a NINJA1 binary patch from original and modified ByteStrings.
createNINJA1 :: BS.ByteString -> BS.ByteString -> BS.ByteString
createNINJA1 old new =
  encodeNINJA1 (diffHunks old new) Nothing Nothing Nothing

-- | Encode pre-diffed records as a NINJA1 Binary (uncompressed) patch.
encodeNINJA1 :: [(Int, BS.ByteString)]
             -> Maybe Word32          -- source CRC32
             -> Maybe BS.ByteString   -- source MD5 (16 bytes)
             -> Maybe BS.ByteString   -- source SHA1 (20 bytes)
             -> BS.ByteString
encodeNINJA1 recs srcCRC srcMD5 srcSHA1 = BL.toStrict $ toLazyByteString $
    byteString "NINJA1B "        -- magic + subformat
    <> word8 0                   -- ROM type: RAW
    <> putWord32BE (maybe 0 id srcCRC)
    <> byteString (maybe (BS.replicate 16 0) id srcMD5)
    <> byteString (maybe (BS.replicate 20 0) id srcSHA1)
    <> foldMap encodeRecord recs
    <> word8 3 <> byteString "EOF"     -- EOF sentinel

encodeRecord :: (Int, BS.ByteString) -> Builder
encodeRecord (off, dat) =
    let offBs = encodeBE (fromIntegral off :: Int64)
        lenBs = encodeBE (fromIntegral (BS.length dat) :: Int64)
    in word8 (fromIntegral (BS.length offBs))
       <> byteString offBs
       <> word8 (fromIntegral (BS.length lenBs))
       <> byteString lenBs
       <> byteString dat

-- | Encode an Int64 as minimal big-endian bytes (at least 1 byte).
encodeBE :: Int64 -> BS.ByteString
encodeBE 0 = BS.singleton 0
encodeBE n = BS.pack (go [] n)
  where
    go acc 0 = acc
    go acc v = go (fromIntegral (v .&. 0xFF) : acc) (v `shiftR` 8)
