{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StrictData #-}

module Patch.NINJA1
  ( NINJA1Patch(..)
  , NINJA1SubFormat(..)
  , NINJA1Record(..)
  , NINJA1RomType(..)
  , toNINJA1RomType
  , fromNINJA1RomType
  , parseNINJA1
  , applyNINJA1
  , applyNINJA1Memory
  , encodeNINJA1
  , ninja1Meta
  , ninja1Info
  , ninja1HashInput
  ) where

-- Canonical reference: docs/specs/ninja-1.01php.tar.gz (Derrick Sobodash, 2004, GPLv2)
-- Format spec: docs/specs/ninja1-filespec10.txt
-- Both archived from http://ninja.cinnamonpirate.com/

import Patch.Get (Get, runGet, getByte, getBytes, remaining)
import Patch.Binary (putWord32BE, copyBSRange)
import Patch.Format (showCRC, padHex, renderField)

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BS8
import Data.ByteString.Internal (unsafeCreate)
import qualified Data.ByteString.Lazy as BL
import Data.ByteString.Builder (Builder, word8, byteString, toLazyByteString)
import Data.Bits (shiftR, (.&.))
import Data.Char (toLower)
import Control.Monad (forM_, when)
import Foreign.Marshal.Utils (fillBytes)
import Foreign.Ptr (plusPtr)
import Data.Int (Int64)
import Data.Word (Word8, Word32)
import Numeric (readHex)
import System.IO

import Patch.Compress (zlibInflate, zlibDeflate)

----------------------------------------------------------------------------
-- Types
----------------------------------------------------------------------------

data NINJA1SubFormat = N1Binary | N1BinaryZ | N1Text | N1TextZ
  deriving (Show, Eq)

-- | ROM platform type. Values 0-17 are defined by the NINJA1 spec;
-- RomUnknown preserves any future/unknown value without crashing.
data NINJA1RomType
  = RomRAW | RomNES | RomSNES | RomN64 | RomGB | RomGBC | RomGBA
  | RomNGP | RomNGPC | RomSMS | RomGameGear | RomGenesis
  | RomPCEngine | RomWonderSwan | RomWonderSwanColor
  | RomLynx | RomJaguar | RomGP32
  | RomUnknown Word8
  deriving (Show, Eq)

toNINJA1RomType :: Word8 -> NINJA1RomType
toNINJA1RomType  0 = RomRAW
toNINJA1RomType  1 = RomNES
toNINJA1RomType  2 = RomSNES
toNINJA1RomType  3 = RomN64
toNINJA1RomType  4 = RomGB
toNINJA1RomType  5 = RomGBC
toNINJA1RomType  6 = RomGBA
toNINJA1RomType  7 = RomNGP
toNINJA1RomType  8 = RomNGPC
toNINJA1RomType  9 = RomSMS
toNINJA1RomType 10 = RomGameGear
toNINJA1RomType 11 = RomGenesis
toNINJA1RomType 12 = RomPCEngine
toNINJA1RomType 13 = RomWonderSwan
toNINJA1RomType 14 = RomWonderSwanColor
toNINJA1RomType 15 = RomLynx
toNINJA1RomType 16 = RomJaguar
toNINJA1RomType 17 = RomGP32
toNINJA1RomType  n = RomUnknown n

fromNINJA1RomType :: NINJA1RomType -> Word8
fromNINJA1RomType RomRAW            = 0
fromNINJA1RomType RomNES            = 1
fromNINJA1RomType RomSNES           = 2
fromNINJA1RomType RomN64            = 3
fromNINJA1RomType RomGB             = 4
fromNINJA1RomType RomGBC            = 5
fromNINJA1RomType RomGBA            = 6
fromNINJA1RomType RomNGP            = 7
fromNINJA1RomType RomNGPC           = 8
fromNINJA1RomType RomSMS            = 9
fromNINJA1RomType RomGameGear       = 10
fromNINJA1RomType RomGenesis        = 11
fromNINJA1RomType RomPCEngine       = 12
fromNINJA1RomType RomWonderSwan     = 13
fromNINJA1RomType RomWonderSwanColor = 14
fromNINJA1RomType RomLynx           = 15
fromNINJA1RomType RomJaguar         = 16
fromNINJA1RomType RomGP32           = 17
fromNINJA1RomType (RomUnknown n)    = n

data NINJA1Patch = NINJA1Patch
  { n1SubFormat  :: NINJA1SubFormat
  , n1RomType    :: NINJA1RomType
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
  | BS.length bs < 8             = Left "NINJA1: input too short"
  | BS.take 6 bs /= "NINJA1"    = Left "not a NINJA1 file (bad magic)"
  | subId == "B "                = parseBin N1Binary payload
  | subId == "BZ"                = zlibDecompress payload >>= parseBin N1BinaryZ
  -- Spec says 0x540d but PHP source uses chr(0x0a); spec hex is wrong.
  | subId == BS.pack [0x54,0x0A] = parseTxt N1Text payload    -- "T\n"
  | subId == "TZ"                = zlibDecompress payload >>= parseTxt N1TextZ
  | otherwise                    = Left ("NINJA1: unsupported subformat: " ++ show subId)
  where
    subId   = BS.take 2 (BS.drop 6 bs)
    payload = BS.drop 8 bs

-- | Zlib decompression (PHP gzcompress = RFC 1950 zlib format).
zlibDecompress :: ByteString -> Either String ByteString
zlibDecompress compressed = case zlibInflate compressed of
  Left _  -> Left "NINJA1: zlib decompression failed"
  Right r -> Right r

----------------------------------------------------------------------------
-- Binary format: 41-byte header + variable-length records + EOF sentinel
--
-- Header: 1B ROM type, 4B CRC32 BE, 16B MD5, 20B SHA1
-- Records: offlen(1B) offset(offlenB BE) lenlen(1B) length(lenlenB BE) data
-- EOF: offlen=3 offset="EOF"
-- All offsets/lengths are big-endian, width given by preceding byte.
-- Patch bytes are raw overwrites (NOT XOR like NINJA2).
-- Large file hash sampling (>0x1e00000): see ninja1HashInput.
----------------------------------------------------------------------------

parseBin :: NINJA1SubFormat -> ByteString -> Either String NINJA1Patch
parseBin fmt payload
  | BS.length payload < 41 = Left "NINJA1: binary payload too short"
  | otherwise = runGet (parseBinGet fmt) payload

parseBinGet :: NINJA1SubFormat -> Get NINJA1Patch
parseBinGet fmt = do
  romType   <- toNINJA1RomType <$> getByte
  crcBytes  <- getBytes 4
  md5Bytes  <- getBytes 16
  sha1Bytes <- getBytes 20
  (recs, clean) <- parseBinRecords
  let crc'  = if BS.all (== 0) crcBytes then Nothing else Just (decodeBE32 crcBytes)
      md5'  = if BS.all (== 0) md5Bytes then Nothing else Just md5Bytes
      sha1' = if BS.all (== 0) sha1Bytes then Nothing else Just sha1Bytes
  pure NINJA1Patch
    { n1SubFormat  = fmt
    , n1RomType    = romType
    , n1SourceCRC  = crc'
    , n1SourceMD5  = md5'
    , n1SourceSHA1 = sha1'
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
    [] -> Left "NINJA1: empty textual patch"
    (hdrLine : recLines) -> do
      let (romType, crc', md5', sha1') = parseTxtHeader hdrLine
      recs <- mapM parseTxtRecord recLines
      Right NINJA1Patch
        { n1SubFormat  = fmt
        , n1RomType    = romType
        , n1SourceCRC  = crc'
        , n1SourceMD5  = md5'
        , n1SourceSHA1 = sha1'
        , n1Records    = recs
        , n1CleanEOF   = True  -- textual format has no EOF sentinel
        }
  where
    isSkippable line = BS.null line || BS8.head line == '#'

parseTxtHeader :: ByteString -> (NINJA1RomType, Maybe Word32, Maybe ByteString, Maybe ByteString)
parseTxtHeader line = (romType, crc', md5', sha1')
  where
    ws = map BS8.unpack (BS8.words line)
    romType = case ws of
      (f:_) -> romTypeFromName f
      _     -> RomRAW
    isUnk s = s == "unk" || s == "unk."
    crc' = case ws of
      (_:c:_) | not (isUnk c) -> case (readHex c :: [(Word32, String)]) of
        [(n, "")] -> Just n
        _         -> Nothing
      _ -> Nothing
    nonEmpty bx = if BS.null bx then Nothing else Just bx
    md5' = case ws of
      (_:_:m:_) | not (isUnk m) -> nonEmpty (hexToBS m)
      _ -> Nothing
    sha1' = case ws of
      (_:_:_:s:_) | not (isUnk s) -> nonEmpty (hexToBS s)
      _ -> Nothing

parseTxtRecord :: ByteString -> Either String NINJA1Record
parseTxtRecord line = case BS8.words line of
  (offStr : datParts@(_:_)) ->
    case (readHex (BS8.unpack offStr) :: [(Int64, String)]) of
      [(off, "")] -> Right (NINJA1Record off (hexToBS (concatMap BS8.unpack datParts)))
      _ -> Left ("NINJA1: invalid offset in text record: " ++ BS8.unpack offStr)
  _ -> Left ("NINJA1: malformed text record: " ++ BS8.unpack line)

hexToBS :: String -> ByteString
hexToBS s = BS.pack (go s)
  where
    go [] = []
    go [_] = []
    go (a:b:rest) = case (readHex [a,b] :: [(Word8, String)]) of
      [(n, "")] -> n : go rest
      _         -> []

romTypeFromName :: String -> NINJA1RomType
romTypeFromName s = case map toLower s of
  "raw"  -> RomRAW;   "nes"  -> RomNES;   "snes" -> RomSNES;  "n64"  -> RomN64
  "gb"   -> RomGB;    "gbc"  -> RomGBC;   "gba"  -> RomGBA;   "ngp"  -> RomNGP
  "ngpc" -> RomNGPC;  "sms"  -> RomSMS;   "gg"   -> RomGameGear; "mega" -> RomGenesis
  "pce"  -> RomPCEngine; "ws" -> RomWonderSwan; "wsc" -> RomWonderSwanColor
  "lynx" -> RomLynx;  "jag"  -> RomJaguar; "gp32" -> RomGP32; _ -> RomRAW

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

-- | Apply a NINJA1 patch in memory: copy source, then overwrite at offsets.
applyNINJA1Memory :: NINJA1Patch -> ByteString -> ByteString
applyNINJA1Memory patch source = unsafeCreate outLen $ \ptr -> do
    copyBSRange ptr 0 source 0 (min srcLen outLen)
    when (outLen > srcLen) $
      fillBytes (ptr `plusPtr` srcLen) (0 :: Word8) (outLen - srcLen)
    forM_ (n1Records patch) $ \(NINJA1Record off dat) ->
      copyBSRange ptr (fromIntegral off) dat 0 (BS.length dat)
  where
    srcLen = BS.length source
    outLen = foldl' max srcLen
      [ fromIntegral (n1RecOffset r) + BS.length (n1RecData r) | r <- n1Records patch ]

----------------------------------------------------------------------------
-- Info
----------------------------------------------------------------------------

ninja1Meta :: NINJA1Patch -> [(String, String)]
ninja1Meta p = concat
  [ [("ROM type", romTypeName (n1RomType p))]
  , case n1SourceCRC p of
      Nothing -> []
      Just c  -> [("source CRC", "0x" ++ showCRC c)]
  , case n1SourceMD5 p of
      Nothing -> []
      Just h  -> [("source MD5", concatMap (\b -> padHex 2 (fromIntegral b)) (BS.unpack h))]
  , case n1SourceSHA1 p of
      Nothing -> []
      Just h  -> [("source SHA1", concatMap (\b -> padHex 2 (fromIntegral b)) (BS.unpack h))]
  ]

ninja1Info :: NINJA1Patch -> String
ninja1Info p = unlines $ filter (not . null) $
  [ "format:      NINJA1 (" ++ subFmtStr ++ ")" ]
  ++ map renderField (ninja1Meta p)
  ++ [ "records:     " ++ show (length (n1Records p))
     , "total bytes: " ++ show totalBytes
     ]
  where
    subFmtStr = case n1SubFormat p of
      N1Binary  -> "binary"
      N1BinaryZ -> "binary, compressed"
      N1Text    -> "text"
      N1TextZ   -> "text, compressed"
    totalBytes = sum (map (BS.length . n1RecData) (n1Records p))

romTypeName :: NINJA1RomType -> String
romTypeName RomRAW            = "RAW"
romTypeName RomNES            = "NES"
romTypeName RomSNES           = "SNES"
romTypeName RomN64            = "N64"
romTypeName RomGB             = "GB"
romTypeName RomGBC            = "GBC"
romTypeName RomGBA            = "GBA"
romTypeName RomNGP            = "NGP"
romTypeName RomNGPC           = "NGPC"
romTypeName RomSMS            = "SMS"
romTypeName RomGameGear       = "Game Gear"
romTypeName RomGenesis        = "Genesis"
romTypeName RomPCEngine       = "PC Engine"
romTypeName RomWonderSwan     = "WonderSwan"
romTypeName RomWonderSwanColor = "WonderSwan Color"
romTypeName RomLynx           = "Lynx"
romTypeName RomJaguar         = "Jaguar"
romTypeName RomGP32           = "GP32"
romTypeName (RomUnknown n)    = "unknown (" ++ show n ++ ")"

----------------------------------------------------------------------------
-- Encode
----------------------------------------------------------------------------

-- | Encode pre-diffed records as a NINJA1 Binary patch.
-- When compress is True, zlib-compresses the payload and emits BZ subformat.
encodeNINJA1 :: [(Int, BS.ByteString)]
             -> Word32          -- source CRC32
             -> BS.ByteString   -- source MD5 (16 bytes)
             -> BS.ByteString   -- source SHA1 (20 bytes)
             -> NINJA1RomType   -- ROM platform type
             -> Bool            -- compress (BZ subformat)
             -> BS.ByteString
encodeNINJA1 recs srcCRC srcMD5 srcSHA1 romType doCompress
  | doCompress = "NINJA1BZ" <> zlibDeflate payload
  | otherwise  = "NINJA1B " <> payload
  where
    payload = BL.toStrict $ toLazyByteString $
        word8 (fromNINJA1RomType romType)
        <> putWord32BE srcCRC
        <> byteString srcMD5
        <> byteString srcSHA1
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

----------------------------------------------------------------------------
-- Large-file hash sampling
--
-- Per the PHP reference (ninja-1.01php), files >0x1e00000 bytes use a
-- sample instead of the full file: first 20 MiB + last 10 MiB + decimal
-- file size string.  CRC32/MD5/SHA1 are computed on this sample.
----------------------------------------------------------------------------

-- | Prepare hash input for NINJA1 source verification.
-- Files >0x1e00000 (30 MiB) use the sampling algorithm from the PHP
-- reference: first 0x1400000 bytes, last 0xa00000 bytes, decimal size.
ninja1HashInput :: BS.ByteString -> BS.ByteString
ninja1HashInput bs
  | BS.length bs > 0x1e00000 =
      let first    = BS.take 0x1400000 bs
          lastPart = BS.drop (BS.length bs - 0xa00000) bs
          sizeStr  = BS8.pack (show (BS.length bs))
      in first <> lastPart <> sizeStr
  | otherwise = bs
