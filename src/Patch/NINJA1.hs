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
import Patch.Binary (putWord32BE, copyByteStringRange)
import Patch.Format (showCRC, padHex, renderField)

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Char8 as ByteString8
import Data.ByteString.Internal (unsafeCreate)
import qualified Data.ByteString.Lazy as LazyByteString
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

data NINJA1SubFormat = Ninja1Binary | Ninja1BinaryCompressed | Ninja1Text | Ninja1TextCompressed
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
toNINJA1RomType  value = RomUnknown value

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
fromNINJA1RomType (RomUnknown value) = value

data NINJA1Patch = NINJA1Patch
  { ninja1SubFormat  :: NINJA1SubFormat
  , ninja1RomType    :: NINJA1RomType
  , ninja1SourceCRC  :: Maybe Word32
  , ninja1SourceMD5  :: Maybe ByteString  -- 16 bytes
  , ninja1SourceSHA1 :: Maybe ByteString  -- 20 bytes
  , ninja1Records    :: [NINJA1Record]
  , ninja1CleanEOF   :: Bool              -- binary: True if EOF sentinel found
  } deriving (Show)

data NINJA1Record = NINJA1Record
  { ninja1RecordOffset :: Int64
  , ninja1RecordData   :: ByteString
  } deriving (Show)

----------------------------------------------------------------------------
-- Parse
----------------------------------------------------------------------------

parseNINJA1 :: ByteString -> Either String NINJA1Patch
parseNINJA1 input
  | ByteString.length input < 8             = Left "NINJA1: input too short"
  | ByteString.take 6 input /= "NINJA1"    = Left "not a NINJA1 file (bad magic)"
  | subFormatIdentifier == "B "                = parseBinary Ninja1Binary payload
  | subFormatIdentifier == "BZ"                = zlibDecompress payload >>= parseBinary Ninja1BinaryCompressed
  -- Spec says 0x540d but PHP source uses chr(0x0a); spec hex is wrong.
  | subFormatIdentifier == ByteString.pack [0x54,0x0A] = parseText Ninja1Text payload    -- "T\n"
  | subFormatIdentifier == "TZ"                = zlibDecompress payload >>= parseText Ninja1TextCompressed
  | otherwise                    = Left ("NINJA1: unsupported subformat: " ++ show subFormatIdentifier)
  where
    subFormatIdentifier   = ByteString.take 2 (ByteString.drop 6 input)
    payload = ByteString.drop 8 input

-- | Zlib decompression (PHP gzcompress = RFC 1950 zlib format).
zlibDecompress :: ByteString -> Either String ByteString
zlibDecompress compressed = case zlibInflate compressed of
  Left _  -> Left "NINJA1: zlib decompression failed"
  Right result -> Right result

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

parseBinary :: NINJA1SubFormat -> ByteString -> Either String NINJA1Patch
parseBinary format payload
  | ByteString.length payload < 41 = Left "NINJA1: binary payload too short"
  | otherwise = runGet (parseBinaryGet format) payload

parseBinaryGet :: NINJA1SubFormat -> Get NINJA1Patch
parseBinaryGet format = do
  romType   <- toNINJA1RomType <$> getByte
  crcBytes  <- getBytes 4
  md5Bytes  <- getBytes 16
  sha1Bytes <- getBytes 20
  (records, clean) <- parseBinaryRecords
  let parsedCRC  = if ByteString.all (== 0) crcBytes then Nothing else Just (decodeBigEndian32 crcBytes)
      parsedMD5  = if ByteString.all (== 0) md5Bytes then Nothing else Just md5Bytes
      parsedSHA1 = if ByteString.all (== 0) sha1Bytes then Nothing else Just sha1Bytes
  pure NINJA1Patch
    { ninja1SubFormat  = format
    , ninja1RomType    = romType
    , ninja1SourceCRC  = parsedCRC
    , ninja1SourceMD5  = parsedMD5
    , ninja1SourceSHA1 = parsedSHA1
    , ninja1Records    = records
    , ninja1CleanEOF   = clean
    }

decodeBigEndian32 :: ByteString -> Word32
decodeBigEndian32 = ByteString.foldl' (\accumulated byte -> accumulated * 256 + fromIntegral byte) 0

decodeBigEndian :: ByteString -> Int64
decodeBigEndian = ByteString.foldl' (\accumulated byte -> accumulated * 256 + fromIntegral byte) 0

parseBinaryRecords :: Get ([NINJA1Record], Bool)
parseBinaryRecords = parseLoop []
  where
    parseLoop accumulated = do
      avail <- remaining
      if avail < 1 then pure (reverse accumulated, False)
      else do
        offsetWidth <- fromIntegral <$> getByte :: Get Int
        if offsetWidth == 0 then pure (reverse accumulated, False)
        else do
          offsetBytes <- getBytes offsetWidth
          if offsetWidth == 3 && offsetBytes == "EOF"
            then pure (reverse accumulated, True)
            else do
              let offset = decodeBigEndian offsetBytes
              dataWidth <- fromIntegral <$> getByte :: Get Int
              dataLenBytes <- getBytes dataWidth
              let dataLength = fromIntegral (decodeBigEndian dataLenBytes) :: Int
              payload <- getBytes dataLength
              parseLoop (NINJA1Record offset payload : accumulated)

----------------------------------------------------------------------------
-- Textual format: line-based, # comments, header + hex records
--
-- Header line: FORMAT CRC32 MD5 SHA1
--   FORMAT = rom type name (raw, snes, gba, etc.)
--   CRC32/MD5/SHA1 = hex string or "unk"/"unk." to skip
-- Record lines: OFFSET HEXDATA (both hex strings, no 0x prefix)
----------------------------------------------------------------------------

parseText :: NINJA1SubFormat -> ByteString -> Either String NINJA1Patch
parseText format payload = do
  let stripCR = ByteString8.takeWhile (/= '\r')
      contentLines = filter (not . isSkippable) (map stripCR (ByteString8.lines payload))
  case contentLines of
    [] -> Left "NINJA1: empty textual patch"
    (headerLine : recordLines) -> do
      let (romType, parsedCRC, parsedMD5, parsedSHA1) = parseTextHeader headerLine
      records <- mapM parseTextRecord recordLines
      Right NINJA1Patch
        { ninja1SubFormat  = format
        , ninja1RomType    = romType
        , ninja1SourceCRC  = parsedCRC
        , ninja1SourceMD5  = parsedMD5
        , ninja1SourceSHA1 = parsedSHA1
        , ninja1Records    = records
        , ninja1CleanEOF   = True  -- textual format has no EOF sentinel
        }
  where
    isSkippable line = ByteString.null line || ByteString8.head line == '#'

parseTextHeader :: ByteString -> (NINJA1RomType, Maybe Word32, Maybe ByteString, Maybe ByteString)
parseTextHeader line = (romType, parsedCRC, parsedMD5, parsedSHA1)
  where
    tokens = map ByteString8.unpack (ByteString8.words line)
    romType = case tokens of
      (formatName:_) -> romTypeFromName formatName
      _              -> RomRAW
    isUnknown text = text == "unk" || text == "unk."
    parsedCRC = case tokens of
      (_:crcText:_) | not (isUnknown crcText) -> case (readHex crcText :: [(Word32, String)]) of
        [(value, "")] -> Just value
        _             -> Nothing
      _ -> Nothing
    nonEmpty bytes = if ByteString.null bytes then Nothing else Just bytes
    parsedMD5 = case tokens of
      (_:_:md5Text:_) | not (isUnknown md5Text) -> nonEmpty (hexToBS md5Text)
      _ -> Nothing
    parsedSHA1 = case tokens of
      (_:_:_:sha1Text:_) | not (isUnknown sha1Text) -> nonEmpty (hexToBS sha1Text)
      _ -> Nothing

parseTextRecord :: ByteString -> Either String NINJA1Record
parseTextRecord line = case ByteString8.words line of
  (offsetString : dataParts@(_:_)) ->
    case (readHex (ByteString8.unpack offsetString) :: [(Int64, String)]) of
      [(offset, "")] -> Right (NINJA1Record offset (hexToBS (concatMap ByteString8.unpack dataParts)))
      _ -> Left ("NINJA1: invalid offset in text record: " ++ ByteString8.unpack offsetString)
  _ -> Left ("NINJA1: malformed text record: " ++ ByteString8.unpack line)

hexToBS :: String -> ByteString
hexToBS text = ByteString.pack (parseHexPairs text)
  where
    parseHexPairs [] = []
    parseHexPairs [_] = []
    parseHexPairs (highNibble:lowNibble:rest) = case (readHex [highNibble,lowNibble] :: [(Word8, String)]) of
      [(value, "")] -> value : parseHexPairs rest
      _             -> []

romTypeFromName :: String -> NINJA1RomType
romTypeFromName text = case map toLower text of
  "raw"  -> RomRAW;   "nes"  -> RomNES;   "snes" -> RomSNES;  "n64"  -> RomN64
  "gb"   -> RomGB;    "gbc"  -> RomGBC;   "gba"  -> RomGBA;   "ngp"  -> RomNGP
  "ngpc" -> RomNGPC;  "sms"  -> RomSMS;   "gg"   -> RomGameGear; "mega" -> RomGenesis
  "pce"  -> RomPCEngine; "ws" -> RomWonderSwan; "wsc" -> RomWonderSwanColor
  "lynx" -> RomLynx;  "jag"  -> RomJaguar; "gp32" -> RomGP32; _ -> RomRAW

----------------------------------------------------------------------------
-- Apply (raw overwrite, like IPS)
----------------------------------------------------------------------------

applyNINJA1 :: NINJA1Patch -> FilePath -> IO Int
applyNINJA1 patch target = withBinaryFile target ReadWriteMode $ \handle -> do
  mapM_ (applyRecord handle) (ninja1Records patch)
  pure (length (ninja1Records patch))

applyRecord :: Handle -> NINJA1Record -> IO ()
applyRecord handle (NINJA1Record offset payload) = do
  hSeek handle AbsoluteSeek (fromIntegral offset)
  ByteString.hPut handle payload

-- | Apply a NINJA1 patch in memory: copy source, then overwrite at offsets.
applyNINJA1Memory :: NINJA1Patch -> ByteString -> ByteString
applyNINJA1Memory patch source = unsafeCreate outputSize $ \outputPointer -> do
    copyByteStringRange outputPointer 0 source 0 (min sourceLength outputSize)
    when (outputSize > sourceLength) $
      fillBytes (outputPointer `plusPtr` sourceLength) (0 :: Word8) (outputSize - sourceLength)
    forM_ (ninja1Records patch) $ \(NINJA1Record offset payload) ->
      copyByteStringRange outputPointer (fromIntegral offset) payload 0 (ByteString.length payload)
  where
    sourceLength = ByteString.length source
    outputSize = foldl' max sourceLength
      [ fromIntegral (ninja1RecordOffset record) + ByteString.length (ninja1RecordData record) | record <- ninja1Records patch ]

----------------------------------------------------------------------------
-- Info
----------------------------------------------------------------------------

ninja1Meta :: NINJA1Patch -> [(String, String)]
ninja1Meta patch = concat
  [ [("ROM type", romTypeName (ninja1RomType patch))]
  , case ninja1SourceCRC patch of
      Nothing  -> []
      Just crc -> [("source CRC", "0x" ++ showCRC crc)]
  , case ninja1SourceMD5 patch of
      Nothing   -> []
      Just hash -> [("source MD5", concatMap (\byte -> padHex 2 (fromIntegral byte)) (ByteString.unpack hash))]
  , case ninja1SourceSHA1 patch of
      Nothing   -> []
      Just hash -> [("source SHA1", concatMap (\byte -> padHex 2 (fromIntegral byte)) (ByteString.unpack hash))]
  ]

ninja1Info :: NINJA1Patch -> String
ninja1Info patch = unlines $ filter (not . null) $
  [ "format:      NINJA1 (" ++ subFormatString ++ ")" ]
  ++ map renderField (ninja1Meta patch)
  ++ [ "records:     " ++ show (length (ninja1Records patch))
     , "total bytes: " ++ show totalBytes
     ]
  where
    subFormatString = case ninja1SubFormat patch of
      Ninja1Binary  -> "binary"
      Ninja1BinaryCompressed -> "binary, compressed"
      Ninja1Text    -> "text"
      Ninja1TextCompressed   -> "text, compressed"
    totalBytes = sum (map (ByteString.length . ninja1RecordData) (ninja1Records patch))

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
romTypeName (RomUnknown value) = "unknown (" ++ show value ++ ")"

----------------------------------------------------------------------------
-- Encode
----------------------------------------------------------------------------

-- | Encode pre-diffed records as a NINJA1 Binary patch.
-- When compress is True, zlib-compresses the payload and emits BZ subformat.
encodeNINJA1 :: [(Int, ByteString.ByteString)]
             -> Word32          -- source CRC32
             -> ByteString.ByteString   -- source MD5 (16 bytes)
             -> ByteString.ByteString   -- source SHA1 (20 bytes)
             -> NINJA1RomType   -- ROM platform type
             -> Bool            -- compress (BZ subformat)
             -> ByteString.ByteString
encodeNINJA1 records sourceCRC sourceMD5 sourceSHA1 romType doCompress
  | doCompress = "NINJA1BZ" <> zlibDeflate payload
  | otherwise  = "NINJA1B " <> payload
  where
    payload = LazyByteString.toStrict $ toLazyByteString $
        word8 (fromNINJA1RomType romType)
        <> putWord32BE sourceCRC
        <> byteString sourceMD5
        <> byteString sourceSHA1
        <> foldMap encodeRecordBuilder records
        <> word8 3 <> byteString "EOF"     -- EOF sentinel

encodeRecordBuilder :: (Int, ByteString.ByteString) -> Builder
encodeRecordBuilder (offset, payload) =
    let offsetEncoded = encodeBigEndian (fromIntegral offset :: Int64)
        lengthEncoded = encodeBigEndian (fromIntegral (ByteString.length payload) :: Int64)
    in word8 (fromIntegral (ByteString.length offsetEncoded))
       <> byteString offsetEncoded
       <> word8 (fromIntegral (ByteString.length lengthEncoded))
       <> byteString lengthEncoded
       <> byteString payload

-- | Encode an Int64 as minimal big-endian bytes (at least 1 byte).
encodeBigEndian :: Int64 -> ByteString.ByteString
encodeBigEndian 0 = ByteString.singleton 0
encodeBigEndian value = ByteString.pack (extractBytes [] value)
  where
    extractBytes accumulated 0 = accumulated
    extractBytes accumulated remainder = extractBytes (fromIntegral (remainder .&. 0xFF) : accumulated) (remainder `shiftR` 8)

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
ninja1HashInput :: ByteString.ByteString -> ByteString.ByteString
ninja1HashInput input
  | ByteString.length input > 0x1e00000 =
      let headSample = ByteString.take 0x1400000 input
          tailSample  = ByteString.drop (ByteString.length input - 0xa00000) input
          sizeString  = ByteString8.pack (show (ByteString.length input))
      in headSample <> tailSample <> sizeString
  | otherwise = input
