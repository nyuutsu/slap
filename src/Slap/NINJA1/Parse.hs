{-# LANGUAGE OverloadedStrings #-}

module Slap.NINJA1.Parse
  ( parseNINJA1
  , zlibDecompress
  , parseBinary
  , parseBinaryGet
  , decodeBigEndian32
  , decodeBigEndian
  , parseBinaryRecords
  , parseText
  , parseTextHeader
  , parseTextRecord
  , hexToBS
  , romTypeFromName
  ) where

-- Canonical reference: docs/specs/ninja-1.01php.tar.gz (Derrick Sobodash, 2004, GPLv2)
-- Format spec: docs/specs/ninja1-filespec10.txt
-- Both archived from http://ninja.cinnamonpirate.com/

import Slap.NINJA1.Types (NINJA1Patch(..), NINJA1Record(..), NINJA1SubFormat(..),
                           NINJA1RomType(..), toNINJA1RomType)
import Slap.Error (SlapError(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.Get (Get, runGet, getByte, getBytes, remaining)
import Slap.Measure (Length(..), Offset(..))
import Slap.Compress (zlibInflate)

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Char8 as ByteString8
import Data.Char (toLower)
import Data.Int (Int64)
import Data.Word (Word8, Word32)
import Numeric (readHex)
import Slap.Checksum (CRC32(..))

parseNINJA1 :: ByteString -> Either SlapError NINJA1Patch
parseNINJA1 input
  | ByteString.length input < 8             = Left (InputTooShort LabelNINJA1 (Length 8) (Length (ByteString.length input)))
  | ByteString.take 6 input /= "NINJA1"    = Left (BadMagic LabelNINJA1 (ByteString.take 6 input))
  | subFormatIdentifier == "B "                = parseBinary Ninja1Binary payload
  | subFormatIdentifier == "BZ"                = zlibDecompress payload >>= parseBinary Ninja1BinaryCompressed
  -- Spec says 0x540d but PHP source uses chr(0x0a); spec hex is wrong.
  | subFormatIdentifier == ByteString.pack [0x54,0x0A] = parseText Ninja1Text payload    -- "T\n"
  | subFormatIdentifier == "TZ"                = zlibDecompress payload >>= parseText Ninja1TextCompressed
  | otherwise                    = Left (UnsupportedSubformat LabelNINJA1 (show subFormatIdentifier))
  where
    subFormatIdentifier   = ByteString.take 2 (ByteString.drop 6 input)
    payload = ByteString.drop 8 input

-- | Zlib decompression (PHP gzcompress = RFC 1950 zlib format).
zlibDecompress :: ByteString -> Either SlapError ByteString
zlibDecompress compressed = case zlibInflate compressed of
  Left _  -> Left (DecompressionFailed LabelNINJA1 "zlib")
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

parseBinary :: NINJA1SubFormat -> ByteString -> Either SlapError NINJA1Patch
parseBinary format payload
  | ByteString.length payload < 41 = Left (InputTooShort LabelNINJA1 (Length 41) (Length (ByteString.length payload)))
  | otherwise = case runGet (parseBinaryGet format) payload of
      Left errorMessage -> Left (ParseError LabelNINJA1 errorMessage)
      Right patch -> Right patch

parseBinaryGet :: NINJA1SubFormat -> Get NINJA1Patch
parseBinaryGet format = do
  romType   <- toNINJA1RomType <$> getByte
  crcBytes  <- getBytes (Length 4)
  md5Bytes  <- getBytes (Length 16)
  sha1Bytes <- getBytes (Length 20)
  (records, clean) <- parseBinaryRecords
  let parsedCRC  = if ByteString.all (== 0) crcBytes then Nothing else Just (CRC32 (decodeBigEndian32 crcBytes))
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
      remainingLength <- remaining
      if unLength remainingLength < 1 then pure (reverse accumulated, False)
      else do
        offsetWidth <- fromIntegral <$> getByte :: Get Int
        if offsetWidth == 0 then pure (reverse accumulated, False)
        else do
          offsetBytes <- getBytes (Length offsetWidth)
          if offsetWidth == 3 && offsetBytes == "EOF"
            then pure (reverse accumulated, True)
            else do
              let recordOffset = Offset (decodeBigEndian offsetBytes)
              dataWidth <- fromIntegral <$> getByte :: Get Int
              dataLenBytes <- getBytes (Length dataWidth)
              let dataLength = fromIntegral (decodeBigEndian dataLenBytes) :: Int
              payload <- getBytes (Length dataLength)
              parseLoop (NINJA1Record recordOffset payload : accumulated)

----------------------------------------------------------------------------
-- Textual format: line-based, # comments, header + hex records
--
-- Header line: FORMAT CRC32 MD5 SHA1
--   FORMAT = rom type name (raw, snes, gba, etc.)
--   CRC32/MD5/SHA1 = hex string or "unk"/"unk." to skip
-- Record lines: OFFSET HEXDATA (both hex strings, no 0x prefix)
----------------------------------------------------------------------------

parseText :: NINJA1SubFormat -> ByteString -> Either SlapError NINJA1Patch
parseText format payload = do
  let stripCR = ByteString8.takeWhile (/= '\r')
      contentLines = filter (not . isSkippable) (map stripCR (ByteString8.lines payload))
  case contentLines of
    [] -> Left (MalformedTextField LabelNINJA1 "empty textual patch")
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

parseTextHeader :: ByteString -> (NINJA1RomType, Maybe CRC32, Maybe ByteString, Maybe ByteString)
parseTextHeader line = (romType, parsedCRC, parsedMD5, parsedSHA1)
  where
    tokens = map ByteString8.unpack (ByteString8.words line)
    romType = case tokens of
      (formatName:_) -> romTypeFromName formatName
      _              -> RomRAW
    isUnknown text = text == "unk" || text == "unk."
    parsedCRC = case tokens of
      (_:crcText:_) | not (isUnknown crcText) -> case (readHex crcText :: [(Word32, String)]) of
        [(value, "")] -> Just (CRC32 value)
        _             -> Nothing
      _ -> Nothing
    nonEmpty bytes = if ByteString.null bytes then Nothing else Just bytes
    parsedMD5 = case tokens of
      (_:_:md5Text:_) | not (isUnknown md5Text) -> nonEmpty (hexToBS md5Text)
      _ -> Nothing
    parsedSHA1 = case tokens of
      (_:_:_:sha1Text:_) | not (isUnknown sha1Text) -> nonEmpty (hexToBS sha1Text)
      _ -> Nothing

parseTextRecord :: ByteString -> Either SlapError NINJA1Record
parseTextRecord line = case ByteString8.words line of
  (offsetString : dataParts@(_:_)) ->
    case (readHex (ByteString8.unpack offsetString) :: [(Int64, String)]) of
      [(offset, "")] -> Right (NINJA1Record (Offset offset) (hexToBS (concatMap ByteString8.unpack dataParts)))
      _ -> Left (MalformedTextField LabelNINJA1 ("invalid offset in text record: " ++ ByteString8.unpack offsetString))
  _ -> Left (MalformedTextField LabelNINJA1 ("malformed text record: " ++ ByteString8.unpack line))

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
