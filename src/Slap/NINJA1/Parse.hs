{-# LANGUAGE OverloadedStrings #-}

module Slap.NINJA1.Parse
  ( parseNINJA1
  , zlibDecompress
  , parseBinary
  , parseBinaryGet
  , decodeBigEndian
  , parseBinaryRecords
  , parseText
  , parseTextHeader
  , parseTextRecord
  , hexToBS
  , romTypeFromName
  ) where

-- Canonical reference: docs/ninja1/upstream/ninja-1.01php.tar.gz (Derrick Sobodash, 2004, GPLv2)
-- Format spec: docs/ninja1/upstream/ninja1-filespec10.txt
-- Both archived from http://ninja.cinnamonpirate.com/

import Slap.NINJA1.Types (NINJA1Patch(..), NINJA1Record(..), NINJA1TextHeader(..),
                           NINJA1SubFormat(..), NINJA1RomType(..),
                           toNINJA1RomType, toNINJA1SubFormat,
                           ninja1MagicBytes,
                           ninja1BinaryEOFMarkerBytes, ninja1BinaryEOFMarkerWidth)
import Slap.Status (SlapError(..), DecompressionFailure(..), Parsed(..),
                    NINJA1Malformation(..),
                    LineText(..), OffsetTokenText(..))
import Slap.FileContents (PatchFileContents(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.ByteParser (ByteParser, runByteParser, getByte, getBytes, remaining)
import Slap.Measure (Length(..), Offset(Offset), offsetFromParsed,
                     RequiredLength(..), ActualLength(..), ActualMagic(..),
                     byteLength)
import Slap.Compression.Stream (zlibInflate)
import Slap.Checksum (CRC32(..), MD5Hash(..), SHA1Hash(..))

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Char8 as ByteString8
import Data.Char (toLower)
import Data.Int (Int64)
import qualified Data.Text as Text
import Data.Word (Word8, Word32)
import Numeric (readHex)

parseNINJA1 :: PatchFileContents -> Either SlapError (Parsed NINJA1Patch)
parseNINJA1 (PatchFileContents input)
  | ByteString.length input < 8                 = Left (InputTooShort LabelNINJA1 (RequiredLength (Length 8)) (ActualLength (byteLength input)))
  | ByteString.take 6 input /= ninja1MagicBytes = Left (BadMagic LabelNINJA1 (ActualMagic (ByteString.take 6 input)))
  | otherwise = case toNINJA1SubFormat subFormatIdentifier of
      Nothing                       -> Left (UnsupportedNINJA1Subformat subFormatIdentifier)
      Just NINJA1Binary             -> wrapParsed (parseBinary NINJA1Binary           (PatchFileContents payload))
      Just NINJA1BinaryCompressed   -> wrapParsed (zlibDecompress payload >>= (parseBinary NINJA1BinaryCompressed . PatchFileContents))
      Just NINJA1Text               -> wrapParsed (parseText   NINJA1Text             (PatchFileContents payload))
      Just NINJA1TextCompressed     -> wrapParsed (zlibDecompress payload >>= (parseText   NINJA1TextCompressed   . PatchFileContents))
  where
    subFormatIdentifier = ByteString.take 2 (ByteString.drop 6 input)
    payload             = ByteString.drop 8 input
    wrapParsed          = fmap (\patch -> Parsed patch [])

-- | Zlib decompression (PHP gzcompress = RFC 1950 zlib format).
zlibDecompress :: ByteString -> Either SlapError ByteString
zlibDecompress compressed = case zlibInflate compressed of
  Left cause   -> Left (DecompressionFailed (NINJA1Failed cause))
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

parseBinary :: NINJA1SubFormat -> PatchFileContents -> Either SlapError NINJA1Patch
parseBinary format (PatchFileContents payload)
  | ByteString.length payload < 41 = Left (InputTooShort LabelNINJA1 (RequiredLength (Length 41)) (ActualLength (byteLength payload)))
  | otherwise = case runByteParser (parseBinaryGet format) payload of
      Left parserError                 -> Left (ParseError LabelNINJA1 parserError)
      Right (EndedWithoutEOFFooter, _)  -> Left NINJA1BinaryMissingEOFFooter
      Right (ReachedEOFFooter, patch)   -> Right patch

parseBinaryGet :: NINJA1SubFormat -> ByteParser (NINJA1BinaryTermination, NINJA1Patch)
parseBinaryGet format = do
  romType   <- toNINJA1RomType <$> getByte
  crcBytes  <- getBytes (Length 4)
  md5Bytes  <- getBytes (Length 16)
  sha1Bytes <- getBytes (Length 20)
  (termination, records) <- parseBinaryRecords
  let parsedCRC  = if ByteString.all (== 0) crcBytes then Nothing else Just (CRC32 (decodeBigEndian crcBytes))
      parsedMD5  = if ByteString.all (== 0) md5Bytes then Nothing else Just (MD5Hash md5Bytes)
      parsedSHA1 = if ByteString.all (== 0) sha1Bytes then Nothing else Just (SHA1Hash sha1Bytes)
  pure (termination, NINJA1Patch
    { ninja1SubFormat  = format
    , ninja1RomType    = romType
    , ninja1SourceCRC  = parsedCRC
    , ninja1SourceMD5  = parsedMD5
    , ninja1SourceSHA1 = parsedSHA1
    , ninja1Records    = records
    })

-- | Decode an unsigned big-endian byte sequence as any 'Num'
-- result type. NINJA1's binary record format encodes offsets and
-- lengths as variable-width unsigned big-endian fields, and slap
-- consumes them at several widths — 'Word32' for the 4-byte
-- header CRC, 'Int' for record offsets and data lengths whose
-- width is given by a preceding byte. The polymorphic result
-- type lets each call site pick the width it needs without a
-- per-width helper.
decodeBigEndian :: Num a => ByteString -> a
decodeBigEndian = ByteString.foldl' (\accumulated byte -> accumulated * 256 + fromIntegral byte) 0

-- | What the binary record walk reads at the cursor on each
-- iteration. Unlike its peers ('Slap.IPS.Parse''s marker peek,
-- 'Slap.VCDIFF.Parse''s remnant peek), this classification consumes:
-- the offset-width byte and the offset bytes must be read before the
-- verdict is knowable, so each constructor carries the evidence the
-- read left behind, and the loop continues from where the read
-- stopped.
data NINJA1BinaryStreamHead
  = EndsWithoutMarker
    -- ^ The input is spent, or a zero offset-width byte ended the
    -- stream early — either way the walk is over with no EOF marker
    -- seen.
  | EOFMarkerFound
    -- ^ The offset field's width and bytes are the EOF marker's: a
    -- cleanly terminated stream.
  | RecordAt !Offset
    -- ^ A record begins here, its offset already decoded; the data
    -- width, length, and payload remain to be read.

data NINJA1BinaryTermination = ReachedEOFFooter | EndedWithoutEOFFooter

parseBinaryRecords :: ByteParser (NINJA1BinaryTermination, [NINJA1Record])
parseBinaryRecords = parseLoop []
  where
    parseLoop accumulated = do
      streamHead <- readBinaryStreamHead
      case streamHead of
        EndsWithoutMarker -> pure (EndedWithoutEOFFooter, reverse accumulated)
        EOFMarkerFound    -> pure (ReachedEOFFooter, reverse accumulated)
        RecordAt recordOffset -> do
          dataWidth    <- fromIntegral <$> getByte :: ByteParser Int
          dataLenBytes <- getBytes (Length dataWidth)
          let dataLength = decodeBigEndian dataLenBytes :: Int
          payload <- getBytes (Length dataLength)
          parseLoop (NINJA1Record recordOffset payload : accumulated)

    -- | Read as far into the next offset field as the verdict
    -- requires, and classify. The reads are sequenced — the offset
    -- bytes cannot be read before the width byte says how many —
    -- which is why this reads rather than peeks.
    readBinaryStreamHead :: ByteParser NINJA1BinaryStreamHead
    readBinaryStreamHead = do
      remainingLength <- remaining
      if unLength remainingLength < 1
        then pure EndsWithoutMarker
        else do
          offsetWidth <- fromIntegral <$> getByte :: ByteParser Int
          if offsetWidth == 0
            then pure EndsWithoutMarker
            else do
              offsetBytes <- getBytes (Length offsetWidth)
              pure $ if offsetWidth == ninja1BinaryEOFMarkerWidth
                          && offsetBytes == ninja1BinaryEOFMarkerBytes
                       then EOFMarkerFound
                       else RecordAt (Offset (decodeBigEndian offsetBytes))

----------------------------------------------------------------------------
-- Textual format: line-based, # comments, header + hex records
--
-- Header line: FORMAT CRC32 MD5 SHA1
--   FORMAT = rom type name (raw, snes, gba, etc.)
--   CRC32/MD5/SHA1 = hex string or "unk"/"unk." to skip
-- Record lines: OFFSET HEXDATA (both hex strings, no 0x prefix)
----------------------------------------------------------------------------

parseText :: NINJA1SubFormat -> PatchFileContents -> Either SlapError NINJA1Patch
parseText format (PatchFileContents payload) = do
  let stripCR = ByteString8.takeWhile (/= '\r')
      contentLines = filter (not . isSkippable) (map stripCR (ByteString8.lines payload))
  case contentLines of
    [] -> Left (MalformedNINJA1Content NINJA1EmptyTextualPatch)
    (headerLine : recordLines) -> do
      header  <- parseTextHeader headerLine
      records <- mapM parseTextRecord recordLines
      Right NINJA1Patch
        { ninja1SubFormat  = format
        , ninja1RomType    = ninja1TextRomType header
        , ninja1SourceCRC  = ninja1TextSourceCRC header
        , ninja1SourceMD5  = ninja1TextSourceMD5 header
        , ninja1SourceSHA1 = ninja1TextSourceSHA1 header
        , ninja1Records    = records
        }
  where
    isSkippable line = ByteString.null line || ByteString8.head line == '#'

-- | Decode the single textual NINJA1 header line. The ROM type
-- token is the only mandatory field; absent or unrecognized ROM
-- type names are refused with 'NINJA1UnknownTextualRomType' (or
-- 'NINJA1MalformedTextRecord' when the line has no tokens at
-- all). CRC32, MD5, and SHA1 fields are optional and tolerate the
-- spec-defined @"unk"@/@"unk."@ placeholders.
parseTextHeader :: ByteString -> Either SlapError NINJA1TextHeader
parseTextHeader line = do
  romType <- case tokens of
    (formatName:_) -> case romTypeFromName formatName of
      Just typed -> Right typed
      Nothing    -> Left (MalformedNINJA1Content (NINJA1UnknownTextualRomType (Text.pack formatName)))
    _              -> Left (MalformedNINJA1Content (NINJA1MalformedTextRecord (LineText (Text.pack (ByteString8.unpack line)))))
  Right NINJA1TextHeader
    { ninja1TextRomType    = romType
    , ninja1TextSourceCRC  = parsedCRC
    , ninja1TextSourceMD5  = parsedMD5
    , ninja1TextSourceSHA1 = parsedSHA1
    }
  where
    tokens = map ByteString8.unpack (ByteString8.words line)
    isUnknown text = text == "unk" || text == "unk."
    parsedCRC = case tokens of
      (_:crcText:_) | not (isUnknown crcText) -> case (readHex crcText :: [(Word32, String)]) of
        [(value, "")] -> Just (CRC32 value)
        _             -> Nothing
      _ -> Nothing
    nonEmpty bytes = if ByteString.null bytes then Nothing else Just bytes
    parsedMD5 = case tokens of
      (_:_:md5Text:_) | not (isUnknown md5Text) -> MD5Hash <$> nonEmpty (hexToBS md5Text)
      _ -> Nothing
    parsedSHA1 = case tokens of
      (_:_:_:sha1Text:_) | not (isUnknown sha1Text) -> SHA1Hash <$> nonEmpty (hexToBS sha1Text)
      _ -> Nothing

parseTextRecord :: ByteString -> Either SlapError NINJA1Record
parseTextRecord line = case ByteString8.words line of
  (offsetString : dataParts@(_:_)) ->
    case (readHex (ByteString8.unpack offsetString) :: [(Int64, String)]) of
      [(offset, "")] -> Right (NINJA1Record (offsetFromParsed offset) (hexToBS (concatMap ByteString8.unpack dataParts)))
      _ -> Left (MalformedNINJA1Content (NINJA1InvalidOffsetInTextRecord (OffsetTokenText (Text.pack (ByteString8.unpack offsetString)))))
  _ -> Left (MalformedNINJA1Content (NINJA1MalformedTextRecord (LineText (Text.pack (ByteString8.unpack line)))))

hexToBS :: String -> ByteString
hexToBS text = ByteString.pack (parseHexPairs text)
  where
    parseHexPairs [] = []
    parseHexPairs [_] = []
    parseHexPairs (highNibble:lowNibble:rest) = case (readHex [highNibble,lowNibble] :: [(Word8, String)]) of
      [(value, "")] -> value : parseHexPairs rest
      _             -> []

-- | Decode the textual NINJA1 ROM type identifier (the first token
-- of the header line). 'Nothing' means the name doesn't match any
-- spec-defined identifier; the caller turns that into
-- 'NINJA1UnknownTextualRomType'. Comparison is case-insensitive
-- via lowercasing the input, matching the PHP reference's
-- @strtolower@ behavior at the corresponding site.
romTypeFromName :: String -> Maybe NINJA1RomType
romTypeFromName text = case map toLower text of
  "raw"  -> Just RomRAW;     "nes"  -> Just RomNES;     "snes" -> Just RomSNES;     "n64"  -> Just RomN64
  "gb"   -> Just RomGB;      "gbc"  -> Just RomGBC;     "gba"  -> Just RomGBA;      "ngp"  -> Just RomNGP
  "ngpc" -> Just RomNGPC;    "sms"  -> Just RomSMS;     "gg"   -> Just RomGameGear; "mega" -> Just RomGenesis
  "pce"  -> Just RomPCEngine; "ws"  -> Just RomWonderSwan; "wsc" -> Just RomWonderSwanColor
  "lynx" -> Just RomLynx;    "jag"  -> Just RomJaguar;  "gp32" -> Just RomGP32
  _      -> Nothing
