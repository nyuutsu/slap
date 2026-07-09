{-# LANGUAGE OverloadedStrings #-}

module Slap.NINJA1.Parse
  ( parseNINJA1
  , zlibDecompress
  , parseBinary
  , parseBinaryGet
  , decodeBigEndian
  , decodeAddressableBigEndian
  , parseBinaryRecords
  , rejectUnaddressableRecordEnds
  , parseText
  , parseTextHeader
  , parseTextRecord
  , hexToBytes
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
                    NINJA1Malformation(..), ByteParserError(..),
                    LineText(..), OffsetTokenText(..), ChecksumTokenText(..))
import Slap.FieldName (FieldName(..))
import Slap.FileContents (PatchFileContents(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.ByteParser (ByteParser, runFormatParser, throwByteParserError,
                        getByte, getBytes, remaining)
import Slap.Measure (Length(..), Offset(Offset), offsetFromParsed,
                     RequiredLength(..), ActualLength(..), ActualMagic(..),
                     ActionIndex, firstAction, nextAction,
                     boundedWriteEnd, byteLength)
import Slap.Compression.Stream (zlibInflate)
import Slap.Checksum (CRC32(..), MD5Hash(..), SHA1Hash(..))

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Char8 as ByteString8
import Data.Char (digitToInt, isHexDigit)
import Data.Text (Text)
import qualified Data.Text as Text
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
    wrapParsed parseResult = do
      patch <- parseResult
      rejectUnaddressableRecordEnds (ninja1Records patch)
      pure (Parsed patch [])

-- | Refuse a record whose write end — offset plus payload length — overflows the 'Int' slap carries positions in.
-- The per-field ceilings bound each offset and length alone;
-- this catches the sum that overflows though both addends fit, once at parse so no downstream fold has to.
rejectUnaddressableRecordEnds :: [NINJA1Record] -> Either SlapError ()
rejectUnaddressableRecordEnds = walkRecords firstAction
  where
    walkRecords _ [] = Right ()
    walkRecords recordIndex (record : rest) =
      case boundedWriteEnd (ninja1RecordOffset record) (byteLength (ninja1RecordData record)) of
        Just _writeEnd -> walkRecords (nextAction recordIndex) rest
        Nothing        -> Left (RecordEndExceedsAddressableRange LabelNINJA1 recordIndex
                                  (ninja1RecordOffset record)
                                  (byteLength (ninja1RecordData record)))

-- | PHP gzcompress = RFC 1950 zlib format.
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
  | otherwise = do
      (termination, patch) <- runFormatParser LabelNINJA1 (parseBinaryGet format) payload
      case termination of
        EndedWithoutEOFFooter -> Left NINJA1BinaryMissingEOFFooter
        ReachedEOFFooter      -> Right patch

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

-- | Decode an unsigned big-endian byte sequence at whatever 'Num' the call site needs —
-- 'Word32' for the header CRC, 'Integer' inside 'decodeAddressableBigEndian' where the ceiling check lives.
decodeBigEndian :: Num a => ByteString -> a
decodeBigEndian = ByteString.foldl' (\accumulated byte -> accumulated * 256 + fromIntegral byte) 0

-- | Decode an unsigned big-endian record field into 'Int', refusing a value past 'maxBound' rather than wrapping.
-- The width prefix is unbounded, so the wire can spell a value no 'Int' holds; decoding at 'Integer' keeps the comparison exact.
decodeAddressableBigEndian :: ActionIndex -> FieldName -> ByteString -> ByteParser Int
decodeAddressableBigEndian recordIndex field fieldBytes
  | decoded > toInteger (maxBound :: Int) =
      throwByteParserError (ByteParserFieldExceedsAddressableRange recordIndex field)
  | otherwise = pure (fromInteger decoded)
  where
    decoded = decodeBigEndian fieldBytes :: Integer

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
parseBinaryRecords = parseLoop firstAction []
  where
    parseLoop recordIndex accumulated = do
      streamHead <- readBinaryStreamHead recordIndex
      case streamHead of
        EndsWithoutMarker -> pure (EndedWithoutEOFFooter, reverse accumulated)
        EOFMarkerFound    -> pure (ReachedEOFFooter, reverse accumulated)
        RecordAt recordOffset -> do
          dataWidth    <- fromIntegral <$> getByte :: ByteParser Int
          dataLenBytes <- getBytes (Length dataWidth)
          dataLength   <- decodeAddressableBigEndian recordIndex FieldRecordLength dataLenBytes
          payload <- getBytes (Length dataLength)
          parseLoop (nextAction recordIndex) (NINJA1Record recordOffset payload : accumulated)

    -- | Read as far into the next offset field as the verdict
    -- requires, and classify. The reads are sequenced — the offset
    -- bytes cannot be read before the width byte says how many —
    -- which is why this reads rather than peeks.
    readBinaryStreamHead :: ActionIndex -> ByteParser NINJA1BinaryStreamHead
    readBinaryStreamHead recordIndex = do
      remainingLength <- remaining
      if unLength remainingLength < 1
        then pure EndsWithoutMarker
        else do
          offsetWidth <- fromIntegral <$> getByte :: ByteParser Int
          if offsetWidth == 0
            then pure EndsWithoutMarker
            else do
              offsetBytes <- getBytes (Length offsetWidth)
              if offsetWidth == ninja1BinaryEOFMarkerWidth
                   && offsetBytes == ninja1BinaryEOFMarkerBytes
                then pure EOFMarkerFound
                else RecordAt . Offset
                       <$> decodeAddressableBigEndian recordIndex FieldRecordOutputOffset offsetBytes

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

-- | Decode the textual NINJA1 header line: a ROM-type name, then up to three checksum slots.
-- The ROM-type token is mandatory — an unrecognized name is kept ('romTypeFromName'), an empty line refused.
-- Each checksum slot is read by 'parseChecksumSlot'.
parseTextHeader :: ByteString -> Either SlapError NINJA1TextHeader
parseTextHeader line = case ByteString8.words line of
  [] -> Left (MalformedNINJA1Content (NINJA1MalformedTextRecord (LineText (asText line))))
  (formatNameToken : checksumTokens) -> do
    sourceCRC  <- parseChecksumSlot FieldSourceCRC  decodeCRCToken  (checksumTokens `atIndex` 0)
    sourceMD5  <- parseChecksumSlot FieldSourceMD5  decodeMD5Token  (checksumTokens `atIndex` 1)
    sourceSHA1 <- parseChecksumSlot FieldSourceSHA1 decodeSHA1Token (checksumTokens `atIndex` 2)
    Right NINJA1TextHeader
      { ninja1TextRomType    = romTypeFromName (asText formatNameToken)
      , ninja1TextSourceCRC  = sourceCRC
      , ninja1TextSourceMD5  = sourceMD5
      , ninja1TextSourceSHA1 = sourceSHA1
      }
  where
    asText = Text.pack . ByteString8.unpack
    atIndex tokens position = case drop position tokens of
      (token : _) -> Just token
      []          -> Nothing

-- | Classify one textual checksum slot: an absent token or @"unk"@\/@"unk."@ declares no checksum,
-- a token the decoder accepts is that checksum, and one it rejects is a malformed patch named by its slot.
-- The 'Nothing' returned means "no checksum here", never "unreadable" — a malformed token is a 'Left'.
parseChecksumSlot
  :: FieldName
  -> (ByteString -> Maybe a)
  -> Maybe ByteString
  -> Either SlapError (Maybe a)
parseChecksumSlot _     _      Nothing      = Right Nothing
parseChecksumSlot field decode (Just token)
  | token == "unk" || token == "unk." = Right Nothing
  | otherwise = case decode token of
      Just value -> Right (Just value)
      Nothing    -> Left (MalformedNINJA1Content
                            (NINJA1MalformedChecksum field
                               (ChecksumTokenText (Text.pack (ByteString8.unpack token)))))

-- | A CRC-32 token: hex naming a value that fits 32 bits, any case — an unpadded @beef@ and a padded @0000beef@ are the same number.
-- Read at 'Integer', so more than 32 bits, or trailing non-hex, is refused rather than wrapped.
decodeCRCToken :: ByteString -> Maybe CRC32
decodeCRCToken token = case readHex (ByteString8.unpack token) :: [(Integer, String)] of
  [(value, "")] | value <= 0xFFFFFFFF -> Just (CRC32 (fromInteger value))
  _                                   -> Nothing

-- | An MD5 token: exactly 32 hex digits — a 128-bit digest — any case.
decodeMD5Token :: ByteString -> Maybe MD5Hash
decodeMD5Token = fmap MD5Hash . decodeFixedWidthDigest 16

-- | A SHA1 token: exactly 40 hex digits — a 160-bit digest — any case.
decodeSHA1Token :: ByteString -> Maybe SHA1Hash
decodeSHA1Token = fmap SHA1Hash . decodeFixedWidthDigest 20

-- | Decode a hex token of exactly @byteWidth@ bytes: all hex digits, and exactly @2 * byteWidth@ of them.
-- A digest's width is part of what it is, so a short, long, or non-hex token is no digest of that width.
decodeFixedWidthDigest :: Int -> ByteString -> Maybe ByteString
decodeFixedWidthDigest byteWidth token
  | ByteString.length token == 2 * byteWidth
  , ByteString8.all isHexDigit token = Just (hexToBytes token)
  | otherwise                        = Nothing

-- | Decode one textual record line: a hex offset, then the payload as hex.
-- The offset is read at 'Integer', since textual offsets have no width limit.
-- A value past 'maxBound' :: 'Int' is refused ('NINJA1UnaddressableOffsetInTextRecord'), not wrapped.
parseTextRecord :: ByteString -> Either SlapError NINJA1Record
parseTextRecord line = case ByteString8.words line of
  (offsetToken : dataParts@(_:_)) ->
    case (readHex (ByteString8.unpack offsetToken) :: [(Integer, String)]) of
      [(offset, "")]
        | offset > toInteger (maxBound :: Int) ->
            Left (MalformedNINJA1Content (NINJA1UnaddressableOffsetInTextRecord (offsetTokenOf offsetToken)))
        | otherwise ->
            Right (NINJA1Record (offsetFromParsed offset) (hexToBytes (ByteString.concat dataParts)))
      _ -> Left (MalformedNINJA1Content (NINJA1InvalidOffsetInTextRecord (offsetTokenOf offsetToken)))
  _ -> Left (MalformedNINJA1Content (NINJA1MalformedTextRecord (LineText (Text.pack (ByteString8.unpack line)))))
  where
    offsetTokenOf = OffsetTokenText . Text.pack . ByteString8.unpack

-- | Decode a run of ASCII hex pairs into their bytes.
-- A lone trailing nibble, or any non-hex character, ends the decode at the last whole pair before it.
hexToBytes :: ByteString -> ByteString
hexToBytes = ByteString.pack . pairsOf . ByteString8.unpack
  where
    pairsOf (highDigit : lowDigit : rest)
      | isHexDigit highDigit && isHexDigit lowDigit =
          fromIntegral (digitToInt highDigit * 16 + digitToInt lowDigit) : pairsOf rest
    pairsOf _ = []

-- | Decode the textual NINJA1 ROM type name (the header line's first token).
-- An unrecognized name is kept as 'RomUnknownName', mirroring the binary path's 'RomUnknown' byte.
-- Matching is case-insensitive, like the PHP reference's @strtolower@.
romTypeFromName :: Text -> NINJA1RomType
romTypeFromName name = case Text.toLower name of
  "raw"  -> RomRAW;      "nes"  -> RomNES;      "snes" -> RomSNES;        "n64"  -> RomN64
  "gb"   -> RomGB;       "gbc"  -> RomGBC;      "gba"  -> RomGBA;         "ngp"  -> RomNGP
  "ngpc" -> RomNGPC;     "sms"  -> RomSMS;      "gg"   -> RomGameGear;    "mega" -> RomGenesis
  "pce"  -> RomPCEngine; "ws"   -> RomWonderSwan; "wsc" -> RomWonderSwanColor
  "lynx" -> RomLynx;     "jag"  -> RomJaguar;   "gp32" -> RomGP32
  _      -> RomUnknownName name
