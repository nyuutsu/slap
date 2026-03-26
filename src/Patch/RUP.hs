{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StrictData #-}

module Patch.RUP
  ( RUPPatch(..)
  , RUPInfo(..)
  , RUPRecord(..)
  , OverflowMode(..)
  , parseRUP
  , applyRUP
  , applyRUPMemory
  , createRUP
  , rupMeta
  , rupInfo
  ) where

-- Canonical reference: docs/specs/ninja2-filespec20.txt (Derrick Sobodash, 2006)
-- Archived from http://ninja.cinnamonpirate.com/files/filespec20.txt
-- Secondary: RomPatcher.js modules/RomPatcher.format.rup.js
-- Note: NINJA2 ROM type numbering differs from NINJA1 (10 types vs 18);
-- see docs/specs/ninja2-cliusage.txt. slap stores RUP ROM type as raw Word8.

import Patch.Get (Get, runGet, getByte, getBytes, atEnd)
import Patch.Binary (diffHunks, md5, copyByteStringRange)
import Patch.Format (padHex, renderField)

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Char8 as ByteString8
import Data.ByteString.Internal (unsafeCreate)
import qualified Data.ByteString.Lazy as LazyByteString
import Data.ByteString.Builder (Builder, word8, byteString, toLazyByteString)
import Data.Bits (xor, (.&.), shiftR)
import Data.Int (Int64)
import Data.Word (Word8)
import Control.Monad (forM_, when)
import Foreign.Marshal.Utils (fillBytes)
import Foreign.Ptr (plusPtr)
import Foreign.Storable (peekByteOff, pokeByteOff)
import System.IO

----------------------------------------------------------------------------
-- Types
----------------------------------------------------------------------------

-- | Overflow mode: how size changes between source and target are handled.
-- 'A' (0x41) = append extra bytes, 'M' (0x4D) = truncate.
-- Spec does not mention XOR-with-0xFF encoding of overflow data;
-- that is a RomPatcher.js convention which we follow for compatibility.
data OverflowMode = OverflowAppend | OverflowTruncate
  deriving (Show, Eq)

toOverflowMode :: Word8 -> Either String OverflowMode
toOverflowMode 0x41 = Right OverflowAppend
toOverflowMode 0x4D = Right OverflowTruncate
toOverflowMode byte = Left ("RUP: unknown overflow type: 0x" ++ padHex 2 (fromIntegral byte))

fromOverflowMode :: OverflowMode -> Word8
fromOverflowMode OverflowAppend   = 0x41  -- 'A'
fromOverflowMode OverflowTruncate = 0x4D  -- 'M'

data RUPPatch = RUPPatch
  { rupHeader       :: RUPInfo
  , rupRecords      :: [RUPRecord]
  , rupOverflow     :: Maybe ByteString  -- on-disk overflow data (XOR'd with 0xFF)
  , rupOverflowType :: Maybe OverflowMode
  , rupSourceMD5    :: Maybe ByteString  -- 16 bytes
  , rupTargetMD5    :: Maybe ByteString  -- 16 bytes
  , rupSourceSize     :: Int64
  , rupTargetSize     :: Int64
  , rupPatchEncoding     :: Word8             -- PATCH_ENC (text encoding, byte 6)
  , rupRomType      :: Word8             -- ROM type byte from OPEN_NEW_FILE command
  } deriving (Show)

data RUPInfo = RUPInfo
  { rupAuthor      :: Maybe ByteString
  , rupVersion     :: Maybe ByteString
  , rupTitle       :: Maybe ByteString
  , rupGenre       :: Maybe ByteString
  , rupLanguage    :: Maybe ByteString
  , rupDate        :: Maybe ByteString
  , rupWebsite     :: Maybe ByteString
  , rupDescription :: Maybe ByteString
  } deriving (Show)

data RUPRecord = RUPRecord
  { rupRecordOffset :: Int64
  , rupRecordXor    :: ByteString
  } deriving (Show)


----------------------------------------------------------------------------
-- VLV: Variable Length Value (1-byte length prefix, then N LE bytes)
----------------------------------------------------------------------------

packedInt :: Get Int64
packedInt = do
  count <- fromIntegral <$> getByte
  bytes <- getBytes count
  -- Only interpret first 8 bytes (enough for Int64); extra bytes are
  -- consumed from the stream but don't contribute to the value.
  let clampedCount = min count 8
  pure $ foldl' (\accumulated index ->
    accumulated + fromIntegral (ByteString.index bytes index) * (256 ^ index)) 0 [0..clampedCount-1]

packedBS :: Get ByteString
packedBS = do
  dataLength <- fromIntegral <$> packedInt
  getBytes dataLength

----------------------------------------------------------------------------
-- Fixed header (2048 bytes): NINJA2 format
-- Spec says "first sector of the patch (1024 bytes)" but actual total is 2048.
-- PATCH_ENC (1B text encoding at offset 6) is stored in rupPatchEncoding.
----------------------------------------------------------------------------

headerSize :: Int
headerSize = 0x800  -- NINJA2 spec: fixed 2048-byte header

-- | Parse the fixed header region.  Field offsets per ninja2-filespec20.txt §2.
parseFixedHeader :: ByteString -> RUPInfo
parseFixedHeader input = RUPInfo
  { rupAuthor      = extractField 0x007 84
  , rupVersion     = extractField 0x05B 11
  , rupTitle       = extractField 0x066 256
  , rupGenre       = extractField 0x166 48
  , rupLanguage    = extractField 0x196 48
  , rupDate        = extractField 0x1C6 8
  , rupWebsite     = extractField 0x1CE 512
  , rupDescription = extractField 0x3CE 1074
  }
  where
    extractField fieldOffset fieldLength =
      let field = ByteString.take fieldLength (ByteString.drop fieldOffset input)
          trimmed = ByteString.takeWhile (/= 0) field
      in if ByteString.null trimmed then Nothing else Just trimmed

----------------------------------------------------------------------------
-- Command stream (starts at offset 0x800)
--   0x01: OPEN_NEW_FILE
--   0x02: XOR record
--   0x00: END
----------------------------------------------------------------------------

parseRUP :: ByteString -> Either String RUPPatch
parseRUP input
  | ByteString.length input < 7 = Left "RUP: input too short"
  | ByteString.take 6 input /= "NINJA2" = Left "not a RUP file (bad magic)"
  | ByteString.length input < headerSize = Left "RUP: truncated header"
  | otherwise = runGet parseRUPBody input
  where
    parseRUPBody :: Get RUPPatch
    parseRUPBody = do
      headerBytes <- getBytes headerSize
      let meta = parseFixedHeader headerBytes
          encoding = ByteString.index headerBytes 6  -- PATCH_ENC byte
      patch <- parseCommands (emptyPatch meta encoding)
      pure patch { rupRecords = reverse (rupRecords patch) }

    emptyPatch meta encoding = RUPPatch
      { rupHeader = meta, rupRecords = [], rupOverflow = Nothing
      , rupOverflowType = Nothing, rupSourceMD5 = Nothing, rupTargetMD5 = Nothing
      , rupSourceSize = 0, rupTargetSize = 0, rupPatchEncoding = encoding, rupRomType = 0
      }

parseCommands :: RUPPatch -> Get RUPPatch
parseCommands patch = do
  done <- atEnd
  if done then pure patch
  else do
    code <- getByte
    case code of
      0x01 -> parseFileCommand patch >>= parseCommands
      0x02 -> parseXorRecord patch >>= parseCommands
      0x00 -> pure patch  -- END marker
      _    -> fail ("RUP: unknown command code: 0x" ++ padHex 2 (fromIntegral code))

-- | Command 0x01: OPEN_NEW_FILE
parseFileCommand :: RUPPatch -> Get RUPPatch
parseFileCommand patch = do
  _filename <- packedBS
  romTypeByte <- getByte  -- ROM type byte
  sourceSize <- packedInt
  targetSize <- packedInt
  sourceMD5 <- getBytes 16
  targetMD5 <- getBytes 16
  (overflowType, overflowData) <- if sourceSize /= targetSize
    then do
      typeByte <- getByte
      case toOverflowMode typeByte of
        Left errorMessage -> fail errorMessage
        Right mode -> do
          payload <- packedBS
          pure (Just mode, Just payload)
    else pure (Nothing, Nothing)
  pure patch { rupSourceMD5    = Just sourceMD5
             , rupTargetMD5    = Just targetMD5
             , rupSourceSize     = sourceSize
             , rupTargetSize     = targetSize
             , rupOverflow     = overflowData
             , rupOverflowType = overflowType
             , rupRomType      = romTypeByte
             }

-- | Command 0x02: XOR record
parseXorRecord :: RUPPatch -> Get RUPPatch
parseXorRecord patch = do
  offset <- packedInt
  xorPayload <- packedBS
  pure patch { rupRecords = RUPRecord offset xorPayload : rupRecords patch }

----------------------------------------------------------------------------
-- Apply
----------------------------------------------------------------------------

applyRUP :: RUPPatch -> FilePath -> IO Int
applyRUP patch target = do
  withBinaryFile target ReadWriteMode $ \handle -> do
    mapM_ (applyRecord handle) (rupRecords patch)
    -- Handle overflow (append data for file size changes).
    -- On-disk overflow is XOR'd with 0xFF; decode before writing.
    case rupOverflow patch of
      Nothing -> pure ()
      Just overflow -> do
        let appendPosition = rupSourceSize patch
        hSeek handle AbsoluteSeek (fromIntegral appendPosition)
        ByteString.hPut handle (ByteString.map (xor 0xFF) overflow)
    -- Handle truncation (if target is smaller than source)
    when (rupTargetSize patch < rupSourceSize patch) $
      hSetFileSize handle (fromIntegral (rupTargetSize patch))
  pure (length (rupRecords patch))

applyRecord :: Handle -> RUPRecord -> IO ()
applyRecord handle (RUPRecord offset xorPayload) = do
  hSeek handle AbsoluteSeek (fromIntegral offset)
  sourceBytes <- ByteString.hGet handle (ByteString.length xorPayload)
  let padded = if ByteString.length sourceBytes < ByteString.length xorPayload
               then sourceBytes <> ByteString.replicate (ByteString.length xorPayload - ByteString.length sourceBytes) 0
               else sourceBytes
      result = ByteString.packZipWith xor padded xorPayload
  hSeek handle AbsoluteSeek (fromIntegral offset)
  ByteString.hPut handle result

-- | Apply a RUP patch in memory: XOR records + overflow handling.
applyRUPMemory :: RUPPatch -> ByteString -> ByteString
applyRUPMemory patch source = unsafeCreate outputLength $ \outputPointer -> do
    -- Copy source, zero-fill any extension
    copyByteStringRange outputPointer 0 source 0 (min sourceLength outputLength)
    when (outputLength > sourceLength) $
      fillBytes (outputPointer `plusPtr` sourceLength) (0 :: Word8) (outputLength - sourceLength)
    -- XOR records: read from buffer, XOR, write back
    forM_ (rupRecords patch) $ \(RUPRecord offset xorPayload) -> do
      let recordOffset = fromIntegral offset :: Int
          recordLength = ByteString.length xorPayload
      forM_ [0..recordLength-1] $ \position -> do
        let bytePosition = recordOffset + position
        original <- peekByteOff outputPointer bytePosition :: IO Word8
        pokeByteOff outputPointer bytePosition (original `xor` ByteString.index xorPayload position)
    -- Overflow: decoded data (XOR'd with 0xFF on disk) written at source end
    case rupOverflow patch of
      Nothing -> pure ()
      Just overflow -> do
        let appendPosition = fromIntegral (rupSourceSize patch) :: Int
            decoded = ByteString.map (xor 0xFF) overflow
        copyByteStringRange outputPointer appendPosition decoded 0 (ByteString.length decoded)
  where
    sourceLength = ByteString.length source
    targetLength = fromIntegral (rupTargetSize patch) :: Int
    outputLength = if targetLength > 0 then targetLength else sourceLength

----------------------------------------------------------------------------
-- Info
----------------------------------------------------------------------------

rupMeta :: RUPPatch -> [(String, String)]
rupMeta patch = concat
  [ metaField "title"       (rupTitle (rupHeader patch))
  , metaField "author"      (rupAuthor (rupHeader patch))
  , metaField "version"     (rupVersion (rupHeader patch))
  , metaField "date"        (rupDate (rupHeader patch))
  , metaField "genre"       (rupGenre (rupHeader patch))
  , metaField "language"    (rupLanguage (rupHeader patch))
  , metaField "website"     (rupWebsite (rupHeader patch))
  , metaField "description" (rupDescription (rupHeader patch))
  , romTypeField
  , sizeFields
  , md5Field "source MD5" (rupSourceMD5 patch)
  , md5Field "target MD5" (rupTargetMD5 patch)
  , overflowField
  ]
  where
    metaField _ Nothing = []
    metaField label (Just value) = [(label, ByteString8.unpack value)]

    romTypeField
      | rupRomType patch == 0 = []
      | otherwise = [("ROM type", show (rupRomType patch))]

    sizeFields
      | rupSourceSize patch == 0 && rupTargetSize patch == 0 = []
      | otherwise = [ ("source size", show (rupSourceSize patch))
                     , ("target size", show (rupTargetSize patch)) ]

    md5Field _ Nothing = []
    md5Field label (Just hash) =
      [(label, concatMap (\byte -> padHex 2 (fromIntegral byte)) (ByteString.unpack hash))]

    overflowField = case (rupOverflowType patch, rupOverflow patch) of
      (Just OverflowAppend,   Just payload) -> [("overflow", "append " ++ show (ByteString.length payload) ++ " bytes")]
      (Just OverflowTruncate, Just payload) -> [("overflow", "truncate " ++ show (ByteString.length payload) ++ " bytes")]
      (_, Just payload)                     -> [("overflow", show (ByteString.length payload) ++ " bytes")]
      _                                     -> []

rupInfo :: RUPPatch -> String
rupInfo patch = unlines $ filter (not . null) $
  [ "format:      RUP (NINJA2)" ]
  ++ map renderField (rupMeta patch)
  ++ [ "records:     " ++ show (length (rupRecords patch)) ]

----------------------------------------------------------------------------
-- Create
----------------------------------------------------------------------------

-- | Create a RUP/NINJA2 patch from original and modified ByteStrings.
-- XOR-based records with VLV encoding; handles size changes via overflow.
createRUP :: ByteString -> ByteString -> RUPInfo -> Word8 -> ByteString
createRUP old new info romType = LazyByteString.toStrict $ toLazyByteString $
    byteString "NINJA2"                  -- magic (6 bytes)
    <> word8 0                           -- text encoding
    <> byteString (encodeFixedHeader info)  -- rest of 2048-byte header
    <> word8 0x01                        -- OPEN_NEW_FILE command
    <> putVLV 0                          -- filename length (empty)
    <> word8 romType                     -- ROM type byte
    <> putVLV (fromIntegral (ByteString.length old))   -- source size
    <> putVLV (fromIntegral (ByteString.length new))   -- target size
    <> byteString (md5 old)              -- source MD5
    <> byteString (md5 new)              -- target MD5
    <> overflowPart
    <> foldMap encodeXorRecord xorHunks
    <> word8 0x00                        -- END command
  where
    -- XOR hunks over the shared region
    minimumLength = min (ByteString.length old) (ByteString.length new)
    oldTrim = ByteString.take minimumLength old
    newTrim = ByteString.take minimumLength new
    -- diffHunks finds changed regions; we then XOR old and new at those positions
    xorHunks = map toXor (diffHunks oldTrim newTrim)
    toXor (offset, newData) =
      let oldData = ByteString.take (ByteString.length newData) (ByteString.drop offset oldTrim)
      in (offset, ByteString.packZipWith xor oldData newData)

    -- Overflow section: emitted whenever sizes differ (parser expects it).
    -- Type byte: 'A' (0x41) = append, 'M' (0x4D) = truncate/minify.
    -- Data is XOR'd with 0xFF on disk (RomPatcher.js convention).
    overflowPart
      | ByteString.length new > ByteString.length old =
          let extra = ByteString.drop (ByteString.length old) new
          in word8 (fromOverflowMode OverflowAppend)
             <> putVLV (fromIntegral (ByteString.length extra))
             <> byteString (ByteString.map (xor 0xFF) extra)
      | ByteString.length new < ByteString.length old =
          let extra = ByteString.drop (ByteString.length new) old
          in word8 (fromOverflowMode OverflowTruncate)
             <> putVLV (fromIntegral (ByteString.length extra))
             <> byteString (ByteString.map (xor 0xFF) extra)
      | otherwise = mempty

-- | Encode a RUPInfo into the fixed header region (bytes 7..2047).
-- Mirrors parseFixedHeader layout: author@0x007/84, version@0x05B/11,
-- title@0x066/256, genre@0x166/48, language@0x196/48, date@0x1C6/8,
-- website@0x1CE/512, description@0x3CE/1074.
encodeFixedHeader :: RUPInfo -> ByteString
encodeFixedHeader info = ByteString.pack $ map byteAt [0 .. headerSize - 8]
  where
    -- Offset relative to byte 7 in the file (first byte after magic+textenc)
    byteAt index = case lookup index fieldBytes of
      Just byte -> byte
      Nothing   -> 0
    fieldBytes = concatMap expand fields
    expand (fieldOffset, fieldLength, maybeValue) = case maybeValue of
      Nothing    -> []
      Just value -> zip [fieldOffset..fieldOffset+fieldLength-1] (ByteString.unpack (padTo fieldLength value))
    padTo count input = ByteString.take count input <> ByteString.replicate (max 0 (count - ByteString.length input)) 0
    fields =
      [ (0x007 - 7, 84,   rupAuthor info)
      , (0x05B - 7, 11,   rupVersion info)
      , (0x066 - 7, 256,  rupTitle info)
      , (0x166 - 7, 48,   rupGenre info)
      , (0x196 - 7, 48,   rupLanguage info)
      , (0x1C6 - 7, 8,    rupDate info)
      , (0x1CE - 7, 512,  rupWebsite info)
      , (0x3CE - 7, 1074, rupDescription info)
      ]

encodeXorRecord :: (Int, ByteString) -> Builder
encodeXorRecord (offset, payload) =
    word8 0x02                                    -- XOR command
    <> putVLV (fromIntegral offset)               -- offset
    <> putVLV (fromIntegral (ByteString.length payload))  -- length
    <> byteString payload                         -- XOR data

-- | VLV: 1-byte length prefix, then N bytes little-endian.
putVLV :: Int64 -> Builder
putVLV 0 = word8 1 <> word8 0
putVLV value =
  let bytes = vlvBytes value
  in word8 (fromIntegral (length bytes)) <> foldMap word8 bytes

vlvBytes :: Int64 -> [Word8]
vlvBytes 0 = []
vlvBytes value = fromIntegral (value .&. 0xFF) : vlvBytes (value `shiftR` 8)
