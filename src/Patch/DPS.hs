{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StrictData #-}

module Patch.DPS
  ( DPSPatch(..)
  , DPSRecord(..)
  , DPSMode(..)
  , DPSPayload(..)
  , DPSStability(..)
  , parseDPS
  , applyDPS
  , createDPS
  , dpsMeta
  , dpsInfo
  , isDPS
  ) where

-- Canonical reference: https://github.com/btimofeev/UniPatcher/wiki/DPS (format spec, from DPS patcher source)
-- Original C source: https://github.com/xperia64/android-rom-patcher/blob/master/jni/dpspatcher/dpspatcher.c
-- Author: Marc de Falco (Deufeufeu); deufeufeu.free.fr is dead.

import Patch.Get (Get, runGet, getByte, getBytes, remaining)
import qualified Patch.Get as Get
import Patch.Measure (Length(..))

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Char8 as ByteString8
import qualified Data.ByteString.Lazy as LazyByteString
import Data.ByteString.Builder (Builder, word8, byteString, toLazyByteString)
import Patch.Binary (putWord32LE, diffHunks)
import Patch.Format (renderField)
import Data.Int (Int64)
import Data.Word (Word8, Word32)

----------------------------------------------------------------------------
-- Types
----------------------------------------------------------------------------

data DPSStability = DPSStable | DPSUnstable
  deriving (Show, Eq)

toDPSStability :: Word8 -> Either String DPSStability
toDPSStability 0 = Right DPSStable
toDPSStability 1 = Right DPSUnstable
toDPSStability flagByte = Left ("DPS: unknown stability flag: " ++ show flagByte)

fromDPSStability :: DPSStability -> Word8
fromDPSStability DPSStable   = 0
fromDPSStability DPSUnstable = 1

data DPSPatch = DPSPatch
  { dpsName       :: ByteString   -- 64 bytes, null-padded
  , dpsAuthor     :: ByteString   -- 64 bytes, null-padded
  , dpsVersion    :: ByteString   -- 64 bytes, null-padded
  , dpsStability       :: DPSStability
  , dpsFormatVersion :: Word8        -- must be 1
  , dpsOriginalSize   :: Int64        -- original ROM size
  , dpsRecords    :: [DPSRecord]
  } deriving (Show)

data DPSMode = CopyFromROM | EnclosedData
  deriving (Show, Eq)

data DPSRecord = DPSRecord
  { dpsRecordMode      :: DPSMode
  , dpsRecordOutputOffset :: Int64       -- write position in output
  , dpsRecordPayload   :: DPSPayload
  } deriving (Show)

data DPSPayload
  = PayloadCopy Int64 Int64        -- source ROM offset, length
  | PayloadData ByteString         -- embedded data
  deriving (Show)

----------------------------------------------------------------------------
-- Detection heuristic (no magic bytes)
----------------------------------------------------------------------------

-- | Heuristic detection: DPS files have a 198-byte header with
-- printable ASCII in the first 192 bytes, version byte = 1 at
-- offset 193, flag byte 0 or 1 at offset 192.
isDPS :: ByteString -> Bool
isDPS input
  | ByteString.length input < 198 = False  -- 3×64 header + flag + version + u32 orig_size
  | ByteString.index input 193 /= 1 = False  -- DPS version must be 1
  | ByteString.index input 192 > 1 = False   -- stability flag must be 0 or 1
  | not (ByteString.all isHeaderByte (ByteString.take 192 input)) = False
  -- Zero-record patch (198 bytes exactly) is valid: identity diff.
  -- When records exist, first byte must be a valid mode (0 or 1).
  | ByteString.length input > 198 = ByteString.index input 198 <= 1
  | otherwise = True
  where
    isHeaderByte headerByte = (headerByte >= 0x20 && headerByte <= 0x7E) || headerByte == 0

----------------------------------------------------------------------------
-- Parse
----------------------------------------------------------------------------

parseDPS :: ByteString -> Either String DPSPatch
parseDPS input
  | ByteString.length input < 198 = Left "DPS: input too short"
  | ByteString.index input 193 /= 1 = Left ("DPS: unsupported version byte: " ++ show (ByteString.index input 193))
  | otherwise = runGet parseDPSBody input

parseDPSBody :: Get DPSPatch
parseDPSBody = do
  name    <- trimNull <$> getBytes (Length 64)
  author  <- trimNull <$> getBytes (Length 64)
  version <- trimNull <$> getBytes (Length 64)
  flagByte <- getByte
  case toDPSStability flagByte of
    Left errorMessage -> fail errorMessage
    Right stability -> do
      formatVersion     <- getByte
      originalSize  <- fromIntegral <$> Get.word32LE
      records    <- parseRecords
      pure DPSPatch
        { dpsName       = name
        , dpsAuthor     = author
        , dpsVersion    = version
        , dpsStability       = stability
        , dpsFormatVersion = formatVersion
        , dpsOriginalSize   = originalSize
        , dpsRecords    = records
        }

parseRecords :: Get [DPSRecord]
parseRecords = do
  available <- remaining
  if unLength available < 5 then pure []
  else do
    mode <- getByte
    outputOffset <- fromIntegral <$> Get.word32LE
    -- UniPatcher wiki swaps mode descriptions; chunk structures are correct.
    record <- case mode of
      0 -> do  -- CopyFromROM: read offset + length from patch
        sourceOffset <- fromIntegral <$> Get.word32LE
        dataLength    <- fromIntegral <$> Get.word32LE
        pure (DPSRecord CopyFromROM outputOffset (PayloadCopy sourceOffset dataLength))
      _ -> do  -- EnclosedData: read length + data from patch
        dataLength  <- fromIntegral <$> Get.word32LE :: Get Int
        payload  <- getBytes (Length dataLength)
        pure (DPSRecord EnclosedData outputOffset (PayloadData payload))
    rest <- parseRecords
    pure (record : rest)

trimNull :: ByteString -> ByteString
trimNull = ByteString.takeWhile (/= 0)

----------------------------------------------------------------------------
-- Apply
----------------------------------------------------------------------------

-- | Apply a DPS patch. Builds output from source ROM + embedded data.
applyDPS :: DPSPatch -> ByteString -> Either String ByteString
applyDPS patch source = Right $ buildOutput source (dpsRecords patch)

buildOutput :: ByteString -> [DPSRecord] -> ByteString
buildOutput source records =
  -- DPS builds output by writing chunks at specified offsets.
  -- Start with a copy of the source, then overwrite at each record's offset.
  let base = source
      applyRecord buffer (DPSRecord _ outputOffset (PayloadData payload)) =
        overwriteAt buffer (fromIntegral outputOffset) payload
      applyRecord buffer (DPSRecord _ outputOffset (PayloadCopy sourceOffset dataLength)) =
        let chunk = takePadded (fromIntegral dataLength) (fromIntegral sourceOffset) source
        in overwriteAt buffer (fromIntegral outputOffset) chunk
  in foldl' applyRecord base records

-- | Write bytes at a given offset, extending with zeros if needed.
overwriteAt :: ByteString -> Int -> ByteString -> ByteString
overwriteAt buffer offset payload
  | offset + ByteString.length payload <= ByteString.length buffer =
      let (before, rest) = ByteString.splitAt offset buffer
          after = ByteString.drop (ByteString.length payload) rest
      in before <> payload <> after
  | offset <= ByteString.length buffer =
      ByteString.take offset buffer <> payload
  | otherwise =
      buffer <> ByteString.replicate (offset - ByteString.length buffer) 0 <> payload

-- | Safe slice from a ByteString, padding with zeros if out of range.
takePadded :: Int -> Int -> ByteString -> ByteString
takePadded dataLength offset input
  | offset >= ByteString.length input = ByteString.replicate dataLength 0
  | offset + dataLength > ByteString.length input =
      let available = ByteString.take (ByteString.length input - offset) (ByteString.drop offset input)
      in available <> ByteString.replicate (dataLength - ByteString.length available) 0
  | otherwise = ByteString.take dataLength (ByteString.drop offset input)

----------------------------------------------------------------------------
-- Info
----------------------------------------------------------------------------

dpsMeta :: DPSPatch -> [(String, String)]
dpsMeta patch = concat
  [ fieldPair "name"    (dpsName patch)
  , fieldPair "author"  (dpsAuthor patch)
  , fieldPair "version" (dpsVersion patch)
  , [("orig size", show (dpsOriginalSize patch))]
  , [("flag", "unstable") | dpsStability patch == DPSUnstable]
  ]
  where
    fieldPair _ value | ByteString.null value = []
    fieldPair label value = [(label, ByteString8.unpack value)]

dpsInfo :: DPSPatch -> String
dpsInfo patch = unlines $ filter (not . null) $
  [ "format:      DPS (Deufeufeu Patching System)" ]
  ++ map renderField (dpsMeta patch)
  ++ [ "records:     " ++ show (length (dpsRecords patch))
     , "  copy:      " ++ show copyCount
     , "  enclosed:  " ++ show enclosedCount
     ]
  where
    copyCount = length [() | DPSRecord CopyFromROM _ _ <- dpsRecords patch]
    enclosedCount = length [() | DPSRecord EnclosedData _ _ <- dpsRecords patch]

----------------------------------------------------------------------------
-- Create
----------------------------------------------------------------------------

-- Encodes changed regions as EnclosedData records and unchanged regions
-- as CopyFromROM records.
createDPS :: ByteString -> ByteString -> String -> String -> String -> DPSStability -> ByteString
createDPS original modified name author version stability = LazyByteString.toStrict $ toLazyByteString $
    padField 64 name                    -- name
    <> padField 64 author               -- author
    <> padField 64 version              -- version
    <> word8 (fromDPSStability stability)  -- flag
    <> word8 1                          -- DPS version
    <> putWord32LE (fromIntegral (ByteString.length original) :: Word32)  -- orig size
    <> foldMap encodeRecord (dpsRecordsFromDiff original modified)
  where
    padField fieldLength fieldString =
      let fieldBytes = ByteString8.pack (take fieldLength fieldString)
      in byteString fieldBytes <> byteString (ByteString.replicate (fieldLength - ByteString.length fieldBytes) 0)

dpsRecordsFromDiff :: ByteString -> ByteString -> [(Word8, Int, ByteString)]
dpsRecordsFromDiff original modified = buildRecords 0 (diffHunks original modified)
  where
    buildRecords _ [] = []
    buildRecords position ((hunkOffset, hunkData) : rest)
      | hunkOffset > position = (0, position, encodeCopy position (hunkOffset - position))    -- CopyFromROM gap
                    : (1, hunkOffset, hunkData)                        -- EnclosedData
                    : buildRecords (hunkOffset + ByteString.length hunkData) rest
      | otherwise = (1, hunkOffset, hunkData) : buildRecords (hunkOffset + ByteString.length hunkData) rest
    encodeCopy sourceOffset copyLength = LazyByteString.toStrict $ toLazyByteString $
      putWord32LE (fromIntegral sourceOffset :: Word32)
      <> putWord32LE (fromIntegral copyLength :: Word32)

encodeRecord :: (Word8, Int, ByteString) -> Builder
encodeRecord (0, outputOffset, copyPayload) =  -- CopyFromROM: mode + outOff + srcOff + len (pre-encoded in copyPayload)
    word8 0
    <> putWord32LE (fromIntegral outputOffset :: Word32)
    <> byteString copyPayload
encodeRecord (_, outputOffset, payload) =      -- EnclosedData: mode + outOff + len + data
    word8 1
    <> putWord32LE (fromIntegral outputOffset :: Word32)
    <> putWord32LE (fromIntegral (ByteString.length payload) :: Word32)
    <> byteString payload
