module Slap.DPS.Parse
  ( parseDPS
  , parseDPSBody
  , parseRecords
  , isDPS
  ) where

-- Canonical reference: https://github.com/btimofeev/UniPatcher/wiki/DPS (format spec, from DPS patcher source)
-- Original C source: https://github.com/xperia64/android-rom-patcher/blob/master/jni/dpspatcher/dpspatcher.c
-- Author: Marc de Falco (Deufeufeu); deufeufeu.free.fr is dead.

import Slap.DPS.Types (DPSPatch(..), DPSRecord(..), DPSPayload(..), DPSMode(..),
                        toDPSStability, trimNull)
import Slap.Get (Get, runGet, getByte, getBytes, remaining)
import qualified Slap.Get as Get
import Slap.Measure (Length(..), Offset(..), FileSize(..))

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString

----------------------------------------------------------------------------
-- Detection heuristic (no magic bytes)
----------------------------------------------------------------------------

-- | Heuristic detection: DPS files have a 198-byte header with
-- printable ASCII and null padding in the first 192 bytes (three
-- 64-byte string fields), version byte = 1 at offset 193,
-- flag byte 0 or 1 at offset 192.
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
      originalSize  <- FileSize . fromIntegral <$> Get.word32LE
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
    outputOffset <- Offset . fromIntegral <$> Get.word32LE
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
