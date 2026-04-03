module Slap.DPS.Parse
  ( parseDPS
  , parseDPSBody
  , parseRecords
  , isDPS
  ) where

-- Canonical reference: https://github.com/btimofeev/UniPatcher/wiki/DPS (format spec, from DPS patcher source)
-- Original C source: https://github.com/xperia64/android-rom-patcher/blob/master/jni/dpspatcher/dpspatcher.c
-- Author: Marc de Falco (Deufeufeu); deufeufeu.free.fr is dead.

import Slap.DPS.Types (DPSPatch(..), DPSRecord(..),
                        toDPSStability,
                        dpsFieldWidth, dpsMetadataSize, dpsMinimumFileSize,
                        dpsVersionOffset, dpsStabilityOffset)
import Slap.Binary (trimNull)
import Slap.Error (SlapError(..))
import Slap.FormatLabel (FormatLabel(..))
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
  | ByteString.length input < dpsMinimumFileSize = False
  | ByteString.index input dpsVersionOffset /= 1 = False
  | ByteString.index input dpsStabilityOffset > 1 = False
  | not (ByteString.all isHeaderByte (ByteString.take dpsMetadataSize input)) = False
  -- Zero-record patch (198 bytes exactly) is valid: identity diff.
  -- When records exist, first byte must be a valid mode (0 or 1).
  | ByteString.length input > dpsMinimumFileSize = ByteString.index input dpsMinimumFileSize <= 1
  | otherwise = True
  where
    isHeaderByte headerByte = (headerByte >= 0x20 && headerByte <= 0x7E) || headerByte == 0

----------------------------------------------------------------------------
-- Parse
----------------------------------------------------------------------------

parseDPS :: ByteString -> Either SlapError DPSPatch
parseDPS input
  | ByteString.length input < dpsMinimumFileSize = Left (InputTooShort LabelDPS (Length dpsMinimumFileSize) (Length (ByteString.length input)))
  | ByteString.index input dpsVersionOffset /= 1 = Left (BadVersion LabelDPS (ByteString.index input dpsVersionOffset))
  | otherwise = case runGet parseDPSBody input of
      Left msg -> Left (ParseError LabelDPS msg)
      Right patch -> Right patch

parseDPSBody :: Get DPSPatch
parseDPSBody = do
  name    <- trimNull <$> getBytes (Length dpsFieldWidth)
  author  <- trimNull <$> getBytes (Length dpsFieldWidth)
  version <- trimNull <$> getBytes (Length dpsFieldWidth)
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
        sourceOffset <- Offset . fromIntegral <$> Get.word32LE
        copyLength   <- Length . fromIntegral <$> Get.word32LE
        pure (DPSCopyFromROM outputOffset sourceOffset copyLength)
      _ -> do  -- EnclosedData: read length + data from patch
        dataLength  <- fromIntegral <$> Get.word32LE :: Get Int
        payload  <- getBytes (Length dataLength)
        pure (DPSEnclosedData outputOffset payload)
    rest <- parseRecords
    pure (record : rest)
