module Slap.DPS.Parse
  ( parseDPS
  , parseRecords
  , isDPS
  ) where

-- Canonical reference: https://github.com/btimofeev/UniPatcher/wiki/DPS (format spec, from DPS patcher source)
-- Original C source: https://github.com/xperia64/android-rom-patcher/blob/master/jni/dpspatcher/dpspatcher.c
-- Author: Marc de Falco (Deufeufeu); deufeufeu.free.fr is dead.

import Slap.DPS.Types (DPSPatch(..), DPSRecord(..), DPSFormatVersion(..),
                        toDPSStability, toDPSFormatVersion,
                        dpsFieldWidth, dpsMinimumFileSize,
                        dpsVersionOffset, dpsStabilityOffset,
                        dpsCopyFromROMMode, dpsEnclosedDataMode,
                        dpsRecordHeaderSize, dpsCopyRecordSize)
import Slap.Binary (trimNull)
import Slap.Error (SlapError(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.Get (Get, runGet, getByte, getBytes, remaining)
import qualified Slap.Get as Get
import Slap.Measure (Length(..), Offset(..), FileSize(..))

import Data.Bits (shiftL, (.|.))
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString

----------------------------------------------------------------------------
-- Detection heuristic (no magic bytes)
----------------------------------------------------------------------------

-- | Heuristic detection: DPS files have version byte = 1 at
-- dpsVersionOffset, stability flag ∈ {0,1} at dpsStabilityOffset,
-- and records that parse cleanly to end of file.
isDPS :: ByteString -> Bool
isDPS input
  | ByteString.length input < dpsMinimumFileSize = False
  | ByteString.index input dpsVersionOffset /= 1 = False
  | ByteString.index input dpsStabilityOffset > 1 = False
  | otherwise = walkRecords dpsMinimumFileSize
  where
    inputLength = ByteString.length input
    -- Tentative record walk: each record starts with a mode byte, then
    -- mode 0 (CopyFromROM): outputOffset(4) + sourceOffset(4) + length(4)
    -- mode 1 (EnclosedData): outputOffset(4) + dataLength(4) + data(dataLength)
    -- Records must consume the remaining bytes exactly.
    walkRecords position
      | position == inputLength = True
      | position > inputLength  = False
      | otherwise =
          let modeByte = ByteString.index input position
          in if modeByte == dpsCopyFromROMMode
             then position + dpsCopyRecordSize <= inputLength
                  && walkRecords (position + dpsCopyRecordSize)
             else if modeByte == dpsEnclosedDataMode
             then let fixedSize = dpsRecordHeaderSize + 4  -- + dataLength field
                  in position + fixedSize <= inputLength
                     && let dataLength = word32LEAt (position + dpsRecordHeaderSize)
                        in walkRecords (position + fixedSize + dataLength)
             else False
    word32LEAt offset
      | offset + 4 > inputLength = inputLength  -- out of bounds → force walk failure
      | otherwise =
          let byte0 = fromIntegral (ByteString.index input offset) :: Int
              byte1 = fromIntegral (ByteString.index input (offset + 1)) `shiftL` 8
              byte2 = fromIntegral (ByteString.index input (offset + 2)) `shiftL` 16
              byte3 = fromIntegral (ByteString.index input (offset + 3)) `shiftL` 24
          in byte0 .|. byte1 .|. byte2 .|. byte3

----------------------------------------------------------------------------
-- Parse
----------------------------------------------------------------------------

parseDPS :: ByteString -> Either SlapError DPSPatch
parseDPS input
  | ByteString.length input < dpsMinimumFileSize = Left (InputTooShort LabelDPS (Length dpsMinimumFileSize) (Length (ByteString.length input)))
  | Left versionError <- toDPSFormatVersion (ByteString.index input dpsVersionOffset)
    = Left versionError
  | otherwise = case runGet parseDPSBody input of
      Left errorMessage -> Left (ParseError LabelDPS errorMessage)
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
      _ <- getByte  -- version byte (validated by parseDPS guard)
      originalSize  <- FileSize . fromIntegral <$> Get.word32LE
      records    <- parseRecords
      pure DPSPatch
        { dpsName       = name
        , dpsAuthor     = author
        , dpsVersion    = version
        , dpsStability       = stability
        , dpsFormatVersion = DPSVersion1
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
