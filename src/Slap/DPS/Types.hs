{-# LANGUAGE StrictData #-}

module Slap.DPS.Types
  ( DPSPatch(..)
  , DPSRecord(..)
  , DPSStability(..)
  , DPSFormatVersion(..)
  , toDPSStability
  , fromDPSStability
  , toDPSFormatVersion
  , fromDPSFormatVersion
    -- * Named constants
  , dpsFieldWidth
  , dpsFieldCount
  , dpsMetadataSize
  , dpsMinimumFileSize
  , dpsVersionOffset
  , dpsStabilityOffset
    -- * Record constants
  , dpsCopyFromROMMode
  , dpsEnclosedDataMode
  , dpsRecordHeaderSize
  , dpsCopyRecordSize
  ) where

import Data.ByteString (ByteString)
import Data.Word (Word8)
import Slap.Error (SlapError(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.Measure (Offset(..), Length(..), FileSize(..), FoundVersion(..))

data DPSStability = DPSStable | DPSUnstable
  deriving (Show, Eq)

toDPSStability :: Word8 -> Either String DPSStability
toDPSStability 0 = Right DPSStable
toDPSStability 1 = Right DPSUnstable
toDPSStability flagByte = Left ("unknown stability flag: " ++ show flagByte)

fromDPSStability :: DPSStability -> Word8
fromDPSStability DPSStable   = 0
fromDPSStability DPSUnstable = 1

data DPSFormatVersion = DPSVersion1
  deriving (Show, Eq)

toDPSFormatVersion :: Word8 -> Either SlapError DPSFormatVersion
toDPSFormatVersion 1 = Right DPSVersion1
toDPSFormatVersion byte = Left (BadVersion LabelDPS (FoundVersion byte))

fromDPSFormatVersion :: DPSFormatVersion -> Word8
fromDPSFormatVersion DPSVersion1 = 1

data DPSPatch = DPSPatch
  { dpsName       :: ByteString   -- wire format: 64 bytes, null-padded; parsed: trimmed
  , dpsAuthor     :: ByteString   -- wire format: 64 bytes, null-padded; parsed: trimmed
  , dpsVersion    :: ByteString   -- wire format: 64 bytes, null-padded; parsed: trimmed
  , dpsStability       :: DPSStability
  , dpsFormatVersion :: DPSFormatVersion
  , dpsOriginalSize   :: !FileSize    -- original ROM size
  , dpsRecords    :: [DPSRecord]
  } deriving (Show)

data DPSRecord
  = DPSCopyFromROM
      { dpsCopyOutputOffset :: !Offset   -- write position in output
      , dpsCopySourceOffset :: !Offset   -- source ROM offset to copy from
      , dpsCopyLength       :: !Length   -- bytes to copy
      }
  | DPSEnclosedData
      { dpsDataOutputOffset :: !Offset   -- write position in output
      , dpsDataPayload      :: !ByteString
      }
  deriving (Show)

----------------------------------------------------------------------------
-- Named constants
----------------------------------------------------------------------------

-- | Each metadata field (name, author, version) is 64 bytes, null-padded.
dpsFieldWidth :: Int
dpsFieldWidth = 64

-- | Number of metadata fields in the header.
dpsFieldCount :: Int
dpsFieldCount = 3

-- | Total metadata size: 3 × 64 = 192 bytes.
dpsMetadataSize :: Int
dpsMetadataSize = dpsFieldCount * dpsFieldWidth

-- | Minimum valid DPS file: 192 (metadata) + 1 (flag) + 1 (version) + 4 (orig size).
dpsMinimumFileSize :: Int
dpsMinimumFileSize = dpsMetadataSize + 6

-- | Byte offset of the version field (0-indexed).
dpsVersionOffset :: Int
dpsVersionOffset = dpsMetadataSize + 1

-- | Byte offset of the stability flag (0-indexed).
dpsStabilityOffset :: Int
dpsStabilityOffset = dpsMetadataSize

-- | Mode byte for CopyFromROM records.
dpsCopyFromROMMode :: Word8
dpsCopyFromROMMode = 0

-- | Mode byte for EnclosedData records.
dpsEnclosedDataMode :: Word8
dpsEnclosedDataMode = 1

-- | Shared record header: mode byte + output offset (1 + 4 bytes).
dpsRecordHeaderSize :: Int
dpsRecordHeaderSize = 5

-- | Full CopyFromROM record: mode + outputOffset + sourceOffset + length (1 + 4 + 4 + 4).
dpsCopyRecordSize :: Int
dpsCopyRecordSize = 13
