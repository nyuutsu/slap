{-# LANGUAGE StrictData #-}

module Slap.DPS.Types
  ( DPSPatch(..)
  , DPSRecord(..)
  , DPSMode(..)
  , DPSPayload(..)
  , DPSStability(..)
  , toDPSStability
  , fromDPSStability
    -- * Named constants
  , dpsFieldWidth
  , dpsFieldCount
  , dpsMetadataSize
  , dpsMinimumFileSize
  , dpsVersionOffset
  , dpsStabilityOffset
  ) where

import Data.ByteString (ByteString)
import Data.Word (Word8)
import Slap.Measure (Offset(..), Length(..), FileSize(..))

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
  { dpsName       :: ByteString   -- wire format: 64 bytes, null-padded; parsed: trimmed
  , dpsAuthor     :: ByteString   -- wire format: 64 bytes, null-padded; parsed: trimmed
  , dpsVersion    :: ByteString   -- wire format: 64 bytes, null-padded; parsed: trimmed
  , dpsStability       :: DPSStability
  , dpsFormatVersion :: Word8        -- must be 1
  , dpsOriginalSize   :: !FileSize    -- original ROM size
  , dpsRecords    :: [DPSRecord]
  } deriving (Show)

data DPSMode = CopyFromROM | EnclosedData
  deriving (Show, Eq)

data DPSRecord = DPSRecord
  { dpsRecordMode      :: DPSMode
  , dpsRecordOutputOffset :: !Offset     -- write position in output
  , dpsRecordPayload   :: DPSPayload
  } deriving (Show)

data DPSPayload
  = PayloadCopy !Offset !Length    -- source ROM offset, copy length
  | PayloadData !ByteString        -- embedded data
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
