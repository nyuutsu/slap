{-# LANGUAGE StrictData #-}

module Slap.DPS.Types
  ( DPSPatch(..)
  , DPSRecord(..)
  , DPSMode(..)
  , DPSPayload(..)
  , DPSStability(..)
  , toDPSStability
  , fromDPSStability
  , trimNull
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.Int (Int64)
import Data.Word (Word8)
import Slap.Measure (Offset(..), FileSize(..))

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
  = PayloadCopy Int64 Int64        -- source ROM offset, length
  | PayloadData ByteString         -- embedded data
  deriving (Show)

trimNull :: ByteString -> ByteString
trimNull = ByteString.takeWhile (/= 0)
