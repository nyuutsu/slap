{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StrictData #-}

module Slap.APSGBA.Types
  ( APSGBAPatch(..)
  , APSGBAHeader(..)
  , APSGBARecord(..)
    -- * Named constants
  , apsGbaMagicBytes
  , apsGbaHeaderSize
  , apsGbaBlockSize
  , apsGbaRecordSize
  ) where

import Data.ByteString (ByteString)
import Slap.Checksum (CRC16)
import Slap.Measure (FileSize, Offset)

data APSGBAPatch = APSGBAPatch APSGBAHeader [APSGBARecord]
  deriving (Show)

data APSGBAHeader = APSGBAHeader
  { apsGbaSourceSize :: FileSize
  , apsGbaTargetSize :: FileSize
  } deriving (Show)

data APSGBARecord = APSGBARecord
  { apsGbaOffset    :: Offset
  , apsGbaSourceCRC :: CRC16
  , apsGbaTargetCRC :: CRC16
  , apsGbaXorData   :: ByteString  -- apsGbaBlockSize bytes
  } deriving (Show)

-- | APS-GBA magic bytes (@"APS1"@). Shared prefix with APS-N64
-- (@"APS10"@) — detection must check the longer probe first.
apsGbaMagicBytes :: ByteString
apsGbaMagicBytes = "APS1"

-- | File header size: 4-byte magic + 4-byte source size + 4-byte target size.
apsGbaHeaderSize :: Int
apsGbaHeaderSize = 12

-- | XOR data block size: 65536 bytes (64 KB).
apsGbaBlockSize :: Int
apsGbaBlockSize = 65536

-- | Total record size: block size + 8 bytes of per-record header
-- (4-byte offset + 2-byte source CRC16 + 2-byte target CRC16).
apsGbaRecordSize :: Int
apsGbaRecordSize = apsGbaBlockSize + 8
