{-# LANGUAGE StrictData #-}

module Slap.APSGBA.Types
  ( APSGBAPatch(..)
  , APSGBAHeader(..)
  , APSGBARecord(..)
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
  , apsGbaXorData   :: ByteString  -- 65536 bytes
  } deriving (Show)
