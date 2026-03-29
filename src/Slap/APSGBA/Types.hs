{-# LANGUAGE StrictData #-}

module Slap.APSGBA.Types
  ( APSGBAPatch(..)
  , APSGBAHeader(..)
  , APSGBARecord(..)
  ) where

import Data.ByteString (ByteString)
import Data.Word (Word16, Word32)

data APSGBAPatch = APSGBAPatch APSGBAHeader [APSGBARecord]
  deriving (Show)

data APSGBAHeader = APSGBAHeader
  { apsGbaSourceSize :: Word32
  , apsGbaTargetSize :: Word32
  } deriving (Show)

data APSGBARecord = APSGBARecord
  { apsGbaOffset    :: Word32
  , apsGbaSourceCRC :: Word16
  , apsGbaTargetCRC :: Word16
  , apsGbaXorData   :: ByteString  -- 65536 bytes
  } deriving (Show)
