{-# LANGUAGE StrictData #-}

module Slap.UPS.Types
  ( UPSBlock(..)
  , UPSBody(..)
  , UPSPatch(..)
  ) where

import Slap.Checksum (CRC32)
import Slap.Measure (FileSize(..), Delta(..))

import Data.ByteString (ByteString)

data UPSBlock = UPSBlock
  { upsSkip    :: !Delta      -- bytes to skip (copy from source unchanged)
  , upsXorData :: !ByteString -- nonzero XOR bytes (terminated by 0x00 in file)
  } deriving (Show)

data UPSBody = UPSBody
  { upsBodySourceSize :: !FileSize
  , upsBodyTargetSize :: !FileSize
  , upsBodyBlocks     :: ![UPSBlock]
  } deriving (Show)

data UPSPatch = UPSPatch
  { upsSourceSize :: !FileSize
  , upsTargetSize :: !FileSize
  , upsBlocks     :: [UPSBlock]
  , upsSourceCRC  :: CRC32
  , upsTargetCRC  :: CRC32
  , upsPatchCRC   :: CRC32
  } deriving (Show)
