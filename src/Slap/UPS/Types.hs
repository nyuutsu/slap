{-# LANGUAGE StrictData #-}

module Slap.UPS.Types
  ( UPSBlock(..)
  , UPSPatch(..)
  ) where

import Slap.Measure (FileSize(..), Delta(..))

import Data.ByteString (ByteString)
import Data.Word (Word32)

data UPSBlock = UPSBlock
  { upsSkip    :: !Delta      -- bytes to skip (copy from source unchanged)
  , upsXorData :: !ByteString -- nonzero XOR bytes (terminated by 0x00 in file)
  } deriving (Show)

data UPSPatch = UPSPatch
  { upsSourceSize :: !FileSize
  , upsTargetSize :: !FileSize
  , upsBlocks     :: [UPSBlock]
  , upsSourceCRC  :: Word32
  , upsTargetCRC  :: Word32
  , upsPatchCRC   :: Word32
  } deriving (Show)
