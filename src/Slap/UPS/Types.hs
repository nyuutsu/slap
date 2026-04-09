{-# LANGUAGE StrictData #-}

module Slap.UPS.Types
  ( UPSBlock(..)
  , UPSBody(..)
  , UPSPatch(..)
    -- * Named constants
  , upsMagicSize
  , upsFooterSize
  , upsTotalOverhead
  ) where

import Slap.Checksum (CRC32)
import Slap.Measure (FileSize(..), Delta(..))

import Data.ByteString (ByteString)
import Data.Vector (Vector)

data UPSBlock = UPSBlock
  { upsSkip    :: !Delta      -- bytes to skip (copy from source unchanged)
  , upsXorData :: !ByteString -- nonzero XOR bytes (terminated by 0x00 in file)
  } deriving (Show)

data UPSBody = UPSBody
  { upsBodySourceSize :: !FileSize
  , upsBodyTargetSize :: !FileSize
  , upsBodyBlocks     :: !(Vector UPSBlock)
  } deriving (Show)

data UPSPatch = UPSPatch
  { upsSourceSize :: !FileSize
  , upsTargetSize :: !FileSize
  , upsBlocks     :: !(Vector UPSBlock)
  , upsSourceCRC  :: CRC32
  , upsTargetCRC  :: CRC32
  , upsPatchCRC   :: CRC32
  } deriving (Show)

-- | Magic ("UPS1") size in bytes.
upsMagicSize :: Int
upsMagicSize = 4

-- | Footer size: three CRC32s (source, target, patch) = 12 bytes.
upsFooterSize :: Int
upsFooterSize = 12

-- | Total framing overhead: magic + footer.
upsTotalOverhead :: Int
upsTotalOverhead = upsMagicSize + upsFooterSize
