{-# LANGUAGE StrictData #-}

module Slap.PCHTXT.Types
  ( PCHTXTEntry(..)
  , PCHTXTBlock(..)
  , PCHTXTPatch(..)
  , FlagResult(..)
    -- * Encoding limits
  , pchtxtLimits
  ) where

import Data.ByteString (ByteString)
import Slap.FormatLabel (FormatLabel(..))
import Slap.Measure (Offset(..))
import Slap.Narrow (EncodingLimits(..))

-- | A single PCHTXT patch entry: absolute offset + data to write.
data PCHTXTEntry = PCHTXTEntry
  { pchtxtOffset :: !Offset
  , pchtxtData   :: !ByteString
  } deriving (Show)

-- | A patch block: enabled/disabled, optional description, entries.
data PCHTXTBlock = PCHTXTBlock
  { pchtxtBlockEnabled     :: Bool
  , pchtxtBlockDescription :: Maybe String
  , pchtxtBlockEntries     :: [PCHTXTEntry]
  } deriving (Show)

-- | A parsed PCHTXT patch.
data PCHTXTPatch = PCHTXTPatch
  { pchtxtNsobid   :: Maybe String
  , pchtxtBlocks   :: [PCHTXTBlock]
  , pchtxtHasShift :: Bool  -- ^ True if @flag offset_shift was applied during parse
  } deriving (Show)

data FlagResult = FlagShift Int | FlagIgnored | FlagError String

-- | PCHTXT's per-entry offset is encoded as 8 hex digits, so offsets
-- must fit in Word32 range (2^32 bytes). Enforced at narrow time so
-- 'Slap.PCHTXT.Create.encodeHunkEntry' cannot emit malformed
-- (>8-digit) hex.
pchtxtLimits :: EncodingLimits
pchtxtLimits = EncodingLimits
  { maximumOffset = Offset 0xFFFFFFFF
  , formatLabel   = LabelPCHTXT
  }
