{-# LANGUAGE StrictData #-}

module Slap.PCHTXT.Types
  ( PCHTXTEntry(..)
  , PCHTXTBlock(..)
  , PCHTXTPatch(..)
  , FlagResult(..)
  ) where

import Data.ByteString (ByteString)
import Data.Int (Int64)
import Slap.Measure (Offset(..))

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

data FlagResult = FlagShift Int64 | FlagIgnored | FlagError String
