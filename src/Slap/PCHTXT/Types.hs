{-# LANGUAGE StrictData #-}

module Slap.PCHTXT.Types
  ( PCHTXTEntry(..)
  , PCHTXTBlock(..)
  , PCHTXTPatch(..)
  , PCHTXTDescription(..)
  , FlagResult(..)
  ) where

import Data.ByteString (ByteString)
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

data FlagResult = FlagShift Int | FlagIgnored | FlagError String

-- | Free-form header description for a PCHTXT patch. Emitted verbatim
-- as either an @\@nsobid-...@ build-ID header (when the string is a
-- 32+-character hex digest) or a @\/\/ ...@ comment line. Introduced
-- so the porcelain surface distinguishes \"the header description\"
-- from every other 'String' at a 'Slap.PCHTXT.Create' call site.
newtype PCHTXTDescription = PCHTXTDescription { unPCHTXTDescription :: String }
  deriving (Eq, Show)
