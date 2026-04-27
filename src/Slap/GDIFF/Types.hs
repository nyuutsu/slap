{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StrictData #-}

module Slap.GDIFF.Types
  ( GDiffPatch(..)
  , GDiffCommand(..)
    -- * Named constants
  , gdiffMagicBytes
  ) where

import Slap.Measure (Offset, FileSize)

import Data.ByteString (ByteString)

data GDiffCommand
  = GDiffData ByteString                             -- literal data to append
  | GDiffCopy { gdiffCopyOffset :: !Offset, gdiffCopyLength :: !FileSize }  -- offset into source, length
  deriving (Show)

data GDiffPatch = GDiffPatch
  { gdiffCommands :: [GDiffCommand]
  } deriving (Show)

-- | GDIFF magic bytes (@0xD1 0xFF 0xD1 0xFF@) per W3C NOTE-GDIFF-19970901.
gdiffMagicBytes :: ByteString
gdiffMagicBytes = "\xd1\xff\xd1\xff"
