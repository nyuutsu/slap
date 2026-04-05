{-# LANGUAGE StrictData #-}

module Slap.GDIFF.Types
  ( GDiffPatch(..)
  , GDiffCommand(..)
  , commandOutputSize
  ) where

import Slap.Measure (Offset(..), FileSize(..))

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
data GDiffCommand
  = GDiffData ByteString                             -- literal data to append
  | GDiffCopy { gdiffCopyOffset :: !Offset, gdiffCopyLength :: !FileSize }  -- offset into source, length
  deriving (Show)

data GDiffPatch = GDiffPatch
  { gdiffCommands :: [GDiffCommand]
  } deriving (Show)

commandOutputSize :: GDiffCommand -> Int
commandOutputSize (GDiffData payload)       = ByteString.length payload
commandOutputSize (GDiffCopy _ copyLength) = unFileSize copyLength
