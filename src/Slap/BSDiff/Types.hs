{-# LANGUAGE StrictData #-}

module Slap.BSDiff.Types
  ( BSDiffPatch(..)
  , BSDiffControl(..)
  ) where

import Data.ByteString (ByteString)
import Data.Int (Int64)
import Slap.Measure (FileSize(..), Delta(..))

data BSDiffPatch = BSDiffPatch
  { bsdiffControlSize :: !FileSize   -- compressed control block size
  , bsdiffDiffSize    :: !FileSize   -- compressed diff block size
  , bsdiffExtraSize   :: !FileSize   -- compressed extra block size
  , bsdiffTargetSize  :: !FileSize   -- target file size
  , bsdiffControls    :: [BSDiffControl]
  , bsdiffDiffData    :: ByteString  -- decompressed diff stream
  , bsdiffExtraData   :: ByteString  -- decompressed extra stream
  } deriving (Show)

data BSDiffControl = BSDiffControl
  { controlAdd  :: !Int64  -- bytes to add from diff stream to source
  , controlCopy :: !Int64  -- bytes to copy from extra stream
  , controlSeek :: !Delta  -- signed seek offset in source
  } deriving (Show)
