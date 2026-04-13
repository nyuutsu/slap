{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StrictData #-}

module Slap.BSDiff.Types
  ( BSDiffPatch(..)
  , BSDiffControl(..)
    -- * Named constants
  , bsdiffMagicBytes
  , bsdiffControlRecordSize
  ) where

import Data.ByteString (ByteString)
import Slap.Measure (FileSize(..), Length(..), Delta(..))

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
  { controlAdd  :: !Length  -- bytes to add from diff stream to source
  , controlCopy :: !Length  -- bytes to copy from extra stream
  , controlSeek :: !Delta   -- signed seek offset in source
  } deriving (Show)

-- | BSDiff magic bytes (@"BSDIFF40"@) per bsdiff 4.3 (Colin Percival).
bsdiffMagicBytes :: ByteString
bsdiffMagicBytes = "BSDIFF40"

-- | Size of one control record: three 8-byte sign-magnitude values
-- (add length, copy length, seek offset).
bsdiffControlRecordSize :: Int
bsdiffControlRecordSize = 24
