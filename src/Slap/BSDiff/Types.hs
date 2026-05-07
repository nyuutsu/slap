{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StrictData #-}

module Slap.BSDiff.Types
  ( BSDiffPatch(..)
  , BSDiffInstruction(..)
    -- * Named constants
  , bsdiffMagicBytes
  , bsdiffInstructionSize
  ) where

import Data.ByteString (ByteString)
import Slap.Measure (FileSize(..), Length(..), Delta(..))

data BSDiffPatch = BSDiffPatch
  { bsdiffControlSize  :: !FileSize   -- compressed control block size
  , bsdiffDiffSize     :: !FileSize   -- compressed diff block size
  , bsdiffExtraSize    :: !FileSize   -- compressed extra block size
  , bsdiffTargetSize   :: !FileSize   -- target file size
  , bsdiffInstructions :: [BSDiffInstruction]
  , bsdiffDiffData     :: ByteString  -- decompressed diff stream
  , bsdiffExtraData    :: ByteString  -- decompressed extra stream
  } deriving (Show)

-- | A single bsdiff control instruction: a triple of (add length, copy
-- length, seek delta) telling the apply algorithm to add that many
-- bytes from the diff stream, copy that many bytes from the extra
-- stream, then seek the source-cursor by that signed amount.  Named
-- 'Instruction' to match XDelta1's and VCDIFF's vocabulary for the
-- same concept; bsdiff calls them "control records" or "control
-- instructions" interchangeably in its own literature.
data BSDiffInstruction = BSDiffInstruction
  { controlAdd  :: !Length  -- bytes to add from diff stream to source
  , controlCopy :: !Length  -- bytes to copy from extra stream
  , controlSeek :: !Delta   -- signed seek offset in source
  } deriving (Show)

-- | BSDiff magic bytes (@"BSDIFF40"@) per bsdiff 4.3 (Colin Percival).
bsdiffMagicBytes :: ByteString
bsdiffMagicBytes = "BSDIFF40"

-- | Size of one bsdiff instruction on the wire: three 8-byte
-- sign-magnitude values (add length, copy length, seek offset).
bsdiffInstructionSize :: Int
bsdiffInstructionSize = 24
