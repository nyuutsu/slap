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
  { bsdiffControlSize  :: !FileSize   -- compressed, on the wire
  , bsdiffDiffSize     :: !FileSize   -- compressed, on the wire
  , bsdiffExtraSize    :: !FileSize   -- compressed, on the wire
  , bsdiffTargetSize   :: !FileSize
  , bsdiffInstructions :: [BSDiffInstruction]
  , bsdiffDiffData     :: ByteString  -- decompressed
  , bsdiffExtraData    :: ByteString  -- decompressed
  } deriving (Show)

-- | A single bsdiff control instruction: a triple of (add length, copy length, seek delta).
-- It tells the apply algorithm to add that many bytes from the diff stream, copy that many from the extra stream, then seek the source-cursor by that signed amount.
data BSDiffInstruction = BSDiffInstruction
  { controlAdd  :: !Length  -- bytes to add from diff stream to source
  , controlCopy :: !Length  -- bytes to copy from extra stream
  , controlSeek :: !Delta   -- signed seek offset in source
  } deriving (Show)

-- | Wire-format magic prefix, per bsdiff 4.3 (Colin Percival).
bsdiffMagicBytes :: ByteString
bsdiffMagicBytes = "BSDIFF40"

-- | Size of one bsdiff instruction on the wire: three 8-byte
-- sign-magnitude values (add length, copy length, seek offset).
bsdiffInstructionSize :: Int
bsdiffInstructionSize = 24
