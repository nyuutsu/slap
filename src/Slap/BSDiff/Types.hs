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
  { bsdiffControlSize  :: !Length     -- compressed, on the wire
  , bsdiffDiffSize     :: !Length     -- compressed, on the wire
  , bsdiffExtraSize    :: !Length     -- compressed, on the wire
  , bsdiffTargetSize   :: !FileSize
  , bsdiffInstructions :: [BSDiffInstruction]
  , bsdiffDiffData     :: ByteString  -- decompressed
  , bsdiffExtraData    :: ByteString  -- decompressed
  } deriving (Show)

-- | A single bsdiff control instruction.
-- The apply runs the three fields in order: add, then copy, then seek.
data BSDiffInstruction = BSDiffInstruction
  { controlAdd  :: !Length  -- bytes to add from diff stream to source
  , controlCopy :: !Length  -- bytes to copy from extra stream
  , controlSeek :: !Delta   -- signed seek offset in source
  } deriving (Show)

-- | Wire-format magic prefix, per bsdiff 4.3 (Colin Percival).
-- BSDIFF40 is the flavor that circulates as patch files;
-- the sibling headers, BSDF2 and ENDSLEY/BSDIFF43, live inside Android's OTA and Play Store pipelines
-- and never travel as patches, so slap does not speak them.
bsdiffMagicBytes :: ByteString
bsdiffMagicBytes = "BSDIFF40"

-- | Size of one bsdiff instruction on the wire: three 8-byte
-- sign-magnitude values (add length, copy length, seek offset).
bsdiffInstructionSize :: Int
bsdiffInstructionSize = 24
