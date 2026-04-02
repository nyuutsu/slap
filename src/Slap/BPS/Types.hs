{-# LANGUAGE StrictData #-}

module Slap.BPS.Types
  ( BPSAction(..)
  , BPSPatch(..)
  , decodeSignedVarint
  ) where

import Data.Bits (shiftR, testBit)
import Data.ByteString (ByteString)
import Data.Int (Int64)
import Slap.Checksum (CRC32)
import Slap.Measure (Length(..), FileSize(..), Delta(..))

data BPSAction
  = SourceRead { sourceReadLength :: !Length }
  | TargetRead { targetReadPayload :: !ByteString }
  | SourceCopy { sourceCopyLength :: !Length, sourceCopyDelta :: !Delta }
  | TargetCopy { targetCopyLength :: !Length, targetCopyDelta :: !Delta }
  deriving (Show)

data BPSPatch = BPSPatch
  { bpsSourceSize :: !FileSize
  , bpsTargetSize :: !FileSize
  , bpsMetadata   :: ByteString
  , bpsActions    :: [BPSAction]
  , bpsSourceCRC  :: CRC32
  , bpsTargetCRC  :: CRC32
  , bpsPatchCRC   :: CRC32
  } deriving (Show)

-- Decode a signed varint: bit 0 = sign (1 = negative), bits 1+ = magnitude.
decodeSignedVarint :: Int64 -> Int64
decodeSignedVarint encoded =
  let magnitude = shiftR encoded 1
  in if testBit encoded 0 then negate magnitude else magnitude
