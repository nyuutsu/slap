module Slap.BPS.Types
  ( BPSAction(..)
  , BPSBody(..)
  , BPSPatch(..)
  , decodeSignedVarint
    -- * Named constants
  , bpsMagicSize
  , bpsCRC32Size
  , bpsFooterSize
  , bpsTotalOverhead
  ) where

import Data.Bits (shiftR, testBit)
import Data.ByteString (ByteString)
import Data.Int (Int64)
import Data.Vector (Vector)
import Slap.Checksum (CRC32)
import Slap.Measure (Length(..), FileSize(..), Delta(..))

data BPSAction
  = SourceRead { sourceReadLength :: !Length }
  | TargetRead { targetReadPayload :: !ByteString }
  | SourceCopy { sourceCopyLength :: !Length, sourceCopyDelta :: !Delta }
  | TargetCopy { targetCopyLength :: !Length, targetCopyDelta :: !Delta }
  deriving (Show)

data BPSBody = BPSBody
  { bpsBodySourceSize :: !FileSize
  , bpsBodyTargetSize :: !FileSize
  , bpsBodyMetadata   :: !ByteString
  , bpsBodyActions    :: ![BPSAction]
  } deriving (Show)

data BPSPatch = BPSPatch
  { bpsSourceSize :: !FileSize
  , bpsTargetSize :: !FileSize
  , bpsMetadata   :: !ByteString
  -- | Action stream as a boxed 'Vector'. Boxed (not unboxed/storable)
  -- because 'BPSAction' is a sum type containing a 'ByteString'. Stored
  -- as a 'Vector' rather than a list so the entire action stream lives
  -- in one contiguous array of pointers — this saves ~90 MB of cons-cell
  -- overhead on a stadium2-scale patch (~5M actions) and lets the GC
  -- treat the action stream as a single object instead of millions of
  -- individually-allocated cells, dramatically reducing minor-GC walk
  -- cost during 'applyBPS'.
  , bpsActions    :: !(Vector BPSAction)
  , bpsSourceCRC  :: !CRC32
  , bpsTargetCRC  :: !CRC32
  , bpsPatchCRC   :: !CRC32
  } deriving (Show)

-- | Magic ("BPS1") size in bytes.
bpsMagicSize :: Int
bpsMagicSize = 4

-- | Size of one CRC32 field in bytes.
bpsCRC32Size :: Int
bpsCRC32Size = 4

-- | Footer size: three CRC32s (source, target, patch).
bpsFooterSize :: Int
bpsFooterSize = 3 * bpsCRC32Size

-- | Total framing overhead: magic + footer.
bpsTotalOverhead :: Int
bpsTotalOverhead = bpsMagicSize + bpsFooterSize

-- | Decode a signed varint: bit 0 = sign (1 = negative), bits 1+ = magnitude.
decodeSignedVarint :: Int64 -> Int64
decodeSignedVarint encoded =
  let magnitude = shiftR encoded 1
  in if testBit encoded 0 then negate magnitude else magnitude
