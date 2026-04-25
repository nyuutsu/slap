{-# LANGUAGE OverloadedStrings #-}

module Slap.BPS.Types
  ( BPSAction(..)
  , BPSBody(..)
  , BPSPatch(..)
  , BPSMetadata(..)
  , decodeSignedVarint
    -- * Named constants
  , bpsMagicBytes
  , bpsMagicLength
  , bpsCRC32Length
  , bpsFooterLength
  , bpsOverheadLength
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
  , bpsBodyMetadata   :: !BPSMetadata
  , bpsBodyActions    :: ![BPSAction]
  } deriving (Show)

data BPSPatch = BPSPatch
  { bpsSourceSize :: !FileSize
  , bpsTargetSize :: !FileSize
  , bpsMetadata   :: !BPSMetadata
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

-- | The free-form metadata blob carried in a BPS patch's body. The
-- BPS spec treats these bytes as opaque — community practice is a
-- small XML document, but nothing below the porcelain layer assumes
-- a shape. This newtype exists so the porcelain surface distinguishes
-- "the metadata blob" from every other 'ByteString' that flows
-- through 'Slap.BPS.Create.createBPS'; the wire-level encoder still
-- takes raw bytes and unwrapping happens at the 'Slap.Create'
-- boundary.
newtype BPSMetadata = BPSMetadata { unBPSMetadata :: ByteString }
  deriving (Eq, Show)

-- | BPS magic bytes (@"BPS1"@) at the start of every patch.
bpsMagicBytes :: ByteString
bpsMagicBytes = "BPS1"

-- | Length of the BPS magic ("BPS1") at the start of every patch.
bpsMagicLength :: Length
bpsMagicLength = Length 4

-- | Length of one CRC32 field in a BPS patch.
bpsCRC32Length :: Length
bpsCRC32Length = Length 4

-- | Length of the BPS footer: three CRC32 fields (source, target, patch).
bpsFooterLength :: Length
bpsFooterLength = bpsCRC32Length <> bpsCRC32Length <> bpsCRC32Length

-- | Total framing overhead of a BPS patch: magic plus footer. The body
-- bytes (sizes, metadata, action stream) occupy the remainder.
bpsOverheadLength :: Length
bpsOverheadLength = bpsMagicLength <> bpsFooterLength

-- | Decode a signed varint: bit 0 = sign (1 = negative), bits 1+ = magnitude.
decodeSignedVarint :: Int64 -> Int64
decodeSignedVarint encoded =
  let magnitude = shiftR encoded 1
  in if testBit encoded 0 then negate magnitude else magnitude
