{-# LANGUAGE OverloadedStrings #-}

module Slap.BPS.Types
  ( BPSAction(..)
  , BPSBody(..)
  , BPSPatch(..)
  , BPSMetadata(..)
  , decodeSignedVarint
  , isNegativeZeroSignedVarint
    -- * Named constants
  , bpsMagicBytes
  , bpsMagicLength
  , bpsCRC32Length
  , bpsFooterLength
  ) where

import Data.Bits (shiftR, testBit)
import Data.ByteString (ByteString)
import Data.Int (Int64)
import Data.Vector (Vector)
import Slap.Checksum (CRC32)
import Slap.Status (SlapAdvisory)
import Slap.Measure (Length(..), FileSize(..), Delta(..))

data BPSAction
  = SourceRead !Length
  | TargetRead !ByteString
  | SourceCopy !Length !Delta
  | TargetCopy !Length !Delta
  deriving (Show)

data BPSBody = BPSBody
  { bpsBodySourceSize :: !FileSize
  , bpsBodyTargetSize :: !FileSize
  , bpsBodyMetadata   :: !BPSMetadata
  , bpsBodyActions    :: ![BPSAction]
  , bpsBodyWarnings   :: ![SlapAdvisory]
  } deriving (Show)

data BPSPatch = BPSPatch
  { bpsSourceSize :: !FileSize
  , bpsTargetSize :: !FileSize
  , bpsMetadata   :: !BPSMetadata
  -- | Boxed (not unboxed/storable) because 'BPSAction' is a sum type containing a 'ByteString'.
  -- A 'Vector' rather than a list so the whole stream is one contiguous array of pointers —
  -- a single GC object instead of a chain of cons cells.
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

-- | Wire-format magic prefix.
bpsMagicBytes :: ByteString
bpsMagicBytes = "BPS1"

bpsMagicLength :: Length
bpsMagicLength = Length 4

bpsCRC32Length :: Length
bpsCRC32Length = Length 4

-- | Length of the BPS footer: three CRC32 fields (source, target, patch).
bpsFooterLength :: Length
bpsFooterLength = bpsCRC32Length <> bpsCRC32Length <> bpsCRC32Length

-- | Decode a signed varint: bit 0 = sign (1 = negative), bits 1+ = magnitude.
decodeSignedVarint :: Int64 -> Int64
decodeSignedVarint encoded =
  let magnitude = shiftR encoded 1
  in if testBit encoded 0 then negate magnitude else magnitude

-- | Recognize the non-canonical @0x81@ encoding of zero in a BPS signed-delta varint.
-- The sign-magnitude scheme used by 'decodeSignedVarint' admits two encodings for delta zero:
-- @0x80@ (sign 0, magnitude 0) is canonical, and @0x81@ (sign 1, magnitude 0) is "negative zero" —
-- semantically identical to @0x80@ but distinct on the wire.
--
-- The 'Int64' input is grandfathered from 'decodeSignedVarint': both
-- functions consume the post-'byuuVarint' integer rather than the
-- raw byte, so the parser can branch and decode in one place
-- without re-reading the wire.
isNegativeZeroSignedVarint :: Int64 -> Bool
isNegativeZeroSignedVarint encoded =
  testBit encoded 0 && shiftR encoded 1 == 0

