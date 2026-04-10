module Slap.UPS.Types
  ( UPSBlock(..)
  , UPSBody(..)
  , UPSPatch(..)
    -- * Named constants
  , upsMagicLength
  , upsCRC32Length
  , upsFooterLength
  , upsOverheadLength
  , upsTerminatorByteLength
  ) where

import Slap.Checksum (CRC32)
import Slap.Measure (Length(..), FileSize(..))

import Data.ByteString (ByteString)
import Data.Vector (Vector)

data UPSBlock = UPSBlock
  { upsSkip    :: !Length
    -- ^ Number of bytes to skip (copied verbatim from source) before
    -- the XOR delta begins.
  , upsXorData :: !ByteString
    -- ^ XOR delta bytes for this block. Per the UPS spec these are
    -- never 0x00 in the encoded stream (a 0x00 byte terminates the
    -- run); the parser strips the terminator before storing. slap
    -- does not enforce the no-zero-byte invariant on the in-memory
    -- representation — it's a property of the encoded form, not a
    -- slap data invariant.
  } deriving (Show)

data UPSBody = UPSBody
  { upsBodySourceSize :: !FileSize
  , upsBodyTargetSize :: !FileSize
  , upsBodyBlocks     :: !(Vector UPSBlock)
  } deriving (Show)

data UPSPatch = UPSPatch
  { upsSourceSize :: !FileSize
  , upsTargetSize :: !FileSize
  , upsBlocks     :: !(Vector UPSBlock)
  , upsSourceCRC  :: !CRC32
  , upsTargetCRC  :: !CRC32
  , upsPatchCRC   :: !CRC32
  } deriving (Show)

-- | Length of the UPS magic ("UPS1") at the start of every patch.
upsMagicLength :: Length
upsMagicLength = Length 4

-- | Length of one CRC32 field in a UPS patch.
upsCRC32Length :: Length
upsCRC32Length = Length 4

-- | Length of the UPS footer: three CRC32 fields (source, target, patch).
upsFooterLength :: Length
upsFooterLength = upsCRC32Length <> upsCRC32Length <> upsCRC32Length

-- | Total framing overhead of a UPS patch: magic plus footer. The body
-- bytes (sizes, block stream) occupy the remainder.
upsOverheadLength :: Length
upsOverheadLength = upsMagicLength <> upsFooterLength

-- | Per the UPS spec, every diff block ends with a 0x00 terminator
-- byte that counts against the target file pointer. This is the
-- length of that terminator (always 1).
upsTerminatorByteLength :: Length
upsTerminatorByteLength = Length 1
