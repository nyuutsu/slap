module Slap.UPS.Types
  ( UPSBlock(..)
  , UPSBody(..)
  , UPSPatch(..)
    -- * Named constants
  , upsMagicSize
  , upsCRC32Size
  , upsFooterSize
  , upsTotalOverhead
  , upsTerminatorByteSize
  ) where

import Slap.Checksum (CRC32)
import Slap.Measure (FileSize(..), Delta(..))

import Data.ByteString (ByteString)
import Data.Vector (Vector)

data UPSBlock = UPSBlock
  { upsSkip    :: !Delta
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

-- | Magic ("UPS1") size in bytes.
upsMagicSize :: Int
upsMagicSize = 4

-- | Size of one CRC32 field in bytes.
upsCRC32Size :: Int
upsCRC32Size = 4

-- | Footer size: three CRC32s (source, target, patch).
upsFooterSize :: Int
upsFooterSize = 3 * upsCRC32Size

-- | Total framing overhead: magic + footer.
upsTotalOverhead :: Int
upsTotalOverhead = upsMagicSize + upsFooterSize

-- | Per the UPS spec, every diff block ends with a 0x00 terminator
-- byte that counts against the target file pointer. This is the
-- size of that terminator (always 1).
upsTerminatorByteSize :: Int
upsTerminatorByteSize = 1
