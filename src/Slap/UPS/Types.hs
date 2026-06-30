{-# LANGUAGE OverloadedStrings #-}

module Slap.UPS.Types
  ( UPSBlock(..)
  , UPSBody(..)
  , UPSPatch(..)
    -- * Named constants
  , upsMagicBytes
  , upsMagicLength
  , upsCRC32Length
  , upsFooterLength
  , upsOverheadLength
  , upsTerminatorByteLength
  , upsTerminatorByte
  ) where

import Slap.Checksum (CRC32)
import Slap.Measure (Length(..), FileSize(..))

import Data.ByteString (ByteString)
import Data.Vector (Vector)
import Data.Word (Word8)

-- | A single UPS block: a skip count followed by the XOR delta
-- bytes for this block. The skip count is the number of bytes to
-- copy verbatim from source before the XOR delta begins. Per the
-- UPS spec the XOR delta bytes are never 0x00 in the encoded
-- stream (a 0x00 byte terminates the run); the parser strips the
-- terminator before storing. slap does not enforce the no-zero-
-- byte invariant on the in-memory representation — it's a
-- property of the encoded form, not a slap data invariant.
data UPSBlock = UPSBlock !Length !ByteString
  deriving (Show)

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

-- | Wire-format magic prefix.
upsMagicBytes :: ByteString
upsMagicBytes = "UPS1"

upsMagicLength :: Length
upsMagicLength = Length 4

upsCRC32Length :: Length
upsCRC32Length = Length 4

-- | Length of the UPS footer: three CRC32 fields (source, target, patch).
upsFooterLength :: Length
upsFooterLength = upsCRC32Length <> upsCRC32Length <> upsCRC32Length

-- | Everything past this overhead — the sizes and block stream — is the body.
upsOverheadLength :: Length
upsOverheadLength = upsMagicLength <> upsFooterLength

-- | Per the UPS spec, every diff block ends with a 0x00 terminator
-- byte that counts against the target file pointer. This is the
-- length of that terminator (always 1).
upsTerminatorByteLength :: Length
upsTerminatorByteLength = Length 1

-- | The block-terminator byte; 'upsTerminatorByteLength' is its width.
upsTerminatorByte :: Word8
upsTerminatorByte = 0x00
