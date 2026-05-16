{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StrictData #-}

module Slap.GDIFF.Types
  ( GDiffPatch(..)
  , GDiffCommand(..)
    -- * Named constants
  , gdiffMagicBytes
  , maxSingleCommandLength
  , maximumTwoByteOffset
  , maximumFourByteOffset
  , maximumOneByteLength
  , maximumTwoByteLength
  ) where

import Slap.Measure (Offset(..), Length(..))

import Data.ByteString (ByteString)

data GDiffCommand
  = GDiffCommandData
      { gdiffDataPayload :: !ByteString
      }
  | GDiffCommandCopy
      { gdiffCopyOffset :: !Offset
      , gdiffCopyLength :: !Length
      }
  deriving (Show)

newtype GDiffPatch = GDiffPatch
  { gdiffCommands :: [GDiffCommand]
  } deriving (Show)

-- | GDIFF magic bytes (@0xD1 0xFF 0xD1 0xFF@) per W3C NOTE-GDIFF-19970901.
gdiffMagicBytes :: ByteString
gdiffMagicBytes = "\xd1\xff\xd1\xff"

-- | Maximum length of a single COPY or DATA command's payload, per
-- the W3C GDIFF spec's @int@ type (signed 32-bit). Lengths exceeding
-- this limit must be split into multiple commands.
maxSingleCommandLength :: Length
maxSingleCommandLength = Length 0x7FFFFFFF

-- | The largest 'Offset' that a two-byte opcode offset field can
-- carry on the wire. COPY opcodes 249, 250, and 251 use this field
-- width for their offset; offsets above this bound require a wider
-- opcode.
maximumTwoByteOffset :: Offset
maximumTwoByteOffset = Offset 0xFFFF

-- | The largest 'Offset' that a four-byte opcode offset field can
-- carry on the wire. COPY opcodes 252, 253, and 254 use this field
-- width for their offset; offsets above this bound require the
-- eight-byte field carried only by COPY 255.
maximumFourByteOffset :: Offset
maximumFourByteOffset = Offset 0xFFFFFFFF

-- | The largest 'Length' that a one-byte opcode length field can
-- carry on the wire. COPY opcodes 249 and 252 use this field width
-- for their length; lengths above this bound require a wider opcode.
maximumOneByteLength :: Length
maximumOneByteLength = Length 0xFF

-- | The largest 'Length' that a two-byte opcode length field can
-- carry on the wire. COPY opcodes 250 and 253 use this field width
-- for their length; lengths above this bound require the four-byte
-- field (itself capped at 'maxSingleCommandLength' by the spec's
-- signed @int@ type).
maximumTwoByteLength :: Length
maximumTwoByteLength = Length 0xFFFF
