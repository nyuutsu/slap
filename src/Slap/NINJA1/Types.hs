{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StrictData #-}

module Slap.NINJA1.Types
  ( NINJA1Patch(..)
  , NINJA1Record(..)
  , NINJA1BinaryResult(..)
  , NINJA1TextHeader(..)
  , NINJA1SubFormat(..)
  , NINJA1RomType(..)
  , NINJA1Compression(..)
  , toNINJA1RomType
  , fromNINJA1RomType
  , toNINJA1SubFormat
  , romTypeName
  , subFormatName
    -- * Named constants
  , ninja1MagicBytes
  , ninja1SentinelOffset
  , ninja1BinaryEOFMarkerBytes
  , ninja1BinaryEOFMarkerWidth
    -- * Source/target size-pair rule
  , ninja1RejectIncompatibleSizeChange
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.Text (Text)
import qualified Data.Text as Text
import Data.Word (Word8)
import Slap.Checksum (CRC32, MD5Hash, SHA1Hash)
import Slap.Measure (Offset(..), SentinelOffset(..),
                     FileSize, ActualSize(..), ExpectedSize(..))
import Slap.Status (SlapError(..), UnencodeabilityReason(..))
import Slap.FormatLabel (FormatLabel(..))

data NINJA1SubFormat = NINJA1Binary | NINJA1BinaryCompressed | NINJA1Text | NINJA1TextCompressed
  deriving (Show, Eq)

-- | Decode the two-byte subformat identifier that follows the
-- 'ninja1MagicBytes' header. The four wire values are @"B "@,
-- @"BZ"@, @"T\\n"@ (bytes 0x54 0x0A), and @"TZ"@; anything else
-- means slap doesn't know what this NINJA1 payload claims to be
-- and 'Slap.NINJA1.Parse.parseNINJA1' refuses it as
-- 'UnsupportedNINJA1Subformat'.
--
-- The text-uncompressed identifier is the one historical
-- divergence between spec and reference implementation: the
-- archived format spec (@docs/specs/ninja1-filespec10.txt@) says
-- the second byte is @0x0D@, but the canonical PHP reference
-- (@docs/specs/ninja-1.01php.tar.gz@) writes @chr(0x0A)@. The
-- spec hex is wrong; slap follows the implementation byte.
toNINJA1SubFormat :: ByteString -> Maybe NINJA1SubFormat
toNINJA1SubFormat bytes
  | bytes == "B "                          = Just NINJA1Binary
  | bytes == "BZ"                          = Just NINJA1BinaryCompressed
  | bytes == ByteString.pack [0x54, 0x0A]  = Just NINJA1Text
  | bytes == "TZ"                          = Just NINJA1TextCompressed
  | otherwise                              = Nothing

-- | Whether the NINJA1 payload is written to disk as raw bytes
-- ('NINJA1Uncompressed', the @"NINJA1B "@ subformat) or zlib-deflated
-- ('NINJA1Compressed', the @"NINJA1BZ"@ subformat). A two-constructor
-- sum rather than a 'Bool' so the BZ vs non-BZ distinction is named
-- at call sites and in error renderings.
data NINJA1Compression = NINJA1Uncompressed | NINJA1Compressed
  deriving (Show, Eq)

-- | ROM platform type. Values 0-17 are defined by the NINJA1 spec;
-- RomUnknown preserves any future/unknown value without crashing.
data NINJA1RomType
  = RomRAW | RomNES | RomSNES | RomN64 | RomGB | RomGBC | RomGBA
  | RomNGP | RomNGPC | RomSMS | RomGameGear | RomGenesis
  | RomPCEngine | RomWonderSwan | RomWonderSwanColor
  | RomLynx | RomJaguar | RomGP32
  | RomUnknown Word8
  deriving (Show, Eq)

toNINJA1RomType :: Word8 -> NINJA1RomType
toNINJA1RomType  0 = RomRAW
toNINJA1RomType  1 = RomNES
toNINJA1RomType  2 = RomSNES
toNINJA1RomType  3 = RomN64
toNINJA1RomType  4 = RomGB
toNINJA1RomType  5 = RomGBC
toNINJA1RomType  6 = RomGBA
toNINJA1RomType  7 = RomNGP
toNINJA1RomType  8 = RomNGPC
toNINJA1RomType  9 = RomSMS
toNINJA1RomType 10 = RomGameGear
toNINJA1RomType 11 = RomGenesis
toNINJA1RomType 12 = RomPCEngine
toNINJA1RomType 13 = RomWonderSwan
toNINJA1RomType 14 = RomWonderSwanColor
toNINJA1RomType 15 = RomLynx
toNINJA1RomType 16 = RomJaguar
toNINJA1RomType 17 = RomGP32
toNINJA1RomType  value = RomUnknown value

fromNINJA1RomType :: NINJA1RomType -> Word8
fromNINJA1RomType RomRAW            = 0
fromNINJA1RomType RomNES            = 1
fromNINJA1RomType RomSNES           = 2
fromNINJA1RomType RomN64            = 3
fromNINJA1RomType RomGB             = 4
fromNINJA1RomType RomGBC            = 5
fromNINJA1RomType RomGBA            = 6
fromNINJA1RomType RomNGP            = 7
fromNINJA1RomType RomNGPC           = 8
fromNINJA1RomType RomSMS            = 9
fromNINJA1RomType RomGameGear       = 10
fromNINJA1RomType RomGenesis        = 11
fromNINJA1RomType RomPCEngine       = 12
fromNINJA1RomType RomWonderSwan     = 13
fromNINJA1RomType RomWonderSwanColor = 14
fromNINJA1RomType RomLynx           = 15
fromNINJA1RomType RomJaguar         = 16
fromNINJA1RomType RomGP32           = 17
fromNINJA1RomType (RomUnknown value) = value

data NINJA1BinaryResult = NINJA1BinaryResult
  { ninja1BinaryRecords  :: ![NINJA1Record]
  , ninja1BinaryCleanEOF :: !Bool
  } deriving (Show)

data NINJA1TextHeader = NINJA1TextHeader
  { ninja1TextRomType    :: !NINJA1RomType
  , ninja1TextSourceCRC  :: !(Maybe CRC32)
  , ninja1TextSourceMD5  :: !(Maybe MD5Hash)
  , ninja1TextSourceSHA1 :: !(Maybe SHA1Hash)
  } deriving (Show)

data NINJA1Patch = NINJA1Patch
  { ninja1SubFormat  :: NINJA1SubFormat
  , ninja1RomType    :: NINJA1RomType
  , ninja1SourceCRC  :: Maybe CRC32
  , ninja1SourceMD5  :: Maybe MD5Hash
  , ninja1SourceSHA1 :: Maybe SHA1Hash
  , ninja1Records    :: [NINJA1Record]
  , ninja1CleanEOF   :: Bool              -- parse completed cleanly (binary: EOF sentinel found; text: always True)
  } deriving (Show)

data NINJA1Record = NINJA1Record
  { ninja1RecordOffset :: !Offset
  , ninja1RecordData   :: !ByteString
  } deriving (Show)

-- | NINJA1 magic bytes (@"NINJA1"@) at the start of every NINJA1 patch.
-- The two bytes following the magic identify the subformat (binary,
-- binary-compressed, text, text-compressed).
ninja1MagicBytes :: ByteString
ninja1MagicBytes = "NINJA1"

-- | The NINJA1 binary format's footer is encoded as a width prefix of 3
-- followed by the bytes "EOF" (0x45 0x4F 0x46). When a record's offset
-- minimally encodes to exactly those three bytes — which happens for
-- offset value 0x454F46 = 4,542,278 — its emitted bytes collide with
-- the footer. Slap detects this collision at create time and shifts
-- the record back to offset 0x454F45, prepending the source byte at
-- 0x454F45 to the payload.
ninja1SentinelOffset :: SentinelOffset
ninja1SentinelOffset = SentinelOffset (Offset 0x454F46)

-- | The 3-byte trailer that closes a NINJA1 binary record stream
-- (@"EOF"@, bytes @0x45 0x4F 0x46@). Encoded on the wire as an
-- offset-width-3 record whose offset bytes spell @"EOF"@; see
-- 'ninja1SentinelOffset' for the collision case the encoder
-- works around.
ninja1BinaryEOFMarkerBytes :: ByteString
ninja1BinaryEOFMarkerBytes = "EOF"

-- | Width of the 'ninja1BinaryEOFMarkerBytes' trailer, in bytes.
-- A 3-byte offset width followed by 'ninja1BinaryEOFMarkerBytes'
-- is the on-wire encoding of the binary-format footer.
ninja1BinaryEOFMarkerWidth :: Int
ninja1BinaryEOFMarkerWidth = 3

romTypeName :: NINJA1RomType -> Text
romTypeName RomRAW            = "RAW"
romTypeName RomNES            = "NES"
romTypeName RomSNES           = "SNES"
romTypeName RomN64            = "N64"
romTypeName RomGB             = "GB"
romTypeName RomGBC            = "GBC"
romTypeName RomGBA            = "GBA"
romTypeName RomNGP            = "NGP"
romTypeName RomNGPC           = "NGPC"
romTypeName RomSMS            = "SMS"
romTypeName RomGameGear       = "Game Gear"
romTypeName RomGenesis        = "Genesis"
romTypeName RomPCEngine       = "PC Engine"
romTypeName RomWonderSwan     = "WonderSwan"
romTypeName RomWonderSwanColor = "WonderSwan Color"
romTypeName RomLynx           = "Lynx"
romTypeName RomJaguar         = "Jaguar"
romTypeName RomGP32           = "GP32"
romTypeName (RomUnknown value) = "unknown (" <> Text.pack (show value) <> ")"

subFormatName :: NINJA1SubFormat -> Text
subFormatName NINJA1Binary           = "binary"
subFormatName NINJA1BinaryCompressed = "binary, compressed"
subFormatName NINJA1Text             = "text"
subFormatName NINJA1TextCompressed   = "text, compressed"

-- | NINJA1 declines (source, target) pairs whose target is shorter than
-- the source. NINJA1 records only write bytes at offsets; the reference
-- maker emits a trailing record to grow a longer target but has no
-- truncate directive and no output-size field, so a shorter output has
-- no representation — applying the offset-writes to the source yields a
-- file no smaller than the source. Growth is fine. See
-- @docs\/ninja1\/upstream\/ninja1-filespec10.txt@.
--
-- Consumed by 'Slap.Convert.rejectIncompatibleSizeChange' through its
-- 'CreateNINJA1' arm.
ninja1RejectIncompatibleSizeChange
  :: FileSize -> FileSize -> Either SlapError ()
ninja1RejectIncompatibleSizeChange sourceSize targetSize
  | sourceSize <= targetSize = Right ()
  | otherwise                = Left (UnencodeablePair LabelNINJA1
      (TargetShrinksBelowSource (ActualSize sourceSize) (ExpectedSize targetSize)))
