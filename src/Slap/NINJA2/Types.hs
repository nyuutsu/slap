{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StrictData #-}

module Slap.NINJA2.Types
  ( NINJA2Patch(..)
  , NINJA2Record(..)
  , NINJA2Info(..)
  , NINJA2Metadata(..)
  , XorRecord(..)
  , OverflowMode(..)
  , toOverflowMode
  , fromOverflowMode
  , PatchEncoding(..)
  , toPatchEncoding
  , fromPatchEncoding
  , patchEncodingName
  , NINJA2RomType(..)
  , toNINJA2RomType
  , fromNINJA2RomType
  , ninja2RomTypeName
  , encodeNINJA2String
  , decodeNINJA2Field
  , parsePackedInteger
  , parsePackedByteString
  , encodeVariableLengthValue
  , variableLengthValueBytes
  , headerSize
    -- * Named constants
  , ninja2MagicBytes
    -- * Field widths
  , ninja2AuthorWidth
  , ninja2VersionWidth
  , ninja2TitleWidth
  , ninja2GenreWidth
  , ninja2LanguageWidth
  , ninja2DateWidth
  , ninja2WebsiteWidth
  , ninja2DescriptionWidth
  ) where

-- Canonical reference: docs/specs/ninja2-filespec20.txt (Derrick Sobodash, 2006)
-- Archived from http://ninja.cinnamonpirate.com/files/filespec20.txt
-- Secondary: RomPatcher.js modules/RomPatcher.format.rup.js
-- NINJA2 ROM type numbering differs from NINJA1 (10 types vs 18);
-- see docs/specs/ninja2-cliusage.txt.  Cross-format conversion goes
-- through 'Slap.PlatformType.PlatformType'.

import Slap.Get (Get, getByte, getBytes)
import Slap.Measure (Length(..), Offset(..), FileSize(..))
import Slap.Format (padHex)
import Slap.PlatformType (PlatformType)

import Slap.TextEncoding (encodeUtf8Field, encodeLocaleField,
                          decodeUtf8Field, decodeLocaleField)

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.ByteString.Builder (Builder, word8)
import Data.Bits ((.&.), shiftR)
import Data.Int (Int64)
import Data.Word (Word8)

----------------------------------------------------------------------------
-- Types
----------------------------------------------------------------------------

-- | Overflow mode: how size changes between source and target are handled.
-- 'A' (0x41) = append extra bytes, 'M' (0x4D) = truncate.
-- Spec does not mention XOR-with-0xFF encoding of overflow data;
-- that is a RomPatcher.js convention which we follow for compatibility.
data OverflowMode = OverflowAppend | OverflowTruncate
  deriving (Show, Eq)

toOverflowMode :: Word8 -> Either String OverflowMode
toOverflowMode 0x41 = Right OverflowAppend
toOverflowMode 0x4D = Right OverflowTruncate
toOverflowMode byte = Left ("unknown overflow type: 0x" ++ padHex 2 byte)

fromOverflowMode :: OverflowMode -> Word8
fromOverflowMode OverflowAppend   = 0x41  -- 'A'
fromOverflowMode OverflowTruncate = 0x4D  -- 'M'

-- | PATCH_ENC: how text fields in the fixed header are encoded.
-- 0 = system codepage (platform-dependent), 1 = UTF-8 (portable).
-- Unknown values are preserved for round-tripping but treated as system.
data PatchEncoding
  = PatchEncodingUTF8
  | PatchEncodingSystem
  | PatchEncodingUnknown !Word8
  deriving (Show, Eq)

toPatchEncoding :: Word8 -> PatchEncoding
toPatchEncoding 1 = PatchEncodingUTF8
toPatchEncoding 0 = PatchEncodingSystem
toPatchEncoding byte = PatchEncodingUnknown byte

fromPatchEncoding :: PatchEncoding -> Word8
fromPatchEncoding PatchEncodingUTF8          = 1
fromPatchEncoding PatchEncodingSystem        = 0
fromPatchEncoding (PatchEncodingUnknown byte) = byte

patchEncodingName :: PatchEncoding -> String
patchEncodingName PatchEncodingUTF8          = "UTF-8"
patchEncodingName PatchEncodingSystem        = "system"
patchEncodingName (PatchEncodingUnknown byte) = "unknown (" ++ show byte ++ ")"

-- | ROM platform type per ninja2-cliusage.txt.  Values 0-9 are
-- documented; Ninja2UnknownRomType preserves any future/unknown value.
-- Numbering diverges from NINJA1 at value 2 (FDS vs SNES).
data NINJA2RomType
  = Ninja2Raw           -- 0: Raw Binary
  | Ninja2NES           -- 1: NES/Famicom
  | Ninja2FDS           -- 2: Famicom Disk System
  | Ninja2SNES          -- 3: SNES/Super Famicom
  | Ninja2N64           -- 4: Nintendo 64
  | Ninja2GB            -- 5: Game Boy
  | Ninja2SMSGameGear   -- 6: SMS/Game Gear
  | Ninja2Genesis       -- 7: Genesis/Megadrive
  | Ninja2PCEngine      -- 8: TurboGrafx-16/PC-Engine
  | Ninja2Lynx          -- 9: Atari Lynx
  | Ninja2UnknownRomType !Word8
  deriving (Show, Eq)

toNINJA2RomType :: Word8 -> NINJA2RomType
toNINJA2RomType 0 = Ninja2Raw
toNINJA2RomType 1 = Ninja2NES
toNINJA2RomType 2 = Ninja2FDS
toNINJA2RomType 3 = Ninja2SNES
toNINJA2RomType 4 = Ninja2N64
toNINJA2RomType 5 = Ninja2GB
toNINJA2RomType 6 = Ninja2SMSGameGear
toNINJA2RomType 7 = Ninja2Genesis
toNINJA2RomType 8 = Ninja2PCEngine
toNINJA2RomType 9 = Ninja2Lynx
toNINJA2RomType value = Ninja2UnknownRomType value

fromNINJA2RomType :: NINJA2RomType -> Word8
fromNINJA2RomType Ninja2Raw                      = 0
fromNINJA2RomType Ninja2NES                      = 1
fromNINJA2RomType Ninja2FDS                      = 2
fromNINJA2RomType Ninja2SNES                     = 3
fromNINJA2RomType Ninja2N64                      = 4
fromNINJA2RomType Ninja2GB                       = 5
fromNINJA2RomType Ninja2SMSGameGear              = 6
fromNINJA2RomType Ninja2Genesis                  = 7
fromNINJA2RomType Ninja2PCEngine                 = 8
fromNINJA2RomType Ninja2Lynx                     = 9
fromNINJA2RomType (Ninja2UnknownRomType value)   = value

ninja2RomTypeName :: NINJA2RomType -> String
ninja2RomTypeName Ninja2Raw                    = "Raw Binary"
ninja2RomTypeName Ninja2NES                    = "NES"
ninja2RomTypeName Ninja2FDS                    = "FDS"
ninja2RomTypeName Ninja2SNES                   = "SNES"
ninja2RomTypeName Ninja2N64                    = "N64"
ninja2RomTypeName Ninja2GB                     = "Game Boy"
ninja2RomTypeName Ninja2SMSGameGear            = "SMS/Game Gear"
ninja2RomTypeName Ninja2Genesis                = "Genesis"
ninja2RomTypeName Ninja2PCEngine               = "PC Engine"
ninja2RomTypeName Ninja2Lynx                   = "Lynx"
ninja2RomTypeName (Ninja2UnknownRomType value) = "unknown (" ++ show value ++ ")"

-- | Encode a String as bytes using the given patch encoding.
encodeNINJA2String :: PatchEncoding -> String -> ByteString
encodeNINJA2String PatchEncodingUTF8 = encodeUtf8Field
encodeNINJA2String _                 = encodeLocaleField

-- | Decode a raw field ByteString to String based on the patch encoding.
-- UTF-8 decodes leniently (invalid bytes become U+FFFD).
-- System and unknown encodings use the system locale.
decodeNINJA2Field :: PatchEncoding -> ByteString -> String
decodeNINJA2Field PatchEncodingUTF8 = decodeUtf8Field
decodeNINJA2Field _                 = decodeLocaleField

data NINJA2Patch = NINJA2Patch
  { ninja2Header         :: NINJA2Info
  , ninja2Records        :: [NINJA2Record]
  , ninja2Overflow       :: Maybe ByteString  -- on-disk overflow data (XOR'd with 0xFF)
  , ninja2OverflowType   :: Maybe OverflowMode
  , ninja2SourceMD5      :: Maybe ByteString  -- 16 bytes
  , ninja2TargetMD5      :: Maybe ByteString  -- 16 bytes
  , ninja2SourceSize     :: !FileSize
  , ninja2TargetSize     :: !FileSize
  , ninja2PatchEncoding  :: PatchEncoding      -- PATCH_ENC (text encoding, byte 6)
  , ninja2RomType        :: NINJA2RomType     -- ROM type from OPEN_NEW_FILE command
  } deriving (Show)

-- | The parsed fixed-header fields from a NINJA2 patch, as raw
-- pre-decoded bytes in whatever encoding the wire declares.
-- Create-path callers should use 'NINJA2Metadata' instead; this type
-- is for the parse side, which reads bytes and surfaces them for later
-- decoding via 'decodeNINJA2Field'.
data NINJA2Info = NINJA2Info
  { ninja2Author      :: Maybe ByteString
  , ninja2Version     :: Maybe ByteString
  , ninja2Title       :: Maybe ByteString
  , ninja2Genre       :: Maybe ByteString
  , ninja2Language    :: Maybe ByteString
  , ninja2Date        :: Maybe ByteString
  , ninja2Website     :: Maybe ByteString
  , ninja2Description :: Maybe ByteString
  } deriving (Show)

-- | User-intent input for 'Slap.NINJA2.Create.createNINJA2'.
-- Strings are held as 'String' (not pre-encoded bytes) so the chosen
-- 'PatchEncoding' travels with the strings that will be encoded under
-- it, and encoding happens exactly once — inside 'createNINJA2'.
-- Platform is held as 'Maybe' 'PlatformType' (not 'NINJA2RomType')
-- so the lossy shared-to-NINJA2 translation, and the warnings it
-- produces for platforms NINJA2 cannot express, also live inside
-- 'createNINJA2'.
data NINJA2Metadata = NINJA2Metadata
  { ninja2MetadataAuthor      :: Maybe String
  , ninja2MetadataVersion     :: Maybe String
  , ninja2MetadataTitle       :: Maybe String
  , ninja2MetadataGenre       :: Maybe String
  , ninja2MetadataLanguage    :: Maybe String
  , ninja2MetadataDate        :: Maybe String
  , ninja2MetadataWebsite     :: Maybe String
  , ninja2MetadataDescription :: Maybe String
  , ninja2MetadataEncoding    :: PatchEncoding
  , ninja2MetadataPlatform    :: Maybe PlatformType
  } deriving (Show)

data NINJA2Record = NINJA2Record
  { ninja2RecordOffset :: !Offset
  , ninja2RecordXor    :: !ByteString
  } deriving (Show)

-- | An XOR record for encoding: offset + XOR'd payload.
data XorRecord = XorRecord
  { xorRecordOffset  :: !Offset
  , xorRecordPayload :: !ByteString
  } deriving (Show)

----------------------------------------------------------------------------
-- VLV: Variable Length Value (1-byte length prefix, then N LE bytes)
----------------------------------------------------------------------------

parsePackedInteger :: Get Int64
parsePackedInteger = do
  count <- fromIntegral <$> getByte
  packedBytes <- getBytes (Length count)
  -- Only interpret first 8 bytes (enough for Int64); extra bytes are
  -- consumed from the stream but don't contribute to the value.
  let clampedCount = min count 8
  pure $ foldl' (\accumulated index ->
    accumulated + fromIntegral (ByteString.index packedBytes index) * (256 ^ index)) 0 [0..clampedCount-1]

parsePackedByteString :: Get ByteString
parsePackedByteString = do
  dataLength <- fromIntegral <$> parsePackedInteger
  getBytes (Length dataLength)

-- | NINJA2 magic bytes (@"NINJA2"@) at the start of every NINJA2 patch.
ninja2MagicBytes :: ByteString
ninja2MagicBytes = "NINJA2"

headerSize :: Int
headerSize = 0x800  -- NINJA2 spec: fixed 2048-byte header

-- | Fixed-header field widths (bytes) per ninja2-filespec20.txt §2.
ninja2AuthorWidth, ninja2VersionWidth, ninja2TitleWidth, ninja2GenreWidth :: Int
ninja2LanguageWidth, ninja2DateWidth, ninja2WebsiteWidth, ninja2DescriptionWidth :: Int
ninja2AuthorWidth      = 84
ninja2VersionWidth     = 11
ninja2TitleWidth       = 256
ninja2GenreWidth       = 48
ninja2LanguageWidth    = 48
ninja2DateWidth        = 8
ninja2WebsiteWidth     = 512
ninja2DescriptionWidth = 1074

-- | VLV: 1-byte length prefix, then N bytes little-endian.
encodeVariableLengthValue :: Int64 -> Builder
encodeVariableLengthValue 0 = word8 1 <> word8 0
encodeVariableLengthValue value =
  let encodedBytes = variableLengthValueBytes value
  in word8 (fromIntegral (length encodedBytes)) <> foldMap word8 encodedBytes

variableLengthValueBytes :: Int64 -> [Word8]
variableLengthValueBytes 0 = []
variableLengthValueBytes value = fromIntegral (value .&. 0xFF) : variableLengthValueBytes (value `shiftR` 8)
