{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StrictData #-}

module Slap.NINJA2.Types
  ( NINJA2Patch(..)
  , NINJA2Record(..)
  , NINJA2Info(..)
  , NINJA2Metadata(..)
  , NINJA2OpenNewFile(..)
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
  , encodeBoundedNINJA2
  , decodeNINJA2Field
  , parsePackedInteger
  , parsePackedByteString
  , encodeVariableLengthValue
  , variableLengthValueBytes
  , headerSize
    -- * Named constants
  , ninja2MagicBytes
    -- * Field offsets
  , ninja2AuthorOffset
  , ninja2VersionOffset
  , ninja2TitleOffset
  , ninja2GenreOffset
  , ninja2LanguageOffset
  , ninja2DateOffset
  , ninja2WebsiteOffset
  , ninja2DescriptionOffset
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

import Slap.Checksum (MD5Hash)
import Slap.Get (Get, getByte, getBytes)
import Slap.Measure (Length(..), Offset(..), FileSize(..))
import Slap.Display.Primitives (padHex)
import Slap.PlatformType (PlatformType)

import Slap.TextEncoding (BoundedResult, encodeBoundedUtf8, encodeBoundedLocale,
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
-- The NINJA2 spec defines no other values; an unrecognized byte is
-- rejected at parse time rather than represented in this type, so
-- every 'PatchEncoding' value we ever hold has a well-defined meaning
-- for downstream text decoding.
data PatchEncoding
  = PatchEncodingUTF8
  | PatchEncodingSystem
  deriving (Show, Eq)

-- | Resolve a raw PATCH_ENC byte. 'Left' carries the unrecognized byte
-- so the parse site can construct a structured rejection from it;
-- 'Right' carries the resolved encoding for the rest of the parse.
toPatchEncoding :: Word8 -> Either Word8 PatchEncoding
toPatchEncoding 0    = Right PatchEncodingSystem
toPatchEncoding 1    = Right PatchEncodingUTF8
toPatchEncoding byte = Left byte

fromPatchEncoding :: PatchEncoding -> Word8
fromPatchEncoding PatchEncodingUTF8   = 1
fromPatchEncoding PatchEncodingSystem = 0

patchEncodingName :: PatchEncoding -> String
patchEncodingName PatchEncodingUTF8   = "UTF-8"
patchEncodingName PatchEncodingSystem = "system"

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

-- | Encode a 'String' into a fixed-width NINJA2 metadata field
-- under the patch's declared encoding, choosing the codepoint-boundary
-- truncator (UTF-8) or the byte-boundary one (system locale).
-- The 'BoundedResult' carries the padded field bytes (always exactly
-- @fieldWidth@ bytes) and an optional 'TruncationInfo' that the
-- create path lifts into a 'FieldTruncated' warning when truncation
-- occurred. Width is held as 'Length' so callers stay in
-- 'Length'-space; the unwrap to 'Int' happens once at this seam.
encodeBoundedNINJA2 :: PatchEncoding -> Length -> String -> BoundedResult
encodeBoundedNINJA2 PatchEncodingUTF8   = encodeBoundedUtf8   . unLength
encodeBoundedNINJA2 PatchEncodingSystem = encodeBoundedLocale . unLength

-- | Decode a raw field ByteString to String based on the patch encoding.
-- UTF-8 decodes leniently (invalid bytes become U+FFFD).
decodeNINJA2Field :: PatchEncoding -> ByteString -> String
decodeNINJA2Field PatchEncodingUTF8   = decodeUtf8Field
decodeNINJA2Field PatchEncodingSystem = decodeLocaleField

data NINJA2Patch = NINJA2Patch
  { ninja2Header         :: NINJA2Info
  , ninja2OpenNewFile    :: Maybe NINJA2OpenNewFile
  , ninja2PatchEncoding  :: PatchEncoding      -- PATCH_ENC (text encoding, byte 6)
  , ninja2Records        :: [NINJA2Record]
  , ninja2Overflow       :: Maybe ByteString  -- on-disk overflow data (XOR'd with 0xFF)
  , ninja2OverflowType   :: Maybe OverflowMode
  } deriving (Show)

-- | Fields populated by NINJA2's @OPEN_NEW_FILE@ command. The patch
-- format permits a body that never declares this command (e.g.,
-- record-only patches that don't change file size or identity); when
-- @OPEN_NEW_FILE@ is absent, none of these fields have meaningful
-- values, and the apply path falls back to source-derived defaults.
-- Grouping them in a single 'Maybe'-wrapped record means presence
-- and absence are answered by one type-level question rather than
-- by inspecting any individual field.
data NINJA2OpenNewFile = NINJA2OpenNewFile
  { openNewFileSourceMD5  :: !MD5Hash
  , openNewFileTargetMD5  :: !MD5Hash
  , openNewFileSourceSize :: !FileSize
  , openNewFileTargetSize :: !FileSize
  , openNewFileRomType    :: !NINJA2RomType
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

-- | A NINJA2 binary record: an offset followed by the XOR payload
-- bytes for that offset.
data NINJA2Record = NINJA2Record !Offset !ByteString
  deriving (Show)

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

-- | Total size of the NINJA2 fixed header in bytes (per
-- ninja2-filespec20.txt §2). Held as 'Length' because every use site
-- treats it as a region size: parsers read this many bytes off the
-- front of the input ('getBytes headerSize'); guards compare it
-- against 'byteLength' of the input. Equals @0x800@.
headerSize :: Length
headerSize = Length 0x800

-- | Per-field absolute offsets in the NINJA2 fixed-header region per
-- ninja2-filespec20.txt §2. Each offset is into the beginning of the
-- patch file (the magic bytes sit at offset 0; PATCH_ENC at offset 6;
-- the author field at offset 0x007); the parse path consumes the
-- entire 'headerSize'-byte prefix as one buffer and then indexes into
-- that buffer with these offsets.
ninja2AuthorOffset, ninja2VersionOffset, ninja2TitleOffset, ninja2GenreOffset :: Offset
ninja2LanguageOffset, ninja2DateOffset, ninja2WebsiteOffset, ninja2DescriptionOffset :: Offset
ninja2AuthorOffset      = Offset 0x007
ninja2VersionOffset     = Offset 0x05B
ninja2TitleOffset       = Offset 0x066
ninja2GenreOffset       = Offset 0x166
ninja2LanguageOffset    = Offset 0x196
ninja2DateOffset        = Offset 0x1C6
ninja2WebsiteOffset     = Offset 0x1CE
ninja2DescriptionOffset = Offset 0x3CE

-- | Per-field widths in the NINJA2 fixed-header region per
-- ninja2-filespec20.txt §2. Held as 'Length' because every use site
-- treats them as region sizes: parsers slice 'fieldWidth' bytes via
-- 'extractField'; the create path passes them to 'encodeBoundedNINJA2'
-- as the truncation budget. Sum of the eight widths equals
-- @headerSize - 7@ (84+11+256+48+48+8+512+1074 = 2041 = 0x800 - 7);
-- this is the byte length of the fixed-header region after the
-- 6-byte magic and 1-byte PATCH_ENC prefix.
ninja2AuthorWidth, ninja2VersionWidth, ninja2TitleWidth, ninja2GenreWidth :: Length
ninja2LanguageWidth, ninja2DateWidth, ninja2WebsiteWidth, ninja2DescriptionWidth :: Length
ninja2AuthorWidth      = Length 84
ninja2VersionWidth     = Length 11
ninja2TitleWidth       = Length 256
ninja2GenreWidth       = Length 48
ninja2LanguageWidth    = Length 48
ninja2DateWidth        = Length 8
ninja2WebsiteWidth     = Length 512
ninja2DescriptionWidth = Length 1074

-- | VLV: 1-byte length prefix, then N bytes little-endian.
encodeVariableLengthValue :: Int64 -> Builder
encodeVariableLengthValue 0 = word8 1 <> word8 0
encodeVariableLengthValue value =
  let encodedBytes = variableLengthValueBytes value
  in word8 (fromIntegral (length encodedBytes)) <> foldMap word8 encodedBytes

variableLengthValueBytes :: Int64 -> [Word8]
variableLengthValueBytes 0 = []
variableLengthValueBytes value = fromIntegral (value .&. 0xFF) : variableLengthValueBytes (value `shiftR` 8)
