{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StrictData #-}

module Slap.NINJA2.Types
  ( NINJA2Patch(..)
  , NINJA2Record(..)
  , NINJA2Info(..)
  , NINJA2CreateMetadata(..)
  , NINJA2OpenNewFile(..)
  , XorRecord(..)
  , OverflowMode(..)
  , toOverflowMode
  , fromOverflowMode
  , PatchEncoding(..)
  , toPatchEncoding
  , fromPatchEncoding
  , patchEncodingName
  , patchEncodingToTag
  , tagToPatchEncoding
  , NINJA2RomType(..)
  , toNINJA2RomType
  , fromNINJA2RomType
  , ninja2RomTypeName
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
import Slap.ByteParser (ByteParser, getByte, getBytes)
import Slap.Measure (Length(..), Offset(..), FileSize(..))
import Slap.Display.Primitives (padHex)
import Slap.PlatformType (PlatformType)
import Slap.Text (EncodedText, EncodingName(..))

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

-- | Translate NINJA2's per-patch 'PatchEncoding' to 'Slap.Text''s
-- per-value 'EncodingName' tag. The two enums encode the same choice
-- under different vocabularies: 'PatchEncoding' is the wire-byte's
-- name (\"the patch declares UTF-8\" vs \"the patch declares system
-- locale\"); 'EncodingName' is the typed-value's tag (\"this
-- 'EncodedText' is UTF-8\" vs \"this 'EncodedText' follows the
-- process locale\"). The parse path uses this to stamp the wire's
-- declaration onto each decoded field; the create path uses
-- 'tagToPatchEncoding' to round-trip the choice back to a wire byte.
patchEncodingToTag :: PatchEncoding -> EncodingName
patchEncodingToTag PatchEncodingUTF8   = EncodingUtf8
patchEncodingToTag PatchEncodingSystem = EncodingLocale

-- | Inverse of 'patchEncodingToTag'. Used by the create path to map
-- the chosen target encoding back to a wire 'PatchEncoding' for the
-- @PATCH_ENC@ byte.
tagToPatchEncoding :: EncodingName -> PatchEncoding
tagToPatchEncoding EncodingUtf8   = PatchEncodingUTF8
tagToPatchEncoding EncodingLocale = PatchEncodingSystem

-- | ROM platform type per ninja2-cliusage.txt.  Values 0-9 are
-- documented; NINJA2UnknownRomType preserves any future/unknown value.
-- Numbering diverges from NINJA1 at value 2 (FDS vs SNES).
data NINJA2RomType
  = NINJA2Raw           -- 0: Raw Binary
  | NINJA2NES           -- 1: NES/Famicom
  | NINJA2FDS           -- 2: Famicom Disk System
  | NINJA2SNES          -- 3: SNES/Super Famicom
  | NINJA2N64           -- 4: Nintendo 64
  | NINJA2GB            -- 5: Game Boy
  | NINJA2SMSGameGear   -- 6: SMS/Game Gear
  | NINJA2Genesis       -- 7: Genesis/Megadrive
  | NINJA2PCEngine      -- 8: TurboGrafx-16/PC-Engine
  | NINJA2Lynx          -- 9: Atari Lynx
  | NINJA2UnknownRomType !Word8
  deriving (Show, Eq)

toNINJA2RomType :: Word8 -> NINJA2RomType
toNINJA2RomType 0 = NINJA2Raw
toNINJA2RomType 1 = NINJA2NES
toNINJA2RomType 2 = NINJA2FDS
toNINJA2RomType 3 = NINJA2SNES
toNINJA2RomType 4 = NINJA2N64
toNINJA2RomType 5 = NINJA2GB
toNINJA2RomType 6 = NINJA2SMSGameGear
toNINJA2RomType 7 = NINJA2Genesis
toNINJA2RomType 8 = NINJA2PCEngine
toNINJA2RomType 9 = NINJA2Lynx
toNINJA2RomType value = NINJA2UnknownRomType value

fromNINJA2RomType :: NINJA2RomType -> Word8
fromNINJA2RomType NINJA2Raw                      = 0
fromNINJA2RomType NINJA2NES                      = 1
fromNINJA2RomType NINJA2FDS                      = 2
fromNINJA2RomType NINJA2SNES                     = 3
fromNINJA2RomType NINJA2N64                      = 4
fromNINJA2RomType NINJA2GB                       = 5
fromNINJA2RomType NINJA2SMSGameGear              = 6
fromNINJA2RomType NINJA2Genesis                  = 7
fromNINJA2RomType NINJA2PCEngine                 = 8
fromNINJA2RomType NINJA2Lynx                     = 9
fromNINJA2RomType (NINJA2UnknownRomType value)   = value

ninja2RomTypeName :: NINJA2RomType -> String
ninja2RomTypeName NINJA2Raw                    = "Raw Binary"
ninja2RomTypeName NINJA2NES                    = "NES"
ninja2RomTypeName NINJA2FDS                    = "FDS"
ninja2RomTypeName NINJA2SNES                   = "SNES"
ninja2RomTypeName NINJA2N64                    = "N64"
ninja2RomTypeName NINJA2GB                     = "Game Boy"
ninja2RomTypeName NINJA2SMSGameGear            = "SMS/Game Gear"
ninja2RomTypeName NINJA2Genesis                = "Genesis"
ninja2RomTypeName NINJA2PCEngine               = "PC Engine"
ninja2RomTypeName NINJA2Lynx                   = "Lynx"
ninja2RomTypeName (NINJA2UnknownRomType value) = "unknown (" ++ show value ++ ")"

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

-- | The parsed fixed-header fields from a NINJA2 patch, decoded under
-- the patch's declared 'PatchEncoding'. Each field carries its
-- encoding tag on the value, so downstream conversion and display
-- sites read the encoding directly off the value rather than
-- consulting a side-channel. Because NINJA2 declares a single
-- @PATCH_ENC@ byte for the whole patch, every field of any given
-- parsed 'NINJA2Info' shares the same tag — but the type stays
-- honest about that being a per-field property, which keeps the
-- seam clean when the fields flow into formats whose encoding model
-- is per-field rather than per-patch.
data NINJA2Info = NINJA2Info
  { ninja2Author      :: Maybe EncodedText
  , ninja2Version     :: Maybe EncodedText
  , ninja2Title       :: Maybe EncodedText
  , ninja2Genre       :: Maybe EncodedText
  , ninja2Language    :: Maybe EncodedText
  , ninja2Date        :: Maybe EncodedText
  , ninja2Website     :: Maybe EncodedText
  , ninja2Description :: Maybe EncodedText
  } deriving (Show)

-- | User-intent input for 'Slap.NINJA2.Create.createNINJA2'. Each
-- text field is 'EncodedText', so the value's encoding decision
-- travels with the text into the encoder; the per-patch
-- 'ninja2CreateMetadataEncoding' picks the target wire encoding (the
-- byte slap writes for @PATCH_ENC@), and 'createNINJA2' transcodes
-- each field's content under that target before writing it to the
-- fixed-width header slot. Platform is held as 'Maybe' 'PlatformType'
-- (not 'NINJA2RomType') so the lossy shared-to-NINJA2 translation,
-- and the warnings it produces for platforms NINJA2 cannot express,
-- both live inside 'createNINJA2'.
data NINJA2CreateMetadata = NINJA2CreateMetadata
  { ninja2CreateMetadataAuthor      :: Maybe EncodedText
  , ninja2CreateMetadataVersion     :: Maybe EncodedText
  , ninja2CreateMetadataTitle       :: Maybe EncodedText
  , ninja2CreateMetadataGenre       :: Maybe EncodedText
  , ninja2CreateMetadataLanguage    :: Maybe EncodedText
  , ninja2CreateMetadataDate        :: Maybe EncodedText
  , ninja2CreateMetadataWebsite     :: Maybe EncodedText
  , ninja2CreateMetadataDescription :: Maybe EncodedText
  , ninja2CreateMetadataEncoding    :: PatchEncoding
  , ninja2CreateMetadataPlatform    :: Maybe PlatformType
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

parsePackedInteger :: ByteParser Int64
parsePackedInteger = do
  count <- fromIntegral <$> getByte
  packedBytes <- getBytes (Length count)
  -- Only interpret first 8 bytes (enough for Int64); extra bytes are
  -- consumed from the stream but don't contribute to the value.
  let clampedCount = min count 8
  pure $ foldl' (\accumulated index ->
    accumulated + fromIntegral (ByteString.index packedBytes index) * (256 ^ index)) 0 [0..clampedCount-1]

parsePackedByteString :: ByteParser ByteString
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
-- treats them as region sizes: parsers slice 'fieldWidth' bytes off
-- the header buffer; the create path passes them to
-- 'Slap.Text.encodeTextBounded' as the truncation budget. Sum of the
-- eight widths equals @headerSize - 7@ (84+11+256+48+48+8+512+1074 =
-- 2041 = 0x800 - 7); this is the byte length of the fixed-header
-- region after the 6-byte magic and 1-byte PATCH_ENC prefix.
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
