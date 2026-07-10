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
  , TextMode(..)
  , toTextMode
  , fromTextMode
  , ninja2TextModeName
  , NINJA2RomType(..)
  , toNINJA2RomType
  , fromNINJA2RomType
  , ninja2RomTypeNeedsNormalization
  , ninja2RomTypeName
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

-- Canonical reference: docs/ninja2/upstream/ninja2-filespec20.txt (Derrick Sobodash, 2006)
-- Archived from http://ninja.cinnamonpirate.com/files/filespec20.txt
-- Secondary: RomPatcher.js modules/RomPatcher.format.rup.js
-- NINJA2 ROM type numbering is defined in docs/ninja2/upstream/ninja2-cliusage.txt.
-- Cross-format conversion goes through 'Slap.PlatformType.PlatformType'.

import Slap.Checksum (MD5Hash)
import Slap.Measure (Length(..), Offset(..), FileSize(..))
import Slap.PlatformType (PlatformType)
import Slap.Text (EncodedText)

import Data.ByteString (ByteString)
import Data.ByteString.Builder (Builder, word8)
import Data.Bits ((.&.), shiftR)
import Data.Int (Int64)
import Data.Text (Text)
import qualified Data.Text as Text
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

-- | Resolve the overflow-type byte: @'A'@ (0x41) is append, @'M'@ (0x4D) truncate, anything else 'Nothing'.
toOverflowMode :: Word8 -> Maybe OverflowMode
toOverflowMode 0x41 = Just OverflowAppend
toOverflowMode 0x4D = Just OverflowTruncate
toOverflowMode _    = Nothing

fromOverflowMode :: OverflowMode -> Word8
fromOverflowMode OverflowAppend   = 0x41  -- 'A'
fromOverflowMode OverflowTruncate = 0x4D  -- 'M'

-- | PATCH_ENC: whether the patch declares its fixed-header text as UTF-8.
-- Byte 1 means UTF-8 (portable).
-- Byte 0 is the spec's "system codepage": decode with whichever codepage the reading machine uses.
-- That instruction names no particular encoding, so the byte carries no decoding information from one machine to another;
-- slap models it as 'TextModeUndeclared' and lets the user's @--metadata-encoding@ choice supply the codepage.
-- The spec defines no other values; an unrecognized byte is rejected at parse time rather than represented in this type,
-- so every 'TextMode' value we ever hold has a well-defined meaning for downstream text decoding.
data TextMode
  = TextModeUTF8
  | TextModeUndeclared
  deriving (Show, Eq)

-- | Resolve a raw PATCH_ENC byte;
-- 'Left' carries the unrecognized byte for the 'NINJA2UnrecognizedTextMode' rejection.
toTextMode :: Word8 -> Either Word8 TextMode
toTextMode 0    = Right TextModeUndeclared
toTextMode 1    = Right TextModeUTF8
toTextMode byte = Left byte

fromTextMode :: TextMode -> Word8
fromTextMode TextModeUTF8       = 1
fromTextMode TextModeUndeclared = 0

ninja2TextModeName :: TextMode -> Text
ninja2TextModeName TextModeUTF8       = "UTF-8"
ninja2TextModeName TextModeUndeclared = "undeclared"

-- | ROM platform type per ninja2-cliusage.txt.  Values 0-9 are
-- documented; NINJA2UnknownRomType preserves any future/unknown value.
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

-- | True for the ROM types NINJA2 defines a normalization for that slap does
-- not yet run: NES, SNES, N64, Game Boy, SMS and Game Gear, Genesis, PC-Engine,
-- and Lynx (@docs/ninja2/upstream/ninja2-convroms.txt@). Raw and FDS have none.
ninja2RomTypeNeedsNormalization :: NINJA2RomType -> Bool
ninja2RomTypeNeedsNormalization romType = case romType of
  NINJA2NES         -> True
  NINJA2SNES        -> True
  NINJA2N64         -> True
  NINJA2GB          -> True
  NINJA2SMSGameGear -> True
  NINJA2Genesis     -> True
  NINJA2PCEngine    -> True
  NINJA2Lynx        -> True
  _                 -> False

ninja2RomTypeName :: NINJA2RomType -> Text
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
ninja2RomTypeName (NINJA2UnknownRomType value) = "unknown (" <> Text.pack (show value) <> ")"

data NINJA2Patch = NINJA2Patch
  { ninja2Header         :: NINJA2Info
  , ninja2OpenNewFile    :: Maybe NINJA2OpenNewFile
  , ninja2TextMode       :: TextMode           -- PATCH_ENC (text mode, byte 6)
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

-- | The parsed fixed-header fields from a NINJA2 patch, decoded under the patch's declared 'TextMode'.
-- Each field carries its encoding tag on the value, so downstream conversion and display sites read the encoding directly off the value rather than consulting a side-channel.
-- Because NINJA2 declares a single @PATCH_ENC@ byte for the whole patch, every field of any given parsed 'NINJA2Info' shares the same tag,
-- but the type still models it per-field, which keeps the seam clean when the fields flow into formats whose encoding model is per-field rather than per-patch.
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

-- | The create-side inputs for 'Slap.NINJA2.Create.createNINJA2'.
-- The text fields arrive as 'EncodedText', but the encoding tag does not reach the wire:
-- create always writes UTF-8, and 'ninja2CreateTextMode' only picks the @PATCH_ENC@ byte that declares it.
data NINJA2CreateMetadata = NINJA2CreateMetadata
  { ninja2CreateMetadataAuthor      :: Maybe EncodedText
  , ninja2CreateMetadataVersion     :: Maybe EncodedText
  , ninja2CreateMetadataTitle       :: Maybe EncodedText
  , ninja2CreateMetadataGenre       :: Maybe EncodedText
  , ninja2CreateMetadataLanguage    :: Maybe EncodedText
  , ninja2CreateMetadataDate        :: Maybe EncodedText
  , ninja2CreateMetadataWebsite     :: Maybe EncodedText
  , ninja2CreateMetadataDescription :: Maybe EncodedText
  , ninja2CreateTextMode            :: TextMode
  , ninja2CreateMetadataPlatform    :: Maybe PlatformType
  } deriving (Show)

-- | The payload is an XOR mask for the bytes at the record's offset,
-- not literal replacement bytes.
data NINJA2Record = NINJA2Record
  { ninja2RecordOffset  :: !Offset
  , ninja2RecordPayload :: !ByteString
  } deriving (Show)

-- | The create-side twin of 'NINJA2Record'.
data XorRecord = XorRecord
  { xorRecordOffset  :: !Offset
  , xorRecordPayload :: !ByteString
  } deriving (Show)

-- | Wire-format magic prefix.
ninja2MagicBytes :: ByteString
ninja2MagicBytes = "NINJA2"

-- | Total size of the NINJA2 fixed header in bytes (per ninja2-filespec20.txt §2).
-- Held as 'Length' because every use site treats it as a region size:
-- parsers read this many bytes off the front of the input ('getBytes headerSize');
-- guards compare it against 'byteLength' of the input.
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

encodeVariableLengthValue :: Int64 -> Builder
encodeVariableLengthValue 0 = word8 1 <> word8 0
encodeVariableLengthValue value =
  let encodedBytes = variableLengthValueBytes value
  in word8 (fromIntegral (length encodedBytes)) <> foldMap word8 encodedBytes

variableLengthValueBytes :: Int64 -> [Word8]
variableLengthValueBytes 0 = []
variableLengthValueBytes value = fromIntegral (value .&. 0xFF) : variableLengthValueBytes (value `shiftR` 8)
