{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StrictData #-}

module Slap.APSN64.Types
  ( APSN64Patch(..)
  , APSN64Record(..)
  , APSN64Header(..)
  , N64CartId(..)
  , N64ChecksumPair(..)
  , APSPatchType(..)
  , APSImageFormat(..)
  , APSRecordEncoding(..)
  , APSN64Country(..)
  , toAPSPatchType
  , fromAPSPatchType
  , toAPSImageFormat
  , fromAPSImageFormat
  , toAPSRecordEncoding
  , fromAPSRecordEncoding
  , toAPSN64Country
  , fromAPSN64Country
  , apsN64CountryName
    -- * Named constants
  , apsN64MagicBytes
  , apsN64DescriptionWidth
  , apsN64MaxChunkSize
  , apsN64RecordHeaderSize
    -- * Encoding limits
  , apsN64Limits
  , APSN64DestinationSize
  , unAPSN64DestinationSize
  , narrowAPSN64DestinationSize
  , apsN64DestinationSizeFromParsed
  , apsN64DestinationSizeAsFileSize
  ) where

import Data.ByteString (ByteString)
import Data.Text (Text)
import Data.Vector (Vector)
import Data.Word (Word8, Word32)
import Slap.Display.Primitives (padHex)
import Slap.FieldName (FieldName(FieldDestinationSize))
import Slap.FormatLabel (FormatLabel(..))
import Slap.Measure (FileSize(..), Length(..), Offset(..))
import Slap.Narrow (EncodingLimits(..), narrowToWord32)
import Slap.Status (APSN64HeaderMalformation(..), SlapError(..))
import Slap.Text (EncodedText)

-- | The 2-byte cart ID copied from the N64 ROM header at offset 0x3C
-- (the "game code" portion of the cartridge ID, e.g. @"SM"@ for
-- Super Mario 64). Carried by APS-N64 patches in the N64-specific
-- header variant and used to warn when the source ROM's cart ID
-- doesn't match. The newtype names the role at the wire boundary;
-- unwrapping happens at the advisory 'ByteCheck' construction site.
newtype N64CartId = N64CartId { unN64CartId :: ByteString }
  deriving (Show, Eq)

-- | The 8-byte checksum pair at N64 ROM header offset 0x10 (CRC1 +
-- CRC2, together sometimes called the "CIC checksum"). Carried by
-- APS-N64 patches in the N64-specific header variant as an advisory
-- identity gate on the source ROM. The newtype names the role at the
-- wire boundary; unwrapping happens at the advisory 'ByteCheck'
-- construction site.
newtype N64ChecksumPair = N64ChecksumPair { unN64ChecksumPair :: ByteString }
  deriving (Show, Eq)

data APSPatchType = APSSimple | APSN64Specific
  deriving (Show, Eq)

toAPSPatchType :: Word8 -> Either APSN64HeaderMalformation APSPatchType
toAPSPatchType 0    = Right APSSimple
toAPSPatchType 1    = Right APSN64Specific
toAPSPatchType byte = Left (APSN64UnknownPatchType byte)

fromAPSPatchType :: APSPatchType -> Word8
fromAPSPatchType APSSimple       = 0
fromAPSPatchType APSN64Specific  = 1

data APSImageFormat = V64Format | Z64Format | UnknownImageFormat Word8
  deriving (Show, Eq)

toAPSImageFormat :: Word8 -> APSImageFormat
toAPSImageFormat 0 = V64Format
toAPSImageFormat 1 = Z64Format
toAPSImageFormat byte = UnknownImageFormat byte

fromAPSImageFormat :: APSImageFormat -> Word8
fromAPSImageFormat V64Format              = 0
fromAPSImageFormat Z64Format              = 1
fromAPSImageFormat (UnknownImageFormat byte) = byte

data APSRecordEncoding
  = APSDefaultRecordEncoding
  | APSUnknownRecordEncoding !Word8
  deriving (Show, Eq)

toAPSRecordEncoding :: Word8 -> APSRecordEncoding
toAPSRecordEncoding 0 = APSDefaultRecordEncoding
toAPSRecordEncoding byte = APSUnknownRecordEncoding byte

fromAPSRecordEncoding :: APSRecordEncoding -> Word8
fromAPSRecordEncoding APSDefaultRecordEncoding        = 0
fromAPSRecordEncoding (APSUnknownRecordEncoding byte) = byte

-- | The N64 ROM country byte (ROM header offset 0x3E), copied into the
-- APS-N64 type-1 header for source verification. The common codes are
-- verified against real patches; the rarer ones are documented but unconfirmed
-- (see docs/aps-n64/country-codes.md). 'APSN64CountryUnrecognized'
-- preserves any other byte for round-tripping.
data APSN64Country
  = APSN64CountryRegionFree      -- 0x00      region-free / unstamped
  | APSN64CountryBeta            -- 0x37 '7'
  | APSN64CountryAll             -- 0x41 'A'  all regions / multi-region
  | APSN64CountryBrazil          -- 0x42 'B'
  | APSN64CountryChina           -- 0x43 'C'
  | APSN64CountryGermany         -- 0x44 'D'
  | APSN64CountryUSA             -- 0x45 'E'
  | APSN64CountryFrance          -- 0x46 'F'
  | APSN64CountryGateway64NTSC   -- 0x47 'G'
  | APSN64CountryNetherlands     -- 0x48 'H'
  | APSN64CountryItaly           -- 0x49 'I'
  | APSN64CountryJapan           -- 0x4A 'J'
  | APSN64CountryKorea           -- 0x4B 'K'
  | APSN64CountryGateway64PAL    -- 0x4C 'L'
  | APSN64CountryCanada          -- 0x4E 'N'
  | APSN64CountryEurope          -- 0x50 'P'  pan-European
  | APSN64CountrySpain           -- 0x53 'S'
  | APSN64CountryAustralia       -- 0x55 'U'
  | APSN64CountryScandinavia     -- 0x57 'W'
  | APSN64CountryEuropeX         -- 0x58 'X'  European, alternate-language SKU
  | APSN64CountryEuropeY         -- 0x59 'Y'  European, alternate-language SKU
  | APSN64CountryEuropeZ         -- 0x5A 'Z'  European, alternate-language SKU
  | APSN64CountryUnrecognized !Word8
  deriving (Show, Eq)

-- | Parse a country byte as an 'APSN64Country'. Total: bytes that
-- aren't recognized N64 country codes become 'APSN64CountryUnrecognized'.
toAPSN64Country :: Word8 -> APSN64Country
toAPSN64Country 0x00 = APSN64CountryRegionFree
toAPSN64Country 0x37 = APSN64CountryBeta
toAPSN64Country 0x41 = APSN64CountryAll
toAPSN64Country 0x42 = APSN64CountryBrazil
toAPSN64Country 0x43 = APSN64CountryChina
toAPSN64Country 0x44 = APSN64CountryGermany
toAPSN64Country 0x45 = APSN64CountryUSA
toAPSN64Country 0x46 = APSN64CountryFrance
toAPSN64Country 0x47 = APSN64CountryGateway64NTSC
toAPSN64Country 0x48 = APSN64CountryNetherlands
toAPSN64Country 0x49 = APSN64CountryItaly
toAPSN64Country 0x4A = APSN64CountryJapan
toAPSN64Country 0x4B = APSN64CountryKorea
toAPSN64Country 0x4C = APSN64CountryGateway64PAL
toAPSN64Country 0x4E = APSN64CountryCanada
toAPSN64Country 0x50 = APSN64CountryEurope
toAPSN64Country 0x53 = APSN64CountrySpain
toAPSN64Country 0x55 = APSN64CountryAustralia
toAPSN64Country 0x57 = APSN64CountryScandinavia
toAPSN64Country 0x58 = APSN64CountryEuropeX
toAPSN64Country 0x59 = APSN64CountryEuropeY
toAPSN64Country 0x5A = APSN64CountryEuropeZ
toAPSN64Country byte = APSN64CountryUnrecognized byte

-- | Round-trip inverse of 'toAPSN64Country'.
fromAPSN64Country :: APSN64Country -> Word8
fromAPSN64Country APSN64CountryRegionFree       = 0x00
fromAPSN64Country APSN64CountryBeta             = 0x37
fromAPSN64Country APSN64CountryAll              = 0x41
fromAPSN64Country APSN64CountryBrazil           = 0x42
fromAPSN64Country APSN64CountryChina            = 0x43
fromAPSN64Country APSN64CountryGermany          = 0x44
fromAPSN64Country APSN64CountryUSA              = 0x45
fromAPSN64Country APSN64CountryFrance           = 0x46
fromAPSN64Country APSN64CountryGateway64NTSC    = 0x47
fromAPSN64Country APSN64CountryNetherlands      = 0x48
fromAPSN64Country APSN64CountryItaly            = 0x49
fromAPSN64Country APSN64CountryJapan            = 0x4A
fromAPSN64Country APSN64CountryKorea            = 0x4B
fromAPSN64Country APSN64CountryGateway64PAL     = 0x4C
fromAPSN64Country APSN64CountryCanada           = 0x4E
fromAPSN64Country APSN64CountryEurope           = 0x50
fromAPSN64Country APSN64CountrySpain            = 0x53
fromAPSN64Country APSN64CountryAustralia        = 0x55
fromAPSN64Country APSN64CountryScandinavia      = 0x57
fromAPSN64Country APSN64CountryEuropeX          = 0x58
fromAPSN64Country APSN64CountryEuropeY          = 0x59
fromAPSN64Country APSN64CountryEuropeZ          = 0x5A
fromAPSN64Country (APSN64CountryUnrecognized b) = b

-- | Human-facing country label for 'slap info'.
apsN64CountryName :: APSN64Country -> Text
apsN64CountryName APSN64CountryRegionFree          = "region-free"
apsN64CountryName APSN64CountryBeta                = "Beta"
apsN64CountryName APSN64CountryAll                 = "all regions"
apsN64CountryName APSN64CountryBrazil              = "Brazil"
apsN64CountryName APSN64CountryChina               = "China"
apsN64CountryName APSN64CountryGermany             = "Germany"
apsN64CountryName APSN64CountryUSA                 = "USA"
apsN64CountryName APSN64CountryFrance              = "France"
apsN64CountryName APSN64CountryGateway64NTSC       = "Gateway 64 (NTSC)"
apsN64CountryName APSN64CountryNetherlands         = "Netherlands"
apsN64CountryName APSN64CountryItaly               = "Italy"
apsN64CountryName APSN64CountryJapan               = "Japan"
apsN64CountryName APSN64CountryKorea               = "Korea"
apsN64CountryName APSN64CountryGateway64PAL        = "Gateway 64 (PAL)"
apsN64CountryName APSN64CountryCanada              = "Canada"
apsN64CountryName APSN64CountryEurope              = "Europe"
apsN64CountryName APSN64CountrySpain               = "Spain"
apsN64CountryName APSN64CountryAustralia           = "Australia"
apsN64CountryName APSN64CountryScandinavia         = "Scandinavia"
apsN64CountryName APSN64CountryEuropeX             = "Europe (X)"
apsN64CountryName APSN64CountryEuropeY             = "Europe (Y)"
apsN64CountryName APSN64CountryEuropeZ             = "Europe (Z)"
apsN64CountryName (APSN64CountryUnrecognized byte) = "unknown (0x" <> padHex 2 byte <> ")"

data APSN64Patch = APSN64Patch APSN64Header !(Vector APSN64Record)
  deriving (Show)

data APSN64Header = APSN64Header
  { apsN64PatchType       :: APSPatchType
  , apsN64Encoding        :: APSRecordEncoding
  , apsN64Description     :: EncodedText
    -- ^ 50-byte description field, decoded at parse time under the
    -- process locale. Same encoding model as PPF1\/PPF2\/PPF3\/PPF4;
    -- the wire field is space-padded on encode.
  , apsN64ImageFormat     :: Maybe APSImageFormat
  , apsN64CartId          :: Maybe N64CartId
  , apsN64Country         :: Maybe APSN64Country
  , apsN64Crc             :: Maybe N64ChecksumPair
  , apsN64DestinationSize :: APSN64DestinationSize
  } deriving (Show)

data APSN64Record
  = APSN64Normal
      { apsN64NormalOffset :: !Offset
      , apsN64NormalData   :: !ByteString
      }
  | APSN64RLE
      { apsN64RLEOffset      :: !Offset
      , apsN64RLEFillValue   :: !Word8
      , apsN64RLERepeatCount :: !Word8
      }
  deriving (Show)

-- | APS-N64 magic bytes (@"APS10"@). One byte longer than
-- APS-GBA's @"APS1"@ — detection must check this probe first.
apsN64MagicBytes :: ByteString
apsN64MagicBytes = "APS10"

-- | Description field width: 50 bytes, space-padded.
apsN64DescriptionWidth :: Length
apsN64DescriptionWidth = Length 50

-- | Maximum data bytes per APS-N64 record (8-bit length field).
apsN64MaxChunkSize :: Length
apsN64MaxChunkSize = Length 255

-- | Each APSN64 record begins with a 4-byte offset and a 1-byte
-- length-or-RLE-marker. A walker needs at least this many bytes
-- remaining to start parsing another record.
apsN64RecordHeaderSize :: Length
apsN64RecordHeaderSize = Length 5

-- | APS-N64's per-record offset wire field is 4-byte little-endian Word32, so offsets must fit in 2^32 bytes.
-- Enforced at narrow time so silent truncation in 'Slap.APSN64.Create.encodeAPSN64Record' is structurally impossible.
apsN64Limits :: EncodingLimits
apsN64Limits = EncodingLimits
  { maximumOffset = Offset 0xFFFFFFFF
  , formatLabel   = LabelAPSN64
  }

-- | APS-N64's 4-byte little-endian destination-size header field,
-- narrowed from a runtime 'FileSize'. Constructor private; values come
-- from 'narrowAPSN64DestinationSize' (the create-path width check, which
-- refuses a value past @0xFFFFFFFF@ rather than masking it) or
-- 'apsN64DestinationSizeFromParsed' (parse-time trust). APS-N64 imposes
-- no source/target size-pair rule, so this rides the create path on its
-- own channel.
newtype APSN64DestinationSize =
  APSN64DestinationSize { unAPSN64DestinationSize :: Word32 }
  deriving (Show, Eq)

narrowAPSN64DestinationSize :: FileSize -> Either SlapError APSN64DestinationSize
narrowAPSN64DestinationSize size =
  case narrowToWord32 LabelAPSN64 FieldDestinationSize (unFileSize size) of
    Left  failure -> Left (NarrowingError failure)
    Right word    -> Right (APSN64DestinationSize word)

-- | Trust a parsed 4-byte field as a destination size; the wire shape
-- already constrained it to a 'Word32'.
apsN64DestinationSizeFromParsed :: Word32 -> APSN64DestinationSize
apsN64DestinationSizeFromParsed = APSN64DestinationSize

-- | Lift a 'APSN64DestinationSize' back to a 'FileSize' for callers in
-- the application's general size currency ('Slap.SomePatch''s output
-- size, 'Slap.APSN64.Describe''s info line). 'Int' is 64-bit in slap,
-- so the 'Word32' → 'Int' conversion never truncates.
apsN64DestinationSizeAsFileSize :: APSN64DestinationSize -> FileSize
apsN64DestinationSizeAsFileSize (APSN64DestinationSize word) =
  FileSize (fromIntegral word)
