{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StrictData #-}

module Slap.APSN64.Types
  ( APSN64Patch(..)
  , APSN64Record(..)
  , APSN64Header(..)
  , APSN64Description(..)
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
    -- * Named constants
  , apsN64MagicBytes
  , apsN64DescriptionWidth
  , apsN64MaxChunkSize
  ) where

import Data.ByteString (ByteString)
import Data.Word (Word8)
import Slap.Measure (FileSize, Offset(..))

-- | The description field of an APS-N64 patch header. Locale-encoded
-- and truncated to 'apsN64DescriptionWidth' bytes on create, with a
-- 'FieldTruncated' warning emitted on overflow.
newtype APSN64Description = APSN64Description { unAPSN64Description :: String }
  deriving (Show, Eq)

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

toAPSPatchType :: Word8 -> Either String APSPatchType
toAPSPatchType 0 = Right APSSimple
toAPSPatchType 1 = Right APSN64Specific
toAPSPatchType byte = Left ("unknown patch type: " ++ show byte)

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

-- | The country code byte at offset 0x3C of an APS-N64 type-1
-- header, copied verbatim from the source N64 ROM's country byte
-- (offset 0x3E of the cartridge ROM header in canonical Z64 byte
-- order). The APS spec describes the byte as "the original image's
-- country code" without enumerating values locally; the enum is
-- defined externally by the N64 cartridge ROM header specification.
-- slap recognises the documented values and preserves any
-- unrecognised byte verbatim with an 'APSN64UnrecognisedCountry'
-- warning so round-trip identity is maintained for patches carrying
-- values slap doesn't know about.
--
-- Cross-referenced against the en64 wiki ROM article and
-- mroach/rom64's @rom_info.md@ in April 2026; both list the same
-- 20 codes.
data APSN64Country
  = APSN64CountryBeta            -- 0x37 '7'
  | APSN64CountryAsian           -- 0x41 'A' (Asian NTSC; commonly Japan+US)
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
  | APSN64CountryPAL             -- 0x50 'P'
  | APSN64CountrySpain           -- 0x53 'S'
  | APSN64CountryAustralia       -- 0x55 'U'
  | APSN64CountryScandinavia     -- 0x57 'W'
  | APSN64CountryEuropeX         -- 0x58 'X' (uncommon European variant)
  | APSN64CountryEuropeY         -- 0x59 'Y' (uncommon European variant)
  | APSN64CountryUnrecognised !Word8
  deriving (Show, Eq)

-- | Parse a country byte as an 'APSN64Country'. Total: bytes that
-- aren't recognised N64 country codes become 'APSN64CountryUnrecognised'.
toAPSN64Country :: Word8 -> APSN64Country
toAPSN64Country 0x37 = APSN64CountryBeta
toAPSN64Country 0x41 = APSN64CountryAsian
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
toAPSN64Country 0x50 = APSN64CountryPAL
toAPSN64Country 0x53 = APSN64CountrySpain
toAPSN64Country 0x55 = APSN64CountryAustralia
toAPSN64Country 0x57 = APSN64CountryScandinavia
toAPSN64Country 0x58 = APSN64CountryEuropeX
toAPSN64Country 0x59 = APSN64CountryEuropeY
toAPSN64Country byte = APSN64CountryUnrecognised byte

-- | Round-trip inverse of 'toAPSN64Country'.
fromAPSN64Country :: APSN64Country -> Word8
fromAPSN64Country APSN64CountryBeta             = 0x37
fromAPSN64Country APSN64CountryAsian            = 0x41
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
fromAPSN64Country APSN64CountryPAL              = 0x50
fromAPSN64Country APSN64CountrySpain            = 0x53
fromAPSN64Country APSN64CountryAustralia        = 0x55
fromAPSN64Country APSN64CountryScandinavia      = 0x57
fromAPSN64Country APSN64CountryEuropeX          = 0x58
fromAPSN64Country APSN64CountryEuropeY          = 0x59
fromAPSN64Country (APSN64CountryUnrecognised b) = b

data APSN64Patch = APSN64Patch APSN64Header [APSN64Record]
  deriving (Show)

data APSN64Header = APSN64Header
  { apsN64PatchType   :: APSPatchType
  , apsN64Encoding    :: APSRecordEncoding
  , apsN64Description :: ByteString   -- 50 bytes
  , apsN64ImageFormat :: Maybe APSImageFormat
  , apsN64CartId      :: Maybe N64CartId
  , apsN64Country     :: Maybe APSN64Country
  , apsN64Crc         :: Maybe N64ChecksumPair
  , apsN64DestinationSize    :: FileSize
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

-- | Description field width: 50 bytes, null-padded.
apsN64DescriptionWidth :: Int
apsN64DescriptionWidth = 50

-- | Maximum data bytes per APS-N64 record (8-bit length field).
apsN64MaxChunkSize :: Int
apsN64MaxChunkSize = 255
