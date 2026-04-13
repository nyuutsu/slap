{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StrictData #-}

module Slap.APSN64.Types
  ( APSN64Patch(..)
  , APSN64Record(..)
  , APSN64Header(..)
  , APSN64Description(..)
  , APSPatchType(..)
  , APSImageFormat(..)
  , APSRecordEncoding(..)
  , toAPSPatchType
  , fromAPSPatchType
  , toAPSImageFormat
  , fromAPSImageFormat
  , toAPSRecordEncoding
  , fromAPSRecordEncoding
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

data APSN64Patch = APSN64Patch APSN64Header [APSN64Record]
  deriving (Show)

data APSN64Header = APSN64Header
  { apsN64PatchType   :: APSPatchType
  , apsN64Encoding    :: APSRecordEncoding
  , apsN64Description :: ByteString   -- 50 bytes
  , apsN64ImageFormat :: Maybe APSImageFormat
  , apsN64CartId      :: Maybe ByteString  -- 2 bytes
  , apsN64Country     :: Maybe Word8
  , apsN64Crc         :: Maybe ByteString  -- 8 bytes
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
