{-# LANGUAGE StrictData #-}

module Slap.APSN64.Types
  ( APSN64Patch(..)
  , APSN64Record(..)
  , APSN64Header(..)
  , APSPatchType(..)
  , APSImageFormat(..)
  , toAPSPatchType
  , fromAPSPatchType
  , toAPSImageFormat
  , fromAPSImageFormat
    -- * Named constants
  , apsN64DescriptionWidth
  ) where

import Data.ByteString (ByteString)
import Data.Word (Word8)
import Slap.Measure (FileSize, Offset(..))

data APSPatchType = APSSimple | APSN64Specific
  deriving (Show, Eq)

toAPSPatchType :: Word8 -> Either String APSPatchType
toAPSPatchType 0 = Right APSSimple
toAPSPatchType 1 = Right APSN64Specific
toAPSPatchType byte = Left ("APS-N64: unknown patch type: " ++ show byte)

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

data APSN64Patch = APSN64Patch APSN64Header [APSN64Record]
  deriving (Show)

data APSN64Header = APSN64Header
  { apsN64PatchType   :: APSPatchType
  , apsN64Encoding    :: Word8        -- encoding method byte (0 in all known patches)
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

-- | Description field width: 50 bytes, null-padded.
apsN64DescriptionWidth :: Int
apsN64DescriptionWidth = 50
