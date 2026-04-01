{-# LANGUAGE StrictData #-}

module Slap.NINJA1.Types
  ( NINJA1Patch(..)
  , NINJA1Record(..)
  , NINJA1SubFormat(..)
  , NINJA1RomType(..)
  , toNINJA1RomType
  , fromNINJA1RomType
  , romTypeName
  ) where

import Data.ByteString (ByteString)
import Data.Word (Word8, Word32)
import Slap.Measure (Offset(..))

data NINJA1SubFormat = Ninja1Binary | Ninja1BinaryCompressed | Ninja1Text | Ninja1TextCompressed
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

data NINJA1Patch = NINJA1Patch
  { ninja1SubFormat  :: NINJA1SubFormat
  , ninja1RomType    :: NINJA1RomType
  , ninja1SourceCRC  :: Maybe Word32
  , ninja1SourceMD5  :: Maybe ByteString  -- 16 bytes
  , ninja1SourceSHA1 :: Maybe ByteString  -- 20 bytes
  , ninja1Records    :: [NINJA1Record]
  , ninja1CleanEOF   :: Bool              -- parse completed cleanly (binary: EOF sentinel found; text: always True)
  } deriving (Show)

data NINJA1Record = NINJA1Record
  { ninja1RecordOffset :: !Offset
  , ninja1RecordData   :: !ByteString
  } deriving (Show)

romTypeName :: NINJA1RomType -> String
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
romTypeName (RomUnknown value) = "unknown (" ++ show value ++ ")"
