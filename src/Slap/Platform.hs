module Slap.Platform
  ( platformName
  , ninja1ToPlatform
  , platformToNINJA1
  , ninja2ToPlatform
  , platformToNINJA2
  ) where

import Slap.PlatformType (PlatformType(..), platformName)
import Slap.NINJA1.Types (NINJA1RomType(..))
import Slap.NINJA2.Types (NINJA2RomType(..))
import Slap.Status (SlapAdvisory(..))
import Slap.FormatLabel (FormatLabel(..))

----------------------------------------------------------------------------
-- NINJA1 conversion
----------------------------------------------------------------------------

ninja1ToPlatform :: NINJA1RomType -> PlatformType
ninja1ToPlatform RomRAW            = PlatformRaw
ninja1ToPlatform RomNES            = PlatformNES
ninja1ToPlatform RomSNES           = PlatformSNES
ninja1ToPlatform RomN64            = PlatformN64
ninja1ToPlatform RomGB             = PlatformGB
ninja1ToPlatform RomGBC            = PlatformGBC
ninja1ToPlatform RomGBA            = PlatformGBA
ninja1ToPlatform RomNGP            = PlatformNGP
ninja1ToPlatform RomNGPC           = PlatformNGPC
ninja1ToPlatform RomSMS            = PlatformSMS
ninja1ToPlatform RomGameGear       = PlatformGameGear
ninja1ToPlatform RomGenesis        = PlatformGenesis
ninja1ToPlatform RomPCEngine       = PlatformPCEngine
ninja1ToPlatform RomWonderSwan     = PlatformWonderSwan
ninja1ToPlatform RomWonderSwanColor = PlatformWonderSwanColor
ninja1ToPlatform RomLynx           = PlatformLynx
ninja1ToPlatform RomJaguar         = PlatformJaguar
ninja1ToPlatform RomGP32           = PlatformGP32
ninja1ToPlatform (RomUnknown _)    = PlatformRaw
ninja1ToPlatform (RomUnknownName _) = PlatformRaw

-- | Convert a shared platform to NINJA1.  Only FDS has no NINJA1
-- representation and falls back to Raw with an advisory.
platformToNINJA1 :: PlatformType -> (NINJA1RomType, [SlapAdvisory])
platformToNINJA1 PlatformRaw            = (RomRAW, [])
platformToNINJA1 PlatformNES            = (RomNES, [])
platformToNINJA1 PlatformFDS            = (RomRAW, [PlatformNotAvailable LabelNINJA1 PlatformFDS])
platformToNINJA1 PlatformSNES           = (RomSNES, [])
platformToNINJA1 PlatformN64            = (RomN64, [])
platformToNINJA1 PlatformGB             = (RomGB, [])
platformToNINJA1 PlatformGBC            = (RomGBC, [])
platformToNINJA1 PlatformGBA            = (RomGBA, [])
platformToNINJA1 PlatformNGP            = (RomNGP, [])
platformToNINJA1 PlatformNGPC           = (RomNGPC, [])
platformToNINJA1 PlatformSMS            = (RomSMS, [])
platformToNINJA1 PlatformGameGear       = (RomGameGear, [])
platformToNINJA1 PlatformGenesis        = (RomGenesis, [])
platformToNINJA1 PlatformPCEngine       = (RomPCEngine, [])
platformToNINJA1 PlatformWonderSwan     = (RomWonderSwan, [])
platformToNINJA1 PlatformWonderSwanColor = (RomWonderSwanColor, [])
platformToNINJA1 PlatformLynx           = (RomLynx, [])
platformToNINJA1 PlatformJaguar         = (RomJaguar, [])
platformToNINJA1 PlatformGP32           = (RomGP32, [])

----------------------------------------------------------------------------
-- NINJA2 conversion
----------------------------------------------------------------------------

ninja2ToPlatform :: NINJA2RomType -> (PlatformType, [SlapAdvisory])
ninja2ToPlatform NINJA2Raw                    = (PlatformRaw, [])
ninja2ToPlatform NINJA2NES                    = (PlatformNES, [])
ninja2ToPlatform NINJA2FDS                    = (PlatformFDS, [])
ninja2ToPlatform NINJA2SNES                   = (PlatformSNES, [])
ninja2ToPlatform NINJA2N64                    = (PlatformN64, [])
ninja2ToPlatform NINJA2GB                     = (PlatformGB, [])
ninja2ToPlatform NINJA2SMSGameGear            = (PlatformSMS, [NINJA2SMSGameGearAmbiguity])
ninja2ToPlatform NINJA2Genesis                = (PlatformGenesis, [])
ninja2ToPlatform NINJA2PCEngine               = (PlatformPCEngine, [])
ninja2ToPlatform NINJA2Lynx                   = (PlatformLynx, [])
ninja2ToPlatform (NINJA2UnknownRomType _)     = (PlatformRaw, [])

-- | Convert a shared platform to NINJA2.  Platforms that NINJA2
-- doesn't enumerate (GBC, GBA, NGP, NGPC, WonderSwan,
-- WonderSwan Color, Jaguar, GP32) fall back to Raw with an advisory.
-- Game Gear maps to NINJA2's combined SMS/Game Gear slot.
platformToNINJA2 :: PlatformType -> (NINJA2RomType, [SlapAdvisory])
platformToNINJA2 PlatformRaw            = (NINJA2Raw, [])
platformToNINJA2 PlatformNES            = (NINJA2NES, [])
platformToNINJA2 PlatformFDS            = (NINJA2FDS, [])
platformToNINJA2 PlatformSNES           = (NINJA2SNES, [])
platformToNINJA2 PlatformN64            = (NINJA2N64, [])
platformToNINJA2 PlatformGB             = (NINJA2GB, [])
platformToNINJA2 PlatformGBC            = (NINJA2Raw, [PlatformNotAvailable LabelNINJA2 PlatformGBC])
platformToNINJA2 PlatformGBA            = (NINJA2Raw, [PlatformNotAvailable LabelNINJA2 PlatformGBA])
platformToNINJA2 PlatformNGP            = (NINJA2Raw, [PlatformNotAvailable LabelNINJA2 PlatformNGP])
platformToNINJA2 PlatformNGPC           = (NINJA2Raw, [PlatformNotAvailable LabelNINJA2 PlatformNGPC])
platformToNINJA2 PlatformSMS            = (NINJA2SMSGameGear, [])
platformToNINJA2 PlatformGameGear       = (NINJA2SMSGameGear, [])
platformToNINJA2 PlatformGenesis        = (NINJA2Genesis, [])
platformToNINJA2 PlatformPCEngine       = (NINJA2PCEngine, [])
platformToNINJA2 PlatformWonderSwan     = (NINJA2Raw, [PlatformNotAvailable LabelNINJA2 PlatformWonderSwan])
platformToNINJA2 PlatformWonderSwanColor = (NINJA2Raw, [PlatformNotAvailable LabelNINJA2 PlatformWonderSwanColor])
platformToNINJA2 PlatformLynx           = (NINJA2Lynx, [])
platformToNINJA2 PlatformJaguar         = (NINJA2Raw, [PlatformNotAvailable LabelNINJA2 PlatformJaguar])
platformToNINJA2 PlatformGP32           = (NINJA2Raw, [PlatformNotAvailable LabelNINJA2 PlatformGP32])
