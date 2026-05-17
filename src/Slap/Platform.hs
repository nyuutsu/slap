module Slap.Platform
  ( platformName
  , ninja1ToPlatform
  , platformToNinja1
  , ninja2ToPlatform
  , platformToNinja2
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

-- | Convert a shared platform to NINJA1.  Only FDS has no NINJA1
-- representation and falls back to Raw with an advisory.
platformToNinja1 :: PlatformType -> (NINJA1RomType, [SlapAdvisory])
platformToNinja1 PlatformRaw            = (RomRAW, [])
platformToNinja1 PlatformNES            = (RomNES, [])
platformToNinja1 PlatformFDS            = (RomRAW, [PlatformNotAvailable LabelNINJA1 PlatformFDS])
platformToNinja1 PlatformSNES           = (RomSNES, [])
platformToNinja1 PlatformN64            = (RomN64, [])
platformToNinja1 PlatformGB             = (RomGB, [])
platformToNinja1 PlatformGBC            = (RomGBC, [])
platformToNinja1 PlatformGBA            = (RomGBA, [])
platformToNinja1 PlatformNGP            = (RomNGP, [])
platformToNinja1 PlatformNGPC           = (RomNGPC, [])
platformToNinja1 PlatformSMS            = (RomSMS, [])
platformToNinja1 PlatformGameGear       = (RomGameGear, [])
platformToNinja1 PlatformGenesis        = (RomGenesis, [])
platformToNinja1 PlatformPCEngine       = (RomPCEngine, [])
platformToNinja1 PlatformWonderSwan     = (RomWonderSwan, [])
platformToNinja1 PlatformWonderSwanColor = (RomWonderSwanColor, [])
platformToNinja1 PlatformLynx           = (RomLynx, [])
platformToNinja1 PlatformJaguar         = (RomJaguar, [])
platformToNinja1 PlatformGP32           = (RomGP32, [])

----------------------------------------------------------------------------
-- NINJA2 conversion
----------------------------------------------------------------------------

ninja2ToPlatform :: NINJA2RomType -> (PlatformType, [SlapAdvisory])
ninja2ToPlatform Ninja2Raw                    = (PlatformRaw, [])
ninja2ToPlatform Ninja2NES                    = (PlatformNES, [])
ninja2ToPlatform Ninja2FDS                    = (PlatformFDS, [])
ninja2ToPlatform Ninja2SNES                   = (PlatformSNES, [])
ninja2ToPlatform Ninja2N64                    = (PlatformN64, [])
ninja2ToPlatform Ninja2GB                     = (PlatformGB, [])
ninja2ToPlatform Ninja2SMSGameGear            = (PlatformSMS, [NINJA2SMSGameGearAmbiguity])
ninja2ToPlatform Ninja2Genesis                = (PlatformGenesis, [])
ninja2ToPlatform Ninja2PCEngine               = (PlatformPCEngine, [])
ninja2ToPlatform Ninja2Lynx                   = (PlatformLynx, [])
ninja2ToPlatform (Ninja2UnknownRomType _)     = (PlatformRaw, [])

-- | Convert a shared platform to NINJA2.  Platforms that NINJA2
-- doesn't enumerate (GBC, GBA, NGP, NGPC, WonderSwan,
-- WonderSwan Color, Jaguar, GP32) fall back to Raw with an advisory.
-- Game Gear maps to NINJA2's combined SMS/Game Gear slot.
platformToNinja2 :: PlatformType -> (NINJA2RomType, [SlapAdvisory])
platformToNinja2 PlatformRaw            = (Ninja2Raw, [])
platformToNinja2 PlatformNES            = (Ninja2NES, [])
platformToNinja2 PlatformFDS            = (Ninja2FDS, [])
platformToNinja2 PlatformSNES           = (Ninja2SNES, [])
platformToNinja2 PlatformN64            = (Ninja2N64, [])
platformToNinja2 PlatformGB             = (Ninja2GB, [])
platformToNinja2 PlatformGBC            = (Ninja2Raw, [PlatformNotAvailable LabelNINJA2 PlatformGBC])
platformToNinja2 PlatformGBA            = (Ninja2Raw, [PlatformNotAvailable LabelNINJA2 PlatformGBA])
platformToNinja2 PlatformNGP            = (Ninja2Raw, [PlatformNotAvailable LabelNINJA2 PlatformNGP])
platformToNinja2 PlatformNGPC           = (Ninja2Raw, [PlatformNotAvailable LabelNINJA2 PlatformNGPC])
platformToNinja2 PlatformSMS            = (Ninja2SMSGameGear, [])
platformToNinja2 PlatformGameGear       = (Ninja2SMSGameGear, [])
platformToNinja2 PlatformGenesis        = (Ninja2Genesis, [])
platformToNinja2 PlatformPCEngine       = (Ninja2PCEngine, [])
platformToNinja2 PlatformWonderSwan     = (Ninja2Raw, [PlatformNotAvailable LabelNINJA2 PlatformWonderSwan])
platformToNinja2 PlatformWonderSwanColor = (Ninja2Raw, [PlatformNotAvailable LabelNINJA2 PlatformWonderSwanColor])
platformToNinja2 PlatformLynx           = (Ninja2Lynx, [])
platformToNinja2 PlatformJaguar         = (Ninja2Raw, [PlatformNotAvailable LabelNINJA2 PlatformJaguar])
platformToNinja2 PlatformGP32           = (Ninja2Raw, [PlatformNotAvailable LabelNINJA2 PlatformGP32])
