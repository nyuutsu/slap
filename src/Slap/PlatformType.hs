{-# LANGUAGE OverloadedStrings #-}

module Slap.PlatformType
  ( PlatformType(..)
  , platformName
  ) where

import Data.Text (Text)

-- | Platform type representing the union of all platforms known to
-- NINJA1 and NINJA2.  Used as the lingua franca for cross-format
-- ROM type conversion; format-specific types (NINJA1RomType,
-- NINJA2RomType) preserve per-format details at the boundaries.
--
-- The conversions ('platformToNINJA1', 'platformToNINJA2',
-- 'ninja1ToPlatform', 'ninja2ToPlatform') live in "Slap.Platform";
-- this module holds only the shared vocabulary so that format-layer
-- modules can name a platform without pulling in the per-format
-- conversion table (and the import cycles that would follow).
data PlatformType
  = PlatformRaw
  | PlatformNES
  | PlatformFDS              -- NINJA2 only
  | PlatformSNES
  | PlatformN64
  | PlatformGB
  | PlatformGBC              -- NINJA1 only
  | PlatformGBA              -- NINJA1 only
  | PlatformNGP              -- NINJA1 only
  | PlatformNGPC             -- NINJA1 only
  | PlatformSMS
  | PlatformGameGear         -- NINJA1 only (NINJA2 combines with SMS)
  | PlatformGenesis
  | PlatformPCEngine
  | PlatformWonderSwan       -- NINJA1 only
  | PlatformWonderSwanColor  -- NINJA1 only
  | PlatformLynx
  | PlatformJaguar           -- NINJA1 only
  | PlatformGP32             -- NINJA1 only
  deriving (Show, Eq)

-- | The user-facing display name for a 'PlatformType'. Used by
-- 'Slap.Status' when rendering the 'PlatformNotAvailable' advisory
-- and by any other site that needs to name a platform in human-
-- readable form. The strings track the names slap surfaces in CLI
-- output and error messages — distinct from any format-specific
-- wire encoding (NINJA1's 'RomNES', NINJA2's 'NINJA2NES', etc.).
platformName :: PlatformType -> Text
platformName PlatformRaw            = "Raw"
platformName PlatformNES            = "NES"
platformName PlatformFDS            = "FDS"
platformName PlatformSNES           = "SNES"
platformName PlatformN64            = "N64"
platformName PlatformGB             = "Game Boy"
platformName PlatformGBC            = "GBC"
platformName PlatformGBA            = "GBA"
platformName PlatformNGP            = "NGP"
platformName PlatformNGPC           = "NGPC"
platformName PlatformSMS            = "SMS"
platformName PlatformGameGear       = "Game Gear"
platformName PlatformGenesis        = "Genesis"
platformName PlatformPCEngine       = "PC Engine"
platformName PlatformWonderSwan     = "WonderSwan"
platformName PlatformWonderSwanColor = "WonderSwan Color"
platformName PlatformLynx           = "Lynx"
platformName PlatformJaguar         = "Jaguar"
platformName PlatformGP32           = "GP32"
