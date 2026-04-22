module Slap.PlatformType
  ( PlatformType(..)
  ) where

-- | Platform type representing the union of all platforms known to
-- NINJA1 and NINJA2.  Used as the lingua franca for cross-format
-- ROM type conversion; format-specific types (NINJA1RomType,
-- NINJA2RomType) preserve per-format details at the boundaries.
--
-- The conversions ('platformToNinja1', 'platformToNinja2',
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
