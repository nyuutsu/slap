-- | Wire-format configuration the user supplies that affects how a
-- format's bytes are interpreted at parse or written at create.
-- Distinct from 'Slap.Constraint.Constraint' (which is a slap-side
-- discipline gate that doesn't change wire output) and from
-- 'Slap.MetadataField.MetadataField' (which is a property the user
-- requests be embedded in a patch). A dialect axis exists when a
-- format's wire-level interpretation has more than one valid reading
-- and the file alone can't disambiguate — the user has to tell slap
-- which reading applies.
--
-- New dialect axes land here as new constructors; the matrix in
-- 'Slap.Convert.acceptedDialects' decides which formats admit each.
module Slap.Dialect
  ( Dialect(..)
  , dialectName
  , dialectFlagName
  ) where

data Dialect
  = PPF1OriginAxis
    -- ^ PPF1's offset-field endianness. PPF1's reference applier
    -- ('docs/ppf/upstream/pdx-ppf1/sources/applyppf.c') reads offsets
    -- with @fread(&Offset, sizeof(long), ...)@ — native-endian, no
    -- byte-swap — so a patch produced on a PC writes offsets LE on
    -- disk and a patch produced on an Amiga writes them BE on disk.
    -- The two are mutually incompatible cross-platform. Default is
    -- PC-origin (LE); the @--is-amiga-patch@ flag selects BE.
    --
    -- Per @slap-format-documentation/ppf/spec.md@ §"Offset size and
    -- endianness".
  deriving (Show, Eq, Ord)

-- | Display name for prose contexts in error and help messages.
dialectName :: Dialect -> String
dialectName PPF1OriginAxis = "PPF1 offset endianness"

-- | The CLI flag spelling for a 'Dialect' axis, without the leading
-- @--@. Single source of truth shared by 'Slap.Status' renderers and
-- the parser declaration in @app\/Main.hs@.
dialectFlagName :: Dialect -> String
dialectFlagName PPF1OriginAxis = "is-amiga-patch"
