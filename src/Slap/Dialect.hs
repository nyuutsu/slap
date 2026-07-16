{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE OverloadedStrings #-}

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

import Data.Aeson (ToJSON)
import Data.Text (Text)
import GHC.Generics (Generic)

import Slap.JSON.Nullary (AsConstructorName(..))

data Dialect
  = PPF1OriginAxis
    -- ^ PPF1's offset-field endianness.
    -- PPF1's reference applier ('sources/applyppf.c' in docs/ppf/upstream/pdx-ppf1.zip) reads offsets with @fread(&Offset, sizeof(long), ...)@ —
    -- native-endian, no byte-swap — so a patch produced on a PC writes offsets LE on disk
    -- and a patch produced on an Amiga writes them BE on disk.
    -- The two are mutually incompatible cross-platform.
    -- Default is PC-origin (LE); the @--is-amiga-patch@ flag selects BE.
    --
    -- This axis is read-only: it selects how slap /decodes/ a PPF1 patch's offsets (apply, undo, info, explain, and convert from a PPF1 source).
    -- It never affects writing — create and convert to PPF1 always emit PC/LE.
    -- The general dialect plumbing can still carry a write-affecting axis; this particular one just doesn't.
    --
    -- Per @docs/ppf/spec.md@ §"Offset size and endianness".
  deriving (Show, Eq, Ord, Generic)
  deriving (ToJSON) via AsConstructorName Dialect

-- | Display name for prose contexts in error and help messages.
dialectName :: Dialect -> Text
dialectName PPF1OriginAxis = "PPF1 offset endianness"

-- | The CLI flag spelling for a 'Dialect' axis, without the leading
-- @--@. Single source of truth shared by 'Slap.Status' renderers and
-- the parser declaration in @app\/CLI.hs@.
dialectFlagName :: Dialect -> Text
dialectFlagName PPF1OriginAxis = "is-amiga-patch"
