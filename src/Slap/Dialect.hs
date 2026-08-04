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
  , PatchOrigin(..)
  , dialectName
  , dialectFlagName
  ) where

import Data.Aeson (FromJSON, ToJSON)
import Data.Text (Text)
import GHC.Generics (Generic, Generically(..))

import Slap.JSON.Nullary (AsConstructorName(..))

data Dialect
  = PatchOriginAxis
    -- ^ The byte-order dialect: read-only, it selects how slap decodes a patch's integers, never how it writes them.
    -- 'Slap.Convert.acceptedDialects' admits it for PPF1 and PPF2; @docs/ppf/spec.md@ §"Endianness and the Amiga question" is the why.
  deriving (Show, Eq, Ord, Generic)
  deriving (ToJSON) via AsConstructorName Dialect

-- | 'OriginPC' decodes a patch's integers little-endian, 'OriginAmiga' big-endian.
-- The default is 'OriginPC'; the @--is-amiga-patch@ flag selects 'OriginAmiga'.
data PatchOrigin = OriginPC | OriginAmiga
  deriving (Show, Eq, Generic)
  deriving (FromJSON) via Generically PatchOrigin

-- | Display name for prose contexts in error and help messages.
dialectName :: Dialect -> Text
dialectName PatchOriginAxis = "patch byte order"

-- | The CLI flag spelling for a 'Dialect' axis, without the leading
-- @--@. Single source of truth shared by 'Slap.Status' renderers and
-- the parser declaration in @app\/CLI.hs@.
dialectFlagName :: Dialect -> Text
dialectFlagName PatchOriginAxis = "is-amiga-patch"
