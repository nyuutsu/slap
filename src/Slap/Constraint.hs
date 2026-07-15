{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE OverloadedStrings #-}

-- | User-opt-in refuse-gates that slap honors at create or convert
-- time. Distinct from 'Slap.MetadataField.MetadataField' because a
-- 'Constraint' is not a property the user requests be embedded in
-- or carried by a patch — slap-with-constraint and slap-without
-- produce bit-identical output when both proceed; the constraint
-- only changes whether they proceed at all. Constraints exist so
-- users with strict downstream requirements (a 1996 applier; a
-- conservative tool chain) can have slap refuse rather than
-- silently emit something that'll fail later.
--
-- New constraints land here as new constructors; the matrix in
-- 'Slap.Convert.acceptedConstraints' decides which formats honor each.
module Slap.Constraint
  ( Constraint(..)
  , constraintName
  , constraintFlagName
  ) where

import Data.Aeson (ToJSON)
import Data.Text (Text)
import GHC.Generics (Generic, Generically(..))

data Constraint
  = SMCShapeConstraint
  deriving (Show, Eq, Ord, Generic)
  deriving (ToJSON) via Generically Constraint

-- | Used by 'Slap.Status' renderers.
constraintName :: Constraint -> Text
constraintName SMCShapeConstraint = "SMC-shaped target size"

-- | The CLI flag spelling for a 'Constraint', without the leading
-- @--@. The renderer in 'Slap.Status' adds the prefix when emitting
-- error messages; the parser declaration in @app\/CLI.hs@ uses this
-- string as its 'long' option name. Single source of truth.
constraintFlagName :: Constraint -> Text
constraintFlagName SMCShapeConstraint = "require-smc-shaped-target-size"
