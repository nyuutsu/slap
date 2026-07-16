{-# LANGUAGE UndecidableInstances #-}

-- | How a sum of empty constructors crosses a JSON boundary: as the constructor's name. Aeson's generic default already encodes
-- multi-constructor sums that way, but turns a lone nullary constructor into @[]@ — and would silently flip that to the name
-- the day a second constructor lands. Single-constructor sums derive via this wrapper instead of 'GHC.Generics.Generically',
-- so their wire shape is the name from the start and gaining a constructor changes nothing.
module Slap.JSON.Nullary
  ( AsConstructorName(..)
  ) where

import Data.Aeson (Options(tagSingleConstructors), ToJSON(..), defaultOptions, genericToJSON, genericToEncoding)
import Data.Aeson.Types (Encoding, GToJSON', Value, Zero)
import GHC.Generics (Generic, Rep)

newtype AsConstructorName a = AsConstructorName a

instance (Generic a, GToJSON' Value Zero (Rep a), GToJSON' Encoding Zero (Rep a)) => ToJSON (AsConstructorName a) where
  toJSON (AsConstructorName value)     = genericToJSON namedOptions value
  toEncoding (AsConstructorName value) = genericToEncoding namedOptions value

namedOptions :: Options
namedOptions = defaultOptions { tagSingleConstructors = True }
