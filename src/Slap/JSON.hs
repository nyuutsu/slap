{-# LANGUAGE OverloadedStrings #-}
-- | JSON extraction for slap. The only JSON in the slap world is the
-- trailing metadata blob carried by EBP patches, so this module's
-- public surface is shaped to that one job: parse the blob and pull
-- out the four prespecified top-level string fields. Anything else
-- the JSON spec permits (nested objects, arrays, numbers, booleans,
-- nulls) is read by aeson under the hood but discarded here — slap
-- has nothing to do with it.
--
-- The four fields slap recognises are the ones EBPatcher established
-- as the EBP metadata contract: @patcher@, @title@, @author@,
-- @description@. Lookup is case-insensitive: there are two notable
-- producers in the wild and they disagree on key casing. EBPatcher
-- (the Python reference patcher) writes lowercase keys.
-- RomPatcher.js (a JavaScript implementation, including a webapp
-- many end-users hit directly) writes capitalised keys for the
-- three user-facing fields and lowercase @patcher@. A slap reader
-- that wants to handle patches end-users actually have needs to
-- tolerate both, so this module folds the comparison.
--
-- Missing fields are tolerated for the same reason: RomPatcher.js's
-- writer skips empty fields entirely, so a real-world EBP patch can
-- arrive with only some of the four keys present. Each field on the
-- returned 'EBPMetadataView' is therefore a 'Maybe' 'String'.
--
-- A malformed blob (not valid JSON, or valid JSON whose root is not
-- an object) yields 'Nothing' from 'parseEBPMetadata'. This is the
-- honest answer — there is no EBP metadata to extract — and is left
-- for callers to handle.
module Slap.JSON
  ( EBPMetadataView(..)
  , parseEBPMetadata
  ) where

import Data.ByteString (ByteString)
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.Key as AesonKey
import qualified Data.Aeson.KeyMap as AesonKeyMap
import qualified Data.Text as Text

-- | The four EBP metadata fields extracted from an EBP patch's
-- trailing JSON blob. Each field is 'Just' the field's value when
-- the key is present at the top level of the parsed object and its
-- value is a JSON string; 'Nothing' when the key is absent or the
-- value is some other JSON type (a number, an object, a null).
--
-- An empty-string value remains @'Just' ""@ here. Callers that
-- treat empty as absent perform that collapse themselves; this
-- module reports what the JSON actually said.
data EBPMetadataView = EBPMetadataView
  { ebpMetadataViewTitle       :: !(Maybe String)
  , ebpMetadataViewAuthor      :: !(Maybe String)
  , ebpMetadataViewDescription :: !(Maybe String)
  , ebpMetadataViewPatcher     :: !(Maybe String)
  } deriving (Eq, Show)

-- | Parse the bytes of an EBP metadata blob. Returns 'Just' a view
-- of the four EBP fields when the bytes are valid JSON whose root
-- is an object, 'Nothing' otherwise.
parseEBPMetadata :: ByteString -> Maybe EBPMetadataView
parseEBPMetadata bytes = case Aeson.eitherDecodeStrict bytes of
  Right (Aeson.Object obj) -> Just EBPMetadataView
    { ebpMetadataViewTitle       = lookupTopLevelString "title"       obj
    , ebpMetadataViewAuthor      = lookupTopLevelString "author"      obj
    , ebpMetadataViewDescription = lookupTopLevelString "description" obj
    , ebpMetadataViewPatcher     = lookupTopLevelString "patcher"     obj
    }
  _ -> Nothing

-- | Case-insensitive lookup of a top-level string-valued field.
-- The expected key name is given in lowercase; each key in the
-- parsed object is folded to lowercase before comparison so a
-- producer using either lowercase or capitalised keys lands the
-- same value.
lookupTopLevelString :: Text.Text -> Aeson.Object -> Maybe String
lookupTopLevelString expectedLowercaseKey obj =
  let folded = [ (Text.toLower (AesonKey.toText actualKey), actualValue)
               | (actualKey, actualValue) <- AesonKeyMap.toList obj
               ]
  in case lookup expectedLowercaseKey folded of
       Just (Aeson.String text) -> Just (Text.unpack text)
       _                        -> Nothing
