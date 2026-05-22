{-# LANGUAGE OverloadedStrings #-}
-- | JSON parsing for slap. The only JSON in the slap world is the
-- trailing metadata blob carried by EBP patches, so this module's
-- public surface is shaped to that one job: turn the trailer bytes
-- into a structured 'EBPMetadata' value. Anything else the JSON
-- spec permits (nested objects, arrays, numbers, booleans, nulls)
-- is read by aeson under the hood and discarded here — slap has
-- nothing to do with it.
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
-- returned 'EBPMetadata' is therefore a 'Maybe' 'EncodedText'.
--
-- Extracted values carry an explicit @EncodingUtf8@ tag: JSON is
-- UTF-8 by RFC 8259, aeson enforces that at the parse boundary, and
-- the tag travels with the value so the convert seam knows the
-- encoding without having to remember the JSON-source provenance
-- out-of-band.
--
-- A malformed blob (not valid JSON, or valid JSON whose root is not
-- an object) yields the all-'Nothing' 'EBPMetadata' value paired
-- with an 'EBPMetadataMalformed' advisory. The patch's IPS records
-- are unaffected — apply and convert paths proceed normally — but
-- the user learns at parse time that the metadata couldn't be read.
module Slap.JSON
  ( parseEBPMetadata
  ) where

import Data.ByteString (ByteString)
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.Key as AesonKey
import qualified Data.Aeson.KeyMap as AesonKeyMap
import qualified Data.Text as Text
import Slap.FormatLabel (FormatLabel(..))
import Slap.IPS.Types (EBPMetadata(..), emptyEBPMetadata)
import Slap.Status (SlapAdvisory(..))
import Slap.Text (EncodedText(..), EncodingName(..))

-- | Parse the bytes of an EBP metadata blob. On well-formed JSON
-- whose root is an object, returns the four extracted fields (each
-- 'Just' when present as a string-valued top-level key,
-- case-insensitively, and 'Nothing' otherwise) with an empty
-- advisory list. On malformed input, returns the all-'Nothing'
-- 'EBPMetadata' paired with @['EBPMetadataMalformed' 'LabelEBP']@
-- so the caller can surface the parse-time observation through the
-- usual advisory channel.
parseEBPMetadata :: ByteString -> (EBPMetadata, [SlapAdvisory])
parseEBPMetadata bytes = case Aeson.eitherDecodeStrict bytes of
  Right (Aeson.Object obj) ->
    ( EBPMetadata
        { ebpMetadataTitle       = lookupTopLevelStringField "title"       obj
        , ebpMetadataAuthor      = lookupTopLevelStringField "author"      obj
        , ebpMetadataDescription = lookupTopLevelStringField "description" obj
        , ebpMetadataPatcher     = lookupTopLevelStringField "patcher"     obj
        }
    , []
    )
  _ -> (emptyEBPMetadata, [EBPMetadataMalformed LabelEBP])

-- | Case-insensitive lookup of a top-level string-valued field.
-- The expected key name is given in lowercase; each key in the
-- parsed object is folded to lowercase before comparison so a
-- producer using either lowercase or capitalised keys lands the
-- same value. The extracted text is tagged 'EncodingUtf8' — aeson
-- already decoded it under JSON's UTF-8 wire contract.
lookupTopLevelStringField :: Text.Text -> Aeson.Object -> Maybe EncodedText
lookupTopLevelStringField expectedLowercaseKey obj =
  let folded = [ (Text.toLower (AesonKey.toText actualKey), actualValue)
               | (actualKey, actualValue) <- AesonKeyMap.toList obj
               ]
  in case lookup expectedLowercaseKey folded of
       Just (Aeson.String text) -> Just (EncodedText EncodingUtf8 text)
       _                        -> Nothing
