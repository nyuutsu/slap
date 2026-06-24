{-# LANGUAGE OverloadedStrings #-}
-- | JSON parsing for slap.
-- The only JSON in the slap world is the trailing metadata blob carried by EBP patches, so the public surface is shaped to that one job:
-- turn the trailer bytes into a structured 'EBPMetadata' value.
-- The four recognised fields (@patcher@, @title@, @author@, @description@) are the contract EBPatcher established;
-- everything else aeson reads and discards.
--
-- Producers disagree on key casing and on which fields they emit, so lookup is case-insensitive and each field is a 'Maybe' —
-- see 'parseEBPMetadata' and 'lookupTopLevelStringField' for the details.
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
