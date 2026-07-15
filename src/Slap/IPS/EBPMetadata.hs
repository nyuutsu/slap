{-# LANGUAGE OverloadedStrings #-}

-- | The JSON metadata blob EBP patches carry: 'buildEBPMetadataJSON' writes it, 'parseEBPMetadata' reads it.
-- The four recognised fields are the contract EBPatcher established; everything else aeson reads and discards.
-- Producers disagree on key casing and on which fields they emit, so lookup is case-insensitive and each parsed field is a 'Maybe'.
module Slap.IPS.EBPMetadata
  ( buildEBPMetadataJSON
  , parseEBPMetadata
  ) where

import Data.ByteString (ByteString)
import qualified Data.Aeson as Aeson
import Data.Aeson ((.=))
import qualified Data.Aeson.Encoding as AesonEncoding
import qualified Data.Aeson.Key as AesonKey
import qualified Data.Aeson.KeyMap as AesonKeyMap
import qualified Data.ByteString.Lazy as LazyByteString
import qualified Data.Text as Text
import Slap.FormatLabel (FormatLabel(..))
import Slap.IPS.Types (EBPMetadata(..), emptyEBPMetadata)
import Slap.Status (SlapAdvisory(..))
import Slap.Text (EncodedText(..), EncodingName(..), encodedTextContent)

-- | The four-key shape matches what EBPatcher and the long-standing community tools emit; a field is emitted only when 'Just'.
-- The 'Text' content lands in the JSON string slots verbatim, whatever encoding tag it arrived under,
-- and 'Aeson.pairs' keeps declared order, so the wire reads @{patcher,title,author,description}@ when all four are present.
buildEBPMetadataJSON :: EBPMetadata -> ByteString
buildEBPMetadataJSON metadata =
  LazyByteString.toStrict (AesonEncoding.encodingToLazyByteString jsonEncoding)
  where
    jsonEncoding = Aeson.pairs
      (  optionalField "patcher"     (ebpMetadataPatcher     metadata)
      <> optionalField "title"       (ebpMetadataTitle       metadata)
      <> optionalField "author"      (ebpMetadataAuthor      metadata)
      <> optionalField "description" (ebpMetadataDescription metadata)
      )
    optionalField _       Nothing      = mempty
    optionalField keyName (Just value) = keyName .= encodedTextContent value

-- | Malformed JSON, or a root that is not an object, is an observation rather than a failure:
-- the fields come back all-'Nothing' beside an 'EBPMetadataMalformed' advisory.
parseEBPMetadata :: ByteString -> (EBPMetadata, [SlapAdvisory])
parseEBPMetadata bytes = case Aeson.eitherDecodeStrict bytes of
  Right (Aeson.Object rootObject) ->
    ( EBPMetadata
        { ebpMetadataTitle       = lookupTopLevelStringField "title"       rootObject
        , ebpMetadataAuthor      = lookupTopLevelStringField "author"      rootObject
        , ebpMetadataDescription = lookupTopLevelStringField "description" rootObject
        , ebpMetadataPatcher     = lookupTopLevelStringField "patcher"     rootObject
        }
    , []
    )
  _ -> (emptyEBPMetadata, [EBPMetadataMalformed LabelEBP])

-- | The expected key arrives lowercase; each object key folds to lowercase before comparison.
-- The extracted text is tagged 'EncodingUtf8': aeson already decoded it under JSON's UTF-8 wire contract.
lookupTopLevelStringField :: Text.Text -> Aeson.Object -> Maybe EncodedText
lookupTopLevelStringField expectedLowercaseKey rootObject =
  let folded = [ (Text.toLower (AesonKey.toText actualKey), actualValue)
               | (actualKey, actualValue) <- AesonKeyMap.toList rootObject
               ]
  in case lookup expectedLowercaseKey folded of
       Just (Aeson.String text) -> Just (EncodedText EncodingUtf8 text)
       _                        -> Nothing
