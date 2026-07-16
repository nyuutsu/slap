-- | How raw bytes cross a JSON boundary: as base64 text, through this one wrapper, so the choice of encoding has one home.
-- Byte-carrying newtypes join it with @deriving (ToJSON) via BytesAsBase64@, and @FromJSON@ likewise where they cross inbound.
module Slap.JSON.Bytes
  ( BytesAsBase64(..)
  ) where

import Data.Aeson (FromJSON(..), ToJSON(..), withText)
import Data.ByteString (ByteString)
import qualified Data.ByteString.Base64 as Base64
import Data.Text (Text)
import qualified Data.Text.Encoding as TextEncoding

newtype BytesAsBase64 = BytesAsBase64 { unBytesAsBase64 :: ByteString }

instance ToJSON BytesAsBase64 where
  toJSON (BytesAsBase64 bytes)     = toJSON (base64Text bytes)
  toEncoding (BytesAsBase64 bytes) = toEncoding (base64Text bytes)

instance FromJSON BytesAsBase64 where
  parseJSON = withText "base64 bytes" $
    either fail (pure . BytesAsBase64) . Base64.decode . TextEncoding.encodeUtf8

base64Text :: ByteString -> Text
base64Text = TextEncoding.decodeLatin1 . Base64.encode
