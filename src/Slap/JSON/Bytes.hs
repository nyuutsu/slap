-- | How raw bytes cross a JSON boundary: as base64 text, through this one wrapper, so the choice of encoding has one home.
-- Byte-carrying newtypes join it with @deriving (ToJSON) via BytesAsBase64@.
module Slap.JSON.Bytes
  ( BytesAsBase64(..)
  ) where

import Data.Aeson (ToJSON(..))
import Data.ByteString (ByteString)
import qualified Data.ByteString.Base64 as Base64
import Data.Text (Text)
import qualified Data.Text.Encoding as TextEncoding

newtype BytesAsBase64 = BytesAsBase64 { unBytesAsBase64 :: ByteString }

instance ToJSON BytesAsBase64 where
  toJSON (BytesAsBase64 bytes)     = toJSON (base64Text bytes)
  toEncoding (BytesAsBase64 bytes) = toEncoding (base64Text bytes)

base64Text :: ByteString -> Text
base64Text = TextEncoding.decodeLatin1 . Base64.encode
