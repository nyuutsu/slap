{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE OverloadedStrings #-}

-- | Content a patch carries embedded in one of its fields:
-- the BPS metadata blob, the xdelta3 application header, the PPF FILE_ID.DIZ.
-- It is a third kind of thing — beside the patch's facts (sizes, CRCs) and its structure (the records) —
-- a payload that rode along inside the patch and that someone might want to read.
--
-- The verbs meet it at different depths:
-- @slap info@ shows only that it is there and how big ('SizeOnly');
-- @slap explain@ opens it up ('WithPayload').
-- 'renderEmbedded' draws both from the one value,
-- so the size line and the content beneath it can never disagree.
module Slap.Display.EmbeddedContent
  ( EmbeddedContent(..)
  , EmbeddedField(..)
  , EmbeddedWireBytes(..)
  , readEmbeddedContent
  , EmbeddedDepth(..)
  , renderEmbedded
  ) where

import Slap.Display.Common (InfoLine(..), renderInfoLine, renderAsText)
import Slap.Display.Primitives (renderEscapingNonPrintable)
import Slap.JSON.Bytes (BytesAsBase64(..))
import Slap.Text (EncodingName, EncodedText, encodedTextContent, decodeTextLenient, substitutionCount)
import Slap.Measure (SubstitutionCount(..))

import Data.Aeson (ToJSON)
import Data.Text (Text)
import qualified Data.Text as Text
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import GHC.Generics (Generic, Generically(..))

data EmbeddedContent = EmbeddedContent
  { embeddedLabel :: !Text
  , embeddedField :: !EmbeddedField
  }
  deriving (Eq, Show, Generic)
  deriving (ToJSON) via Generically EmbeddedContent

-- | An embedded field's bytes exactly as they sat on the wire, kept so an extraction is byte-exact.
newtype EmbeddedWireBytes = EmbeddedWireBytes { unEmbeddedWireBytes :: ByteString }
  deriving (Eq, Show)
  deriving (ToJSON) via BytesAsBase64

-- | 'FieldAbsent' and 'FieldEmpty' part ways only where a format can tell them apart:
-- the xdelta3 appheader's presence bit makes "declared but empty" a different fact from "never declared."
-- A format without that bit reaches for 'FieldAbsent'.
data EmbeddedField
  = FieldAbsent
  | FieldEmpty
  | FieldContent !EmbeddedWireBytes !EncodedText !SubstitutionCount
    -- ^ The reading a lenient decode made of the wire bytes, and how many sequences it substituted —
    -- the count is what the size glance reads to tell characters from bytes.
  deriving (Eq, Show, Generic)
  deriving (ToJSON) via Generically EmbeddedField

-- | Decode a field's wire bytes into its content — always a 'FieldContent'.
-- A caller with empty or absent bytes reaches for 'FieldEmpty' \/ 'FieldAbsent' itself.
readEmbeddedContent :: EncodingName -> ByteString -> EmbeddedField
readEmbeddedContent encoding bytes =
  let (reading, notices) = decodeTextLenient encoding bytes
  in FieldContent (EmbeddedWireBytes bytes) reading (substitutionCount notices)

-- | How far a view opens the content:
-- the size glance alone, or the glance with the payload tucked beneath it.
data EmbeddedDepth = SizeOnly | WithPayload

-- | The label-and-size line, and — at 'WithPayload' — the content indented under it,
-- so the payload reads as belonging to the field that named it.
renderEmbedded :: EmbeddedDepth -> EmbeddedContent -> [Text]
renderEmbedded depth content =
  renderInfoLine (InfoLine (embeddedLabel content) (sizeGlance field))
    : case depth of
        SizeOnly    -> []
        WithPayload -> map ("  " <>) (payloadLines field)
  where
    field = embeddedField content

-- | A reading that decoded cleanly counts in characters; one that had to substitute is really bytes, and says so.
sizeGlance :: EmbeddedField -> Text
sizeGlance FieldAbsent = "(none)"
sizeGlance FieldEmpty  = "(empty)"
sizeGlance (FieldContent (EmbeddedWireBytes bytes) reading (SubstitutionCount substituted))
  | substituted == 0 = renderAsText (Text.length (encodedTextContent reading)) <> " characters"
  | otherwise        = renderAsText (ByteString.length bytes) <> " bytes"

payloadLines :: EmbeddedField -> [Text]
payloadLines FieldAbsent               = []
payloadLines FieldEmpty                = []
payloadLines (FieldContent _ reading _) = textLines (encodedTextContent reading)

-- | Break content on its own line breaks, escaping anything unprintable left within a line —
-- so embedded newlines read as newlines, while a stray control byte still cannot scramble the terminal.
textLines :: Text -> [Text]
textLines = map renderEscapingNonPrintable . Text.lines
