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
  , EmbeddedDepth(..)
  , renderEmbedded
  ) where

import Slap.Display.Common (InfoLine(..), renderInfoLine, renderAsText)
import Slap.Display.Primitives (renderEscapingNonPrintable)
import Slap.Text (EncodingName, EncodedText, encodedTextContent, encodingDisplayName,
                  OpaqueFieldReading(..), readOpaqueField)

import Data.Text (Text)
import qualified Data.Text as Text
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString

data EmbeddedContent = EmbeddedContent
  { embeddedLabel :: !Text
  , embeddedField :: !EmbeddedField
  }
  deriving (Eq, Show)

-- | 'FieldAbsent' and 'FieldEmpty' part ways only where a format can tell them apart:
-- the xdelta3 appheader's presence bit makes "declared but empty" a different fact from "never declared."
-- A format without that bit reaches for 'FieldAbsent'.
data EmbeddedField
  = FieldAbsent
  | FieldEmpty
  | FieldOpaque !EncodingName !ByteString
  | FieldText !EncodedText
  deriving (Eq, Show)

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

sizeGlance :: EmbeddedField -> Text
sizeGlance FieldAbsent           = "(none)"
sizeGlance FieldEmpty            = "(empty)"
sizeGlance (FieldOpaque _ bytes) = renderAsText (ByteString.length bytes) <> " bytes"
sizeGlance (FieldText text)      = renderAsText (Text.length (encodedTextContent text)) <> " characters"

payloadLines :: EmbeddedField -> [Text]
payloadLines FieldAbsent                  = []
payloadLines FieldEmpty                   = []
payloadLines (FieldOpaque encoding bytes) = case readOpaqueField encoding bytes of
  OpaqueReadsAsText text -> textLines text
  OpaqueNotText          -> ["(not valid " <> encodingDisplayName encoding <> ")"]
payloadLines (FieldText text)             = textLines (encodedTextContent text)

-- | Break content on its own line breaks, escaping anything unprintable left within a line —
-- so embedded newlines read as newlines, while a stray control byte still cannot scramble the terminal.
textLines :: Text -> [Text]
textLines = map renderEscapingNonPrintable . Text.lines
