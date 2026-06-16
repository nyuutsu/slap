{-# LANGUAGE OverloadedStrings #-}

-- | The render half of the opaque-field display lens: turning a run of
-- opaque metadata bytes into a viewable info-line value, read through
-- the @--metadata-encoding@ the user chose.
--
-- Two of slap's fields are opaque blobs the format fixes no meaning to —
-- the BPS metadata blob and the xdelta3 application header — and both
-- show through this one body, so the viewing behavior lives in a single
-- place rather than once per format. The decode half, "do these bytes
-- read as text under this encoding," is 'Slap.Text.readOpaqueField'; the
-- escaping-and-phrasing half is here.
--
-- This is its own module, not part of 'Slap.Display.Common', for a
-- layering reason: it imports 'Slap.Text', and 'Slap.Text' reaches
-- 'Slap.Display.Common' through 'Slap.Status', so hosting the render in
-- @Common@ would close an import cycle. A small dedicated module keeps
-- the dependency one-way.
module Slap.Display.OpaqueField
  ( renderOpaqueFieldBytes
  ) where

import Slap.Display.Common (renderAsText)
import Slap.Display.Primitives (renderEscapingNonPrintable)
import Slap.Text (EncodingName, encodingDisplayName,
                  OpaqueFieldReading(..), readOpaqueField)

import Data.Text (Text)
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString

-- | Render present, non-empty opaque field bytes through the
-- @--metadata-encoding@ lens. Where they read as text under the chosen
-- encoding, the decoded text shows with every non-printable codepoint
-- escaped for the terminal; where they don't, a byte count and the
-- encoding's name stand in. The caller owns the absent/empty framing
-- each field expresses in its own vocabulary.
renderOpaqueFieldBytes :: EncodingName -> ByteString -> Text
renderOpaqueFieldBytes encoding fieldBytes = case readOpaqueField encoding fieldBytes of
  OpaqueReadsAsText text -> byteCountPhrase <> ": " <> renderEscapingNonPrintable text
  OpaqueNotText          -> byteCountPhrase <> " (not valid " <> encodingDisplayName encoding <> ")"
  where
    byteCountPhrase = renderAsText (ByteString.length fieldBytes) <> " bytes"
