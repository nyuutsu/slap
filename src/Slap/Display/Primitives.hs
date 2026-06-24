{-# LANGUAGE OverloadedStrings #-}

module Slap.Display.Primitives
  ( -- * Width padding
    padHex
  , padNum
  , padRight
    -- * Signed-hex rendering
  , showSigned
    -- * ByteString rendering
  , hexByteString
  , hexDump
    -- * Shape-recognized byte display
  , renderPrintableASCIIOrHex
    -- * Safe text display
  , renderEscapingNonPrintable
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Char8 as ByteString8
import Data.Char (isPrint, ord)
import Data.Text (Text)
import qualified Data.Text as Text
import Data.Word (Word8, Word64)
import Numeric (showHex)

padHex :: (Integral a) => Int -> a -> Text
padHex minWidth value =
  let digits = showHex (fromIntegral value :: Word64) ""
  in Text.pack (replicate (minWidth - length digits) '0' ++ digits)

padNum :: Int -> Text
padNum number =
  let digits = show number
  in Text.pack (replicate (4 - length digits) ' ' ++ digits)

padRight :: Int -> Text -> Text
padRight minWidth text = text <> Text.replicate (minWidth - Text.length text) " "

-- | Show a signed offset as +0xNNNNNN or -0xNNNNNN.
showSigned :: Int -> Text
showSigned value
  | value >= 0 = "+0x" <> padHex 6 value
  | otherwise  = "-0x" <> padHex 6 (abs value)

-- | Hex dump of a ByteString, showing up to 64 bytes in 16-byte rows.
hexDump :: ByteString -> Text
hexDump input
  | ByteString.null input = ""
  | otherwise =
      let maxBytes = 64
          toShow = ByteString.unpack (ByteString.take maxBytes input)
          rows = chunksOf 16 toShow
          formatted = map formatRow rows
          ellipsis = if ByteString.length input > maxBytes then ["      ..."] else []
      in Text.unlines (map ("      " <>) (formatted ++ ellipsis))

formatRow :: [Word8] -> Text
formatRow bytes =
  let hexParts = map (\byte -> padHex 2 byte) bytes
      (left, right) = splitAt 8 hexParts
  in Text.intercalate " " left <> "  " <> Text.intercalate " " right

chunksOf :: Int -> [a] -> [[a]]
chunksOf _ [] = []
chunksOf size items = let (chunk, rest) = splitAt size items in chunk : chunksOf size rest

-- | Render a ByteString as a lowercase hex string (e.g. "a3f0...").
hexByteString :: ByteString -> Text
hexByteString = Text.concat . map (padHex 2) . ByteString.unpack

----------------------------------------------------------------------------
-- Shape-recognized byte display
----------------------------------------------------------------------------

-- | Render a byte sequence as ASCII text if every byte is in the
-- printable range (0x20–0x7E inclusive). Falls back to a hex dump
-- prefixed with @0x@ otherwise. Suitable for protocol bytes that
-- are spec'd ASCII (e.g. magic bytes, trailer markers).
renderPrintableASCIIOrHex :: ByteString -> Text
renderPrintableASCIIOrHex bytes
  | ByteString.all isPrintableAscii bytes =
      Text.pack (ByteString8.unpack bytes)
  | otherwise =
      "0x" <> hexByteString bytes

-- | True for the printable ASCII range (space through tilde
-- inclusive).
isPrintableAscii :: Word8 -> Bool
isPrintableAscii byte = byte >= 0x20 && byte <= 0x7E

----------------------------------------------------------------------------
-- Safe text display
----------------------------------------------------------------------------

-- | Render 'Text' for safe terminal display:
-- every printable codepoint passes through literally, every non-printable one becomes a visible @\<U+XXXX\>@ token.
-- "Printable" is 'Data.Char.isPrint', so newlines, terminal-escape introducers, and bidi/zero-width spoofing characters all become inert tokens.
--
-- Nothing is dropped: a hostile blob is shown in full, just defanged.
-- Suitable for previewing arbitrary text from an untrusted patch (the BPS metadata glance is the first caller).
renderEscapingNonPrintable :: Text -> Text
renderEscapingNonPrintable = Text.concatMap renderCodepoint
  where
    renderCodepoint codepoint
      | isPrint codepoint = Text.singleton codepoint
      | otherwise         = escapeCodepoint codepoint
    escapeCodepoint codepoint =
      "<U+" <> Text.toUpper (padHex 4 (ord codepoint)) <> ">"
