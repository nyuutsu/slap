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
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Char8 as ByteString8
import Data.Word (Word8, Word64)
import Numeric (showHex)

padHex :: (Integral a) => Int -> a -> String
padHex minWidth value =
  let digits = showHex (fromIntegral value :: Word64) ""
  in replicate (minWidth - length digits) '0' ++ digits

padNum :: Int -> String
padNum number =
  let digits = show number
  in replicate (4 - length digits) ' ' ++ digits

padRight :: Int -> String -> String
padRight minWidth text = text ++ replicate (minWidth - length text) ' '

-- | Show a signed offset as +0xNNNNNN or -0xNNNNNN.
showSigned :: Int -> String
showSigned value
  | value >= 0 = "+0x" ++ padHex 6 value
  | otherwise  = "-0x" ++ padHex 6 (abs value)

-- | Hex dump of a ByteString, showing up to 64 bytes in 16-byte rows.
hexDump :: ByteString -> String
hexDump input
  | ByteString.null input = ""
  | otherwise =
      let maxBytes = 64
          toShow = ByteString.unpack (ByteString.take maxBytes input)
          rows = chunksOf 16 toShow
          formatted = map formatRow rows
          ellipsis = if ByteString.length input > maxBytes then ["      ..."] else []
      in unlines (map ("      " ++) (formatted ++ ellipsis))

formatRow :: [Word8] -> String
formatRow bytes =
  let hexParts = map (\byte -> padHex 2 byte) bytes
      (left, right) = splitAt 8 hexParts
  in unwords left ++ "  " ++ unwords right

chunksOf :: Int -> [a] -> [[a]]
chunksOf _ [] = []
chunksOf size items = let (chunk, rest) = splitAt size items in chunk : chunksOf size rest

-- | Render a ByteString as a lowercase hex string (e.g. "a3f0...").
hexByteString :: ByteString -> String
hexByteString = concatMap (\byte -> padHex 2 byte) . ByteString.unpack

----------------------------------------------------------------------------
-- Shape-recognized byte display
----------------------------------------------------------------------------

-- | Render a byte sequence as ASCII text if every byte is in the
-- printable range (0x20–0x7E inclusive). Falls back to a hex dump
-- prefixed with @0x@ otherwise. Suitable for protocol bytes that
-- are spec'd ASCII (e.g. magic bytes, trailer markers) where the
-- printable case is the common path and the hex fallback exists
-- as defensive cover for malformed or unexpected input.
renderPrintableASCIIOrHex :: ByteString -> String
renderPrintableASCIIOrHex bytes
  | ByteString.all isPrintableAscii bytes =
      ByteString8.unpack bytes
  | otherwise =
      "0x" ++ hexByteString bytes

-- | True for the printable ASCII range (space through tilde
-- inclusive).
isPrintableAscii :: Word8 -> Bool
isPrintableAscii byte = byte >= 0x20 && byte <= 0x7E
