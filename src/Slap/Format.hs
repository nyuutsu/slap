module Slap.Format
  ( -- * Hex formatting
    showCRC
  , padHex
  , padNum
  , padRight
  , showSigned
  , hexByteString
    -- * Key-value rendering
  , renderField
    -- * Structured fields
  , MetaField(..)
    -- * Hex dump
  , hexDump
  , chunksOf
    -- * Shape-recognised byte display
  , renderPrintableASCIIOrHex
  , renderUTF8OrByteCount
    -- * Display glyphs
  , rightwardsArrow
  , checkMark
  , ballotX
  , enDash
  , emDash
  , spacePaddedRightwardsArrow
  , spacePaddedEnDash
  ) where

import Slap.TextEncoding (isValidUtf8, decodeUtf8Field, truncateUtf8)

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Char8 as ByteString8
import Data.Word (Word8, Word32, Word64)
import Numeric (showHex)

showCRC :: Word32 -> String
showCRC crc = padHex 8 crc

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

-- | A labeled metadata value for display. This is the output of
-- the Describe layer: structured domain data has already been
-- translated into human-readable strings by the time MetaField
-- is constructed. MetaField is a display type, not a domain type.
data MetaField = MetaField
  { metaFieldLabel :: !String
  , metaFieldValue :: !String
  } deriving (Eq, Show)

-- | Render a MetaField with column-13 alignment.
renderField :: MetaField -> String
renderField (MetaField label value) =
  label ++ ":" ++ replicate (max 1 (13 - length label - 1)) ' ' ++ value

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
-- Shape-recognised byte display
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

-- | Render a byte sequence as text if it is valid UTF-8, truncated
-- to a maximum length for display. Falls back to a description of
-- byte count and "not valid UTF-8" if decoding fails. Suitable for
-- content bytes that are UTF-8 by spec or convention (e.g. EBP
-- metadata) where the goal is human-legible display rather than
-- byte-exact rendering.
--
-- The truncation cap counts bytes of the original UTF-8, not
-- decoded characters; for human display previews this is usually
-- what's wanted (a 200-byte cap shows ~200 bytes worth of content
-- regardless of character width).
renderUTF8OrByteCount :: Int -> ByteString -> String
renderUTF8OrByteCount maxPreviewBytes bytes
  | isValidUtf8 bytes =
      let preview  = truncateUtf8 maxPreviewBytes bytes
          ellipsis = if ByteString.length bytes > maxPreviewBytes
                     then "..."
                     else ""
      in decodeUtf8Field preview ++ ellipsis
  | otherwise =
      show (ByteString.length bytes) ++ " bytes, not valid UTF-8"

-- | True for the printable ASCII range (space through tilde
-- inclusive).
isPrintableAscii :: Word8 -> Bool
isPrintableAscii byte = byte >= 0x20 && byte <= 0x7E

----------------------------------------------------------------------------
-- Display glyphs
----------------------------------------------------------------------------

-- The codepoints below are domain symbols in slap's CLI output
-- (output redirection, verification status, range separators,
-- sentence-internal pause).  Naming them once means call sites
-- read as the meaning they carry rather than as a numeric escape.

-- | U+2192 (→).  Output redirection in CLI status lines, e.g.
-- @applied 23 records → output.bin@.
rightwardsArrow :: Char
rightwardsArrow = '\8594'

-- | U+2713 (✓).  Verification success in dry-run output.
checkMark :: Char
checkMark = '\10003'

-- | U+2717 (✗).  Verification failure in dry-run output, paired
-- with the expected value.
ballotX :: Char
ballotX = '\10007'

-- | U+2013 (–).  Inclusive range separator in Explain output, e.g.
-- @0x000000 – 0x00FFFF@.
enDash :: Char
enDash = '\8211'

-- | U+2014 (—).  Sentence-internal pause in error messages.
emDash :: Char
emDash = '\8212'

-- | 'rightwardsArrow' flanked by single spaces; the recurring shape
-- in CLI status lines like @INPUT → OUTPUT@.
spacePaddedRightwardsArrow :: String
spacePaddedRightwardsArrow = [' ', rightwardsArrow, ' ']

-- | 'enDash' flanked by single spaces; the recurring shape in
-- Explain range output like @0x000000 – 0x00FFFF@.
spacePaddedEnDash :: String
spacePaddedEnDash = [' ', enDash, ' ']
