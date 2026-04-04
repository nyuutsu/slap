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
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.Int (Int64)
import Data.Word (Word8, Word32, Word64)
import Numeric (showHex)

showCRC :: Word32 -> String
showCRC crc = padHex 8 (fromIntegral crc)

padHex :: Int -> Int64 -> String
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
showSigned :: Int64 -> String
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
  let hexParts = map (\byte -> padHex 2 (fromIntegral byte)) bytes
      (left, right) = splitAt 8 hexParts
  in unwords left ++ "  " ++ unwords right

chunksOf :: Int -> [a] -> [[a]]
chunksOf _ [] = []
chunksOf size items = let (chunk, rest) = splitAt size items in chunk : chunksOf size rest

-- | Render a ByteString as a lowercase hex string (e.g. "a3f0...").
hexByteString :: ByteString -> String
hexByteString = concatMap (\byte -> padHex 2 (fromIntegral byte)) . ByteString.unpack
