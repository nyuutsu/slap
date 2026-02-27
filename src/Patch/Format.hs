module Patch.Format
  ( -- * Hex formatting
    showCRC
  , padHex
  , padNum
  , padRight
  , showSigned
    -- * Key-value rendering
  , renderField
    -- * Hex dump
  , hexDump
  , chunksOf
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Int (Int64)
import Data.Word (Word8, Word32, Word64)
import Numeric (showHex)

showCRC :: Word32 -> String
showCRC w = padHex 8 (fromIntegral w)

padHex :: Int -> Int64 -> String
padHex w val =
  let s = showHex (fromIntegral val :: Word64) ""
  in replicate (w - length s) '0' ++ s

padNum :: Int -> String
padNum n =
  let s = show n
  in replicate (4 - length s) ' ' ++ s

padRight :: Int -> String -> String
padRight w s = s ++ replicate (w - length s) ' '

-- | Show a signed offset as +0xNNNNNN or -0xNNNNNN.
showSigned :: Int64 -> String
showSigned v
  | v >= 0    = "+0x" ++ padHex 6 v
  | otherwise = "-0x" ++ padHex 6 (abs v)

-- | Render a key-value pair with column-13 alignment.
renderField :: (String, String) -> String
renderField (k, v) = k ++ ":" ++ replicate (max 1 (13 - length k - 1)) ' ' ++ v

-- | Hex dump of a ByteString, showing up to 64 bytes in 16-byte rows.
hexDump :: ByteString -> String
hexDump bs
  | BS.null bs = ""
  | otherwise =
      let maxBytes = 64
          toShow = BS.unpack (BS.take maxBytes bs)
          rows = chunksOf 16 toShow
          formatted = map formatRow rows
          ellipsis = if BS.length bs > maxBytes then ["      ..."] else []
      in unlines (map ("      " ++) (formatted ++ ellipsis))

formatRow :: [Word8] -> String
formatRow bs =
  let hexParts = map (\b -> padHex 2 (fromIntegral b)) bs
      (left, right) = splitAt 8 hexParts
  in unwords left ++ "  " ++ unwords right

chunksOf :: Int -> [a] -> [[a]]
chunksOf _ [] = []
chunksOf n xs = let (a, b) = splitAt n xs in a : chunksOf n b
