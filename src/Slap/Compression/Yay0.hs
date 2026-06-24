{-# LANGUAGE OverloadedStrings #-}

-- | Yay0 (Nintendo LZSS) detection.
--
-- The decompression itself lives in rusty-slap; see
-- 'Slap.Compression.Stream.yay0Decompress'. What stays here is the
-- four-byte magic check used by 'Slap.SomePatch' to dispatch into the
-- Yay0 envelope branch. Crossing the FFI seam to compare four bytes
-- would be silly, so the predicate sits next to the format it names.
module Slap.Compression.Yay0 (isYay0) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString

isYay0 :: ByteString -> Bool
isYay0 input = ByteString.take 4 input == "Yay0"
