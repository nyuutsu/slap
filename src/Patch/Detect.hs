{-# LANGUAGE OverloadedStrings #-}

module Patch.Detect (detectFormat) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Patch.Types (PatchFormat(..))

-- | Detect patch format from magic bytes at the start of the file.
detectFormat :: ByteString -> Maybe PatchFormat
detectFormat bs
  | BS.length bs < 4    = Nothing
  | magic4 == "PPF1"    = Just FmtPPF
  | magic4 == "PPF2"    = Just FmtPPF
  | magic4 == "PPF3"    = Just FmtPPF
  | magic4 == "PPF4"    = Just FmtPPF
  | otherwise            = Nothing
  where
    magic4 = BS.take 4 bs
