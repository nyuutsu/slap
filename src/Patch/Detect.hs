{-# LANGUAGE OverloadedStrings #-}

module Patch.Detect (detectFormat) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Patch.Types (PatchFormat(..))

-- | Detect patch format from magic bytes at the start of the file.
detectFormat :: ByteString -> Maybe PatchFormat
detectFormat bs
  | BS.length bs < 4    = Nothing
  | BS.take 3 magic4 == "PPF" = Just FmtPPF
  | magic5 == "PATCH"         = Just FmtIPS
  | magic4 == "IPS3"          = Just FmtIPS   -- IPS32: magic "IPS32"
  | magic4 == "BPS1"          = Just FmtBPS
  | otherwise                 = Nothing
  where
    magic4 = BS.take 4 bs
    magic5 = BS.take 5 bs
