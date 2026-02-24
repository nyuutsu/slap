{-# LANGUAGE OverloadedStrings #-}

module Patch.Detect (detectFormat) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BS8
import Patch.Types (PatchFormat(..))

-- | Detect patch format from the first few bytes (magic).
detectFormat :: ByteString -> Maybe PatchFormat
detectFormat bs
  | BS.length bs < 4 = Nothing
  | BS.take 3 magic4 == "PPF" = Just FmtPPF
  | magic5 == "PATCH"         = Just FmtIPS
  | magic5 == "IPS32"         = Just FmtIPS   -- IPS32
  | magic4 == "BPS1"          = Just FmtBPS
  | magic4 == "UPS1"          = Just FmtUPS
  | BS.take 3 magic4 == "\xd6\xc3\xc4" = Just FmtVCDIFF
  | magic5 == "APS10"         = Just FmtAPS   -- APS N64
  | magic4 == "APS1"          = Just FmtAPS   -- APS GBA (magic is "APS1" + first byte of source size)
  | BS.length bs >= 6 && BS.take 6 bs == "NINJA2" = Just FmtRUP
  | BS.length bs >= 8 && BS.take 6 bs == "NINJA1"  = Just FmtNINJA1
  | BS.length bs >= 8 && BS.take 8 bs == "BSDIFF40" = Just FmtBSDiff
  | magic4 == "\xd1\xff\xd1\xff" = Just FmtGDIFF
  | BS.length bs >= 8 && BS.take 4 bs == "%XDZ" = Just FmtXDelta1
  | BS.length bs >= 7 && BS.take 7 bs == "%XDELTA" = Just FmtXDelta1
  | magic4 == "PMSR"          = Just FmtPMSR
  | detectPCHTXT bs            = Just FmtPCHTXT
  | otherwise                 = Nothing
  where
    magic4 = BS.take 4 bs
    magic5 = BS.take 5 bs

-- | Detect PCHTXT by scanning for a known directive on the first non-comment line.
detectPCHTXT :: ByteString -> Bool
detectPCHTXT raw = check (BS8.lines (BS.take 512 raw))
  where
    check [] = False
    check (l:ls)
      | BS.null s              = check ls
      | BS.take 1 s == "#"     = check ls
      | BS.take 1 s == "/"     = check ls
      | BS.take 7 s == "@nsobid"  = True
      | BS.take 6 s == "@flag "   = True
      | BS.take 8 s == "@enabled" = True
      | BS.take 9 s == "@disabled" = True
      | otherwise              = False
      where s = BS8.dropWhile (\c -> c == ' ' || c == '\t' || c == '\r') l
