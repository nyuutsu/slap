{-# LANGUAGE OverloadedStrings #-}

module Patch.Detect (detectFormat) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Char8 as ByteString8
import Patch.Types (PatchFormat(..))

-- | Detect patch format from the first few bytes (magic).
detectFormat :: ByteString -> Maybe PatchFormat
detectFormat input
  | ByteString.length input < 4 = Nothing
  | ByteString.take 3 magic4 == "PPF" = Just FormatPPF
  | magic5 == "PATCH"         = Just FormatIPS
  | magic5 == "IPS32"         = Just FormatIPS   -- IPS32
  | magic4 == "BPS1"          = Just FormatBPS
  | magic4 == "UPS1"          = Just FormatUPS
  | ByteString.take 3 magic4 == "\xd6\xc3\xc4" = Just FormatVCDIFF
  | magic5 == "APS10"         = Just FormatAPSN64
  | magic4 == "APS1"          = Just FormatAPSGBA
  | ByteString.length input >= 6 && ByteString.take 6 input == "NINJA2" = Just FormatRUP
  | ByteString.length input >= 8 && ByteString.take 6 input == "NINJA1"  = Just FormatNINJA1
  | ByteString.length input >= 8 && ByteString.take 8 input == "BSDIFF40" = Just FormatBSDiff
  | magic4 == "\xd1\xff\xd1\xff" = Just FormatGDIFF
  | ByteString.length input >= 8 && ByteString.take 4 input == "%XDZ" = Just FormatXDelta1
  | ByteString.length input >= 7 && ByteString.take 7 input == "%XDELTA" = Just FormatXDelta1
  | magic4 == "PMSR"          = Just FormatPMSR
  | detectPCHTXT input        = Just FormatPCHTXT
  | otherwise                 = Nothing
  where
    magic4 = ByteString.take 4 input
    magic5 = ByteString.take 5 input

-- | Detect PCHTXT by scanning for a known directive on the first non-comment line.
detectPCHTXT :: ByteString -> Bool
detectPCHTXT raw = scanLines (ByteString8.lines (ByteString.take 512 raw))
  where
    scanLines [] = False
    scanLines (line:rest)
      | ByteString.null trimmed          = scanLines rest
      | ByteString.take 1 trimmed == "#" = scanLines rest
      | ByteString.take 1 trimmed == "/" = scanLines rest
      | ByteString.take 7 trimmed == "@nsobid"  = True
      | ByteString.take 6 trimmed == "@flag "   = True
      | ByteString.take 8 trimmed == "@enabled" = True
      | ByteString.take 9 trimmed == "@disabled" = True
      | otherwise                = False
      where trimmed = ByteString8.dropWhile (\char -> char == ' ' || char == '\t' || char == '\r') line
