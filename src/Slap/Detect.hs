{-# LANGUAGE OverloadedStrings #-}

module Slap.Detect (detectFormat) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Char8 as ByteString8
import Slap.FileContents (PatchFileContents(..))
import Slap.Types (PatchFormat(..), DirectFormat(..), DiffFormat(..))
import qualified Slap.DPS.Parse as DPS

----------------------------------------------------------------------------
-- Named magic byte constants
----------------------------------------------------------------------------

vcdiffMagic :: ByteString
vcdiffMagic = "\xd6\xc3\xc4"

gdiffMagic :: ByteString
gdiffMagic = "\xd1\xff\xd1\xff"

----------------------------------------------------------------------------
-- PCHTXT directives
----------------------------------------------------------------------------

pchtxtDirectives :: [ByteString]
pchtxtDirectives = ["@nsobid", "@flag ", "@enabled", "@disabled"]

----------------------------------------------------------------------------
-- Detection
----------------------------------------------------------------------------

-- | Detect patch format.  Most formats are identified by magic bytes.
-- DPS uses a structural heuristic (version and stability flag bytes,
-- tentative record walk).  PCHTXT scans for known directives on the
-- first non-comment non-blank line.
detectFormat :: PatchFileContents -> Maybe PatchFormat
detectFormat (PatchFileContents input)
  | ByteString.length input < 4 = Nothing
  | ByteString.take 3 magic4 == "PPF" = Just (PatchDirect FormatPPF)
  | magic5 == "PATCH"         = Just (PatchDirect FormatIPS)
  | magic5 == "IPS32"         = Just (PatchDirect FormatIPS)   -- IPS32
  | magic4 == "BPS1"          = Just (PatchDiff FormatBPS)
  | magic4 == "UPS1"          = Just (PatchDiff FormatUPS)
  | ByteString.take 3 magic4 == vcdiffMagic = Just (PatchDiff FormatVCDIFF)
  | magic5 == "APS10"         = Just (PatchDirect FormatAPSN64)
  | magic4 == "APS1"          = Just (PatchDiff FormatAPSGBA)
  | ByteString.length input >= 6 && ByteString.take 6 input == "NINJA2" = Just (PatchDiff FormatRUP)
  | ByteString.length input >= 8 && ByteString.take 6 input == "NINJA1"  = Just (PatchDirect FormatNINJA1)
  | ByteString.length input >= 8 && ByteString.take 8 input == "BSDIFF40" = Just (PatchDiff FormatBSDiff)
  | magic4 == gdiffMagic      = Just (PatchDiff FormatGDIFF)
  | ByteString.length input >= 8 && ByteString.take 4 input == "%XDZ" = Just (PatchDiff FormatXDelta1)
  | ByteString.length input >= 7 && ByteString.take 7 input == "%XDELTA" = Just (PatchDiff FormatXDelta1)
  | magic4 == "PMSR"          = Just (PatchDirect FormatPMSR)
  | detectPCHTXT input        = Just (PatchDirect FormatPCHTXT)
  | DPS.isDPS input           = Just (PatchDiff FormatDPS)
  | otherwise                 = Nothing
  where
    magic4 = ByteString.take 4 input
    magic5 = ByteString.take 5 input

-- | Detect PCHTXT by scanning for a known directive on the first
-- non-comment non-blank line.  Scans the full input (directives
-- appear very early in real PCHTXT files).
detectPCHTXT :: ByteString -> Bool
detectPCHTXT inputBytes = scanLines (ByteString8.lines inputBytes)
  where
    scanLines [] = False
    scanLines (line:rest)
      | ByteString.null trimmed          = scanLines rest
      | ByteString.take 1 trimmed == "#" = scanLines rest
      | ByteString.take 1 trimmed == "/" = scanLines rest
      | any (`ByteString.isPrefixOf` trimmed) pchtxtDirectives = True
      | otherwise                = False
      where trimmed = ByteString8.dropWhile (\char -> char == ' ' || char == '\t' || char == '\r') line
