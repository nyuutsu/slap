{-# LANGUAGE OverloadedStrings #-}

module Slap.Detect (detectFormat) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Char8 as ByteString8
import Data.List (find)
import Slap.APSGBA.Types (apsGbaMagicBytes)
import Slap.APSN64.Types (apsN64MagicBytes)
import Slap.BPS.Types (bpsMagicBytes)
import Slap.BSDiff.Types (bsdiffMagicBytes)
import qualified Slap.DPS.Parse as DPS
import Slap.FileContents (PatchFileContents(..))
import Slap.GDIFF.Types (gdiffMagicBytes)
import Slap.IPS.Types (IPSVariant(..), ipsMagicBytes, ips32MagicBytes)
import Slap.NINJA1.Types (ninja1MagicBytes)
import Slap.NINJA2.Types (ninja2MagicBytes)
import Slap.PMSR.Types (pmsrMagicBytes)
import Slap.PPF.Types (ppf1MagicBytes, ppf2MagicBytes, ppf3MagicBytes, ppf4MagicBytes)
import Slap.Types (PatchFormat(..), DirectFormat(..), DiffFormat(..))
import Slap.UPS.Types (upsMagicBytes)
import Slap.VCDIFF.Types (vcdiffMagicBytes)

----------------------------------------------------------------------------
-- Magic prefix detection
----------------------------------------------------------------------------

-- | A byte sequence that, when present at the start of a patch file,
-- identifies its format.  Exists so that 'probeMatches' can
-- distinguish the needle (the magic to test) from the haystack (the
-- file contents being classified) at the type level — without it,
-- both arguments to 'ByteString.isPrefixOf' would be bare
-- 'ByteString' and a transposition would silently invert the
-- semantics.
newtype MagicPrefix = MagicPrefix { unMagicPrefix :: ByteString }

data FormatProbe = FormatProbe
  { probeMagic  :: !MagicPrefix
  , probeFormat :: !PatchFormat
  }

-- | Ordered by descending prefix length so that a longer probe
-- always wins over a shorter one that happens to be its prefix.
-- The pairs where this matters today: 'apsN64MagicBytes'
-- (@"APS10"@, 5 bytes) before 'apsGbaMagicBytes' (@"APS1"@,
-- 4 bytes), and @"%XDELTA"@ (7 bytes) before @"%XDZ"@ (4 bytes).
-- When two probes share no prefix, their relative order is
-- irrelevant.
--
-- Formats whose detection requires structural inspection rather
-- than a leading byte sequence (PCHTXT, DPS) are not in this table
-- and are handled as fallbacks in 'detectFormat'.
magicProbes :: [FormatProbe]
magicProbes =
  [ FormatProbe (MagicPrefix bsdiffMagicBytes)  (PatchDiff   FormatBSDiff)
  , FormatProbe (MagicPrefix "%XDELTA")         (PatchDiff   FormatXDelta1)
  , FormatProbe (MagicPrefix ninja2MagicBytes)  (PatchDiff   FormatNINJA2)
  , FormatProbe (MagicPrefix ninja1MagicBytes)  (PatchDirect FormatNINJA1)
  , FormatProbe (MagicPrefix apsN64MagicBytes)  (PatchDirect FormatAPSN64)
  , FormatProbe (MagicPrefix ipsMagicBytes)     (PatchDirect (FormatIPS StandardIPS))
  , FormatProbe (MagicPrefix ips32MagicBytes)   (PatchDirect (FormatIPS IPS32))
  , FormatProbe (MagicPrefix bpsMagicBytes)     (PatchDiff   FormatBPS)
  , FormatProbe (MagicPrefix upsMagicBytes)     (PatchDiff   FormatUPS)
  , FormatProbe (MagicPrefix apsGbaMagicBytes)  (PatchDiff   FormatAPSGBA)
  , FormatProbe (MagicPrefix "%XDZ")            (PatchDiff   FormatXDelta1)
  , FormatProbe (MagicPrefix pmsrMagicBytes)    (PatchDirect FormatPMSR)
  , FormatProbe (MagicPrefix gdiffMagicBytes)   (PatchDiff   FormatGDIFF)
  , FormatProbe (MagicPrefix ppf1MagicBytes)    (PatchDirect FormatPPF1)
  , FormatProbe (MagicPrefix ppf2MagicBytes)    (PatchDirect FormatPPF2)
  , FormatProbe (MagicPrefix ppf3MagicBytes)    (PatchDirect FormatPPF3)
  , FormatProbe (MagicPrefix ppf4MagicBytes)    (PatchDirect FormatPPF4)
  , FormatProbe (MagicPrefix vcdiffMagicBytes)  (PatchDiff   FormatVCDIFF)
  ]

probeMatches :: PatchFileContents -> FormatProbe -> Bool
probeMatches (PatchFileContents fileBytes) probe =
  unMagicPrefix (probeMagic probe) `ByteString.isPrefixOf` fileBytes

----------------------------------------------------------------------------
-- Detection
----------------------------------------------------------------------------

-- | Detect patch format.  Most formats are identified by a magic byte
-- sequence at the start of the file, matched against the
-- 'magicProbes' table.  Two formats require structural inspection
-- instead: DPS has no magic and is detected by a heuristic walk
-- ('Slap.DPS.Parse.isDPS'), and PCHTXT is detected by scanning for
-- a known directive on the first non-comment non-blank line.
detectFormat :: PatchFileContents -> Maybe PatchFormat
detectFormat patchFile =
  case find (probeMatches patchFile) magicProbes of
    Just probe -> Just (probeFormat probe)
    Nothing
      | detectPCHTXT fileBytes -> Just (PatchDirect FormatPCHTXT)
      | DPS.isDPS fileBytes    -> Just (PatchDiff   FormatDPS)
      | otherwise              -> Nothing
  where
    PatchFileContents fileBytes = patchFile

----------------------------------------------------------------------------
-- PCHTXT directives
----------------------------------------------------------------------------

pchtxtDirectives :: [ByteString]
pchtxtDirectives = ["@nsobid", "@flag ", "@enabled", "@disabled"]

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
