{-# LANGUAGE OverloadedStrings #-}

module Slap.Detect (detectFormat) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.List (find)
import qualified Slap.APSGBA.Parse as APSGBA (isAPSGBAStructured)
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
import Slap.PPF1.Types (ppf1MagicBytes)
import Slap.PPF2.Types (ppf2MagicBytes)
import Slap.PPF3.Types (ppf3MagicBytes)
import Slap.PPF4.Types (ppf4MagicBytes)
import Slap.PatchFormat (PatchFormat(..), DirectFormat(..), DifferentialFormat(..))
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
-- than a leading byte sequence (DPS) are not in this table and are
-- handled as fallbacks in 'detectFormat'.
magicProbes :: [FormatProbe]
magicProbes =
  [ FormatProbe (MagicPrefix bsdiffMagicBytes)  (PatchDifferential FormatBSDiff)
  , FormatProbe (MagicPrefix "%XDELTA")         (PatchDifferential FormatXDelta1)
  , FormatProbe (MagicPrefix ninja2MagicBytes)  (PatchDifferential FormatNINJA2)
  , FormatProbe (MagicPrefix ninja1MagicBytes)  (PatchDirect       FormatNINJA1)
  , FormatProbe (MagicPrefix apsN64MagicBytes)  (PatchDirect       FormatAPSN64)
  , FormatProbe (MagicPrefix ipsMagicBytes)     (PatchDirect       (FormatIPS StandardIPS))
  , FormatProbe (MagicPrefix ips32MagicBytes)   (PatchDirect       (FormatIPS IPS32))
  , FormatProbe (MagicPrefix bpsMagicBytes)     (PatchDifferential FormatBPS)
  , FormatProbe (MagicPrefix upsMagicBytes)     (PatchDifferential FormatUPS)
  , FormatProbe (MagicPrefix apsGbaMagicBytes)  (PatchDifferential FormatAPSGBA)
  , FormatProbe (MagicPrefix "%XDZ")            (PatchDifferential FormatXDelta1)
  , FormatProbe (MagicPrefix pmsrMagicBytes)    (PatchDirect       FormatPMSR)
  , FormatProbe (MagicPrefix gdiffMagicBytes)   (PatchDifferential FormatGDIFF)
  , FormatProbe (MagicPrefix ppf1MagicBytes)    (PatchDirect       FormatPPF1)
  , FormatProbe (MagicPrefix ppf2MagicBytes)    (PatchDirect       FormatPPF2)
  , FormatProbe (MagicPrefix ppf3MagicBytes)    (PatchDirect       FormatPPF3)
  , FormatProbe (MagicPrefix ppf4MagicBytes)    (PatchDirect       FormatPPF4)
  , FormatProbe (MagicPrefix vcdiffMagicBytes)  (PatchDifferential FormatVCDIFF)
  ]

probeMatches :: PatchFileContents -> FormatProbe -> Bool
probeMatches (PatchFileContents fileBytes) probe =
  unMagicPrefix (probeMagic probe) `ByteString.isPrefixOf` fileBytes

----------------------------------------------------------------------------
-- Detection
----------------------------------------------------------------------------

-- | Most formats are identified by a magic byte sequence at the start of the file, matched against the 'magicProbes' table.
-- DPS is the lone exception: it has no magic and is detected by a heuristic walk ('Slap.DPS.Parse.isDPS').
detectFormat :: PatchFileContents -> Maybe PatchFormat
detectFormat patchFile =
  case find (probeMatches patchFile) magicProbes of
    Just probe -> Just (resolveAmbiguity (probeFormat probe))
    Nothing
      | DPS.isDPS fileBytes -> Just (PatchDifferential FormatDPS)
      | otherwise           -> Nothing
  where
    PatchFileContents fileBytes = patchFile

    -- Some probe results are ambiguous between two formats and need a
    -- structural test to disambiguate. Today's only such case: APSN64
    -- and APS-GBA share enough magic prefix that an APS-GBA file with
    -- @source_size == 0x30@ reads as @"APS10"@ for its first 5 bytes
    -- and the longer-wins probe rule routes it to APSN64. The APS-GBA
    -- record-shape test catches this and re-routes to 'FormatAPSGBA'.
    resolveAmbiguity :: PatchFormat -> PatchFormat
    resolveAmbiguity (PatchDirect FormatAPSN64)
      | APSGBA.isAPSGBAStructured fileBytes = PatchDifferential FormatAPSGBA
    resolveAmbiguity format = format
