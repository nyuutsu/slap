{-# LANGUAGE StrictData #-}

module Patch.Types
  ( PatchFormat(..)
  , SomePatch(..)
  , ChecksumResult(..)
  , checksumOk
  ) where

import Data.Word (Word32)

import qualified Patch.PPF.Types as PPF
import qualified Patch.IPS       as IPS
import qualified Patch.BPS       as BPS
import qualified Patch.UPS       as UPS
import qualified Patch.VCDIFF    as VCDIFF
import qualified Patch.APS       as APS
import qualified Patch.RUP       as RUP

-- | Detected patch format.
data PatchFormat = FmtPPF | FmtIPS | FmtBPS | FmtUPS | FmtVCDIFF | FmtAPS | FmtRUP
  deriving (Show, Eq)

-- | A parsed patch of any supported format.
data SomePatch
  = SomePPF   PPF.Patch
  | SomeIPS   IPS.IPSPatch
  | SomeBPS   BPS.BPSPatch
  | SomeUPS   UPS.UPSPatch
  | SomeVCDIFF VCDIFF.VCDIFFPatch
  | SomeAPS   APS.APSPatch
  | SomeRUP   RUP.RUPPatch

-- | Result of a checksum comparison.
data ChecksumResult
  = CrcMatch
  | CrcMismatch String Word32 Word32  -- label, expected, actual
  deriving (Show)

checksumOk :: ChecksumResult -> Bool
checksumOk CrcMatch = True
checksumOk _        = False
