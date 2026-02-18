{-# LANGUAGE StrictData #-}

module Patch.Types
  ( PatchFormat(..)
  , SomePatch(..)
  ) where

import qualified Patch.PPF.Types as PPF
import qualified Patch.IPS       as IPS
import qualified Patch.BPS       as BPS
import qualified Patch.UPS       as UPS
import qualified Patch.VCDIFF    as VCDIFF
import qualified Patch.APS       as APS
import qualified Patch.RUP       as RUP
import qualified Patch.BSDiff    as BSDiff
import qualified Patch.GDIFF     as GDIFF
import qualified Patch.XDelta1   as XDelta1
import qualified Patch.PMSR      as PMSR

-- | Detected patch format.
data PatchFormat = FmtPPF | FmtIPS | FmtBPS | FmtUPS | FmtVCDIFF | FmtAPS | FmtRUP | FmtBSDiff | FmtGDIFF | FmtXDelta1 | FmtPMSR
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
  | SomeBSDiff BSDiff.BSDiffPatch
  | SomeGDIFF  GDIFF.GDiffPatch
  | SomeXDelta1 XDelta1.XDelta1Patch
  | SomePMSR  PMSR.PMSRPatch

