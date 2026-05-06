module Slap.Types
  ( DirectFormat(..)
  , DifferentialFormat(..)
  , PatchFormat(..)
  ) where

import Slap.IPS.Types (IPSVariant(..))

-- | Direct patch format: encodes "write these bytes at offset X."
-- The source file is not needed to reconstruct the target — the patch
-- carries the literal replacement bytes (or fill values) at each offset.
data DirectFormat
  = FormatIPS IPSVariant
  | FormatPPF1
  | FormatPPF2
  | FormatPPF3
  | FormatPPF4
  | FormatNINJA1
  | FormatPMSR
  | FormatPCHTXT
  | FormatAPSN64
  deriving (Show, Eq)

-- | Differential patch format: encodes instructions that transform
-- source bytes into target bytes.  The source file is required.
data DifferentialFormat
  = FormatBPS | FormatUPS | FormatVCDIFF | FormatAPSGBA | FormatNINJA2
  | FormatBSDiff | FormatGDIFF | FormatXDelta1 | FormatDPS
  deriving (Show, Eq, Enum, Bounded)

-- | Detected patch format, classified by its intrinsic nature.
data PatchFormat
  = PatchDirect DirectFormat
  | PatchDifferential DifferentialFormat
  deriving (Show, Eq)
