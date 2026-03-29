module Slap.Types
  ( DirectFormat(..)
  , DiffFormat(..)
  , PatchFormat(..)
  ) where

-- | Direct patch format: encodes "write these bytes at offset X."
-- The source file is not needed to reconstruct the target — the patch
-- carries the literal replacement bytes (or fill values) at each offset.
data DirectFormat
  = FormatIPS | FormatPPF | FormatNINJA1 | FormatPMSR
  | FormatPCHTXT | FormatAPSN64
  deriving (Show, Eq, Enum, Bounded)

-- | Differential patch format: encodes instructions that transform
-- source bytes into target bytes.  The source file is required.
data DiffFormat
  = FormatBPS | FormatUPS | FormatVCDIFF | FormatAPSGBA | FormatRUP
  | FormatBSDiff | FormatGDIFF | FormatXDelta1 | FormatDPS
  deriving (Show, Eq, Enum, Bounded)

-- | Detected patch format, classified by its intrinsic nature.
data PatchFormat
  = PatchDirect DirectFormat
  | PatchDiff DiffFormat
  deriving (Show, Eq)
