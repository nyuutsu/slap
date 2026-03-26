module Patch.Types (PatchFormat(..)) where

-- | Detected patch format.
data PatchFormat = FormatPPF | FormatIPS | FormatBPS | FormatUPS | FormatVCDIFF | FormatAPSN64 | FormatAPSGBA | FormatRUP | FormatNINJA1 | FormatBSDiff | FormatGDIFF | FormatXDelta1 | FormatPMSR | FormatPCHTXT
  deriving (Show, Eq)
