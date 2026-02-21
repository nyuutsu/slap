module Patch.Types (PatchFormat(..)) where

-- | Detected patch format.
data PatchFormat = FmtPPF | FmtIPS | FmtBPS | FmtUPS | FmtVCDIFF | FmtAPS | FmtRUP | FmtNINJA1 | FmtBSDiff | FmtGDIFF | FmtXDelta1 | FmtPMSR | FmtPCHTXT
  deriving (Show, Eq)
