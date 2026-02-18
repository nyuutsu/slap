module Patch.Types (PatchFormat(..)) where

-- | Detected patch format.
data PatchFormat = FmtPPF | FmtIPS | FmtBPS | FmtUPS | FmtVCDIFF | FmtAPS | FmtRUP | FmtBSDiff | FmtGDIFF | FmtXDelta1 | FmtPMSR
  deriving (Show, Eq)
