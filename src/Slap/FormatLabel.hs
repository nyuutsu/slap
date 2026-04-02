module Slap.FormatLabel
  ( FormatLabel(..)
  , formatLabelName
  ) where

data FormatLabel
  = LabelIPS
  | LabelIPS32
  | LabelEBP
  | LabelBPS
  | LabelUPS
  | LabelPPF1
  | LabelPPF2
  | LabelPPF3
  | LabelPPF4
  | LabelVCDIFF
  | LabelBSDiff
  | LabelAPSN64
  | LabelAPSGBA
  | LabelRUP
  | LabelNINJA1
  | LabelGDIFF
  | LabelXDelta1
  | LabelDPS
  | LabelPMSR
  | LabelPCHTXT
  deriving (Show, Eq, Enum, Bounded)

formatLabelName :: FormatLabel -> String
formatLabelName LabelIPS     = "IPS"
formatLabelName LabelIPS32   = "IPS32"
formatLabelName LabelEBP     = "EBP"
formatLabelName LabelBPS     = "BPS"
formatLabelName LabelUPS     = "UPS"
formatLabelName LabelPPF1    = "PPF1"
formatLabelName LabelPPF2    = "PPF2"
formatLabelName LabelPPF3    = "PPF3"
formatLabelName LabelPPF4    = "PPF4"
formatLabelName LabelVCDIFF  = "VCDIFF"
formatLabelName LabelBSDiff  = "BSDiff"
formatLabelName LabelAPSN64  = "APS-N64"
formatLabelName LabelAPSGBA  = "APS-GBA"
formatLabelName LabelRUP     = "RUP"
formatLabelName LabelNINJA1  = "NINJA1"
formatLabelName LabelGDIFF   = "GDIFF"
formatLabelName LabelXDelta1 = "xdelta1"
formatLabelName LabelDPS     = "DPS"
formatLabelName LabelPMSR    = "PMSR"
formatLabelName LabelPCHTXT  = "PCHTXT"
