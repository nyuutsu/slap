{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE OverloadedStrings #-}

module Slap.FormatLabel
  ( FormatLabel(..)
  , formatLabelName
  , formatLabelWithIndefiniteArticle
  ) where

import Data.Aeson (ToJSON)
import Data.Text (Text)
import GHC.Generics (Generic, Generically(..))

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
  | LabelNINJA2
  | LabelNINJA1
  | LabelGDIFF
  | LabelXDelta1
  | LabelDPS
  | LabelPMSR
  deriving (Show, Eq, Enum, Bounded, Generic)
  deriving (ToJSON) via Generically FormatLabel

formatLabelName :: FormatLabel -> Text
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
formatLabelName LabelNINJA2  = "NINJA2"
formatLabelName LabelNINJA1  = "NINJA1"
formatLabelName LabelGDIFF   = "GDIFF"
formatLabelName LabelXDelta1 = "xdelta1"
formatLabelName LabelDPS     = "DPS"
formatLabelName LabelPMSR    = "PMSR"

-- | The format's name with its indefinite article, for prose like "an IPS patch" or "a PPF2 patch".
-- The article follows the spoken name, so the vowel-sounded ones take "an".
formatLabelWithIndefiniteArticle :: FormatLabel -> Text
formatLabelWithIndefiniteArticle label
  | label `elem` vowelSoundedLabels = "an " <> formatLabelName label
  | otherwise                       = "a "  <> formatLabelName label
  where
    vowelSoundedLabels =
      [LabelIPS, LabelIPS32, LabelEBP, LabelAPSN64, LabelAPSGBA, LabelXDelta1]
