module Slap.BSDiff.Describe
  ( bsdiffInfo
  , bsdiffMeta
  , explainBSDiff
  , makeBSDiffRegion
  ) where

import Slap.BSDiff.Types (BSDiffPatch(..), BSDiffControl(..))
import Slap.Explain
  ( ExplainData(..)
  , ExplainSection(..)
  , ExplainRegion(..)
  , ExplainPayload(..)
  , ExplainSummary(..)
  , Annotation(..)
  )
import Slap.Format (renderField)
import Slap.Measure (Offset(..), Length(..), FileSize(..))
import Data.List (mapAccumL)

----------------------------------------------------------------------------
-- Info
----------------------------------------------------------------------------

bsdiffMeta :: BSDiffPatch -> [(String, String)]
bsdiffMeta patch =
  [ ("new size", show (unFileSize (bsdiffTargetSize patch)))
  , ("ctrl block", show (unFileSize (bsdiffControlSize patch)) ++ " bytes (compressed)")
  , ("diff block", show (unFileSize (bsdiffDiffSize patch)) ++ " bytes (compressed)")
  , ("extra block", show (unFileSize (bsdiffExtraSize patch)) ++ " bytes (compressed)")
  ]

bsdiffInfo :: BSDiffPatch -> String
bsdiffInfo patch = unlines $ filter (not . null) $
  [ "format:      BSDiff / BDF (BSDIFF40)" ]
  ++ map renderField (bsdiffMeta patch)
  ++ [ controlString ]
  where
    controlString
      | null (bsdiffControls patch) = ""
      | otherwise = "controls:    " ++ show (length (bsdiffControls patch)) ++ " tuples"

----------------------------------------------------------------------------
-- Explain
----------------------------------------------------------------------------

explainBSDiff :: BSDiffPatch -> ExplainData
explainBSDiff patch = ExplainData
  { explainFormat   = "BSDiff / BDF (BSDIFF40)"
  , explainHeader   = bsdiffMeta patch
  , explainSections = if null (bsdiffControls patch)
                 then [SectionText "(control data not decoded)"]
                 else [SectionRegions (snd (mapAccumL makeBSDiffRegion (Offset 0) (bsdiffControls patch)))]
  , explainSummary  = if null (bsdiffControls patch)
                 then SummaryNone
                 else Summary (length (bsdiffControls patch)) "control tuples" Nothing
  , explainNotes    = []
  }

makeBSDiffRegion :: Offset -> BSDiffControl -> (Offset, ExplainRegion)
makeBSDiffRegion outputPosition control =
  let addLength = controlAdd control
      copyLength = controlCopy control
  in ( Offset (unOffset outputPosition + addLength + copyLength)
     , ExplainRegion
       { regionOffset     = outputPosition
       , regionSize       = Length (fromIntegral (addLength + copyLength))
       , regionLabel      = ""
       , regionPayload    = PayloadMeta []
       , regionAnnotation = AnnotBSDiff (FileSize addLength) (FileSize copyLength) (controlSeek control)
       }
     )
