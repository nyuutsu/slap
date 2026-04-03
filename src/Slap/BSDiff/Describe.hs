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
  , SummaryInfo(..)
  , Annotation(..)
  )
import Slap.Format (MetaField(..), renderField)
import Slap.Measure (Offset(..), Length(..), FileSize(..))
import Data.List (mapAccumL)

----------------------------------------------------------------------------
-- Info
----------------------------------------------------------------------------

bsdiffMeta :: BSDiffPatch -> [MetaField]
bsdiffMeta patch =
  [ MetaField "new size" (show (unFileSize (bsdiffTargetSize patch)))
  , MetaField "ctrl block" (show (unFileSize (bsdiffControlSize patch)) ++ " bytes (compressed)")
  , MetaField "diff block" (show (unFileSize (bsdiffDiffSize patch)) ++ " bytes (compressed)")
  , MetaField "extra block" (show (unFileSize (bsdiffExtraSize patch)) ++ " bytes (compressed)")
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
                 else Summary (SummaryInfo (length (bsdiffControls patch)) "control tuples" Nothing)
  , explainNotes    = []
  }

makeBSDiffRegion :: Offset -> BSDiffControl -> (Offset, ExplainRegion)
makeBSDiffRegion outputPosition control =
  let addLength = controlAdd control
      copyLength = controlCopy control
  in ( Offset (unOffset outputPosition + fromIntegral (unLength addLength) + fromIntegral (unLength copyLength))
     , ExplainRegion
       { regionOffset     = outputPosition
       , regionSize       = Length (unLength addLength + unLength copyLength)
       , regionLabel      = ""
       , regionPayload    = PayloadMeta []
       , regionAnnotation = AnnotBSDiff addLength copyLength (controlSeek control)
       }
     )
