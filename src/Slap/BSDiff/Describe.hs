module Slap.BSDiff.Describe
  ( bsdiffMeta
  , analyzeBSDiff
  , makeBSDiffRegion
  ) where

import Slap.BSDiff.Types (BSDiffPatch(..), BSDiffControl(..))
import Slap.Display.Analysis
  ( PatchAnalysis(..)
  , AnalysisSection(..)
  , AnalysisRegion(..)
  , AnalysisPayload(..)
  , AnalysisSummary(..)
  , SummaryInfo(..)
  , Annotation(..)
  )
import Slap.Display.Common (InfoLine(..), Tally(..), CountUnit(..))
import Slap.Measure (Offset(..), FileSize(..), advance)
import Data.List (mapAccumL)

----------------------------------------------------------------------------
-- Info
----------------------------------------------------------------------------

bsdiffMeta :: BSDiffPatch -> [InfoLine]
bsdiffMeta patch =
  [ InfoLine "new size" (show (unFileSize (bsdiffTargetSize patch)))
  , InfoLine "ctrl block" (show (unFileSize (bsdiffControlSize patch)) ++ " bytes (compressed)")
  , InfoLine "diff block" (show (unFileSize (bsdiffDiffSize patch)) ++ " bytes (compressed)")
  , InfoLine "extra block" (show (unFileSize (bsdiffExtraSize patch)) ++ " bytes (compressed)")
  ]

----------------------------------------------------------------------------
-- Analyze
----------------------------------------------------------------------------

analyzeBSDiff :: BSDiffPatch -> PatchAnalysis
analyzeBSDiff patch = PatchAnalysis
  { analysisSections = if null (bsdiffControls patch)
                  then [SectionText "(control data not decoded)"]
                  else [SectionRegions (snd (mapAccumL makeBSDiffRegion (Offset 0) (bsdiffControls patch)))]
  , analysisSummary  = if null (bsdiffControls patch)
                  then SummaryNone
                  else Summary (SummaryInfo (Tally (length (bsdiffControls patch))) ControlTuples Nothing)
  }

makeBSDiffRegion :: Offset -> BSDiffControl -> (Offset, AnalysisRegion)
makeBSDiffRegion outputPosition control =
  let addLength = controlAdd control
      copyLength = controlCopy control
  in ( advance outputPosition (addLength <> copyLength)
     , AnalysisRegion
       { regionOffset     = outputPosition
       , regionSize       = addLength <> copyLength
       , regionLabel      = ""
       , regionPayload    = PayloadMeta []
       , regionAnnotation = AnnotationBSDiff control
       }
     )
