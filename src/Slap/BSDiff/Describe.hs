{-# LANGUAGE OverloadedStrings #-}

module Slap.BSDiff.Describe
  ( bsdiffMeta
  , analyzeBSDiff
  , makeBSDiffRegion
  ) where

import Slap.BSDiff.Types (BSDiffPatch(..), BSDiffInstruction(..))
import Slap.Display.Analysis
  ( PatchAnalysis(..)
  , AnalysisSection(..)
  , AnalysisRegion(..)
  , AnalysisPayload(..)
  , AnalysisSummary(..)
  , SummaryInfo(..)
  , Annotation(..)
  )
import Slap.Display.Common (InfoLine(..), Tally(..), CountUnit(..), renderAsText)
import Slap.Measure (Offset(..), FileSize(..), advance)
import Data.List (mapAccumL)

----------------------------------------------------------------------------
-- Info
----------------------------------------------------------------------------

bsdiffMeta :: BSDiffPatch -> [InfoLine]
bsdiffMeta patch =
  [ InfoLine "new size" (renderAsText (unFileSize (bsdiffTargetSize patch)))
  , InfoLine "ctrl block" (renderAsText (unFileSize (bsdiffControlSize patch)) <> " bytes (compressed)")
  , InfoLine "diff block" (renderAsText (unFileSize (bsdiffDiffSize patch)) <> " bytes (compressed)")
  , InfoLine "extra block" (renderAsText (unFileSize (bsdiffExtraSize patch)) <> " bytes (compressed)")
  ]

----------------------------------------------------------------------------
-- Analyze
----------------------------------------------------------------------------

analyzeBSDiff :: BSDiffPatch -> PatchAnalysis
analyzeBSDiff patch = PatchAnalysis
  { analysisSections = if null (bsdiffInstructions patch)
                  then [SectionText "(control data not decoded)"]
                  else [SectionRegions (snd (mapAccumL makeBSDiffRegion (Offset 0) (bsdiffInstructions patch)))]
  , analysisSummary  = if null (bsdiffInstructions patch)
                  then SummaryNone
                  else Summary (SummaryInfo (Tally (length (bsdiffInstructions patch))) Instructions Nothing)
  }

makeBSDiffRegion :: Offset -> BSDiffInstruction -> (Offset, AnalysisRegion)
makeBSDiffRegion outputPosition instruction =
  let addLength = controlAdd instruction
      copyLength = controlCopy instruction
  in ( advance outputPosition (addLength <> copyLength)
     , AnalysisRegion
       { regionOffset     = outputPosition
       , regionSize       = addLength <> copyLength
       , regionLabel      = ""
       , regionPayload    = PayloadMeta []
       , regionAnnotation = AnnotationBSDiff instruction
       }
     )
