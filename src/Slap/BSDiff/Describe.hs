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
  , OffsetKind(..)
  , AnnotDetail(..)
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
  { analysisSections = if hasInstructions
                  then [SectionRegions (snd (mapAccumL makeBSDiffRegion (Offset 0) instructions))]
                  else [SectionText "(no control instructions)"]
  , analysisSummary  = if hasInstructions
                  then Summary (SummaryInfo (Tally (length instructions)) Instructions Nothing)
                  else SummaryNone
  }
  where
    instructions    = bsdiffInstructions patch
    hasInstructions = not (null instructions)

makeBSDiffRegion :: Offset -> BSDiffInstruction -> (Offset, AnalysisRegion)
makeBSDiffRegion outputPosition instruction =
  let addLength  = controlAdd instruction
      copyLength = controlCopy instruction
  in ( advance outputPosition (addLength <> copyLength)
     , AnalysisRegion
       { regionOffset     = outputPosition
       , regionSize       = addLength <> copyLength
       , regionLabel      = ""
       , regionPayload    = PayloadMeta []
       , regionAnnotation = AnnotationAt AtOutput outputPosition
                              [ DetailAdd addLength
                              , DetailCopy copyLength
                              , DetailSeek (controlSeek instruction)
                              ]
       }
     )
