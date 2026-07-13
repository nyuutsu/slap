{-# LANGUAGE OverloadedStrings #-}

module Slap.APSGBA.Describe
  ( apsGBAMeta
  , analyzeAPSGBA
  , makeGBARegion
  ) where

import Slap.APSGBA.Types
import Slap.Display.Analysis (PatchAnalysis(..), AnalysisSection(..), AnalysisRegion(..),
                     AnalysisPayload(..), AnalysisSummary(..), SummaryInfo(..),
                     Annotation(..), OffsetKind(..), AnnotDetail(..))
import Slap.Display.Common (InfoLine(..), Tally(..), CountUnit(..), renderAsText)
import Slap.Measure (Length(..), FileSize(..))

apsGBAMeta :: APSGBAPatch -> [InfoLine]
apsGBAMeta (APSGBAPatch header _) =
  [ InfoLine "source size" (renderAsText (unFileSize (apsGbaSourceSize header)))
  , InfoLine "target size" (renderAsText (unFileSize (apsGbaTargetSize header)))
  ]

analyzeAPSGBA :: APSGBAPatch -> PatchAnalysis
analyzeAPSGBA (APSGBAPatch _header records) = PatchAnalysis
  { analysisSections = [SectionRegions (map makeGBARegion records)]
  , analysisSummary  = Summary (SummaryInfo (Tally (length records)) Blocks Nothing)
  }

makeGBARegion :: APSGBARecord -> AnalysisRegion
makeGBARegion record = AnalysisRegion
  { regionOffset     = apsGbaOffset record
  , regionSize       = Length (fromIntegral apsGbaBlockSize)
  , regionLabel      = "XOR block  "
  , regionPayload    = PayloadXOR (Just (apsGbaXorData record))
  , regionAnnotation = AnnotationAt AtOffset (apsGbaOffset record)
      [DetailCRC16 (apsGbaSourceCRC record) (apsGbaTargetCRC record)]
  }
