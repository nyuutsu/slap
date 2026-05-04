module Slap.APSGBA.Describe
  ( apsGBAMeta
  , analyzeAPSGBA
  , makeGBARegion
  ) where

import Slap.APSGBA.Types
import Slap.Explain (PatchAnalysis(..), AnalysisSection(..), AnalysisRegion(..),
                     AnalysisPayload(..), AnalysisSummary(..), SummaryInfo(..),
                     Annotation(..), OffsetKind(..), AnnotDetail(..))
import Slap.Display (InfoLine(..), Tally(..), CountUnit(..))
import Slap.Measure (Length(..), FileSize(..))

apsGBAMeta :: APSGBAPatch -> [InfoLine]
apsGBAMeta (APSGBAPatch header _) =
  [ InfoLine "source size" (show (unFileSize (apsGbaSourceSize header)))
  , InfoLine "target size" (show (unFileSize (apsGbaTargetSize header)))
  ]

analyzeAPSGBA :: APSGBAPatch -> PatchAnalysis
analyzeAPSGBA (APSGBAPatch _header records) = PatchAnalysis
  { analysisSections = [SectionRegions (map makeGBARegion records)]
  , analysisSummary  = Summary (SummaryInfo (Tally (length records)) Blocks Nothing)
  }

makeGBARegion :: APSGBARecord -> AnalysisRegion
makeGBARegion record = AnalysisRegion
  { regionOffset     = apsGbaOffset record
  , regionSize       = Length apsGbaBlockSize
  , regionLabel      = "XOR block  "
  , regionPayload    = PayloadXOR (Just (apsGbaXorData record))
  , regionAnnotation = AnnotAt AtOffset (apsGbaOffset record)
      [DetailCRC16 (apsGbaSourceCRC record) (apsGbaTargetCRC record)]
  }
