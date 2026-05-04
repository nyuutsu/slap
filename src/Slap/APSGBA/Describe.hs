module Slap.APSGBA.Describe
  ( apsGBAMeta
  , explainAPSGBA
  , makeGBARegion
  ) where

import Slap.APSGBA.Types
import Slap.Explain (ExplainData(..), ExplainSection(..), ExplainRegion(..),
                     ExplainPayload(..), ExplainSummary(..), SummaryInfo(..),
                     Annotation(..), OffsetKind(..), AnnotDetail(..))
import Slap.Display (InfoLine(..))
import Slap.Measure (Length(..), FileSize(..))

apsGBAMeta :: APSGBAPatch -> [InfoLine]
apsGBAMeta (APSGBAPatch header _) =
  [ InfoLine "source size" (show (unFileSize (apsGbaSourceSize header)))
  , InfoLine "target size" (show (unFileSize (apsGbaTargetSize header)))
  ]

explainAPSGBA :: APSGBAPatch -> ExplainData
explainAPSGBA patch@(APSGBAPatch _header records) = ExplainData
  { explainFormat   = "APS (GBA)"
  , explainHeader   = apsGBAMeta patch
  , explainSections = [SectionRegions (map makeGBARegion records)]
  , explainSummary  = Summary (SummaryInfo (length records) "blocks" Nothing)
  , explainNotes    = []
  }

makeGBARegion :: APSGBARecord -> ExplainRegion
makeGBARegion record = ExplainRegion
  { regionOffset     = apsGbaOffset record
  , regionSize       = Length apsGbaBlockSize
  , regionLabel      = "XOR block  "
  , regionPayload    = PayloadXOR (Just (apsGbaXorData record))
  , regionAnnotation = AnnotAt AtOffset (apsGbaOffset record)
      [DetailCRC16 (apsGbaSourceCRC record) (apsGbaTargetCRC record)]
  }
