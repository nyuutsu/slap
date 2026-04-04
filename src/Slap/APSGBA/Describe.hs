module Slap.APSGBA.Describe
  ( apsGBAInfo
  , apsGBAMeta
  , explainAPSGBA
  , makeGBARegion
  ) where

import Slap.APSGBA.Types
import Slap.Explain (ExplainData(..), ExplainSection(..), ExplainRegion(..),
                     ExplainPayload(..), ExplainSummary(..), SummaryInfo(..),
                     Annotation(..), OffsetKind(..), AnnotDetail(..))
import Slap.Format (MetaField(..), renderField)
import Slap.Measure (Length(..), FileSize(..))

apsGBAMeta :: APSGBAPatch -> [MetaField]
apsGBAMeta (APSGBAPatch header _) =
  [ MetaField "source size" (show (unFileSize (apsGbaSourceSize header)))
  , MetaField "target size" (show (unFileSize (apsGbaTargetSize header)))
  ]

apsGBAInfo :: APSGBAPatch -> String
apsGBAInfo patch@(APSGBAPatch _ records) = unlines $ filter (not . null) $
  [ "format:      APS (GBA)" ]
  ++ map renderField (apsGBAMeta patch)
  ++ [ "blocks:      " ++ show (length records) ]

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
