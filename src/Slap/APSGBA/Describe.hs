module Slap.APSGBA.Describe
  ( apsGBAInfo
  , apsGBAMeta
  , explainAPSGBA
  , makeGBARegion
  ) where

import Slap.APSGBA.Types
import Slap.Explain (ExplainData(..), ExplainSection(..), ExplainRegion(..),
                     ExplainPayload(..), ExplainSummary(..), Annotation(..),
                     OffsetKind(..), AnnotDetail(..))
import Slap.Format (renderField)
import Slap.Measure (Offset(..), Length(..))

apsGBAMeta :: APSGBAPatch -> [(String, String)]
apsGBAMeta (APSGBAPatch header _) =
  [ ("source size", show (apsGbaSourceSize header))
  , ("target size", show (apsGbaTargetSize header))
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
  , explainSummary  = Summary (length records) "blocks" Nothing
  , explainNotes    = []
  }

makeGBARegion :: APSGBARecord -> ExplainRegion
makeGBARegion record = ExplainRegion
  { regionOffset     = Offset (fromIntegral (apsGbaOffset record))
  , regionSize       = Length 65536
  , regionLabel      = "XOR block  "
  , regionPayload    = PayloadXOR (Just (apsGbaXorData record))
  , regionAnnotation = AnnotAt AtOffset (Offset (fromIntegral (apsGbaOffset record)))
      [DetailCRC16 (fromIntegral (apsGbaSourceCRC record)) (fromIntegral (apsGbaTargetCRC record))]
  }
