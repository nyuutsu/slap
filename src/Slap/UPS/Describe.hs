{-# LANGUAGE OverloadedStrings #-}

module Slap.UPS.Describe
  ( upsMeta
  , analyzeUPS
  , makeUPSRegion
  ) where

import Slap.UPS.Types (UPSPatch(..), UPSBlock(..), upsTerminatorByteLength)
import Slap.Display.Analysis
    ( PatchAnalysis(..), AnalysisSection(..), AnalysisRegion(..)
    , AnalysisPayload(..), XORDeltaBytes(..), AnalysisSummary(..)
    , SummaryInfo(..), Annotation(..), OffsetKind(..), AnnotDetail(..)
    )
import Slap.Checksum (showCRC32)
import Slap.Display.Common (InfoLine(..), Tally(..), CountUnit(..), renderAsText)
import Slap.Measure (Offset(..), FileSize(..), advance, byteLength)

import qualified Data.Vector as Vector

upsMeta :: UPSPatch -> [InfoLine]
upsMeta patch =
  [ InfoLine "source size" (renderAsText (unFileSize (upsSourceSize patch)))
  , InfoLine "target size" (renderAsText (unFileSize (upsTargetSize patch)))
  , InfoLine "source CRC" (showCRC32 (upsSourceCRC patch))
  , InfoLine "target CRC" (showCRC32 (upsTargetCRC patch))
  , InfoLine "patch CRC" (showCRC32 (upsPatchCRC patch))
  ]

analyzeUPS :: UPSPatch -> PatchAnalysis
analyzeUPS patch = PatchAnalysis
  { analysisSections =
      let buildRegion (currentPosition, accumulatedRegions) block =
            let (nextPosition, region) = makeUPSRegion currentPosition block
            in (nextPosition, region : accumulatedRegions)
          (_, reversedRegions) = Vector.foldl' buildRegion (Offset 0, []) (upsBlocks patch)
      in [SectionRegions (reverse reversedRegions)]
  , analysisSummary  = Summary (SummaryInfo (Tally blockCount) Blocks Nothing)
  }
  where
    blockCount = Vector.length (upsBlocks patch)

makeUPSRegion :: Offset -> UPSBlock -> (Offset, AnalysisRegion)
makeUPSRegion position (UPSBlock skipLength xorData) =
  let xorOffset = advance position skipLength
      xorDataLength = byteLength xorData
      nextPosition = advance xorOffset (xorDataLength <> upsTerminatorByteLength)
  in ( nextPosition
     , AnalysisRegion xorOffset xorDataLength "XOR  " (PayloadXOR (XORDeltaBytes xorData))
         (AnnotationAt AtOffset xorOffset [DetailSkip skipLength])
     )
