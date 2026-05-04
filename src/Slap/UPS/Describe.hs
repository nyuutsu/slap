module Slap.UPS.Describe
  ( upsMeta
  , analyzeUPS
  , makeUPSRegion
  ) where

import Slap.UPS.Types (UPSPatch(..), UPSBlock(..), upsTerminatorByteLength)
import Slap.Explain
    ( PatchAnalysis(..), AnalysisSection(..), AnalysisRegion(..)
    , AnalysisPayload(..), AnalysisSummary(..)
    , SummaryInfo(..), Annotation(..), OffsetKind(..), AnnotDetail(..)
    )
import Slap.Checksum (showCRC32)
import Slap.Display (InfoLine(..))
import Slap.Measure (Offset(..), Length(..), FileSize(..), advance)

import qualified Data.ByteString as ByteString
import qualified Data.Vector as Vector

upsMeta :: UPSPatch -> [InfoLine]
upsMeta patch =
  [ InfoLine "source size" (show (unFileSize (upsSourceSize patch)))
  , InfoLine "target size" (show (unFileSize (upsTargetSize patch)))
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
  , analysisSummary  = Summary (SummaryInfo blockCount "blocks" Nothing)
  }
  where
    blockCount = Vector.length (upsBlocks patch)

makeUPSRegion :: Offset -> UPSBlock -> (Offset, AnalysisRegion)
makeUPSRegion position (UPSBlock skipLength xorData) =
  let xorOffset = advance position skipLength
      xorDataLength = Length (ByteString.length xorData)
      nextPosition = advance xorOffset (xorDataLength <> upsTerminatorByteLength)
  in ( nextPosition
     , AnalysisRegion xorOffset xorDataLength "XOR  " (PayloadXOR (Just xorData))
         (AnnotAt AtOffset xorOffset [DetailSkip skipLength])
     )
