module Slap.UPS.Describe
  ( upsMeta
  , explainUPS
  , makeUPSRegion
  ) where

import Slap.UPS.Types (UPSPatch(..), UPSBlock(..), upsTerminatorByteLength)
import Slap.Explain
    ( ExplainData(..), ExplainSection(..), ExplainRegion(..)
    , ExplainPayload(..), ExplainSummary(..)
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

explainUPS :: UPSPatch -> ExplainData
explainUPS patch = ExplainData
  { explainFormat   = "UPS"
  , explainHeader   = upsMeta patch
  , explainSections =
      let buildRegion (currentPosition, accumulatedRegions) block =
            let (nextPosition, region) = makeUPSRegion currentPosition block
            in (nextPosition, region : accumulatedRegions)
          (_, reversedRegions) = Vector.foldl' buildRegion (Offset 0, []) (upsBlocks patch)
      in [SectionRegions (reverse reversedRegions)]
  , explainSummary  = Summary (SummaryInfo blockCount "blocks" Nothing)
  , explainNotes    = []
  }
  where
    blockCount = Vector.length (upsBlocks patch)

makeUPSRegion :: Offset -> UPSBlock -> (Offset, ExplainRegion)
makeUPSRegion position (UPSBlock skipLength xorData) =
  let xorOffset = advance position skipLength
      xorDataLength = Length (ByteString.length xorData)
      nextPosition = advance xorOffset (xorDataLength <> upsTerminatorByteLength)
  in ( nextPosition
     , ExplainRegion xorOffset xorDataLength "XOR  " (PayloadXOR (Just xorData))
         (AnnotAt AtOffset xorOffset [DetailSkip skipLength])
     )
