module Slap.UPS.Describe
  ( upsInfo
  , upsMeta
  , explainUPS
  , makeUPSRegion
  ) where

import Slap.UPS.Types (UPSPatch(..), UPSBlock(..), upsTerminatorByteSize)
import Slap.Explain
    ( ExplainData(..), ExplainSection(..), ExplainRegion(..)
    , ExplainPayload(..), ExplainSummary(..)
    , SummaryInfo(..), Annotation(..), OffsetKind(..), AnnotDetail(..)
    )
import Slap.Checksum (showCRC32)
import Slap.Format (MetaField(..), renderField)
import Slap.Measure (Offset(..), Length(..), FileSize(..), advance, displace)

import qualified Data.ByteString as ByteString
import qualified Data.Vector as Vector

upsMeta :: UPSPatch -> [MetaField]
upsMeta patch =
  [ MetaField "source size" (show (unFileSize (upsSourceSize patch)))
  , MetaField "target size" (show (unFileSize (upsTargetSize patch)))
  , MetaField "source CRC" (showCRC32 (upsSourceCRC patch))
  , MetaField "target CRC" (showCRC32 (upsTargetCRC patch))
  , MetaField "patch CRC" (showCRC32 (upsPatchCRC patch))
  ]

upsInfo :: UPSPatch -> String
upsInfo patch = unlines $
  [ "format:      UPS" ]
  ++ map renderField (upsMeta patch)
  ++ [ "blocks:      " ++ show (Vector.length (upsBlocks patch)) ]

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
makeUPSRegion position (UPSBlock skipDelta xorData) =
  let xorOffset = displace position skipDelta
      xorDataLength = ByteString.length xorData
      nextPosition = advance xorOffset (Length (xorDataLength + upsTerminatorByteSize))
  in ( nextPosition
     , ExplainRegion xorOffset (Length xorDataLength) "XOR  " (PayloadXOR (Just xorData))
         (AnnotAt AtOffset xorOffset [DetailSkip skipDelta])
     )
