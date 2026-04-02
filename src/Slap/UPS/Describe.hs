module Slap.UPS.Describe
  ( upsInfo
  , upsMeta
  , explainUPS
  , makeUPSRegion
  ) where

import Slap.UPS.Types (UPSPatch(..), UPSBlock(..))
import Slap.Explain
    ( ExplainData(..), ExplainSection(..), ExplainRegion(..)
    , ExplainPayload(..), ExplainSummary(..)
    , Annotation(..), OffsetKind(..), AnnotDetail(..)
    )
import Slap.Checksum (showCRC32)
import Slap.Format (renderField)
import Slap.Measure (Offset(..), Length(..), FileSize(..), Delta(..))

import qualified Data.ByteString as ByteString
import Data.List (mapAccumL)

upsMeta :: UPSPatch -> [(String, String)]
upsMeta patch =
  [ ("source size", show (unFileSize (upsSourceSize patch)))
  , ("target size", show (unFileSize (upsTargetSize patch)))
  , ("source CRC", showCRC32 (upsSourceCRC patch))
  , ("target CRC", showCRC32 (upsTargetCRC patch))
  , ("patch CRC", showCRC32 (upsPatchCRC patch))
  ]

upsInfo :: UPSPatch -> String
upsInfo patch = unlines $
  [ "format:      UPS" ]
  ++ map renderField (upsMeta patch)
  ++ [ "blocks:      " ++ show (length (upsBlocks patch)) ]

explainUPS :: UPSPatch -> ExplainData
explainUPS patch = ExplainData
  { explainFormat   = "UPS"
  , explainHeader   = upsMeta patch
  , explainSections = [SectionRegions (snd (mapAccumL makeUPSRegion (Offset 0) (upsBlocks patch)))]
  , explainSummary  = Summary blockCount "blocks" Nothing
  , explainNotes    = []
  }
  where
    blockCount = length (upsBlocks patch)

makeUPSRegion :: Offset -> UPSBlock -> (Offset, ExplainRegion)
makeUPSRegion position (UPSBlock skipDelta deltaBytes) =
  let xorOffset = Offset (unOffset position + unDelta skipDelta)
      dataLength = ByteString.length deltaBytes
      nextPosition = Offset (unOffset xorOffset + fromIntegral dataLength + 1)  -- +1 for 0x00 terminator byte
  in ( nextPosition
     , ExplainRegion xorOffset (Length dataLength) "XOR  " (PayloadXOR (Just deltaBytes))
         (AnnotAt AtOffset xorOffset [DetailSkip skipDelta])
     )
