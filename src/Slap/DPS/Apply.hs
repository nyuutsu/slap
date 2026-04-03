module Slap.DPS.Apply
  ( applyDPS
  , buildOutput
  , overwriteAt
  , takePadded
  ) where

import Slap.DPS.Types (DPSPatch(..), DPSRecord(..))
import Slap.Measure (Offset(..), Length(..))

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString

-- | Apply a DPS patch. Builds output from source ROM + embedded data.
applyDPS :: DPSPatch -> ByteString -> Either String ByteString
applyDPS patch source = Right $ buildOutput source (dpsRecords patch)

buildOutput :: ByteString -> [DPSRecord] -> ByteString
buildOutput source records =
  -- DPS builds output by writing chunks at specified offsets.
  -- Start with a copy of the source, then overwrite at each record's offset.
  let base = source
      applyRecord buffer (DPSEnclosedData outputOffset payload) =
        overwriteAt buffer (fromIntegral (unOffset outputOffset)) payload
      applyRecord buffer (DPSCopyFromROM outputOffset sourceOffset copyLength) =
        let chunk = takePadded (unLength copyLength) (fromIntegral (unOffset sourceOffset)) source
        in overwriteAt buffer (fromIntegral (unOffset outputOffset)) chunk
  in foldl' applyRecord base records

-- | Write bytes at a given offset, extending with zeros if needed.
overwriteAt :: ByteString -> Int -> ByteString -> ByteString
overwriteAt buffer offset payload
  | offset + ByteString.length payload <= ByteString.length buffer =
      let (before, rest) = ByteString.splitAt offset buffer
          after = ByteString.drop (ByteString.length payload) rest
      in before <> payload <> after
  | offset <= ByteString.length buffer =
      ByteString.take offset buffer <> payload
  | otherwise =
      buffer <> ByteString.replicate (offset - ByteString.length buffer) 0 <> payload

-- | Safe slice from a ByteString, padding with zeros if out of range.
takePadded :: Int -> Int -> ByteString -> ByteString
takePadded dataLength offset input
  | offset >= ByteString.length input = ByteString.replicate dataLength 0
  | offset + dataLength > ByteString.length input =
      let available = ByteString.take (ByteString.length input - offset) (ByteString.drop offset input)
      in available <> ByteString.replicate (dataLength - ByteString.length available) 0
  | otherwise = ByteString.take dataLength (ByteString.drop offset input)
