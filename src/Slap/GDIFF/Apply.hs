module Slap.GDIFF.Apply
  ( applyGDIFF
  ) where

import Slap.GDIFF.Types (GDiffPatch(..), GDiffCommand(..), commandOutputSize)
import Slap.Binary (copyRegion)
import Slap.Measure (Offset(..), Length(..), FileSize(..), Cursor(..))

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.ByteString.Internal (unsafeCreate)

applyGDIFF :: GDiffPatch -> ByteString -> ByteString
applyGDIFF patch source
  | totalSize == 0 = ByteString.empty
  | otherwise = unsafeCreate totalSize $ \outputPointer ->
      let
        applyLoop :: Offset -> [GDiffCommand] -> IO ()
        applyLoop _outputPosition [] = pure ()
        applyLoop !outputPosition (command:remaining) = case command of
          GDiffData payload -> do
            let dataLength = Length (ByteString.length payload)
            copyRegion outputPointer outputPosition payload (Offset 0) dataLength
            applyLoop (advance outputPosition dataLength) remaining
          GDiffCopy sourceOffset copyLength -> do
            let count = Length (unFileSize copyLength)
            copyRegion outputPointer outputPosition source sourceOffset count
            applyLoop (advance outputPosition count) remaining
      in applyLoop (Offset 0) (gdiffCommands patch)
  where
    totalSize = sum (map commandOutputSize (gdiffCommands patch))
