module Slap.GDIFF.Apply
  ( applyGDIFF
  ) where

import Slap.GDIFF.Types (GDiffPatch(..), GDiffCommand(..), commandOutputSize)
import Slap.Binary (copyRegion)
import Slap.Measure (Offset(..), Length(..), FileSize(..), Cursor(..))

import Slap.FileContents (SourceFileContents(..), TargetFileContents(..))

import qualified Data.ByteString as ByteString
import Data.ByteString.Internal (unsafeCreate)

applyGDIFF :: GDiffPatch -> SourceFileContents -> TargetFileContents
applyGDIFF patch (SourceFileContents source)
  | totalSize == 0 = TargetFileContents ByteString.empty
  | otherwise = TargetFileContents $ unsafeCreate totalSize $ \outputPointer ->
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
