module Slap.XDelta1.Apply
  ( applyXDelta1
  ) where

import Slap.XDelta1.Types (XDelta1Patch(..), XDelta1Source(..), XDelta1Instruction(..), XDelta1SourceKind(..))
import Slap.Error (SlapError(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.Binary (copyRegion)
import Slap.Measure (Offset(..), Length(..), FileSize(..), Cursor(..), remainingFromOffset)

import Slap.FileContents (InputFileContents(..), OutputFileContents(..))

import Data.Array (listArray, (!), bounds)
import qualified Data.ByteString as ByteString
import Data.ByteString.Internal (unsafeCreate)

----------------------------------------------------------------------------
-- Apply
----------------------------------------------------------------------------

applyXDelta1 :: XDelta1Patch -> InputFileContents -> Either SlapError OutputFileContents
applyXDelta1 patch _
  | unFileSize (xdelta1TargetLength patch) == 0 = Right (OutputFileContents ByteString.empty)
  | unFileSize (xdelta1TargetLength patch) < 0  = Left (NegativeTargetSize LabelXDelta1 (xdelta1TargetLength patch))
applyXDelta1 patch (InputFileContents source) = Right $ OutputFileContents $ unsafeCreate outputSize $ \targetPointer ->
    let
      applyLoop :: Offset -> [XDelta1Instruction] -> IO ()
      applyLoop _outputPosition [] = pure ()
      applyLoop !outputPosition (instruction:rest) = do
        let index = fromIntegral (xdelta1InstructionIndex instruction) :: Int
            (lowBound, highBound) = bounds sourceArray
            sourceBytes = if index >= lowBound && index <= highBound
                             && xdelta1SourceKind (sourceArray ! index) == DataSegmentSource
                          then dataSegment
                          else source
            instructionOffset = xdelta1InstructionOffset instruction
            instructionLength = Length (unFileSize (xdelta1InstructionLength instruction))
            safeLength = min instructionLength (remainingFromOffset outputPosition targetFileSize)
            sourceSafeLength =
              if unOffset instructionOffset >= 0
                 && unOffset instructionOffset < ByteString.length sourceBytes
              then min safeLength (Length (ByteString.length sourceBytes - unOffset instructionOffset))
              else Length 0
        copyRegion targetPointer outputPosition sourceBytes instructionOffset sourceSafeLength
        applyLoop (advance outputPosition safeLength) rest
    in applyLoop (Offset 0) (xdelta1Instructions patch)
  where
    outputSize     = unFileSize (xdelta1TargetLength patch)
    targetFileSize = xdelta1TargetLength patch
    sourceArray    = let sourceList = xdelta1Sources patch
                     in listArray (0, length sourceList - 1) sourceList
    dataSegment    = xdelta1DataSegment patch
