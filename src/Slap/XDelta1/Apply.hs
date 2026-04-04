module Slap.XDelta1.Apply
  ( applyXDelta1
  ) where

import Slap.XDelta1.Types (XDelta1Patch(..), XDelta1Source(..), XDelta1Instruction(..), XDelta1SourceKind(..))
import Slap.Binary (copyByteStringRange)
import Slap.Error (SlapError(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.Measure (Offset(..), FileSize(..))

import Data.Array (listArray, (!), bounds)
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.ByteString.Internal (unsafeCreate)
import Data.Word (Word8)
import Foreign.Ptr (Ptr)

----------------------------------------------------------------------------
-- Apply
----------------------------------------------------------------------------

applyXDelta1 :: XDelta1Patch -> ByteString -> Either SlapError ByteString
applyXDelta1 patch _source
  | unFileSize (xdelta1TargetLength patch) == 0 = Right ByteString.empty
  | unFileSize (xdelta1TargetLength patch) < 0  = Left (NegativeTargetSize LabelXDelta1 (xdelta1TargetLength patch))
applyXDelta1 patch source = Right $ unsafeCreate outputSize $ \targetPointer ->
    applyLoop targetPointer 0 (xdelta1Instructions patch)
  where
    outputSize = fromIntegral (unFileSize (xdelta1TargetLength patch))
    sourceArray   = let sourceList = xdelta1Sources patch
                    in listArray (0, length sourceList - 1) sourceList
    dataSegment    = xdelta1DataSegment patch

    applyLoop :: Ptr Word8 -> Int -> [XDelta1Instruction] -> IO ()
    applyLoop _targetPointer _position [] = pure ()
    applyLoop targetPointer position (instruction:rest) = do
      let index = fromIntegral (xdelta1InstructionIndex instruction) :: Int
          (lowBound, highBound) = bounds sourceArray
          sourceBytes = if index >= lowBound && index <= highBound
                           && xdelta1SourceKind (sourceArray ! index) == DataSegmentSource
                        then dataSegment
                        else source
          instructionOffset = fromIntegral (unOffset (xdelta1InstructionOffset instruction))
          instructionLength = fromIntegral (unFileSize (xdelta1InstructionLength instruction)) :: Int
          -- Clamp to remaining output buffer
          safeLength = max 0 $ min instructionLength (outputSize - position)
          -- Clamp source read to available data
          sourceSafeLength = if instructionOffset >= 0 && instructionOffset < ByteString.length sourceBytes
                             then min safeLength (ByteString.length sourceBytes - instructionOffset)
                             else 0
      copyByteStringRange targetPointer position sourceBytes instructionOffset sourceSafeLength
      applyLoop targetPointer (position + safeLength) rest
