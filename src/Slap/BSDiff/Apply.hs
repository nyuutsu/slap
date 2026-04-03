module Slap.BSDiff.Apply
  ( applyBSDiff
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.ByteString.Internal (unsafeCreate)
import Slap.Binary (copyByteStringRange)
import Slap.BSDiff.Types (BSDiffPatch(..), BSDiffControl(..))
import Slap.Error (SlapError(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.Measure (FileSize(..), Length(..), Delta(..))
import Data.Word (Word8)
import Foreign.Ptr (Ptr)
import Foreign.Storable (pokeByteOff)

applyBSDiff :: BSDiffPatch -> ByteString -> Either SlapError ByteString
applyBSDiff patch _source
  | unFileSize (bsdiffTargetSize patch) == 0 = Right ByteString.empty
  | unFileSize (bsdiffTargetSize patch) < 0  = Left (NegativeTargetSize LabelBSDiff (bsdiffTargetSize patch))
applyBSDiff patch source = Right $ unsafeCreate outputSize $ \targetPointer ->
  applyLoop targetPointer 0 0 0 0 (bsdiffControls patch)
  where
    outputSize = fromIntegral (unFileSize (bsdiffTargetSize patch))
    sourceLength  = ByteString.length source
    diffBytes  = bsdiffDiffData patch
    extraBytes = bsdiffExtraData patch
    diffLength = ByteString.length diffBytes
    extraLength = ByteString.length extraBytes

    applyLoop :: Ptr Word8 -> Int -> Int -> Int -> Int -> [BSDiffControl] -> IO ()
    applyLoop _targetPointer _diffOffset _extraOffset _originalPosition _outputPosition [] = pure ()
    applyLoop targetPointer diffOffset extraOffset originalPosition outputPosition (control:rest) = do
      -- Clamp add/copy lengths to remaining output buffer space
      let addLength = max 0 $ min (fromIntegral (unLength (controlAdd control))) (outputSize - outputPosition)
          copyLength  = max 0 $ min (fromIntegral (unLength (controlCopy control))) (outputSize - outputPosition - addLength)
          seekOffset     = fromIntegral (unDelta (controlSeek control))
      -- Add: target[outputPosition+i] = source[originalPosition+i] + diff[diffOffset+i]
      mapM_ (\index -> do
        let sourceByte = if originalPosition + index >= 0 && originalPosition + index < sourceLength
                then ByteString.index source (originalPosition + index) else 0
            diffByte = if diffOffset + index >= 0 && diffOffset + index < diffLength
                then ByteString.index diffBytes (diffOffset + index) else 0
        pokeByteOff targetPointer (outputPosition + index) (sourceByte + diffByte :: Word8)) [0..addLength-1]
      -- Copy: target[outputPosition+addLength..] = extra[extraOffset..]
      let safeCopyLength = if extraOffset >= 0 && extraOffset < extraLength
                      then min copyLength (extraLength - extraOffset)
                      else 0
      copyByteStringRange targetPointer (outputPosition + addLength) extraBytes extraOffset safeCopyLength
      applyLoop targetPointer (diffOffset + addLength) (extraOffset + copyLength)
        (originalPosition + addLength + seekOffset) (outputPosition + addLength + copyLength) rest
