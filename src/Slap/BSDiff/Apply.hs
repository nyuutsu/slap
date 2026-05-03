module Slap.BSDiff.Apply
  ( applyBSDiff
  ) where

import Slap.FileContents (SourceFileContents(..), TargetFileContents(..))

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.ByteString.Internal (unsafeCreate)
import Slap.BSDiff.Types (BSDiffPatch(..), BSDiffControl(..))
import Slap.Error (SlapError(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.Binary (copyRegion)
import Slap.Measure (Offset(..), Length(..), FileSize(..),
                     SignedOffset(..), Cursor(..), remainingFromOffset)
import Data.Word (Word8)
import Foreign.Ptr (plusPtr)
import Foreign.Storable (pokeByteOff)

applyBSDiff :: BSDiffPatch -> SourceFileContents -> Either SlapError TargetFileContents
applyBSDiff patch _
  | unFileSize (bsdiffTargetSize patch) == 0 = Right (TargetFileContents ByteString.empty)
  | unFileSize (bsdiffTargetSize patch) < 0  = Left (NegativeTargetSize LabelBSDiff (bsdiffTargetSize patch))
applyBSDiff patch (SourceFileContents source) = Right $ TargetFileContents $ unsafeCreate outputSize $ \targetPointer ->
    let
      applyLoop
        :: Offset -> Offset -> SignedOffset -> Offset -> [BSDiffControl] -> IO ()
      applyLoop _diffOffset _extraOffset _originalPosition _outputPosition [] = pure ()
      applyLoop !diffOffset !extraOffset !originalPosition !outputPosition (control:rest) = do
        let addLength = min (controlAdd control)
              (remainingFromOffset outputPosition targetFileSize)
            copyLength = min (controlCopy control)
              (remainingFromOffset (advance outputPosition addLength) targetFileSize)
            seekDelta = controlSeek control
        -- Add: target[outputPosition+i] = source[originalPosition+i] + diff[diffOffset+i]
        let totalBytes = unLength addLength
            sourceBase = unSignedOffset originalPosition
            diffBase   = unOffset diffOffset
            writeBase  = targetPointer `plusPtr` unOffset outputPosition
            addLoop !byteOffset
              | byteOffset >= totalBytes = pure ()
              | otherwise = do
                  let sourceByte = safeByteAt source    (sourceBase + byteOffset)
                      diffByte   = safeByteAt diffBytes (diffBase + byteOffset)
                  pokeByteOff writeBase byteOffset (sourceByte + diffByte :: Word8)
                  addLoop (byteOffset + 1)
        addLoop 0
        -- Copy: target[outputPosition+addLength..] = extra[extraOffset..]
        let safeCopyLength = if unOffset extraOffset >= 0 && unOffset extraOffset < extraLength
                        then min copyLength (Length (extraLength - unOffset extraOffset))
                        else Length 0
        copyRegion targetPointer (advance outputPosition addLength) extraBytes extraOffset safeCopyLength
        applyLoop
          (advance diffOffset addLength)
          (advance extraOffset copyLength)
          (displace (advance originalPosition addLength) seekDelta)
          (advance outputPosition (addLength <> copyLength))
          rest
    in applyLoop (Offset 0) (Offset 0) (SignedOffset 0) (Offset 0) (bsdiffControls patch)
  where
    outputSize     = unFileSize (bsdiffTargetSize patch)
    targetFileSize = bsdiffTargetSize patch
    diffBytes      = bsdiffDiffData patch
    extraBytes     = bsdiffExtraData patch
    extraLength    = ByteString.length extraBytes

    -- | Read a byte at @index@ from @bytes@, returning 0 for out-of-bounds
    -- reads. Used by BSDiff's Add step, where 0 is the neutral element for
    -- the byte-wise addition of the source and diff byte streams.
    safeByteAt :: ByteString -> Int -> Word8
    safeByteAt bytes index
      | index >= 0 && index < ByteString.length bytes =
          ByteString.index bytes index
      | otherwise = 0
