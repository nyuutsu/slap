module Slap.NINJA2.Apply
  ( applyNINJA2
  , undoNINJA2
  ) where

import Slap.NINJA2.Types
import Slap.Status (SlapError(..), ApplyError(..), ApplyDirection(..), addressableByteCount)
import Slap.FormatLabel (FormatLabel(..))
import Slap.Binary (copyRegion, fillNewBuffer, seedBufferFromSource, takeLength)
import Slap.Measure (Offset(..), Length, FileSize,
                     ActionIndex, RequestedLength(..),
                     byteFileSize, byteLength, fileSizeToOffset, fitsWithin, offsetToFileSize,
                     plusOffset, remainingFromOffset,
                     firstAction, nextAction, streamEndIndex)

import Slap.FileContents (InputFileContents(..), OutputFileContents(..))

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.Bits (xor)
import Data.Word (Word8)
import Foreign.Ptr (Ptr)
import Foreign.Storable (peekByteOff, pokeByteOff)
import System.IO.Unsafe (unsafePerformIO)

applyNINJA2 :: NINJA2Patch -> InputFileContents -> Either SlapError OutputFileContents
applyNINJA2 patch (InputFileContents source) =
  OutputFileContents <$> runNINJA2XorWalk patch source Forward

undoNINJA2 :: NINJA2Patch -> OutputFileContents -> Either SlapError InputFileContents
undoNINJA2 patch (OutputFileContents modified) =
  InputFileContents <$> runNINJA2XorWalk patch modified Reverse

-- | The two directions walk the same records, because XOR undoes itself; only the world around the walk changes.
-- A record is judged against the forward output size either way, so a write the apply refuses, the undo refuses too.
-- Everything past the direction's own buffer belongs to the file this walk is not building:
-- record bytes that land there are clipped away, and the other mode's overflow is never written.
runNINJA2XorWalk :: NINJA2Patch -> ByteString -> ApplyDirection -> Either SlapError ByteString
runNINJA2XorWalk patch input direction =
  case addressableByteCount LabelNINJA2 outputSize of
    Left refusal          -> Left refusal
    Right addressableSize -> unsafePerformIO $ do
      (result, maybeErr) <- fillNewBuffer addressableSize runWalk
      pure $ case maybeErr of
        Just walkErr -> Left (wrapWalkError walkErr)
        Nothing      -> Right result
  where
    sourceSize = maybe (byteFileSize input) openNewFileSourceSize (ninja2OpenNewFile patch)
    targetSize = maybe (byteFileSize input) openNewFileTargetSize (ninja2OpenNewFile patch)

    forwardOutputSize = targetSize
    (outputSize, writtenOverflowMode, overflowPosition) = case direction of
      Forward -> (targetSize, OverflowAppend,   fileSizeToOffset sourceSize)
      Reverse -> (sourceSize, OverflowTruncate, fileSizeToOffset targetSize)

    wrapWalkError = case direction of
      Forward -> ApplyFailed LabelNINJA2
      Reverse -> UndoFailed  LabelNINJA2

    records             = ninja2Records patch
    -- one index past the last record, so an overflow error never wears a record's index
    overflowActionIndex = streamEndIndex records

    checkWriteFits :: ActionIndex -> Offset -> Length -> FileSize
                   -> Either ApplyError ()
    checkWriteFits actionIndex writePosition writeLength bound
      | unOffset writePosition < 0 =
          Left (ApplyNegativeRecordOffset actionIndex writePosition)
      | not (fitsWithin writePosition writeLength bound) =
          Left (ApplyAbsoluteWritePastTarget actionIndex
                 writePosition
                 (RequestedLength writeLength)
                 bound)
      | otherwise = Right ()

    clipToOutput :: Offset -> ByteString -> ByteString
    clipToOutput writePosition xorPayload
      | fitsWithin writePosition (byteLength xorPayload) outputSize = xorPayload
      | offsetToFileSize writePosition >= outputSize                = ByteString.empty
      | otherwise = takeLength (remainingFromOffset writePosition outputSize) xorPayload

    -- | The pointer loop trusts its caller: the payload arrives already checked and clipped to the buffer.
    executeXorRecord :: Ptr Word8 -> Offset -> ByteString -> IO ()
    executeXorRecord outputPointer writePosition xorPayload =
        writeRemainingBytes 0
      where
        recordLength = ByteString.length xorPayload
        writeBase    = outputPointer `plusOffset` writePosition
        writeRemainingBytes !byteOffset
          | byteOffset >= recordLength = pure ()
          | otherwise = do
              original <- peekByteOff writeBase byteOffset :: IO Word8
              pokeByteOff writeBase byteOffset
                (original `xor` ByteString.index xorPayload byteOffset)
              writeRemainingBytes (byteOffset + 1)

    applyRecords :: Ptr Word8 -> ActionIndex -> [NINJA2Record]
                 -> IO (Maybe ApplyError)
    applyRecords outputPointer _actionIndex [] =
      applyOverflowWrite outputPointer
    applyRecords outputPointer !actionIndex
                 (NINJA2Record writePosition xorPayload : remainingRecords) =
      case checkWriteFits actionIndex writePosition (byteLength xorPayload) forwardOutputSize of
        Left err -> pure (Just err)
        Right () -> do
          executeXorRecord outputPointer writePosition (clipToOutput writePosition xorPayload)
          applyRecords outputPointer (nextAction actionIndex) remainingRecords

    applyOverflowWrite :: Ptr Word8 -> IO (Maybe ApplyError)
    applyOverflowWrite outputPointer =
      case (ninja2OverflowType patch, ninja2Overflow patch) of
        (Just mode, Just overflow) | mode == writtenOverflowMode ->
          let decoded = ByteString.map (xor 0xFF) overflow
          in case checkWriteFits overflowActionIndex overflowPosition (byteLength decoded) outputSize of
               Left err -> pure (Just err)
               Right () -> do
                 copyRegion outputPointer overflowPosition
                            decoded (Offset 0) (byteLength decoded)
                 pure Nothing
        _ -> pure Nothing

    runWalk outputPointer = do
      seedBufferFromSource outputPointer outputSize input
      applyRecords outputPointer firstAction records
