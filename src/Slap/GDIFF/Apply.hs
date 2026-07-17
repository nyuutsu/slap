module Slap.GDIFF.Apply
  ( applyGDIFF
    -- * Pre-flight (exported for testing)
  , validateCommands
  ) where

import Slap.GDIFF.Types (GDiffPatch(..), GDiffCommand(..))
import Slap.Binary (copyRegion, filledBufferOfSize)
import Slap.Measure
  ( Offset(..), FileSize(..), ActionIndex
  , advance, byteLength, firstAction, nextAction, fitsWithin, offsetToFileSize, boundedWriteEnd, byteFileSize
  )
import Slap.Status (SlapError(..), ApplyError(..), addressableByteCount)
import Slap.FormatLabel (FormatLabel(..))

import Slap.FileContents (InputFileContents(..), OutputFileContents(..))

import qualified Data.ByteString as ByteString

-- | The command stream is walked twice:
-- once by 'validateCommands' to bounds-check every COPY's source range and compute the total output size, and once by the write loop below.
-- The split makes the write loop infallible: by the time we reach 'filledBufferOfSize',
-- every COPY has been proven to read inside @source@ and the buffer sized to fit every DATA payload plus every COPY length.
--
-- A pre-flight pass is sound because GDIFF's command stream has no relative cursor and no target self-reference:
-- each command's output size and source-read range are independent of prior commands' effects.
-- Formats with target self-reference (BPS, IPS, DPS) can't validate ahead of time, so they validate inline during the write.
applyGDIFF :: GDiffPatch -> InputFileContents -> Either SlapError OutputFileContents
applyGDIFF patch (InputFileContents source) =
  case validateCommands sourceSize commands of
    Left applyError       -> Left (ApplyFailed LabelGDIFF applyError)
    Right (FileSize 0)    -> Right (OutputFileContents ByteString.empty)
    Right totalOutputSize -> case addressableByteCount LabelGDIFF totalOutputSize of
      Left refusal          -> Left refusal
      Right addressableSize -> Right (OutputFileContents (writeOutput addressableSize))
  where
    commands   = gdiffCommands patch
    sourceSize = byteFileSize source

    writeOutput addressableSize = filledBufferOfSize addressableSize $ \outputPointer ->
      let
        applyLoop :: Offset -> [GDiffCommand] -> IO ()
        applyLoop _outputPosition [] = pure ()
        applyLoop !outputPosition (command : remainingCommands) = case command of
          GDiffCommandData { gdiffDataPayload = payload } -> do
            let dataLength = byteLength payload
            copyRegion outputPointer outputPosition payload (Offset 0) dataLength
            applyLoop (advance outputPosition dataLength) remainingCommands
          GDiffCommandCopy { gdiffCopyOffset = sourceOffset, gdiffCopyLength = copyLength } -> do
            copyRegion outputPointer outputPosition source sourceOffset copyLength
            applyLoop (advance outputPosition copyLength) remainingCommands
      in applyLoop (Offset 0) commands

-- | Pre-flight bounds check on a GDIFF command stream.
-- Walks it once, returning the total output size 'applyGDIFF' allocates, or the first 'ApplyError'.
validateCommands :: FileSize -> [GDiffCommand] -> Either ApplyError FileSize
validateCommands sourceSize = validateCommandStream firstAction (Offset 0)
  where
    validateCommandStream
      :: ActionIndex -> Offset -> [GDiffCommand] -> Either ApplyError FileSize
    validateCommandStream _actionIndex outputEnd [] =
      Right (offsetToFileSize outputEnd)
    validateCommandStream !actionIndex !outputEnd (command : remainingCommands) =
      case command of
        GDiffCommandData { gdiffDataPayload = payload } ->
          extendOutput (byteLength payload)
        GDiffCommandCopy { gdiffCopyOffset = sourceOffset, gdiffCopyLength = copyLength }
          -- Opcode 255's offset is a signed int64BE; the other COPY opcodes read unsigned 16/32-bit fields,
          -- so only a 255 command can present a negative offset.
          | unOffset sourceOffset < 0 ->
              Left (ApplyNegativeRecordOffset actionIndex sourceOffset)
          | not (fitsWithin sourceOffset copyLength sourceSize) ->
              Left (ApplySourceReadOutOfBounds actionIndex
                      (advance sourceOffset copyLength) sourceSize)
          | otherwise ->
              extendOutput copyLength
      where
        extendOutput producedLength =
          case boundedWriteEnd outputEnd producedLength of
            Nothing      -> Left (ApplyOutputExceedsAddressableRange actionIndex outputEnd producedLength)
            Just nextEnd -> validateCommandStream (nextAction actionIndex) nextEnd remainingCommands
