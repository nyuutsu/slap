module Slap.GDIFF.Apply
  ( applyGDIFF
  ) where

import Slap.GDIFF.Types (GDiffPatch(..), GDiffCommand(..))
import Slap.Binary (copyRegion)
import Slap.Measure
  ( Offset(..), Length(..), FileSize(..), ActionIndex
  , advance, byteLength, firstAction, nextAction, fitsWithin, lengthToFileSize, byteFileSize
  )
import Slap.Status (SlapError(..), ApplyError(..))
import Slap.FormatLabel (FormatLabel(..))

import Slap.FileContents (InputFileContents(..), OutputFileContents(..))

import qualified Data.ByteString as ByteString
import Data.ByteString.Internal (unsafeCreate)

-- | Apply a GDIFF patch to a source. The command stream is walked
-- twice: once by 'validateCommands' to bounds-check every COPY's
-- source range and compute the total output size, and once by the
-- write loop below. The split makes the write loop infallible — by
-- the time we reach 'unsafeCreate', every COPY has been proven to
-- read inside @source@ and the buffer has been sized to fit every
-- DATA payload plus every COPY length.
--
-- GDIFF's command stream has no relative cursor and no target
-- self-reference, so a pre-flight pass is structurally sound: each
-- command's output size and source-read range are independent of
-- prior commands' effects. Formats with target self-reference
-- (BPS, IPS, DPS) cannot validate ahead of time and instead validate
-- inline during the write.
applyGDIFF :: GDiffPatch -> InputFileContents -> Either SlapError OutputFileContents
applyGDIFF patch (InputFileContents source) =
  case validateCommands sourceSize commands of
    Left applyError       -> Left (ApplyFailed LabelGDIFF applyError)
    Right (FileSize 0)    -> Right (OutputFileContents ByteString.empty)
    Right totalOutputSize -> Right (OutputFileContents (writeOutput totalOutputSize))
  where
    commands   = gdiffCommands patch
    sourceSize = byteFileSize source

    writeOutput totalOutputSize = unsafeCreate (unFileSize totalOutputSize) $ \outputPointer ->
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

-- | Pre-flight bounds check on a GDIFF command stream. Walks the
-- list once; returns the total output size if every command is
-- sound, or the first 'ApplyError' encountered. The returned
-- 'FileSize' is exactly what 'applyGDIFF' allocates for the output
-- buffer, so the apply loop itself does not need bounds checks:
-- every COPY's source range was verified here, every DATA's payload
-- is its own length, and the buffer was sized to fit their sum.
validateCommands :: FileSize -> [GDiffCommand] -> Either ApplyError FileSize
validateCommands sourceSize = validateCommandStream firstAction (Length 0)
  where
    validateCommandStream
      :: ActionIndex -> Length -> [GDiffCommand] -> Either ApplyError FileSize
    validateCommandStream _actionIndex accumulatedOutput [] =
      Right (lengthToFileSize accumulatedOutput)
    validateCommandStream !actionIndex !accumulatedOutput (command : remainingCommands) =
      case command of
        GDiffCommandData { gdiffDataPayload = payload } ->
          let payloadLength = byteLength payload
          in validateCommandStream
               (nextAction actionIndex)
               (accumulatedOutput <> payloadLength)
               remainingCommands
        GDiffCommandCopy { gdiffCopyOffset = sourceOffset, gdiffCopyLength = copyLength }
          -- Opcode 255's offset is a signed int64BE; the other COPY opcodes read unsigned 16/32-bit fields,
          -- so only a 255 command can present a negative offset.
          | unOffset sourceOffset < 0 ->
              Left (ApplyNegativeRecordOffset actionIndex sourceOffset)
          | not (fitsWithin sourceOffset copyLength sourceSize) ->
              Left (ApplySourceReadOutOfBounds actionIndex
                      (advance sourceOffset copyLength) sourceSize)
          | otherwise ->
              validateCommandStream
                (nextAction actionIndex)
                (accumulatedOutput <> copyLength)
                remainingCommands
