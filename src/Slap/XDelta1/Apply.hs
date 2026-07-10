module Slap.XDelta1.Apply
  ( applyXDelta1
  ) where

import Slap.XDelta1.Types
    ( XDelta1Patch(..), XDelta1Instruction(..)
    , XDelta1SourceRoster(..)
    , XDelta1InstructionTarget(..)
    , XDelta1FileAtDeltaTime(..)
    )
import Slap.Status (SlapError(..), SlapAdvisory(..), ApplyError(..),
                    Outcome(..), XDelta1GzipStreamInputs(..),
                    XDelta1SourcelessShape(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.Binary (copyRegion, fillNewBuffer)
import Slap.Measure (Offset(..), Length(..), FileSize(..), Cursor(..),
                     ActionIndex, RequestedLength(..), RemainingLength(..),
                     ExpectedSize(..), WritePosition(..), ReadOffset(..),
                     fitsWithin, remainingFromOffset, byteFileSize,
                     firstAction, nextAction)

import Slap.FileContents (InputFileContents(..), OutputFileContents(..))

import Control.Monad.IO.Class (liftIO)
import Control.Monad.Trans.State.Strict (StateT, evalStateT, get, modify)
import Data.ByteString (ByteString)
import System.IO.Unsafe (unsafePerformIO)

----------------------------------------------------------------------------
-- Apply
----------------------------------------------------------------------------

-- | Walk the instruction stream, copying each instruction's resolved source into the output.
-- Which source it reads is a total dispatch on 'XDelta1InstructionTarget' — parse already rejected any index the roster has no position for,
-- so apply needs no runtime check. The read itself is bounds-checked:
-- a length or offset past the source's end returns 'ApplySourceReadOutOfBounds', never partial output.
--
-- The pre-compression posture is checked first. If either input was a gzip stream at delta time ('FLAG_FROM_COMPRESSED' or 'FLAG_TO_COMPRESSED'),
-- apply refuses with 'XDelta1InputPreCompressionUnsupported':
-- slap has no apply-time gzip transparency, so running against the literal source bytes would quietly produce wrong output.
--
-- A roster naming no file source ('DataSourceOnly', 'NoSources') never reads the handed input. Apply still proceeds,
-- and the 'Outcome' carries an 'XDelta1InputFileNotConsulted' note — as the reference does, applying such a patch against any from-file argument.
applyXDelta1 :: XDelta1Patch -> InputFileContents -> Either SlapError (Outcome OutputFileContents)
applyXDelta1 patch sourceContents =
  case (xdelta1FromAtDeltaTime patch, xdelta1ToAtDeltaTime patch) of
    (FileWasGzipStream, FileWasRawBytes)
      -> Left (XDelta1InputPreCompressionUnsupported OnlyFromFileWasGzipStream)
    (FileWasRawBytes,   FileWasGzipStream)
      -> Left (XDelta1InputPreCompressionUnsupported OnlyToFileWasGzipStream)
    (FileWasGzipStream, FileWasGzipStream)
      -> Left (XDelta1InputPreCompressionUnsupported BothFilesWereGzipStreams)
    (FileWasRawBytes,   FileWasRawBytes)
      | unFileSize targetFileSize < 0
          -> Left (NegativeTargetSize LabelXDelta1 targetFileSize)
      | otherwise
          -> attachSourcelessNotes <$> proceedWithApply sourceContents
  where
    targetFileSize = xdelta1TargetLength patch
    dataSegment    = xdelta1DataSegment patch

    attachSourcelessNotes producedOutput = Outcome producedOutput sourcelessNotes
    sourcelessNotes = case xdelta1SourceRoster patch of
      DataAndFileSources _ -> []
      FileSourceOnly _     -> []
      DataSourceOnly       -> [XDelta1InputFileNotConsulted OutputComesFromDataSegment]
      NoSources            -> [XDelta1InputFileNotConsulted OutputIsEmpty]

    sourceBytesFor :: ByteString -> XDelta1InstructionTarget -> ByteString
    sourceBytesFor _      FromDataSource = dataSegment
    sourceBytesFor source FromFileSource = source

    -- | The read is bounded by the per-instruction resolved source, the data segment or file, as 'sourceBytesFor' resolves.
    checkInstructionPreconditions :: ActionIndex -> Length
                                  -> WritePosition -> ReadOffset -> FileSize
                                  -> Either ApplyError ()
    checkInstructionPreconditions actionIndex instructionLength
                                  (WritePosition outputPosition) (ReadOffset instructionOffset) sourceFileSize
      | not (fitsWithin outputPosition instructionLength targetFileSize) =
          Left (ApplyWritesPastTarget actionIndex
                 (RequestedLength instructionLength)
                 (RemainingLength (remainingFromOffset outputPosition targetFileSize)))
      | not (fitsWithin instructionOffset instructionLength sourceFileSize) =
          Left (ApplySourceReadOutOfBounds actionIndex
                 (advance instructionOffset instructionLength) sourceFileSize)
      | otherwise = Right ()

    proceedWithApply (InputFileContents source) = unsafePerformIO $ do
      (result, maybeErr) <- fillNewBuffer targetFileSize runApply
      pure $ case maybeErr of
        Just applyErr -> Left (ApplyFailed LabelXDelta1 applyErr)
        Nothing       -> Right (OutputFileContents result)
      where
        runApply targetPointer =
          let
            advanceOutputByInstruction :: Length -> XDelta1Apply ()
            advanceOutputByInstruction stride =
              modify (\outputPosition -> advance outputPosition stride)

            -- | End-of-stream verifies the entire target buffer was filled.
            applyLoop :: [XDelta1Instruction] -> ActionIndex -> XDelta1Apply (Maybe ApplyError)
            applyLoop [] _actionIndex = do
              outputPosition <- get
              if remainingFromOffset outputPosition targetFileSize == Length 0
                then pure Nothing
                else pure (Just (ApplyTargetUnderfilled
                                   (WritePosition outputPosition)
                                   (ExpectedSize targetFileSize)))
            applyLoop (instruction:rest) !actionIndex = do
              outputPosition <- get
              let instructionOffset = xdelta1InstructionOffset instruction
                  instructionLength = Length (unFileSize (xdelta1InstructionLength instruction))
                  sourceBytes       = sourceBytesFor source (xdelta1InstructionTarget instruction)
                  sourceFileSize    = byteFileSize sourceBytes
              case checkInstructionPreconditions actionIndex instructionLength
                                                 (WritePosition outputPosition) (ReadOffset instructionOffset) sourceFileSize of
                Left err -> pure (Just err)
                Right () -> do
                  liftIO (copyRegion targetPointer outputPosition
                                     sourceBytes instructionOffset instructionLength)
                  advanceOutputByInstruction instructionLength
                  applyLoop rest (nextAction actionIndex)
          in evalStateT (applyLoop (xdelta1Instructions patch) firstAction) (Offset 0)

----------------------------------------------------------------------------
-- Cursor state
----------------------------------------------------------------------------

-- | The state slot carries the output cursor, advanced by one instruction's length per step.
type XDelta1Apply = StateT Offset IO
