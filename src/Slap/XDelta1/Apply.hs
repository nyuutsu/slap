module Slap.XDelta1.Apply
  ( applyXDelta1
  ) where

import Slap.XDelta1.Types
    ( XDelta1Patch(..), XDelta1Instruction(..)
    , XDelta1InstructionTarget(..)
    , XDelta1FileAtDeltaTime(..)
    )
import Slap.Status (SlapError(..), ApplyError(..), XDelta1GzipStreamInputs(..))
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
import qualified Data.ByteString as ByteString
import System.IO.Unsafe (unsafePerformIO)

----------------------------------------------------------------------------
-- Apply
----------------------------------------------------------------------------

-- | Walks the instruction stream, copying bytes from the resolved source for each instruction.
-- Which source an instruction reads is a total two-arm dispatch on 'XDelta1InstructionTarget':
-- 'Slap.XDelta1.Parse.translateInstruction' rejects any other index at parse time, so apply needs no runtime check there.
-- The read within that source is bounds-checked per instruction: a length/offset past the source's end returns 'ApplySourceReadOutOfBounds' rather than partial output.
--
-- The recorded input pre-compression posture is checked first:
-- if either input was a gzip stream at delta time ('FLAG_FROM_COMPRESSED' or 'FLAG_TO_COMPRESSED' set), apply refuses with 'XDelta1InputPreCompressionUnsupported'.
-- Slap doesn't implement the apply-time gzip transparency canonical xdelta-1.x does, so proceeding against the user's literal source bytes would silently produce wrong output.
applyXDelta1 :: XDelta1Patch -> InputFileContents -> Either SlapError OutputFileContents
applyXDelta1 patch sourceContents =
  case (xdelta1FromAtDeltaTime patch, xdelta1ToAtDeltaTime patch) of
    (FileWasGzipStream, FileWasRawBytes)
      -> Left (XDelta1InputPreCompressionUnsupported OnlyFromFileWasGzipStream)
    (FileWasRawBytes,   FileWasGzipStream)
      -> Left (XDelta1InputPreCompressionUnsupported OnlyToFileWasGzipStream)
    (FileWasGzipStream, FileWasGzipStream)
      -> Left (XDelta1InputPreCompressionUnsupported BothFilesWereGzipStreams)
    (FileWasRawBytes,   FileWasRawBytes)
      | unFileSize targetFileSize == 0
          -> Right (OutputFileContents ByteString.empty)
      | unFileSize targetFileSize < 0
          -> Left (NegativeTargetSize LabelXDelta1 targetFileSize)
      | otherwise
          -> proceedWithApply sourceContents
  where
    targetFileSize = xdelta1TargetLength patch
    dataSegment    = xdelta1DataSegment patch

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

            -- | The output cursor lives in 'XDelta1Apply' state, so each step needs only the remaining instructions and the running action index.
            -- End-of-stream verifies the walker filled the entire target buffer.
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

-- | The state slot carries the output cursor, the apply's only threaded value, advanced by one instruction's length per step.
type XDelta1Apply = StateT Offset IO
