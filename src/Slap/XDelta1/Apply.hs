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
                     ExpectedSize(..), WritePosition(..),
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

-- | Apply an xdelta1 patch by walking its instruction stream and
-- copying bytes from the resolved source for each instruction. The
-- per-instruction source dispatch is total in
-- 'XDelta1InstructionTarget': the parser
-- ('Slap.XDelta1.Parse.translateInstruction') guarantees that every
-- instruction targets one of the patch's two sources, so no runtime
-- bounds check is needed.
-- Per-instruction OOB on the resolved source — a length/offset
-- combination that would read past that source's end — is a
-- precondition violation enforced at the instruction boundary; the
-- apply loop returns 'ApplySourceReadOutOfBounds' rather than
-- producing partial output.
--
-- Before any target-length interpretation, the patch's recorded
-- input pre-compression posture is checked: if either input was a
-- gzip stream at delta time ('FLAG_FROM_COMPRESSED' bit 1 or
-- 'FLAG_TO_COMPRESSED' bit 2 set in the wire header), apply refuses
-- with 'XDelta1InputPreCompressionUnsupported'. Slap doesn't
-- implement the apply-time gzip transparency that canonical
-- xdelta-1.x does; proceeding against the user's literal source
-- bytes would silently produce wrong output.
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

    -- | Per-instruction guards: the write must fit in the remaining
    -- target buffer, and the read must fit in the per-instruction
    -- resolved source (data segment or file, as 'sourceBytesFor'
    -- resolves).
    checkInstructionPreconditions :: ActionIndex -> Length
                                  -> Offset -> Offset -> FileSize
                                  -> Either ApplyError ()
    checkInstructionPreconditions actionIndex instructionLength
                                  outputPosition instructionOffset sourceFileSize
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

            -- | Tail-recursive walk over the instruction list. The
            -- output cursor lives in 'XDelta1Apply' state, so each
            -- step needs only the remaining instructions and the
            -- running action index. End-of-stream verifies the
            -- walker filled the entire target buffer.
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
                                                 outputPosition instructionOffset sourceFileSize of
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

-- | Strict 'StateT' over 'IO'. The state slot carries the output
-- cursor — the apply's only threaded value, advanced by one
-- instruction's length per step.
type XDelta1Apply = StateT Offset IO
