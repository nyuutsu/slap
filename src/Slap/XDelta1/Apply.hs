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
import Slap.Binary (copyRegion)
import Slap.Measure (Offset(..), Length(..), FileSize(..), Cursor(..),
                     ActionIndex, RequestedLength(..), RemainingLength(..),
                     ExpectedSize(..), WritePosition(..),
                     fitsWithin, remainingFromOffset, byteFileSize,
                     firstAction, nextAction)

import Slap.FileContents (InputFileContents(..), OutputFileContents(..))

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.ByteString.Internal (createAndTrim')
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
-- bounds check is needed on the source dispatch and 'sourceBytesFor'
-- is a two-arm pattern-match. Per-instruction OOB on the resolved
-- source — a length/offset combination that would read past that
-- source's end — is a precondition violation enforced at the
-- instruction boundary; the apply loop returns
-- 'ApplySourceReadOutOfBounds' rather than producing partial
-- output.
--
-- Before any target-length interpretation, the patch's recorded
-- input pre-compression posture is checked: if either input was a
-- gzip stream at delta time ('FLAG_FROM_COMPRESSED' bit 1 or
-- 'FLAG_TO_COMPRESSED' bit 2 set in the wire header), apply refuses
-- with 'XDelta1InputPreCompressionUnsupported'. Slap doesn't
-- implement the apply-time gzip transparency that canonical
-- xdelta-1.x does; proceeding against the user's literal source
-- bytes would silently produce wrong output. The 4-arm gate is
-- total over 'XDelta1FileAtDeltaTime' × 'XDelta1FileAtDeltaTime' —
-- three refusal arms, each naming a distinct
-- 'XDelta1GzipStreamInputs' constructor, and one proceed arm that
-- carries the target-length sub-cases (empty / negative / positive)
-- on its sub-guards so that the gate's precedence over the size
-- shortcuts is unambiguous on the page.
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
    outputSize     = unFileSize targetFileSize
    targetFileSize = xdelta1TargetLength patch
    dataSegment    = xdelta1DataSegment patch

    sourceBytesFor :: ByteString -> XDelta1InstructionTarget -> ByteString
    sourceBytesFor _      FromDataSource = dataSegment
    sourceBytesFor source FromFileSource = source

    proceedWithApply (InputFileContents source) = unsafePerformIO $ do
      (result, outcome) <- createAndTrim' outputSize $ \targetPointer -> do
        maybeErr <- runApply targetPointer
        pure (0, outputSize, maybeErr)
      pure $ case outcome of
        Just applyErr -> Left (ApplyFailed LabelXDelta1 applyErr)
        Nothing       -> Right (OutputFileContents result)
      where
        runApply targetPointer =
          let
            applyLoop :: Offset -> [XDelta1Instruction] -> ActionIndex -> IO (Maybe ApplyError)
            applyLoop !outputPosition [] _actionIndex
              | remainingFromOffset outputPosition targetFileSize == Length 0 =
                  pure Nothing
              | otherwise =
                  pure (Just (ApplyTargetUnderfilled
                                (WritePosition outputPosition)
                                (ExpectedSize targetFileSize)))
            applyLoop !outputPosition (instruction:rest) !actionIndex =
              let instructionOffset = xdelta1InstructionOffset instruction
                  instructionLength = Length (unFileSize (xdelta1InstructionLength instruction))
                  sourceBytes       = sourceBytesFor source (xdelta1InstructionTarget instruction)
                  sourceFileSize    = byteFileSize sourceBytes
                  remainingForWrite = remainingFromOffset outputPosition targetFileSize
              in if not (fitsWithin outputPosition instructionLength targetFileSize)
                   then pure (Just (ApplyWritesPastTarget actionIndex
                                     (RequestedLength instructionLength)
                                     (RemainingLength remainingForWrite)))
                   else if not (fitsWithin instructionOffset instructionLength sourceFileSize)
                   then pure (Just (ApplySourceReadOutOfBounds actionIndex
                                     (advance instructionOffset instructionLength) sourceFileSize))
                   else do
                     copyRegion targetPointer outputPosition sourceBytes instructionOffset instructionLength
                     applyLoop (advance outputPosition instructionLength) rest (nextAction actionIndex)
          in applyLoop (Offset 0) (xdelta1Instructions patch) firstAction
