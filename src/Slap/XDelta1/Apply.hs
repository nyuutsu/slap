module Slap.XDelta1.Apply
  ( applyXDelta1
  ) where

import Slap.XDelta1.Types
    ( XDelta1Patch(..), XDelta1Instruction(..)
    , XDelta1InstructionTarget(..)
    , XDelta1FileAtDeltaTime(..)
    )
import Slap.Error (SlapError(..), XDelta1GzipStreamInputs(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.Binary (copyRegion)
import Slap.Measure (Offset(..), Length(..), FileSize(..), Cursor(..), remainingFromOffset)

import Slap.FileContents (InputFileContents(..), OutputFileContents(..))

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.ByteString.Internal (unsafeCreate)

----------------------------------------------------------------------------
-- Apply
----------------------------------------------------------------------------

-- | Apply an xdelta1 patch by walking its instruction stream and
-- copying bytes from the resolved source for each instruction. The
-- per-instruction source dispatch is total in
-- 'XDelta1InstructionTarget': the parser
-- ('Slap.XDelta1.Parse.translateInstruction') guarantees that every
-- instruction targets one of the patch's two sources, so no runtime
-- bounds check is needed here and 'sourceBytesFor' is a two-arm
-- pattern-match.
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
      | unFileSize (xdelta1TargetLength patch) == 0
          -> Right (OutputFileContents ByteString.empty)
      | unFileSize (xdelta1TargetLength patch) < 0
          -> Left (NegativeTargetSize LabelXDelta1 (xdelta1TargetLength patch))
      | otherwise
          -> proceedWithApply sourceContents
  where
    outputSize     = unFileSize (xdelta1TargetLength patch)
    targetFileSize = xdelta1TargetLength patch
    dataSegment    = xdelta1DataSegment patch

    sourceBytesFor :: ByteString -> XDelta1InstructionTarget -> ByteString
    sourceBytesFor _      FromDataSource = dataSegment
    sourceBytesFor source FromFileSource = source

    proceedWithApply (InputFileContents source) =
      Right $ OutputFileContents $ unsafeCreate outputSize $ \targetPointer ->
        let
          applyLoop :: Offset -> [XDelta1Instruction] -> IO ()
          applyLoop _outputPosition [] = pure ()
          applyLoop !outputPosition (instruction:rest) = do
            let sourceBytes       = sourceBytesFor source (xdelta1InstructionTarget instruction)
                instructionOffset = xdelta1InstructionOffset instruction
                instructionLength = Length (unFileSize (xdelta1InstructionLength instruction))
                safeLength        = min instructionLength (remainingFromOffset outputPosition targetFileSize)
                sourceSafeLength =
                  if unOffset instructionOffset >= 0
                     && unOffset instructionOffset < ByteString.length sourceBytes
                  then min safeLength (Length (ByteString.length sourceBytes - unOffset instructionOffset))
                  else Length 0
            copyRegion targetPointer outputPosition sourceBytes instructionOffset sourceSafeLength
            applyLoop (advance outputPosition safeLength) rest
        in applyLoop (Offset 0) (xdelta1Instructions patch)
