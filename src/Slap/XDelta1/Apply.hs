module Slap.XDelta1.Apply
  ( applyXDelta1
  ) where

import Slap.XDelta1.Types
    ( XDelta1Patch(..), XDelta1Instruction(..)
    , XDelta1SourceShape(..)
    )
import Slap.Error (SlapError(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.Binary (copyRegion)
import Slap.Measure (Offset(..), Length(..), FileSize(..), Cursor(..), remainingFromOffset)

import Slap.FileContents (InputFileContents(..), OutputFileContents(..))

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.ByteString.Internal (unsafeCreate)
import Data.Int (Int64)

----------------------------------------------------------------------------
-- Apply
----------------------------------------------------------------------------

-- | Apply an xdelta1 patch by walking its instruction stream and
-- copying bytes from the resolved source for each instruction. The
-- per-instruction source dispatch is total in 'XDelta1SourceShape':
-- the parser ('Slap.XDelta1.Parse.classifyXDelta1Shape',
-- 'Slap.XDelta1.Parse.validateInstructionIndices') guarantees that
-- every instruction's index is in range for the patch's shape, so
-- no runtime bounds check is needed here. For the single-source
-- shapes ('XDelta1DataOnly' and 'XDelta1FileOnly') the source
-- bytes are constant across the loop and bound once outside it;
-- only the two-source 'XDelta1DataAndFile' case needs a per-
-- instruction selector.
applyXDelta1 :: XDelta1Patch -> InputFileContents -> Either SlapError OutputFileContents
applyXDelta1 patch _
  | unFileSize (xdelta1TargetLength patch) == 0 = Right (OutputFileContents ByteString.empty)
  | unFileSize (xdelta1TargetLength patch) < 0  = Left (NegativeTargetSize LabelXDelta1 (xdelta1TargetLength patch))
applyXDelta1 patch (InputFileContents source) = Right $ OutputFileContents $ unsafeCreate outputSize $ \targetPointer ->
    let
      applyLoop :: Offset -> [XDelta1Instruction] -> IO ()
      applyLoop _outputPosition [] = pure ()
      applyLoop !outputPosition (instruction:rest) = do
        let sourceBytes       = sourceBytesFor (xdelta1InstructionIndex instruction)
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
  where
    outputSize     = unFileSize (xdelta1TargetLength patch)
    targetFileSize = xdelta1TargetLength patch
    dataSegment    = xdelta1DataSegment patch

    -- | Resolve a parse-validated index to its source bytes. Hoisted
    -- out of the per-instruction loop because for the single-source
    -- shapes the answer is constant; for 'XDelta1DataAndFile' the
    -- per-call branch is the minimum work the loop has to do.
    -- Unreachable arms can't fire: 'validateInstructionIndices'
    -- (in the parser) rejects any instruction whose index is
    -- out-of-range for the shape, so 'XDelta1NoSources' never sees
    -- a call here, and 'XDelta1DataAndFile' only sees indices 0 or 1.
    sourceBytesFor :: Int64 -> ByteString
    sourceBytesFor = case xdelta1SourceShape patch of
      XDelta1NoSources       -> \_   -> ByteString.empty
      XDelta1DataOnly _      -> \_   -> dataSegment
      XDelta1FileOnly _      -> \_   -> source
      XDelta1DataAndFile _ _ -> \idx -> if idx == 0 then dataSegment else source
