module Slap.BSDiff.Apply
  ( applyBSDiff
  ) where

import Slap.FileContents (InputFileContents(..), OutputFileContents(..))

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Slap.BSDiff.Types (BSDiffPatch(..), BSDiffInstruction(..))
import Slap.Status (SlapError(..), ApplyError(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.Binary (copyRegion, fillNewBuffer)
import Slap.Measure (Offset(..), Length(..), FileSize(..),
                     SignedOffset(..), Cursor(..), Delta,
                     ActionIndex, RequestedLength(..), RemainingLength(..),
                     ExpectedSize(..), WritePosition(..),
                     fitsWithin, remainingFromOffset, byteFileSize,
                     firstAction, nextAction)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Trans.State.Strict (StateT, evalStateT, gets, modify)
import Data.Word (Word8)
import Foreign.Ptr (plusPtr)
import Foreign.Storable (pokeByteOff)
import System.IO.Unsafe (unsafePerformIO)

----------------------------------------------------------------------------
-- Apply-time cursors
----------------------------------------------------------------------------

-- | The four cursors threaded through 'applyLoop': one per stream
-- (diff, extra, source, output). Lifted into a record so each cursor
-- is identified by name, never by position.
data BSDiffCursors = BSDiffCursors
  { -- | Read cursor into the diff byte stream. Advances by
    -- @addLength@ per instruction.
    diffStreamRead  :: !Offset
    -- | Read cursor into the extra byte stream. Advances by
    -- @copyLength@ per instruction.
  , extraStreamRead :: !Offset
    -- | Read cursor into the source ROM. Carried as 'SignedOffset'
    -- because BSDiff's seek delta can take the cursor negative or
    -- past the end of the source. The matching-window extension
    -- rule (see 'sourceByteOrZero') treats source positions outside
    -- @[0, sourceLength)@ as contributing zero to the byte-wise sum,
    -- which is required for correctness — valid patches use this to
    -- encode bytes in a match-section whose corresponding source
    -- position falls outside the source.
  , originalRead    :: !SignedOffset
    -- | Write cursor into the output target buffer. Advances by
    -- @addLength <> copyLength@ per instruction.
  , outputWrite     :: !Offset
  } deriving (Show)

-- | Strict 'StateT' over 'IO' carrying 'BSDiffCursors'. Strict
-- because the cursors update on every instruction and lazy thunk
-- build-up across a long control stream would buy nothing.
type BSDiffApply = StateT BSDiffCursors IO

-- | Cursor record at the start of an apply: every stream reads from
-- its own offset zero, and the output buffer's write head sits at
-- offset zero.
initialCursors :: BSDiffCursors
initialCursors = BSDiffCursors
  { diffStreamRead  = Offset 0
  , extraStreamRead = Offset 0
  , originalRead    = SignedOffset 0
  , outputWrite     = Offset 0
  }

----------------------------------------------------------------------------
-- applyBSDiff
----------------------------------------------------------------------------

-- | Apply a parsed BSDiff patch to a source ByteString. Each
-- instruction in the patch's control stream describes one
-- (ADD, COPY) pair plus a signed seek over the source; the apply
-- walks the stream and runs the per-instruction preconditions at
-- the instruction boundary, returning 'Left' with a structured
-- 'ApplyError' if any precondition fails. The source cursor is
-- intentionally unbounded — see 'sourceByteOrZero' for the
-- matching-window extension rule that makes this safe.
applyBSDiff :: BSDiffPatch -> InputFileContents -> Either SlapError OutputFileContents
applyBSDiff patch _
  | unFileSize (bsdiffTargetSize patch) == 0 = Right (OutputFileContents ByteString.empty)
  | unFileSize (bsdiffTargetSize patch) < 0  = Left (NegativeTargetSize LabelBSDiff (bsdiffTargetSize patch))
applyBSDiff patch (InputFileContents source) = unsafePerformIO $ do
    (result, maybeErr) <- fillNewBuffer targetFileSize runApply
    pure $ case maybeErr of
      Just applyErr -> Left (ApplyFailed LabelBSDiff applyErr)
      Nothing       -> Right (OutputFileContents result)
  where
    targetFileSize = bsdiffTargetSize patch
    diffBytes      = bsdiffDiffData patch
    extraBytes     = bsdiffExtraData patch
    diffSize       = byteFileSize diffBytes
    extraSize      = byteFileSize extraBytes

    -- | Per-instruction guards for an ADD region: the write must fit
    -- in the remaining target buffer, and the diff read must fit in
    -- the remaining diff stream. The source byte read is intentionally
    -- unbounded — the matching-window extension rule (see
    -- 'sourceByteOrZero') defines the algorithm for source positions
    -- outside @[0, sourceLength)@, so there is no precondition to
    -- enforce on the source side.
    checkAddPreconditions :: ActionIndex -> Length -> Offset -> Offset
                          -> Either ApplyError ()
    checkAddPreconditions actionIndex addLength outputPosition diffReadOffset
      | not (fitsWithin outputPosition addLength targetFileSize) =
          Left (ApplyWritesPastTarget actionIndex
                 (RequestedLength addLength)
                 (RemainingLength (remainingFromOffset outputPosition targetFileSize)))
      | not (fitsWithin diffReadOffset addLength diffSize) =
          Left (ApplyDiffReadOutOfBounds actionIndex
                 (advance diffReadOffset addLength) diffSize)
      | otherwise = Right ()

    -- | Per-instruction guards for a COPY region: the write must fit
    -- in the remaining target buffer, and the extra read must fit in
    -- the remaining extra stream.
    checkCopyPreconditions :: ActionIndex -> Length -> Offset -> Offset
                           -> Either ApplyError ()
    checkCopyPreconditions actionIndex copyLength outputAfterAdd extraReadOffset
      | not (fitsWithin outputAfterAdd copyLength targetFileSize) =
          Left (ApplyWritesPastTarget actionIndex
                 (RequestedLength copyLength)
                 (RemainingLength (remainingFromOffset outputAfterAdd targetFileSize)))
      | not (fitsWithin extraReadOffset copyLength extraSize) =
          Left (ApplyExtraReadOutOfBounds actionIndex
                 (advance extraReadOffset copyLength) extraSize)
      | otherwise = Right ()

    runApply targetPointer =
      let
        -- | The cursor transition done after an instruction's ADD
        -- region completes. The diff cursor advances by @addLength@
        -- (one diff byte was consumed per output byte). The source
        -- cursor advances by @addLength@ (one source byte was
        -- consumed per output byte under the matching-window
        -- extension rule) and then displaces by the instruction's
        -- signed seek delta, which re-bases the source cursor for
        -- the next match. The output cursor advances by @addLength@.
        advanceForAdd :: Length -> Delta -> BSDiffApply ()
        advanceForAdd addLength seekDelta = modify $ \cursors -> cursors
          { diffStreamRead = advance (diffStreamRead cursors) addLength
          , originalRead   = displace (advance (originalRead cursors) addLength) seekDelta
          , outputWrite    = advance (outputWrite cursors) addLength
          }

        -- | The cursor transition done after an instruction's COPY
        -- region completes. The extra cursor advances by @copyLength@
        -- (one extra byte was consumed per output byte). The output
        -- cursor advances by @copyLength@.
        advanceForCopy :: Length -> BSDiffApply ()
        advanceForCopy copyLength = modify $ \cursors -> cursors
          { extraStreamRead = advance (extraStreamRead cursors) copyLength
          , outputWrite     = advance (outputWrite cursors) copyLength
          }

        -- | Materialise one ADD region into the target buffer:
        -- @target[outputPosition+i] = source[originalPosition+i] + diff[diffReadOffset+i]@
        -- for @i@ in @[0, addLength)@. The source read goes through
        -- 'sourceByteOrZero', so positions outside the source contribute
        -- zero per the matching-window extension rule.
        executeAddRegion :: Length -> SignedOffset -> Offset -> Offset -> IO ()
        executeAddRegion addLength originalPosition diffReadOffset outputPosition =
            writeRemainingBytes 0
          where
            totalBytes = unLength addLength
            sourceBase = unSignedOffset originalPosition
            diffBase   = unOffset diffReadOffset
            writeBase  = targetPointer `plusPtr` unOffset outputPosition
            writeRemainingBytes !byteOffset
              | byteOffset >= totalBytes = pure ()
              | otherwise = do
                  let sourceByte = sourceByteOrZero source (sourceBase + byteOffset)
                      diffByte   = ByteString.index diffBytes (diffBase + byteOffset)
                  pokeByteOff writeBase byteOffset (sourceByte + diffByte :: Word8)
                  writeRemainingBytes (byteOffset + 1)

        -- | Tail-recursive walk over the instruction list. The four
        -- cursors live in 'BSDiffApply' state, so each step needs
        -- only the remaining instructions and the running action
        -- index. End-of-stream verifies the walker filled the entire
        -- target buffer.
        applyLoop :: [BSDiffInstruction] -> ActionIndex -> BSDiffApply (Maybe ApplyError)
        applyLoop [] _actionIndex = do
          finalOutput <- gets outputWrite
          if remainingFromOffset finalOutput targetFileSize == Length 0
            then pure Nothing
            else pure (Just (ApplyTargetUnderfilled
                              (WritePosition finalOutput)
                              (ExpectedSize targetFileSize)))
        applyLoop (instruction:rest) !actionIndex = do
          outputPosition   <- gets outputWrite
          diffReadOffset   <- gets diffStreamRead
          originalPosition <- gets originalRead
          let addLength  = controlAdd instruction
              copyLength = controlCopy instruction
              seekDelta  = controlSeek instruction
          case checkAddPreconditions actionIndex addLength outputPosition diffReadOffset of
            Left err -> pure (Just err)
            Right () -> do
              liftIO (executeAddRegion addLength originalPosition
                                       diffReadOffset outputPosition)
              advanceForAdd addLength seekDelta
              outputAfterAdd  <- gets outputWrite
              extraReadOffset <- gets extraStreamRead
              case checkCopyPreconditions actionIndex copyLength
                                          outputAfterAdd extraReadOffset of
                Left err -> pure (Just err)
                Right () -> do
                  liftIO (copyRegion targetPointer outputAfterAdd
                                     extraBytes extraReadOffset copyLength)
                  advanceForCopy copyLength
                  applyLoop rest (nextAction actionIndex)
      in evalStateT (applyLoop (bsdiffInstructions patch) firstAction) initialCursors

-- | Read a byte at @index@ from the source ByteString, returning 0
-- for out-of-bounds indices (negative or past the end).
--
-- This implements the bsdiff matching-window extension rule: a
-- single ADD instruction encodes a match-window of @addLength@
-- bytes where the diff stream stores @new[i] − old[oldpos+i]@.
-- The compressor exploits this encoding to extend matches past
-- either end of the source by storing the full target byte
-- verbatim in the diff stream — those bytes get "added to zero"
-- at apply time and reproduce exactly.
--
-- This rule applies to the source byte specifically. The diff
-- stream is bounds-checked per-instruction and produces an
-- 'ApplyDiffReadOutOfBounds' error on overflow; only the source
-- side carries the extension-zero semantics.
sourceByteOrZero :: ByteString -> Int -> Word8
sourceByteOrZero bytes index
  | index >= 0 && index < ByteString.length bytes =
      ByteString.index bytes index
  | otherwise = 0
