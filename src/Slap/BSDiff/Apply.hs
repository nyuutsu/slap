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

-- | The four cursors threaded through 'applyLoop', one per stream.
data BSDiffCursors = BSDiffCursors
  { -- | Read cursor into the diff byte stream. Advances by
    -- @addLength@ per instruction.
    diffStreamRead  :: !Offset
    -- | Read cursor into the extra byte stream. Advances by
    -- @copyLength@ per instruction.
  , extraStreamRead :: !Offset
    -- | Read cursor into the source ROM.
    -- Carried as 'SignedOffset' because BSDiff's seek delta can take the cursor negative or past the end of the source;
    -- 'sourceByteOrZero' handles reads from those out-of-range positions.
  , originalRead    :: !SignedOffset
    -- | Write cursor into the output target buffer. Advances by
    -- @addLength <> copyLength@ per instruction.
  , outputWrite     :: !Offset
  } deriving (Show)

type BSDiffApply = StateT BSDiffCursors IO

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

-- | Each instruction in the patch's control stream describes one (ADD, COPY) pair plus a signed seek over the source;
-- the apply walks the stream and runs the per-instruction preconditions at the instruction boundary,
-- returning 'Left' with a structured 'ApplyError' if any precondition fails.
-- The source cursor is unbounded; 'sourceByteOrZero' handles out-of-range source reads.
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

    -- | The source read is unguarded; see 'sourceByteOrZero'.
    checkAddPreconditions :: ActionIndex -> Length -> Offset -> Offset
                          -> Either ApplyError ()
    checkAddPreconditions actionIndex addLength outputPosition diffReadOffset
      | unLength addLength < 0 =
          Left (ApplyNegativeControlLength actionIndex (RequestedLength addLength))
      | not (fitsWithin outputPosition addLength targetFileSize) =
          Left (ApplyWritesPastTarget actionIndex
                 (RequestedLength addLength)
                 (RemainingLength (remainingFromOffset outputPosition targetFileSize)))
      | not (fitsWithin diffReadOffset addLength diffSize) =
          Left (ApplyDiffReadOutOfBounds actionIndex
                 (advance diffReadOffset addLength) diffSize)
      | otherwise = Right ()

    -- | Unlike the ADD guards, every read here is bounded; nothing falls through to 'sourceByteOrZero'.
    checkCopyPreconditions :: ActionIndex -> Length -> Offset -> Offset
                           -> Either ApplyError ()
    checkCopyPreconditions actionIndex copyLength outputAfterAdd extraReadOffset
      | unLength copyLength < 0 =
          Left (ApplyNegativeControlLength actionIndex (RequestedLength copyLength))
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
        -- | Cursor transition after an instruction's ADD region.
        -- The seek delta re-bases the source cursor for the next match.
        advanceForAdd :: Length -> Delta -> BSDiffApply ()
        advanceForAdd addLength seekDelta = modify $ \cursors -> cursors
          { diffStreamRead = advance (diffStreamRead cursors) addLength
          , originalRead   = displace (advance (originalRead cursors) addLength) seekDelta
          , outputWrite    = advance (outputWrite cursors) addLength
          }

        -- | Cursor transition after an instruction's COPY region.
        -- Each output byte consumes one byte of the extra stream.
        advanceForCopy :: Length -> BSDiffApply ()
        advanceForCopy copyLength = modify $ \cursors -> cursors
          { extraStreamRead = advance (extraStreamRead cursors) copyLength
          , outputWrite     = advance (outputWrite cursors) copyLength
          }

        -- | Materialise one ADD region into the target buffer:
        -- @target[outputPosition+i] = source[originalPosition+i] + diff[diffReadOffset+i]@
        -- for @i@ in @[0, addLength)@.
        -- The source read goes through 'sourceByteOrZero'.
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

        -- | The four cursors live in 'BSDiffApply' state, so each step needs only the remaining instructions and the running action index.
        -- End-of-stream checks whether the target buffer was filled, raising 'ApplyTargetUnderfilled' otherwise.
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

-- | Read a byte at @index@ from the source ByteString, returning 0 for out-of-bounds indices (negative or past the end).
--
-- This is the bsdiff matching-window extension rule.
-- An ADD region forms @new[i] = old[oldpos+i] + diff[i]@; for a position past either end of the source, @old@ contributes 0,
-- so a diff byte holding the target byte verbatim reconstructs that target byte.
-- This lets one ADD region cover bytes whose source position falls outside @[0, sourceLength)@.
--
-- The extension-zero semantics are the source side only.
-- The diff stream is bounds-checked per-instruction and overflow raises 'ApplyDiffReadOutOfBounds'.
sourceByteOrZero :: ByteString -> Int -> Word8
sourceByteOrZero bytes index
  | index >= 0 && index < ByteString.length bytes =
      ByteString.index bytes index
  | otherwise = 0
