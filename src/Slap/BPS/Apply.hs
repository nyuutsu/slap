module Slap.BPS.Apply
  ( applyBPS
  , TargetCopyStrategy(..)
  , classifyTargetCopy
  ) where

import Slap.BPS.Types (BPSPatch(..), BPSAction(..))
import Slap.Binary (copyRegion, copyInPlace, fillRegion, fillNewBuffer)
import Slap.Status (SlapError(..), ApplyError(..), CursorKind(..), addressableByteCount)
import Slap.FormatLabel (FormatLabel(..))
import Slap.Measure (Offset(..), Length(..), FileSize(..),
                     SignedOffset(..), Delta, ActionIndex(unActionIndex),
                     SignedOffsetSign(..),
                     ReadOffset(..), WritePosition(..),
                     RequestedLength(..), RemainingLength(..),
                     ExpectedSize(..),
                     Cursor(..), distance, examineSignedOffset, fitsWithin,
                     remainingFromOffset, byteFileSize, byteLength,
                     firstAction, nextAction, streamEndIndex, plusOffset)
import Slap.FileContents (InputFileContents(..), OutputFileContents(..))

import Control.Monad.IO.Class (liftIO)
import Control.Monad.Trans.State.Strict (StateT, evalStateT, gets, modify)
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.Vector as Vector
import Data.Word (Word8)
import Foreign.Storable (peekByteOff, pokeByteOff)
import System.IO.Unsafe (unsafePerformIO)

----------------------------------------------------------------------------
-- BPS-specific cursor newtypes
----------------------------------------------------------------------------

-- | A relative-displacement cursor for BPS's @SourceCopy@ action.
-- Carried as 'SignedOffset' because BPS's @actionDelta@ can take it
-- negative; the negative case is detected at the read site via
-- 'examineSignedOffset' and produces 'ApplyCursorUnderflow'. Distinct
-- from 'TargetRelativeOffset' so the action-stream walker cannot
-- transpose the two at the recursive call.
newtype SourceRelativeOffset = SourceRelativeOffset
  { unSourceRelativeOffset :: SignedOffset
  } deriving (Eq, Ord, Show)

-- | A relative-displacement cursor for BPS's @TargetCopy@ action.
-- Mirrors 'SourceRelativeOffset'.
newtype TargetRelativeOffset = TargetRelativeOffset
  { unTargetRelativeOffset :: SignedOffset
  } deriving (Eq, Ord, Show)

instance Cursor SourceRelativeOffset where
  advance  (SourceRelativeOffset position) stride = SourceRelativeOffset (advance  position stride)
  displace (SourceRelativeOffset position) delta  = SourceRelativeOffset (displace position delta)

instance Cursor TargetRelativeOffset where
  advance  (TargetRelativeOffset position) stride = TargetRelativeOffset (advance  position stride)
  displace (TargetRelativeOffset position) delta  = TargetRelativeOffset (displace position delta)

----------------------------------------------------------------------------
-- TargetCopy classification
----------------------------------------------------------------------------

-- | How to execute a 'TargetCopy' action.
data TargetCopyStrategy
  = TargetCopyNonOverlapping
    -- ^ The source range ends at or before the destination begins.
    -- Safe to execute as a single 'copyInPlace' ('memmove') call.
  | TargetCopySingleByteRun
    -- ^ The source is a single byte immediately before the
    -- destination (@readStart == writePosition - 1@). Every iteration
    -- reads the same byte, so this is byte run-length encoding —
    -- execute as a single 'peekByteOff' + 'fillRegion' ('memset').
  | TargetCopyGeneralOverlap
    -- ^ LZ77-style self-referential overlap. Must be executed as a
    -- byte-by-byte loop because each written byte becomes part of
    -- the source for subsequent iterations.
  deriving (Show, Eq)

-- | Classify a TargetCopy's execution strategy.
-- Assumes the caller has already validated @readStart >= 0@ and @readStart < writePosition@;
-- the strict apply path always validates before classifying.
classifyTargetCopy :: ReadOffset -> WritePosition -> Length -> TargetCopyStrategy
classifyTargetCopy readStart writePosition copyLength
  | readEnd <= outputOffset                                  = TargetCopyNonOverlapping
  | distance readStartOffset outputOffset == Length 1        = TargetCopySingleByteRun
  | otherwise                                                = TargetCopyGeneralOverlap
  where
    readStartOffset = unReadOffset readStart
    readEnd         = advance readStartOffset copyLength
    outputOffset    = unWritePosition writePosition

----------------------------------------------------------------------------
-- applyBPS
----------------------------------------------------------------------------

bpsActionOutputLength :: BPSAction -> Length
bpsActionOutputLength (SourceRead actionLength)   = actionLength
bpsActionOutputLength (TargetRead payload)        = byteLength payload
bpsActionOutputLength (SourceCopy actionLength _) = actionLength
bpsActionOutputLength (TargetCopy actionLength _) = actionLength

-- | Returns 'Left' with a structured error if the patch's action stream is semantically malformed:
-- negative cursors, out-of-bounds reads, forward reads in TargetCopy, writes past target, or stream exhaustion before the target is filled.
-- The caller is still responsible for validating CRCs before calling;
-- a 'Left' here means the action stream is invalid, not that the patch bytes were corrupted.
applyBPS :: BPSPatch -> InputFileContents -> Either SlapError OutputFileContents
applyBPS patch (InputFileContents source)
  -- A zero-size target is coherent only with no actions; with actions, the walk below refuses each write past the empty buffer.
  | unFileSize targetSize == 0 && null actions =
      Right (OutputFileContents ByteString.empty)
  | actionsOutputReach < declaredTarget =
      Left (ApplyFailed LabelBPS
             (ApplyTargetUnderfilled (WritePosition (Offset actionsOutputReach)) (ExpectedSize targetSize)))
  | otherwise = case addressableByteCount LabelBPS targetSize of
      Left refusal          -> Left refusal
      Right addressableSize -> unsafePerformIO $ do
        (result, maybeErr) <- fillNewBuffer addressableSize runApply
        pure $ case maybeErr of
          Just applyErr -> Left (ApplyFailed LabelBPS applyErr)
          Nothing       -> Right (OutputFileContents result)
  where
    targetSize      = bpsTargetSize patch
    sourceSize      = byteFileSize source
    actions         = bpsActions patch
    actionStreamEnd = streamEndIndex actions

    -- The actions tile the target in order, so their lengths sum to where the walk would end.
    -- Summing here, capped at the declared size, catches a target declared past what its actions fill,
    -- before 'fillNewBuffer' would allocate that whole declared size and abort.
    declaredTarget     = unFileSize targetSize
    actionsOutputReach = Vector.foldl' addCappedOutput 0 actions
    addCappedOutput reached action
      | reached    >= declaredTarget            = declaredTarget
      | contributed >= declaredTarget - reached = declaredTarget
      | otherwise                               = reached + contributed
      where contributed = unLength (bpsActionOutputLength action)

    -- | Per-action guards for 'SourceRead': the write must fit in
    -- the remaining target buffer, and the parallel source read
    -- (at the same offset) must fit in the source ROM.
    checkSourceReadPreconditions :: ActionIndex -> Length -> Offset
                                 -> Either ApplyError ()
    checkSourceReadPreconditions actionIndex actionLength outputOffset
      | not (fitsWithin outputOffset actionLength targetSize) =
          Left (ApplyWritesPastTarget actionIndex
                 (RequestedLength actionLength)
                 (RemainingLength (remainingFromOffset outputOffset targetSize)))
      | not (fitsWithin outputOffset actionLength sourceSize) =
          Left (ApplySourceReadOutOfBounds actionIndex
                 (advance outputOffset actionLength) sourceSize)
      | otherwise = Right ()

    -- | Per-action guards for 'SourceCopy': the write must fit in
    -- the remaining target buffer; the post-displace source-relative
    -- cursor must be non-negative; and the source read at that
    -- cursor must fit in the source ROM. The validated source
    -- start is returned to the caller so the copy can use it
    -- without re-extracting it from the sum type.
    checkSourceCopyPreconditions :: ActionIndex -> Length -> SignedOffset -> Offset
                                 -> Either ApplyError Offset
    checkSourceCopyPreconditions actionIndex actionLength nextSourceSigned outputOffset
      | not (fitsWithin outputOffset actionLength targetSize) =
          Left (ApplyWritesPastTarget actionIndex
                 (RequestedLength actionLength)
                 (RemainingLength (remainingFromOffset outputOffset targetSize)))
      | otherwise = case examineSignedOffset nextSourceSigned of
          NegativeCursor negativeCursor ->
            Left (ApplyCursorUnderflow SourceCursor actionIndex negativeCursor)
          NonNegativeCursor safeSourceStart
            | not (fitsWithin safeSourceStart actionLength sourceSize) ->
                Left (ApplySourceReadOutOfBounds actionIndex
                       (advance safeSourceStart actionLength) sourceSize)
            | otherwise -> Right safeSourceStart

    -- | Per-action guards for 'TargetCopy': the write must fit in
    -- the remaining target buffer; the post-displace target-relative
    -- cursor must be non-negative; and the read must point strictly
    -- before the write head (TargetCopy can only re-read bytes that
    -- have already been written). The validated read start is
    -- returned so the caller can pass it to 'executeTargetCopy'.
    checkTargetCopyPreconditions :: ActionIndex -> Length -> SignedOffset -> WritePosition
                                 -> Either ApplyError Offset
    checkTargetCopyPreconditions actionIndex actionLength nextTargetSigned writePosition
      | not (fitsWithin outputOffset actionLength targetSize) =
          Left (ApplyWritesPastTarget actionIndex
                 (RequestedLength actionLength)
                 (RemainingLength (remainingFromOffset outputOffset targetSize)))
      | otherwise = case examineSignedOffset nextTargetSigned of
          NegativeCursor negativeCursor ->
            Left (ApplyCursorUnderflow TargetCursor actionIndex negativeCursor)
          NonNegativeCursor readStartOffset
            | readStartOffset >= outputOffset ->
                Left (ApplyTargetReadUnwritten actionIndex
                       (ReadOffset readStartOffset)
                       writePosition)
            | otherwise -> Right readStartOffset
      where
        outputOffset = unWritePosition writePosition

    runApply outputPointer =
      let
        actionAt index =
          Vector.unsafeIndex actions (unActionIndex index)

        generalOverlapLoop :: ReadOffset -> WritePosition -> Length -> IO ()
        generalOverlapLoop readStart writePosition copyLength =
            copyFromByteOffset 0
          where
            readBase  = plusOffset outputPointer (unReadOffset readStart)
            writeBase = plusOffset outputPointer (unWritePosition writePosition)
            -- The loop cursor stays Int: it is the Storable byte offset for both the peek and the poke.
            copyByteCount = fromIntegral (unLength copyLength)
            copyFromByteOffset !byteOffset
              | byteOffset >= copyByteCount = pure ()
              | otherwise = do
                  copiedByte <- peekByteOff readBase byteOffset :: IO Word8
                  pokeByteOff writeBase byteOffset copiedByte
                  copyFromByteOffset (byteOffset + 1)

        -- | Pure 'IO': takes the write position as an argument and
        -- does not touch 'BPSApply' state. The caller reads the
        -- current write position out of state, passes it here, and
        -- issues the matching state update afterwards.
        executeTargetCopy :: WritePosition -> ReadOffset -> Length -> IO ()
        executeTargetCopy writePosition readStart copyLength =
          let outputOffset = unWritePosition writePosition
          in case classifyTargetCopy readStart writePosition copyLength of
               TargetCopyNonOverlapping ->
                 copyInPlace outputPointer (unReadOffset readStart) outputOffset copyLength
               TargetCopySingleByteRun -> do
                 repeatedByte <- peekByteOff (plusOffset outputPointer outputOffset)
                                             (-1) :: IO Word8
                 fillRegion outputPointer outputOffset repeatedByte copyLength
               TargetCopyGeneralOverlap ->
                 generalOverlapLoop readStart writePosition copyLength

        -- | The cursor transition done by 'SourceRead' and 'TargetRead': those actions move the write head only.
        advanceOutput :: Length -> BPSApply ()
        advanceOutput stride = modify $ \cursors ->
          cursors { outputPosition = advance (outputPosition cursors) stride }

        -- | The cursor transition done by 'SourceCopy': re-base the
        -- source-relative cursor (the caller has already applied
        -- the action's signed delta) and then advance both the
        -- write head and the source-relative cursor by @stride@.
        advanceOutputAndSource :: SourceRelativeOffset -> Length -> BPSApply ()
        advanceOutputAndSource newSourceRelative stride = modify $ \cursors -> cursors
          { outputPosition = advance (outputPosition cursors) stride
          , sourceRelative = advance newSourceRelative stride
          }

        -- | The cursor transition done by 'TargetCopy': re-base the
        -- target-relative cursor (the caller has already applied
        -- the action's signed delta) and then advance both the
        -- write head and the target-relative cursor by @stride@.
        advanceOutputAndTarget :: TargetRelativeOffset -> Length -> BPSApply ()
        advanceOutputAndTarget newTargetRelative stride = modify $ \cursors -> cursors
          { outputPosition = advance (outputPosition cursors) stride
          , targetRelative = advance newTargetRelative stride
          }

        -- | The three cursors live in 'BPSApply' state, so each step needs only the current action index.
        -- End-of-stream verifies that the walker filled the entire target buffer.
        applyActionStream :: ActionIndex -> BPSApply (Maybe ApplyError)
        applyActionStream !actionIndex
          | actionIndex >= actionStreamEnd = do
              -- Over-fill needs no check here: every writing action rejects a past-target write per-action with 'ApplyWritesPastTarget',
              -- so outputPosition > targetSize is unreachable.
              writePosition <- gets outputPosition
              let outputOffset = unWritePosition writePosition
              if remainingFromOffset outputOffset targetSize == Length 0
                then pure Nothing
                else pure (Just (ApplyTargetUnderfilled writePosition (ExpectedSize targetSize)))
          | otherwise = case actionAt actionIndex of
              SourceRead actionLength            -> handleSourceRead actionIndex actionLength
              TargetRead payload                 -> handleTargetRead actionIndex payload
              SourceCopy actionLength actionDelta -> handleSourceCopy actionIndex actionLength actionDelta
              TargetCopy actionLength actionDelta -> handleTargetCopy actionIndex actionLength actionDelta

        handleSourceRead :: ActionIndex -> Length -> BPSApply (Maybe ApplyError)
        handleSourceRead actionIndex actionLength = do
          writePosition <- gets outputPosition
          let outputOffset = unWritePosition writePosition
          case checkSourceReadPreconditions actionIndex actionLength outputOffset of
            Left err -> pure (Just err)
            Right () -> do
              liftIO (copyRegion outputPointer outputOffset
                                 source outputOffset actionLength)
              advanceOutput actionLength
              applyActionStream (nextAction actionIndex)

        handleTargetRead :: ActionIndex -> ByteString -> BPSApply (Maybe ApplyError)
        handleTargetRead actionIndex payload = do
          writePosition <- gets outputPosition
          let outputOffset  = unWritePosition writePosition
              remaining     = remainingFromOffset outputOffset targetSize
              payloadLength = byteLength payload
          if not (fitsWithin outputOffset payloadLength targetSize)
            then pure (Just (ApplyWritesPastTarget actionIndex
                              (RequestedLength payloadLength)
                              (RemainingLength remaining)))
            else do
              liftIO (copyRegion outputPointer outputOffset
                                 payload (Offset 0) payloadLength)
              advanceOutput payloadLength
              applyActionStream (nextAction actionIndex)

        handleSourceCopy :: ActionIndex -> Length -> Delta -> BPSApply (Maybe ApplyError)
        handleSourceCopy actionIndex actionLength actionDelta = do
          writePosition         <- gets outputPosition
          currentSourceRelative <- gets sourceRelative
          let outputOffset       = unWritePosition writePosition
              nextSourceRelative = displace currentSourceRelative actionDelta
          case checkSourceCopyPreconditions actionIndex actionLength
                 (unSourceRelativeOffset nextSourceRelative) outputOffset of
            Left err -> pure (Just err)
            Right safeSourceStart -> do
              liftIO (copyRegion outputPointer outputOffset
                                 source safeSourceStart actionLength)
              advanceOutputAndSource nextSourceRelative actionLength
              applyActionStream (nextAction actionIndex)

        handleTargetCopy :: ActionIndex -> Length -> Delta -> BPSApply (Maybe ApplyError)
        handleTargetCopy actionIndex actionLength actionDelta = do
          writePosition         <- gets outputPosition
          currentTargetRelative <- gets targetRelative
          let nextTargetRelative = displace currentTargetRelative actionDelta
          case checkTargetCopyPreconditions actionIndex actionLength
                 (unTargetRelativeOffset nextTargetRelative) writePosition of
            Left err -> pure (Just err)
            Right readStartOffset -> do
              liftIO (executeTargetCopy writePosition
                                        (ReadOffset readStartOffset)
                                        actionLength)
              advanceOutputAndTarget nextTargetRelative actionLength
              applyActionStream (nextAction actionIndex)

        initialCursors = BPSCursors
          { outputPosition = WritePosition (Offset 0)
          , sourceRelative = SourceRelativeOffset (SignedOffset 0)
          , targetRelative = TargetRelativeOffset (SignedOffset 0)
          }

      in evalStateT (applyActionStream firstAction) initialCursors

----------------------------------------------------------------------------
-- Cursor state
----------------------------------------------------------------------------

-- | The three cursors threaded through the BPS action-stream walk.
-- Bundled into a record so 'BPSApply' can carry them implicitly.
-- Each handler updates only the slots its action class touches.
data BPSCursors = BPSCursors
  { outputPosition :: !WritePosition
  , sourceRelative :: !SourceRelativeOffset
  , targetRelative :: !TargetRelativeOffset
  }

-- | Strict because the cursors update on nearly every action; a lazy thunk build-up would buy nothing.
type BPSApply = StateT BPSCursors IO
