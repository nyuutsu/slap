module Slap.BPS.Apply
  ( applyBPS
  , TargetCopyStrategy(..)
  , classifyTargetCopy
  ) where

import Slap.BPS.Types (BPSPatch(..), BPSAction(..))
import Slap.Binary (copyRegion, copyInPlace)
import Slap.Error (SlapError(..), ApplyError(..), CursorKind(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.Measure (Offset(..), Length(..), FileSize(..),
                     SignedOffset(..), ActionIndex(unActionIndex),
                     SignedOffsetSign(..),
                     ReadOffset(..), WritePosition(..),
                     RequestedLength(..), RemainingLength(..),
                     ExpectedSize(..),
                     Cursor(..), distance, examineSignedOffset, fitsWithin,
                     remainingFromOffset, byteFileSize,
                     firstAction, nextAction, streamEndIndex, plusOffset)
import Slap.FileContents (InputFileContents(..), OutputFileContents(..))

import qualified Data.ByteString as ByteString
import Data.ByteString.Internal (createAndTrim')
import qualified Data.Vector as Vector
import Data.Word (Word8)
import Foreign.Marshal.Utils (fillBytes)
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
-- Mirrors 'SourceRelativeOffset'; the two are role-distinct so the
-- action-stream walker cannot transpose them at the recursive call.
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

-- | How to execute a 'TargetCopy' action, given its validated
-- source position, the current write position, and the copy length.
-- Classification is a pure function of three typed arguments and
-- can be property-tested in isolation.
data TargetCopyStrategy
  = TargetCopyNonOverlapping
    -- ^ The source range ends at or before the destination begins.
    -- Safe to execute as a single 'copyInPlace' ('memmove') call.
  | TargetCopySingleByteRun
    -- ^ The source is a single byte immediately before the
    -- destination (@readStart == writePos - 1@). Every iteration
    -- reads the same byte, so this is byte run-length encoding —
    -- execute as a single 'peekByteOff' + 'fillBytes' ('memset').
  | TargetCopyGeneralOverlap
    -- ^ LZ77-style self-referential overlap. Must be executed as a
    -- byte-by-byte loop because each written byte becomes part of
    -- the source for subsequent iterations.
  deriving (Show, Eq)

-- | Classify a TargetCopy execution strategy. Assumes the caller
-- has already validated that @readStart >= 0@ and
-- @readStart < writePos@ — classification is only meaningful on
-- valid inputs. The strict apply path always validates before
-- classifying.
classifyTargetCopy :: ReadOffset -> WritePosition -> Length -> TargetCopyStrategy
classifyTargetCopy readStart writePos copyLength
  | readEnd <= writePosOffset                                = TargetCopyNonOverlapping
  | distance readStartOffset writePosOffset == Length 1      = TargetCopySingleByteRun
  | otherwise                                                = TargetCopyGeneralOverlap
  where
    readStartOffset = unReadOffset readStart
    readEnd         = advance readStartOffset copyLength
    writePosOffset  = unWritePosition writePos

----------------------------------------------------------------------------
-- applyBPS
----------------------------------------------------------------------------

-- | Apply a parsed BPS patch to a source ByteString. Returns
-- 'Left' with a structured error if the patch's action stream is
-- semantically malformed (negative cursors, out-of-bounds reads,
-- forward reads in TargetCopy, actions that would write past target,
-- or stream exhaustion before the target is filled). The caller is
-- still responsible for validating CRCs before calling this; a
-- 'Left' return here means the action stream is semantically
-- invalid, not that the patch bytes were corrupted.
applyBPS :: BPSPatch -> InputFileContents -> Either SlapError OutputFileContents
applyBPS patch (InputFileContents source)
  | unFileSize targetSize < 0 =
      Left (NegativeTargetSize LabelBPS targetSize)
  | unFileSize targetSize == 0 =
      Right (OutputFileContents ByteString.empty)
  | otherwise = unsafePerformIO $ do
      (result, outcome) <- createAndTrim' (unFileSize targetSize) $ \outputPointer -> do
        maybeErr <- runApply outputPointer
        pure (0, unFileSize targetSize, maybeErr)
      pure $ case outcome of
        Just applyErr -> Left (ApplyFailed LabelBPS applyErr)
        Nothing       -> Right (OutputFileContents result)
  where
    targetSize      = bpsTargetSize patch
    sourceSize      = byteFileSize source
    actions         = bpsActions patch
    actionStreamEnd = streamEndIndex actions

    runApply outputPointer =
      let
        actionAt index =
          Vector.unsafeIndex actions (unActionIndex index)

        generalOverlapLoop :: ReadOffset -> WritePosition -> Length -> IO ()
        generalOverlapLoop readStart writePos copyLength =
          let readBase   = plusOffset outputPointer (unReadOffset readStart)
              writeBase  = plusOffset outputPointer (unWritePosition writePos)
              totalBytes = unLength copyLength
              loop !byteOffset
                | byteOffset >= totalBytes = pure ()
                | otherwise = do
                    byte <- peekByteOff readBase byteOffset :: IO Word8
                    pokeByteOff writeBase byteOffset byte
                    loop (byteOffset + 1)
          in loop 0

        applyActionStream
          :: ActionIndex -> WritePosition -> SourceRelativeOffset -> TargetRelativeOffset
          -> IO (Maybe ApplyError)
        applyActionStream !actionIndex !outputPosition !sourceRelative !targetRelative
          | actionIndex >= actionStreamEnd =
              -- End of action stream: verify we wrote the full target.
              -- Note: no corresponding over-filled check because
              -- ApplyWritesPastTarget catches over-writes per-action
              -- before they can happen, so outputPosition > targetSize
              -- is unreachable here.
              if remainingFromOffset outputOffset targetSize == Length 0
                then pure Nothing
                else pure (Just (ApplyTargetUnderfilled outputPosition (ExpectedSize targetSize)))
          | otherwise = case actionAt actionIndex of
              SourceRead actionLength ->
                handleSourceRead actionLength
              TargetRead payload ->
                handleTargetRead payload
              SourceCopy actionLength actionDelta ->
                handleSourceCopy actionLength actionDelta
              TargetCopy actionLength actionDelta ->
                handleTargetCopy actionLength actionDelta
          where
            outputOffset = unWritePosition outputPosition
            remaining    = remainingFromOffset outputOffset targetSize

            recurse newOutput newSource newTarget =
              applyActionStream
                (nextAction actionIndex) newOutput newSource newTarget

            handleSourceRead actionLength
              | not (fitsWithin outputOffset actionLength targetSize) =
                  pure (Just (ApplyWritesPastTarget actionIndex
                               (RequestedLength actionLength)
                               (RemainingLength remaining)))
              | not (fitsWithin outputOffset actionLength sourceSize) =
                  pure (Just (ApplySourceReadOutOfBounds actionIndex
                               (advance outputOffset actionLength) sourceSize))
              | otherwise = do
                  copyRegion outputPointer outputOffset
                             source outputOffset actionLength
                  recurse (advance outputPosition actionLength)
                          sourceRelative targetRelative

            handleTargetRead payload =
              let payloadLength = Length (ByteString.length payload)
              in if not (fitsWithin outputOffset payloadLength targetSize)
                   then pure (Just (ApplyWritesPastTarget actionIndex
                                     (RequestedLength payloadLength)
                                     (RemainingLength remaining)))
                   else do
                     copyRegion outputPointer outputOffset
                                payload (Offset 0) payloadLength
                     recurse (advance outputPosition payloadLength)
                             sourceRelative targetRelative

            handleSourceCopy actionLength actionDelta =
              let nextSourceRelative = displace sourceRelative actionDelta
              in if not (fitsWithin outputOffset actionLength targetSize)
                   then pure (Just (ApplyWritesPastTarget actionIndex
                                     (RequestedLength actionLength)
                                     (RemainingLength remaining)))
                   else case examineSignedOffset (unSourceRelativeOffset nextSourceRelative) of
                     NegativeCursor negativeCursor ->
                       pure (Just (ApplyCursorUnderflow SourceCursor
                                    actionIndex negativeCursor))
                     NonNegativeCursor safeSourceStart ->
                       if not (fitsWithin safeSourceStart actionLength sourceSize)
                         then pure (Just (ApplySourceReadOutOfBounds actionIndex
                                           (advance safeSourceStart actionLength)
                                           sourceSize))
                         else do
                           copyRegion outputPointer outputOffset
                                      source safeSourceStart actionLength
                           recurse (advance outputPosition actionLength)
                                   (advance nextSourceRelative actionLength)
                                   targetRelative

            handleTargetCopy actionLength actionDelta =
              let nextTargetRelative = displace targetRelative actionDelta
              in if not (fitsWithin outputOffset actionLength targetSize)
                   then pure (Just (ApplyWritesPastTarget actionIndex
                                     (RequestedLength actionLength)
                                     (RemainingLength remaining)))
                   else case examineSignedOffset (unTargetRelativeOffset nextTargetRelative) of
                     NegativeCursor negativeCursor ->
                       pure (Just (ApplyCursorUnderflow TargetCursor
                                    actionIndex negativeCursor))
                     NonNegativeCursor readStartOffset ->
                       if readStartOffset >= outputOffset
                         then pure (Just (ApplyTargetReadUnwritten actionIndex
                                           (ReadOffset readStartOffset)
                                           outputPosition))
                         else do
                           executeTargetCopy (ReadOffset readStartOffset) actionLength
                           recurse (advance outputPosition actionLength)
                                   sourceRelative
                                   (advance nextTargetRelative actionLength)

            executeTargetCopy readStart copyLength =
              case classifyTargetCopy readStart outputPosition copyLength of
                TargetCopyNonOverlapping ->
                  copyInPlace outputPointer (unReadOffset readStart) outputOffset copyLength
                TargetCopySingleByteRun -> do
                  byte <- peekByteOff outputPointer
                                      (unOffset outputOffset - 1) :: IO Word8
                  fillBytes (plusOffset outputPointer outputOffset)
                            byte (unLength copyLength)
                TargetCopyGeneralOverlap ->
                  generalOverlapLoop readStart outputPosition copyLength

      in applyActionStream firstAction
                           (WritePosition (Offset 0))
                           (SourceRelativeOffset (SignedOffset 0))
                           (TargetRelativeOffset (SignedOffset 0))
