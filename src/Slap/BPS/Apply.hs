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
                     SignedOffset(..), ActionIndex(..),
                     SignedOffsetSign(..),
                     ReadOffset(..), WritePosition(..),
                     RequestedLength(..), RemainingLength(..),
                     ActualSize(..), ExpectedSize(..),
                     Cursor(..), examineSignedOffset, fitsWithin,
                     remainingFromOffset,
                     firstAction, nextAction, plusOffset)

import Control.Monad (unless)
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.ByteString.Internal (create)
import Data.IORef (newIORef, readIORef, writeIORef)
import qualified Data.Vector as Vector
import Data.Word (Word8)
import Foreign.Marshal.Utils (fillBytes)
import Foreign.Storable (peekByteOff, pokeByteOff)
import System.IO.Unsafe (unsafePerformIO)

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
classifyTargetCopy :: Offset -> Offset -> Length -> TargetCopyStrategy
classifyTargetCopy readStart writePos copyLength
  | readEnd <= writePos                         = TargetCopyNonOverlapping
  | unOffset readStart == unOffset writePos - 1 = TargetCopySingleByteRun
  | otherwise                                   = TargetCopyGeneralOverlap
  where
    readEnd = advance readStart copyLength

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
applyBPS :: BPSPatch -> ByteString -> Either SlapError ByteString
applyBPS patch source
  | unFileSize targetSize < 0 =
      Left (NegativeTargetSize LabelBPS targetSize)
  | unFileSize targetSize == 0 =
      Right ByteString.empty
  | otherwise = unsafePerformIO $ do
      errorRef <- newIORef Nothing
      result <- create (unFileSize targetSize) $ \outputPointer ->
        runApply outputPointer errorRef
      errorState <- readIORef errorRef
      pure $ case errorState of
        Just applyErr -> Left (ApplyFailed LabelBPS applyErr)
        Nothing       -> Right result
  where
    targetSize      = bpsTargetSize patch
    sourceSize      = FileSize (ByteString.length source)
    actions         = bpsActions patch
    actionStreamEnd = ActionIndex (Vector.length actions)

    runApply outputPointer errorRef =
      let
        actionAt index =
          Vector.unsafeIndex actions (unActionIndex index)

        abort :: ApplyError -> IO ()
        abort applyErr = writeIORef errorRef (Just applyErr)

        generalOverlapLoop :: Offset -> Offset -> Length -> IO ()
        generalOverlapLoop readStart writePos copyLength =
          let readBase   = plusOffset outputPointer readStart
              writeBase  = plusOffset outputPointer writePos
              totalBytes = unLength copyLength
              loop !byteOffset
                | byteOffset >= totalBytes = pure ()
                | otherwise = do
                    byte <- peekByteOff readBase byteOffset :: IO Word8
                    pokeByteOff writeBase byteOffset byte
                    loop (byteOffset + 1)
          in loop 0

        applyActionStream
          :: ActionIndex -> Offset -> SignedOffset -> SignedOffset -> IO ()
        applyActionStream !actionIndex !outputPosition !sourceRelative !targetRelative
          | actionIndex >= actionStreamEnd =
              -- End of action stream: verify we wrote the full target.
              -- Note: no corresponding over-filled check because
              -- ApplyWritesPastTarget catches over-writes per-action
              -- before they can happen, so outputPosition > targetSize
              -- is unreachable here.
              unless (unOffset outputPosition == unFileSize targetSize) $
                let actualWritten = ActualSize (FileSize (unOffset outputPosition))
                    expected = ExpectedSize targetSize
                in abort (ApplyTargetUnderfilled actualWritten expected)
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
            remaining = remainingFromOffset outputPosition targetSize

            recurse newOutput newSource newTarget =
              applyActionStream
                (nextAction actionIndex) newOutput newSource newTarget

            handleSourceRead actionLength
              | not (fitsWithin outputPosition actionLength targetSize) =
                  abort (ApplyWritesPastTarget actionIndex
                          (RequestedLength actionLength)
                          (RemainingLength remaining))
              | not (fitsWithin outputPosition actionLength sourceSize) =
                  abort (ApplySourceReadOutOfBounds actionIndex
                          (advance outputPosition actionLength) sourceSize)
              | otherwise = do
                  copyRegion outputPointer outputPosition
                             source outputPosition actionLength
                  recurse (advance outputPosition actionLength)
                          sourceRelative targetRelative

            handleTargetRead payload =
              let payloadLength = Length (ByteString.length payload)
              in if not (fitsWithin outputPosition payloadLength targetSize)
                   then abort (ApplyWritesPastTarget actionIndex
                                (RequestedLength payloadLength)
                                (RemainingLength remaining))
                   else do
                     copyRegion outputPointer outputPosition
                                payload (Offset 0) payloadLength
                     recurse (advance outputPosition payloadLength)
                             sourceRelative targetRelative

            handleSourceCopy actionLength actionDelta =
              let nextSourceRelative = displace sourceRelative actionDelta
              in if not (fitsWithin outputPosition actionLength targetSize)
                   then abort (ApplyWritesPastTarget actionIndex
                                (RequestedLength actionLength)
                                (RemainingLength remaining))
                   else case examineSignedOffset nextSourceRelative of
                     NegativeCursor negativeCursor ->
                       abort (ApplyCursorUnderflow SourceCursor
                               actionIndex negativeCursor)
                     NonNegativeCursor safeSourceStart ->
                       if not (fitsWithin safeSourceStart actionLength sourceSize)
                         then abort (ApplySourceReadOutOfBounds actionIndex
                                      (advance safeSourceStart actionLength)
                                      sourceSize)
                         else do
                           copyRegion outputPointer outputPosition
                                      source safeSourceStart actionLength
                           recurse (advance outputPosition actionLength)
                                   (advance nextSourceRelative actionLength)
                                   targetRelative

            handleTargetCopy actionLength actionDelta =
              let nextTargetRelative = displace targetRelative actionDelta
              in if not (fitsWithin outputPosition actionLength targetSize)
                   then abort (ApplyWritesPastTarget actionIndex
                                (RequestedLength actionLength)
                                (RemainingLength remaining))
                   else case examineSignedOffset nextTargetRelative of
                     NegativeCursor negativeCursor ->
                       abort (ApplyCursorUnderflow TargetCursor
                               actionIndex negativeCursor)
                     NonNegativeCursor readStart ->
                       if readStart >= outputPosition
                         then abort (ApplyTargetReadUnwritten actionIndex
                                      (ReadOffset readStart)
                                      (WritePosition outputPosition))
                         else do
                           executeTargetCopy readStart actionLength
                           recurse (advance outputPosition actionLength)
                                   sourceRelative
                                   (advance nextTargetRelative actionLength)

            executeTargetCopy readStart copyLength =
              case classifyTargetCopy readStart outputPosition copyLength of
                TargetCopyNonOverlapping ->
                  copyInPlace outputPointer readStart outputPosition copyLength
                TargetCopySingleByteRun -> do
                  byte <- peekByteOff outputPointer
                                      (unOffset outputPosition - 1) :: IO Word8
                  fillBytes (plusOffset outputPointer outputPosition)
                            byte (unLength copyLength)
                TargetCopyGeneralOverlap ->
                  generalOverlapLoop readStart outputPosition copyLength

      in applyActionStream firstAction (Offset 0) (SignedOffset 0) (SignedOffset 0)
