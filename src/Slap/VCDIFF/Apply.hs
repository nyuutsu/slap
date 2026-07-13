-- | Parse has already checked the three core invariants, so the only checks left here are the ones that need the source:
-- each window's source segment must lie within the source file, or within the target produced so far.
module Slap.VCDIFF.Apply
  ( applyVCDIFF
    -- * COPY resolution (exported for testing)
  , CopyRead(..)
  , TargetExpansion(..)
  , WindowWriteContext(..)
  , resolveCopyAddress
  ) where

import Slap.VCDIFF.Types
  ( VCDIFFPatch(..), Window(..), VCDIFFInstruction(..)
  , SourceSegment(..), SegmentOrigin(..), windowOutputLength
  , xdelta3WindowBody )
import Slap.Binary (copyRegion, copyInPlace, fillNewBuffer)
import Slap.Status (SlapError(..), ApplyError(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.FileContents (InputFileContents(..), OutputFileContents(..))
import Slap.Measure
  (lengthToInt,  Offset(..), Length(..), FileSize(..)
  , ReadOffset(..), WritePosition(..)
  , ActionIndex, firstAction, nextAction
  , Cursor(..), fitsWithin, offsetToFileSize
  , byteFileSize, byteLength, plusOffset )

import qualified Data.ByteString as ByteString
import qualified Data.Vector as Vector
import Data.Word (Word8)
import Foreign.Marshal.Utils (fillBytes)
import Foreign.Ptr (Ptr)
import Foreign.Storable (peekByteOff, pokeByteOff)
import System.IO.Unsafe (unsafePerformIO)

----------------------------------------------------------------------------
-- COPY resolution
----------------------------------------------------------------------------

-- | 'resolveCopyAddress' needs the base to place reads of the window's own output, and the head to spot an overrun.
data WindowWriteContext = WindowWriteContext
  { windowOutputBase    :: !WritePosition
  , windowProducedSoFar :: !Length
  }
  deriving (Eq, Show)

-- | Where a COPY's bytes physically live, resolved against the superstring @U@.
data CopyRead
  = CopyFromSource !ReadOffset !Length
  | CopyFromTarget !ReadOffset !Length
  | ExpandFromTarget !ReadOffset !Length !TargetExpansion
    -- ^ The read overruns the write head: VCDIFF's run-length back-reference, where bytes written now feed the rest of the read.
  deriving (Eq, Show)

data TargetExpansion
  = ExpandByteRun
    -- ^ Correct only when the read is exactly one byte behind the head; 'resolveCopyAddress' guarantees that distance, the types do not.
  | ExpandForward
  deriving (Eq, Show)

-- | The downstream half of Parse's 'decodeCopyAddress': decode produces one absolute @U@ offset, this turns it into a physical read.
-- Assumes parse's core invariants hold and 'checkSourceSegment' has accepted the window:
-- a COPY reading past the head or across the segment boundary resolves to garbage here.
resolveCopyAddress
  :: Maybe SourceSegment
  -> WindowWriteContext
  -> Length
  -> Offset                -- ^ the COPY's decoded superstring address
  -> CopyRead
resolveCopyAddress maybeSegment writeContext copyLength copyAddress =
  case maybeSegment of
    Nothing -> readOwnOutput mempty
    Just (SourceSegment origin (Offset segmentPosition) segmentLength)
      | address < unLength segmentLength ->
          let segmentRead = ReadOffset (Offset (segmentPosition + address))
          in case origin of
               FromSourceFile     -> CopyFromSource segmentRead copyLength
               FromProducedTarget -> CopyFromTarget segmentRead copyLength
      | otherwise -> readOwnOutput segmentLength
  where
    address    = unOffset copyAddress
    count      = unLength copyLength
    windowBase = unOffset (unWritePosition (windowOutputBase writeContext))
    writeHead  = windowBase + unLength (windowProducedSoFar writeContext)

    readOwnOutput :: Length -> CopyRead
    readOwnOutput contributedBySource
      | readStart + count <= writeHead = CopyFromTarget ownRead copyLength
      | writeHead - readStart == 1     = ExpandFromTarget ownRead copyLength ExpandByteRun
      | otherwise                      = ExpandFromTarget ownRead copyLength ExpandForward
      where
        readStart = windowBase + (address - unLength contributedBySource)
        ownRead   = ReadOffset (Offset readStart)

----------------------------------------------------------------------------
-- applyVCDIFF
----------------------------------------------------------------------------

applyVCDIFF :: VCDIFFPatch -> InputFileContents -> Either SlapError OutputFileContents
applyVCDIFF patch (InputFileContents source)
  | unFileSize totalTargetSize == 0 =
      Right (OutputFileContents ByteString.empty)
  | otherwise = unsafePerformIO $ do
      (result, maybeError) <- fillNewBuffer totalTargetSize runApply
      pure $ case maybeError of
        Just applyError -> Left (ApplyFailed LabelVCDIFF applyError)
        Nothing         -> Right (OutputFileContents result)
  where
    windows = case patch of
      PatchCoreOnly windowVector        -> windowVector
      PatchRFC      _ windowVector      -> windowVector
      PatchXDelta3  _ xdelta3Windows    -> fmap xdelta3WindowBody xdelta3Windows

    sourceSize      = byteFileSize source
    totalTargetSize =
      FileSize (Vector.sum (Vector.map (unFileSize . windowTargetSize) windows))

    -- | The source-segment check is the only thing apply can reject.
    runApply :: Ptr Word8 -> IO (Maybe ApplyError)
    runApply outputPointer =
        walkWindows (WritePosition (Offset 0)) firstAction (Vector.toList windows)
      where
        walkWindows :: WritePosition -> ActionIndex -> [Window] -> IO (Maybe ApplyError)
        walkWindows _ _ [] = pure Nothing
        walkWindows windowBase windowIndex (window : rest) =
          case checkSourceSegment windowBase windowIndex window of
            Just segmentError -> pure (Just segmentError)
            Nothing -> do
              executeWindow outputPointer windowBase window
              walkWindows (advance windowBase (windowOutputLength window))
                          (nextAction windowIndex)
                          rest

    settledBeforeWindow :: WritePosition -> FileSize
    settledBeforeWindow (WritePosition base) = offsetToFileSize base

    -- | A source segment must lie within what it draws from: the source file,
    -- or for a target-backed window the target produced by earlier windows (everything before this window's base).
    checkSourceSegment :: WritePosition -> ActionIndex -> Window -> Maybe ApplyError
    checkSourceSegment windowBase windowIndex window =
      case windowSourceSegment window of
        Nothing -> Nothing
        Just (SourceSegment origin position segmentLength) -> case origin of
          FromSourceFile
            | fitsWithin position segmentLength sourceSize -> Nothing
            | otherwise -> Just (ApplySourceReadOutOfBounds
                                   windowIndex
                                   (advance position segmentLength)
                                   sourceSize)
          FromProducedTarget
            | fitsWithin position segmentLength (settledBeforeWindow windowBase) -> Nothing
            | otherwise -> Just (ApplyTargetReadUnwritten
                                   windowIndex
                                   (ReadOffset (advance position segmentLength))
                                   windowBase)

    executeWindow :: Ptr Word8 -> WritePosition -> Window -> IO ()
    executeWindow outputPointer windowBase window =
      walkInstructions mempty (Vector.toList (windowInstructions window))
      where
        maybeSegment = windowSourceSegment window

        walkInstructions :: Length -> [VCDIFFInstruction] -> IO ()
        walkInstructions _ [] = pure ()
        walkInstructions produced (instruction : rest) = do
          producedHere <- runInstruction produced instruction
          walkInstructions (produced <> producedHere) rest

        runInstruction :: Length -> VCDIFFInstruction -> IO Length
        runInstruction produced instruction =
          let writeHead = advance windowBase produced
          in case instruction of
               Add literal -> do
                 copyRegion outputPointer (unWritePosition writeHead)
                            literal (Offset 0) (byteLength literal)
                 pure (byteLength literal)
               Run count fillByte -> do
                 fillBytes (plusOffset outputPointer (unWritePosition writeHead))
                           fillByte (lengthToInt count)
                 pure count
               Copy count address -> do
                 executeCopyRead writeHead
                   (resolveCopyAddress maybeSegment
                      (WindowWriteContext windowBase produced)
                      count
                      address)
                 pure count

        executeCopyRead :: WritePosition -> CopyRead -> IO ()
        executeCopyRead writeHead copyRead = case copyRead of
          CopyFromSource (ReadOffset sourceStart) count ->
            copyRegion outputPointer (unWritePosition writeHead)
                       source sourceStart count
          CopyFromTarget (ReadOffset readStart) count ->
            copyInPlace outputPointer readStart (unWritePosition writeHead) count
          ExpandFromTarget (ReadOffset readStart) count ExpandByteRun -> do
            repeatedByte <- peekByteOff (plusOffset outputPointer readStart) 0 :: IO Word8
            fillBytes (plusOffset outputPointer (unWritePosition writeHead))
                      repeatedByte (lengthToInt count)
          ExpandFromTarget (ReadOffset readStart) count ExpandForward ->
            expandForward readStart writeHead count

        expandForward :: Offset -> WritePosition -> Length -> IO ()
        expandForward readStart writeHead count = copyByteByByte 0
          where
            readBase   = plusOffset outputPointer readStart
            writeBase  = plusOffset outputPointer (unWritePosition writeHead)
            totalBytes = lengthToInt count
            copyByteByByte !byteIndex
              | byteIndex >= totalBytes = pure ()
              | otherwise = do
                  byte <- peekByteOff readBase byteIndex :: IO Word8
                  pokeByteOff writeBase byteIndex byte
                  copyByteByByte (byteIndex + 1)
