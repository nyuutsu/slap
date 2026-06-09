-- | Apply a parsed VCDIFF patch to a source file, producing the target.
--
-- The patch arrives already validated by 'Slap.VCDIFF.Parse': the three
-- core invariants hold, so every instruction is in-bounds against the
-- superstring by construction. The only checks left are the ones parse
-- could not make without the source — that a window's source segment
-- actually lies within the source (or, for a target-sourced window,
-- within the target produced so far).
--
-- The target is the windows' outputs concatenated. Each window builds
-- its output @T@ by executing its instructions over the superstring
-- @U = S + T@: ADD appends literal bytes, RUN repeats one byte, and
-- COPY reads from @U@ — either a bulk read from the source segment, or
-- a self-copy within the produced target that runs byte by byte
-- forward so a read trailing the write expands correctly (the
-- run-length case). Shape and buffer handling mirror 'Slap.BPS.Apply'.
module Slap.VCDIFF.Apply
  ( applyVCDIFF
  ) where

import Slap.VCDIFF.Types
  ( VCDIFFPatch(..), Window(..), VCDIFFInstruction(..)
  , SourceSegment(..), SegmentOrigin(..), xdelta3WindowBody )
import Slap.Binary (copyRegion, copyInPlace, fillNewBuffer)
import Slap.Status (SlapError(..), ApplyError(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.FileContents (InputFileContents(..), OutputFileContents(..))
import Slap.Measure
  ( Offset(..), Length(..), FileSize(..)
  , ReadOffset(..), WritePosition(..)
  , actionAtPosition, byteFileSize, byteLength, plusOffset )

import qualified Data.ByteString as ByteString
import qualified Data.Vector as Vector
import Data.Word (Word8)
import Foreign.Marshal.Utils (fillBytes)
import Foreign.Ptr (Ptr)
import Foreign.Storable (peekByteOff, pokeByteOff)
import System.IO.Unsafe (unsafePerformIO)

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

    -- | Walk the windows, writing each at its base offset in the output
    -- buffer. Each window's source segment is validated against the
    -- bytes it claims before its instructions run; a bad segment is the
    -- only failure apply can surface.
    runApply :: Ptr Word8 -> IO (Maybe ApplyError)
    runApply outputPointer = walkWindows 0 0 (Vector.toList windows)
      where
        walkWindows _ _ [] = pure Nothing
        walkWindows windowBase windowIndex (window : rest) =
          case checkSourceSegment windowBase windowIndex window of
            Just segmentError -> pure (Just segmentError)
            Nothing -> do
              executeWindow outputPointer windowBase window
              walkWindows (windowBase + unFileSize (windowTargetSize window))
                          (windowIndex + 1)
                          rest

    -- | A window's source segment must lie within the bytes it draws
    -- from: the source file, or — for a target-sourced window — the
    -- target produced by earlier windows (everything before this
    -- window's base).
    checkSourceSegment :: Int -> Int -> Window -> Maybe ApplyError
    checkSourceSegment windowBase windowIndex window =
      case windowSourceSegment window of
        Nothing -> Nothing
        Just (SourceSegment origin (Offset position) (Length len)) -> case origin of
          FromSourceFile
            | position + len <= unFileSize sourceSize -> Nothing
            | otherwise -> Just (ApplySourceReadOutOfBounds
                                   (actionAtPosition windowIndex)
                                   (Offset (position + len))
                                   sourceSize)
          FromProducedTarget
            | position + len <= windowBase -> Nothing
            | otherwise -> Just (ApplyTargetReadUnwritten
                                   (actionAtPosition windowIndex)
                                   (ReadOffset (Offset (position + len)))
                                   (WritePosition (Offset windowBase)))

    -- | Execute one window's instructions, writing into the output
    -- buffer starting at @windowBase@. The within-window cursor is the
    -- bytes produced so far; @windowBase + cursor@ is the absolute
    -- write position.
    executeWindow :: Ptr Word8 -> Int -> Window -> IO ()
    executeWindow outputPointer windowBase window =
      walkInstructions 0 (Vector.toList (windowInstructions window))
      where
        (segmentOrigin, segmentPosition, segmentLength) =
          case windowSourceSegment window of
            Nothing -> (FromSourceFile, 0, 0)
            Just (SourceSegment origin (Offset position) (Length len)) ->
              (origin, position, len)

        walkInstructions _ [] = pure ()
        walkInstructions cursor (instruction : rest) = do
          produced <- runInstruction cursor instruction
          walkInstructions (cursor + produced) rest

        runInstruction :: Int -> VCDIFFInstruction -> IO Int
        runInstruction cursor instruction =
          let writePosition = windowBase + cursor
          in case instruction of
               Add literal -> do
                 copyRegion outputPointer (Offset writePosition)
                            literal (Offset 0) (byteLength literal)
                 pure (ByteString.length literal)
               Run (Length count) fillByte -> do
                 fillBytes (plusOffset outputPointer (Offset writePosition)) fillByte count
                 pure count
               Copy (Length count) (Offset address)
                 | address + count <= segmentLength ->
                     -- Entirely within the source segment: one bulk copy.
                     case segmentOrigin of
                       FromSourceFile -> do
                         copyRegion outputPointer (Offset writePosition)
                                    source (Offset (segmentPosition + address)) (Length count)
                         pure count
                       FromProducedTarget -> do
                         copyInPlace outputPointer
                                     (Offset (segmentPosition + address))
                                     (Offset writePosition) (Length count)
                         pure count
                 | otherwise -> do
                     -- Entirely within the produced target (the source
                     -- segment is exhausted; invariant 2 rules out a copy
                     -- that crosses the boundary). Self-copy semantics.
                     let readPosition = windowBase + (address - segmentLength)
                     copyWithinTarget outputPointer readPosition writePosition count
                     pure count

-- | A copy whose read region lies within the already-produced target.
-- The read start is strictly before the write start (guaranteed by
-- core invariant 1), so three cases cover it: a clean memmove when the
-- read ends at or before the write begins; a single-byte fill when the
-- read is the one byte just behind the write (run-length expansion of
-- one byte); and a forward byte-by-byte loop otherwise, where each
-- freshly written byte feeds the same copy.
copyWithinTarget :: Ptr Word8 -> Int -> Int -> Int -> IO ()
copyWithinTarget outputPointer readStart writeStart count
  | readStart + count <= writeStart =
      copyInPlace outputPointer (Offset readStart) (Offset writeStart) (Length count)
  | writeStart - readStart == 1 = do
      repeatedByte <- peekByteOff (plusOffset outputPointer (Offset readStart)) 0 :: IO Word8
      fillBytes (plusOffset outputPointer (Offset writeStart)) repeatedByte count
  | otherwise = expandForward 0
  where
    readBase  = plusOffset outputPointer (Offset readStart)
    writeBase = plusOffset outputPointer (Offset writeStart)
    expandForward byteIndex
      | byteIndex >= count = pure ()
      | otherwise = do
          byte <- peekByteOff readBase byteIndex :: IO Word8
          pokeByteOff writeBase byteIndex byte
          expandForward (byteIndex + 1)
