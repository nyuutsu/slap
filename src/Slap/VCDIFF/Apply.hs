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
-- its output @T@ by executing its instructions: ADD appends literal
-- bytes, RUN repeats one byte, and COPY first resolves where its bytes
-- physically live — the source file, or the output buffer — through
-- 'resolveCopyAddress', and then moves them. The superstring
-- @U = S + T@ that COPY addresses index is Parse's vocabulary; by the
-- time bytes move there are only the two stores and one wrinkle, a
-- read that overruns the write head. Shape and buffer handling mirror
-- 'Slap.BPS.Apply'.
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
  ( Offset(..), Length(..), FileSize(..)
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

-- | Where a window's output stands in the buffer: the position its
-- first byte occupies, and how much of it exists so far. The two
-- together fix the write head ('windowOutputBase' advanced by
-- 'windowProducedSoFar'), and 'resolveCopyAddress' needs both — the
-- base to place reads of the window's own output (a COPY's
-- target-side addresses are window-relative), the head for the
-- overrun decision. A record rather than two positional arguments so
-- the produced count can never be transposed with the COPY's length.
data WindowWriteContext = WindowWriteContext
  { windowOutputBase    :: !WritePosition
    -- ^ The write position at which this window's output begins.
  , windowProducedSoFar :: !Length
    -- ^ How much of the window's output exists already.
  }
  deriving (Eq, Show)

-- | Where a COPY's bytes physically live, resolved against the
-- superstring @U = S ++ T@. The address space is Parse's concern; by
-- the time bytes move there are only two stores — the source file and
-- the output buffer — and one wrinkle, a read that overruns the write
-- head. 'resolveCopyAddress' decides this in full before any IO;
-- execution is a total dispatch that only moves bytes.
data CopyRead
  = CopyFromSource !ReadOffset !Length
    -- ^ The address falls in a source-file-backed segment: one bulk
    -- read from the source file.
  | CopyFromTarget !ReadOffset !Length
    -- ^ The address falls in output bytes settled before the write
    -- head: one bulk in-buffer copy. Reached today by a window's
    -- non-overrunning read of its own output; a target-backed source
    -- segment resolves here too, but such windows are refused at
    -- parse ('Slap.Status.VCDIFFTargetWindow') until the RFC arc
    -- lands, so that route is readiness, not reachable code.
  | ExpandFromTarget !ReadOffset !Length !TargetExpansion
    -- ^ The address falls in this window's own output and the read
    -- overruns the write head: VCDIFF's run-length back-reference,
    -- where bytes written now feed the rest of the read.
  deriving (Eq, Show)

-- | How an overrunning COPY expands. Production code obtains this
-- through 'resolveCopyAddress'; the constructors are exported for
-- pattern matching and tests, and constructing 'ExpandByteRun' for a
-- read more than one byte behind the head would compile — the
-- distance fact is a discipline enforced at the construction site,
-- not by the type, the same trade 'Slap.BPS.Apply.TargetCopyStrategy'
-- makes.
data TargetExpansion
  = ExpandByteRun
    -- ^ The read is the single byte just behind the head: that byte,
    -- repeated (a memset).
  | ExpandForward
    -- ^ A forward byte-by-byte expansion; each written byte extends
    -- the read.
  deriving (Eq, Show)

-- | Resolve a COPY against the superstring: which store its bytes
-- live in, at what offset, and whether the read overruns the write
-- head. The downstream half of the pipeline that begins at
-- 'Slap.VCDIFF.Parse.decodeCopyAddress' — decode turns wire address
-- modes into one absolute @U@ offset, and this turns that offset into
-- a physical read. A 'Nothing' segment means the window has no @S@,
-- so every COPY resolves against @T@ alone: the absence is a real
-- case, not a zero-length segment.
--
-- Pure arithmetic over typed inputs, fenced kernel-style like
-- 'Slap.VCDIFF.Parse.decodeCopyAddress'. Assumes the parse-side core
-- invariants (a COPY neither reads at or past the write head nor
-- crosses the segment boundary) and that 'checkSourceSegment' has
-- accepted the window: resolution is only meaningful on valid inputs,
-- the same contract as 'Slap.BPS.Apply.classifyTargetCopy'.
resolveCopyAddress
  :: Maybe SourceSegment   -- ^ the window's source segment, as parsed
  -> WindowWriteContext    -- ^ where the window's output stands
  -> Length                -- ^ the COPY's length
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
    -- The kernel's arithmetic domain is Int; the typed inputs unwrap
    -- once, here.
    address    = unOffset copyAddress
    count      = unLength copyLength
    windowBase = unOffset (unWritePosition (windowOutputBase writeContext))
    writeHead  = windowBase + unLength (windowProducedSoFar writeContext)

    -- | A read of the window's own output: place the window-relative
    -- address absolutely, then classify the read against the head.
    -- The argument is the length @S@ contributes to @U@ — 'mempty'
    -- when the window has no segment.
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

    -- | Walk the windows, writing each at its base position in the
    -- output buffer. Each window's source segment is validated against
    -- the bytes it claims before its instructions run; a bad segment is
    -- the only failure apply can surface.
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

    -- | The settled region of the output: every byte before the
    -- window's base, measured as the whole space a target-backed
    -- segment may address. Total by 'offsetToFileSize''s contract —
    -- the base is one position past the last settled byte.
    settledBeforeWindow :: WritePosition -> FileSize
    settledBeforeWindow (WritePosition base) = offsetToFileSize base

    -- | A window's source segment must lie within the bytes it draws
    -- from: the source file, or — for a target-sourced window — the
    -- target produced by earlier windows (everything before this
    -- window's base).
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

    -- | Execute one window's instructions, writing into the output
    -- buffer from @windowBase@ onward. The within-window state is the
    -- bytes produced so far; the write head is @windowBase@ advanced
    -- by it.
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
                           fillByte (unLength count)
                 pure count
               Copy count address -> do
                 executeCopyRead writeHead
                   (resolveCopyAddress maybeSegment
                      (WindowWriteContext windowBase produced)
                      count
                      address)
                 pure count

        -- | Move the bytes a resolved COPY names. A total dispatch
        -- with no arithmetic: every offset was placed by
        -- 'resolveCopyAddress', and each arm touches the buffer once
        -- (the byte loop of 'ExpandForward' being the operation
        -- itself, not a fallback).
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
                      repeatedByte (unLength count)
          ExpandFromTarget (ReadOffset readStart) count ExpandForward ->
            expandForward readStart writeHead count

        -- | The forward byte-by-byte expansion: each written byte
        -- becomes part of the read for subsequent iterations.
        expandForward :: Offset -> WritePosition -> Length -> IO ()
        expandForward readStart writeHead count = copyByteByByte 0
          where
            readBase   = plusOffset outputPointer readStart
            writeBase  = plusOffset outputPointer (unWritePosition writeHead)
            totalBytes = unLength count
            copyByteByByte !byteIndex
              | byteIndex >= totalBytes = pure ()
              | otherwise = do
                  byte <- peekByteOff readBase byteIndex :: IO Word8
                  pokeByteOff writeBase byteIndex byte
                  copyByteByByte (byteIndex + 1)
