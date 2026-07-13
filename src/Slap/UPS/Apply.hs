module Slap.UPS.Apply
  ( applyUPS
  , undoUPS
  , detectOOBBlocks
  ) where

import Slap.UPS.Types (UPSPatch(..), UPSBlock(..), upsTerminatorByteLength)
import Slap.Status (SlapError(..), SlapAdvisory(..), Outcome(..),
                   OOBBlockCount(..), OOBOvershootBytes(..),
                   ApplyDirection(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.Measure (lengthToInt, offsetToInt, fileSizeToInt, Offset(..), Length(..), FileSize(..),
                     ActionIndex(unActionIndex),
                     Cursor(..), fitsWithin, offsetToFileSize,
                     remainingFromOffset,
                     subtractLength, minLength,
                     byteFileSize, byteLength,
                     firstAction, nextAction,
                     streamEndIndex, actionAtPosition, plusOffset)
import Slap.FileContents (InputFileContents(..), OutputFileContents(..))

import Control.Monad (when)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Trans.State.Strict (StateT, evalStateT, get, modify)
import Data.Bits (xor)
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.ByteString.Internal (create)
import Data.ByteString.Unsafe (unsafeIndex, unsafeUseAsCStringLen)
import qualified Data.Vector as Vector
import Data.Word (Word8)
import Foreign.Marshal.Utils (copyBytes, fillBytes)
import Foreign.Ptr (Ptr, castPtr, plusPtr)
import Foreign.Storable (peekByteOff, pokeByteOff)
import System.IO.Unsafe (unsafePerformIO)

----------------------------------------------------------------------------
-- Placement classifiers
----------------------------------------------------------------------------

-- | Where a UPS block's declared span sits relative to the active
-- output buffer. UPS blocks have a fixed declared stride
-- (@skipLength + xorDataLength + 1@) and the canonical encoder walks a
-- block stream that covers @max sourceSize targetSize@ bytes' worth
-- of output, so the stream can extend past whichever of
-- @source_size@ / @target_size@ the current direction is writing
-- to. The walker ('runUPSXorWalk') is direction-blind — it knows
-- only its own 'outputSize', supplied by 'applyUPS' or 'undoUPS' —
-- and classifies each block against it.
data BlockPlacement
  = BlockFitsWithinOutput
    -- ^ The block's declared span — skip, xor, terminator — lies
    -- entirely within the output buffer. Every sub-operation writes
    -- its declared length; no clipping happens. The common case for
    -- any block whose footprint ends before @output_size@.
  | BlockPartiallyOvershoots !Length
    -- ^ The block starts in bounds but its declared span extends
    -- past the output boundary. The carried 'Length' is the
    -- in-bounds prefix the walker still writes; the remainder
    -- (skip\/xor\/terminator bytes past the boundary) is dropped.
    -- The per-sub-operation clip — how the prefix divides across
    -- skip, xor, terminator — happens at the write site.
    --
    -- Reachable whenever a block straddles the active output
    -- boundary. Some UPS creation tools emit a final block whose
    -- terminator lands at @output_size@ rather than
    -- @output_size - 1@, so its trailing byte clips here. The
    -- quirk is direction-independent — it fires whenever the
    -- straddling block's first OOB byte falls on the boundary, in
    -- either 'applyUPS' or 'undoUPS', depending on which size the
    -- encoder rounded against.
  | BlockEntirelyPhantom
    -- ^ The block's start sits at or past the output boundary; no
    -- sub-operation has any in-bounds bytes. The walker writes
    -- nothing for this block; only the cursor advance is
    -- observable, so any subsequent blocks (rare past an OOB
    -- block, but legal) remain on stride.
    --
    -- Reachable whenever a direction writes the smaller of the two declared sizes and the block stream continues past that smaller size:
    -- the canonical encoder walks the larger size, so only the smaller-writing direction sees a phantom tail.
    -- Growth patches put that tail on 'undoUPS' (writes the smaller source);
    -- shrink patches put it on 'applyUPS' (writes the smaller target).
  deriving (Show, Eq)

-- | Classify a UPS block's placement against the output buffer.
-- Its full declared span is @skipLength + xorDataLength + 1@.
classifyBlockPlacement :: Offset -> Length -> FileSize -> BlockPlacement
classifyBlockPlacement blockStart totalBlockLength outputSize
  | fitsWithin blockStart totalBlockLength outputSize = BlockFitsWithinOutput
  | offsetToFileSize blockStart >= outputSize      = BlockEntirelyPhantom
  | otherwise =
      BlockPartiallyOvershoots (remainingFromOffset blockStart outputSize)

-- | Where a source-byte copy operation sits relative to the source
-- buffer. UPS's spec-mandated zero-fill semantics for
-- @source_size < target_size@ make past-source-end a real algorithmic
-- state: a copy that starts inside source can run off the end, and a
-- copy can begin at or past the end altogether (every byte read as a
-- virtual zero). Used by 'copySourceSlice' and 'xorSourceSlice' to
-- dispatch on the three structural arms; each arm contains only the
-- writes its case needs, no @when (n > 0)@ guards.
--
-- Parallel to 'BlockPlacement' (which classifies a block's write span
-- against the output buffer). Same three-arm shape, same fits \/
-- straddles \/ entirely-past structure, different reference buffer.
data SourceCopyPlacement
  = SourceCopyEntirelyInSource
    -- ^ The copy span ends at or before source end: every byte is a
    -- source-byte read. The handler runs only the source-read path;
    -- the zero-fill path is unreachable for this arm.
  | SourceCopyStraddlesSourceEnd !Length !Length
    -- ^ The copy starts inside source but extends past source end.
    -- The two carried 'Length's are the in-bounds prefix (source-
    -- read phase length) and the zero-fill tail (virtual-zero phase
    -- length), in that order. Their sum equals the requested copy
    -- length.
  | SourceCopyEntirelyPastSource
    -- ^ The copy starts at or past source end: every byte is a
    -- virtual zero. The handler runs only the zero-fill path; the
    -- source-read path is unreachable for this arm.
  deriving (Show, Eq)

-- | Classify a source-byte copy against the source buffer.
-- The output position where writing starts is also where the source read begins.
-- The straddle arm's tail length is computed here once, so neither 'copySourceSlice' nor 'xorSourceSlice' has to subtract downstream.
classifySourceCopy :: Offset -> Length -> FileSize -> SourceCopyPlacement
classifySourceCopy outputPosition copyLength sourceSize
  | fitsWithin outputPosition copyLength sourceSize = SourceCopyEntirelyInSource
  | offsetToFileSize outputPosition >= sourceSize   = SourceCopyEntirelyPastSource
  | otherwise =
      let inBoundsPrefix = remainingFromOffset outputPosition sourceSize
          zeroFillTail   = subtractLength copyLength inBoundsPrefix
      in SourceCopyStraddlesSourceEnd inBoundsPrefix zeroFillTail

data BlockWrite = BlockWrite
  { blockSkipStart     :: !Offset
  , blockSkipLength    :: !Length
  , blockXorStart      :: !Offset
  , blockXorLength     :: !Length
  , blockXorData       :: !ByteString
  , blockTerminatorStart :: !Offset
  }

----------------------------------------------------------------------------
-- applyUPS / undoUPS
----------------------------------------------------------------------------

-- | Walks the block stream against @source@ and writes the result into a target-sized output buffer.
-- The reverse-direction sibling is 'undoUPS'; both go through the same internal walker ('runUPSXorWalk'),
-- parameterised on the output buffer size.
-- The direction choice lives in these two thin wrappers, not threaded through the walker.
--
-- Returns 'Left' with a structured error if the declared target size is negative (unreachable — the size is read from a non-negative varint).
-- Blocks whose span exceeds the output size are clipped to it;
-- see 'BlockPlacement' for how the prefix is written and the terminator quirk it tolerates.
-- The returned 'Outcome' carries an 'ApplyOOBBlocksSkipped' advisory measured against the apply-direction output size ('upsTargetSize').
--
-- Source-shorter-than-target is legal (spec-mandated zero-fill past source end) and is handled inline by the helpers, not as an error.
-- The caller is still responsible for CRC validation before calling.
applyUPS :: UPSPatch -> InputFileContents -> Either SlapError (Outcome OutputFileContents)
applyUPS patch (InputFileContents source) = do
  bytes <- runUPSXorWalk patch source outputSize
  pure (Outcome (OutputFileContents bytes) (detectOOBBlocks patch Forward outputSize))
  where
    outputSize = upsTargetSize patch

-- | Reverse-direction sibling to 'applyUPS'.
-- UPS XOR is self-inverse, so reconstructing the source from the target walks the same block stream the same way —
-- only the output buffer size differs (@source_size@ instead of @target_size@), and clipping follows the same rules.
-- The returned 'Outcome' carries an 'ApplyOOBBlocksSkipped' advisory measured against the undo-direction output size ('upsSourceSize').
-- For growth patches that reports many more blocks and bytes than the apply-direction advisory does on the same patch.
undoUPS :: UPSPatch -> OutputFileContents -> Either SlapError (Outcome InputFileContents)
undoUPS patch (OutputFileContents modified) = do
  bytes <- runUPSXorWalk patch modified outputSize
  pure (Outcome (InputFileContents bytes) (detectOOBBlocks patch Reverse outputSize))
  where
    outputSize = upsSourceSize patch

-- | Internal: walks a UPS patch's block stream against @inputBytes@, writing an output buffer of @outputSize@ bytes.
-- The two public entry points ('applyUPS' and 'undoUPS') differ only in which declared size they pass here.
-- Renders 'NegativeTargetSize' for a negative output size —
-- the variant is named after the apply direction's "target" but covers both directions.
runUPSXorWalk :: UPSPatch -> ByteString -> FileSize -> Either SlapError ByteString
runUPSXorWalk patch source outputSize
  | unFileSize outputSize < 0 =
      Left (NegativeTargetSize LabelUPS outputSize)
  | unFileSize outputSize == 0 =
      Right ByteString.empty
  | otherwise = Right $ unsafePerformIO $
      create (fileSizeToInt outputSize) $ \outputPointer ->
        unsafeUseAsCStringLen source $ \(sourcePointerCString, _) ->
          let sourcePointer = castPtr sourcePointerCString :: Ptr Word8
          in runApply outputPointer sourcePointer
  where
    sourceSize     = byteFileSize source
    blocks         = upsBlocks patch
    blockStreamEnd = streamEndIndex blocks

    runApply outputPointer sourcePointer =
      let
        -- | Copy bytes from source to output at the given position, zero-filling past source end (spec-mandated for source-shorter-than-target).
        -- Dispatches on 'classifySourceCopy'.
        -- The caller is responsible for ensuring the copy fits within target bounds —
        -- this helper does not clip to target.
        copySourceSlice :: Offset -> Length -> IO ()
        copySourceSlice outputPosition copyLength =
          case classifySourceCopy outputPosition copyLength sourceSize of
            SourceCopyEntirelyInSource ->
              copyBytes
                (plusOffset outputPointer outputPosition)
                (sourcePointer `plusPtr` offsetToInt outputPosition)
                (lengthToInt copyLength)
            SourceCopyStraddlesSourceEnd inBoundsPrefix zeroFillTail -> do
              copyBytes
                (plusOffset outputPointer outputPosition)
                (sourcePointer `plusPtr` offsetToInt outputPosition)
                (lengthToInt inBoundsPrefix)
              fillBytes
                (plusOffset outputPointer
                            (advance outputPosition inBoundsPrefix))
                0
                (lengthToInt zeroFillTail)
            SourceCopyEntirelyPastSource ->
              fillBytes
                (plusOffset outputPointer outputPosition)
                0
                (lengthToInt copyLength)

        -- | XOR source bytes with xorData, writing result to output.
        -- Past source end, source bytes are treated as 0x00 (so xorData bytes are written verbatim: x XOR 0 == x).
        -- Dispatches on 'classifySourceCopy'.
        -- The caller is responsible for ensuring the write fits within target bounds —
        -- this helper does not clip to target.
        xorSourceSlice :: Offset -> Length -> ByteString -> IO ()
        xorSourceSlice outputPosition xorDataLength xorData =
          let readBase  = sourcePointer `plusPtr` offsetToInt outputPosition
              writeBase = plusOffset outputPointer outputPosition

              -- Phase 1: source in bounds.
              xorWithSourceLoop !byteOffset !endByteOffset
                | byteOffset >= endByteOffset = pure ()
                | otherwise = do
                    sourceByte <- peekByteOff readBase byteOffset :: IO Word8
                    let xorByte = unsafeIndex xorData byteOffset
                    pokeByteOff writeBase byteOffset
                      (sourceByte `xor` xorByte :: Word8)
                    xorWithSourceLoop (byteOffset + 1) endByteOffset

              -- Phase 2: source past end.
              xorWithZeroLoop !byteOffset !endByteOffset
                | byteOffset >= endByteOffset = pure ()
                | otherwise = do
                    let xorByte = unsafeIndex xorData byteOffset
                    pokeByteOff writeBase byteOffset xorByte
                    xorWithZeroLoop (byteOffset + 1) endByteOffset

          in case classifySourceCopy outputPosition xorDataLength sourceSize of
               SourceCopyEntirelyInSource ->
                 xorWithSourceLoop 0 (lengthToInt xorDataLength)
               SourceCopyStraddlesSourceEnd inBoundsPrefix zeroFillTail -> do
                 let inBoundsByteCount = lengthToInt inBoundsPrefix
                     zeroFillEnd       = inBoundsByteCount + lengthToInt zeroFillTail
                 xorWithSourceLoop 0 inBoundsByteCount
                 xorWithZeroLoop inBoundsByteCount zeroFillEnd
               SourceCopyEntirelyPastSource ->
                 xorWithZeroLoop 0 (lengthToInt xorDataLength)

        -- | Write a block whose declared span crosses the output
        -- boundary. Divides the in-bounds prefix sequentially across
        -- the block's three sub-operations (skip, xor, terminator) —
        -- each takes as much as is left, the next picks up whatever
        -- remains, and the trailing OOB bytes drop. The block-stride
        -- cursor advance is the caller's responsibility and fires
        -- regardless of how the prefix divides.
        --
        -- A clipped length may be zero — when @skipLength@ is zero or
        -- when a preceding sub-op consumed the whole prefix. No
        -- guard at this level: 'copySourceSlice' \/ 'xorSourceSlice'
        -- dispatch on 'classifySourceCopy' and a zero-length copy
        -- lands on an arm whose write is itself a no-op.
        writeStraddlingBlock :: Length -> BlockWrite -> IO ()
        writeStraddlingBlock inBoundsPrefix blockWrite = do
          let clippedSkipLength = minLength (blockSkipLength blockWrite) inBoundsPrefix
              afterSkip      = subtractLength inBoundsPrefix clippedSkipLength
              clippedXorLength  = minLength (blockXorLength blockWrite) afterSkip
              afterXor       = subtractLength afterSkip clippedXorLength
              clippedTerminatorLength = minLength upsTerminatorByteLength afterXor
          copySourceSlice (blockSkipStart blockWrite) clippedSkipLength
          xorSourceSlice  (blockXorStart blockWrite) clippedXorLength
            (ByteString.take (lengthToInt clippedXorLength) (blockXorData blockWrite))
          copySourceSlice (blockTerminatorStart blockWrite) clippedTerminatorLength

        -- | The single cursor transition done after every block.
        -- The output cursor advances by the block's full declared
        -- span regardless of which 'BlockPlacement' arm classified
        -- the block: the patch was authored with that stride, and
        -- any subsequent blocks (rare past an OOB block, but legal)
        -- depend on it.
        advanceOutputByBlock :: Length -> UPSApply ()
        advanceOutputByBlock stride =
          modify (\outputPosition -> advance outputPosition stride)

        -- | The output cursor lives in 'UPSApply' state, so each step needs only the running block index.
        -- End-of-stream issues the tail copy that fills any output bytes the block stream didn't name.
        -- No underfill check is needed: UPS's tail copy fills the buffer to exactly its end.
        -- The cursor may sit past 'outputSize' when phantom or straddling blocks advanced it beyond the buffer;
        -- the at-or-past arm short-circuits before asking 'remainingFromOffset' a question whose only sensible answer is "no bytes left."
        applyBlockStream :: ActionIndex -> UPSApply ()
        applyBlockStream !blockIndex
          | blockIndex >= blockStreamEnd = do
              outputPosition <- get
              when (offsetToFileSize outputPosition < outputSize) $ do
                let tailLength = remainingFromOffset outputPosition outputSize
                liftIO (copySourceSlice outputPosition tailLength)
          | otherwise =
              handleBlock blockIndex
                (Vector.unsafeIndex blocks (unActionIndex blockIndex))

        -- | Per-block dispatch.
        -- The three arms read top-to-bottom in order of decreasing in-bounds payload:
        -- fits writes all three sub-ops, straddles writes a clipped prefix of them, phantom writes nothing.
        handleBlock :: ActionIndex -> UPSBlock -> UPSApply ()
        handleBlock blockIndex (UPSBlock skipLength xorData) = do
          outputPosition <- get
          let xorLength        = byteLength xorData
              totalBlockLength = skipLength <> xorLength <> upsTerminatorByteLength
              skipStart     = outputPosition
              xorStart      = advance skipStart skipLength
              terminatorStart = advance xorStart xorLength
              blockWrite    = BlockWrite
                { blockSkipStart     = skipStart
                , blockSkipLength    = skipLength
                , blockXorStart      = xorStart
                , blockXorLength     = xorLength
                , blockXorData       = xorData
                , blockTerminatorStart = terminatorStart
                }
              placement     = classifyBlockPlacement
                                outputPosition totalBlockLength outputSize
          case placement of
            BlockFitsWithinOutput -> liftIO $ do
              copySourceSlice skipStart skipLength
              xorSourceSlice  xorStart  xorLength xorData
              copySourceSlice terminatorStart upsTerminatorByteLength
            BlockPartiallyOvershoots inBoundsPrefix -> liftIO $
              writeStraddlingBlock inBoundsPrefix blockWrite
            BlockEntirelyPhantom -> pure ()
          advanceOutputByBlock totalBlockLength
          applyBlockStream (nextAction blockIndex)

      in evalStateT (applyBlockStream firstAction) (Offset 0)

----------------------------------------------------------------------------
-- Cursor state
----------------------------------------------------------------------------

-- | The state slot carries the output cursor.
-- Kept as a bare 'Offset' rather than a one-field record because there is nothing else to bundle with it;
-- UPS's apply has a single piece of state.
type UPSApply = StateT Offset IO

----------------------------------------------------------------------------
-- OOB block detection
----------------------------------------------------------------------------

-- | Per-block walk state for 'detectOOBBlocks'.
-- Threaded through 'Vector.ifoldl'' over the patch's blocks; each block either falls entirely within the declared target
-- (cursor advances; counts unchanged) or extends past it (cursor still advances, counts update).
data OOBWalkState = OOBWalkState
  { oobPosition   :: !Offset
  , oobCount      :: !OOBBlockCount
  , oobFirstIndex :: !(Maybe ActionIndex)
  , oobOvershoot  :: !OOBOvershootBytes
  }

-- | Walk the block stream and mark blocks whose declared span exceeds the supplied @outputSize@.
-- Returns a single summary advisory if any OOB blocks exist, or an empty list if all blocks fit.
-- The output_size parameter is direction-dependent:
-- apply supplies 'upsTargetSize', undo supplies 'upsSourceSize', so the two directions see different OOB profiles on the same stream.
--
-- The direction parameter tags the advisory with which operation
-- produced it ('Forward' for apply, 'Reverse' for undo), so the
-- rendered text matches the operation the user invoked.
detectOOBBlocks :: UPSPatch -> ApplyDirection -> FileSize -> [SlapAdvisory]
detectOOBBlocks patch direction outputSize = case oobFirstIndex finalState of
  Nothing       -> []
  Just firstIndex ->
    [ApplyOOBBlocksSkipped LabelUPS direction
      (oobCount finalState) firstIndex
      (oobOvershoot finalState) outputSize]
  where
    initialState = OOBWalkState
      { oobPosition   = Offset 0
      , oobCount      = OOBBlockCount 0
      , oobFirstIndex = Nothing
      , oobOvershoot  = mempty
      }

    finalState = Vector.ifoldl' walkBlock initialState (upsBlocks patch)

    walkBlock state blockIndex (UPSBlock skipLength xorData) =
      let xorLength        = byteLength xorData
          totalBlockLength = skipLength <> xorLength <> upsTerminatorByteLength
          nextPosition  = advance (oobPosition state) totalBlockLength
          placement     = classifyBlockPlacement
                            (oobPosition state) totalBlockLength outputSize
      in case placement of
           BlockFitsWithinOutput          -> state { oobPosition = nextPosition }
           BlockPartiallyOvershoots inBoundsPrefix ->
             recordOOBBlock state blockIndex nextPosition
                            (subtractLength totalBlockLength inBoundsPrefix)
           BlockEntirelyPhantom           ->
             recordOOBBlock state blockIndex nextPosition totalBlockLength

    recordOOBBlock state blockIndex nextPosition blockOvershoot =
      let OOBBlockCount currentCount = oobCount state
      in state
        { oobPosition   = nextPosition
        , oobCount      = OOBBlockCount (currentCount + 1)
        , oobFirstIndex = case oobFirstIndex state of
            Just _  -> oobFirstIndex state
            Nothing -> Just (actionAtPosition blockIndex)
        , oobOvershoot  = oobOvershoot state <> OOBOvershootBytes blockOvershoot
        }
