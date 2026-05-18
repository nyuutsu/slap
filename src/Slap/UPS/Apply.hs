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
import Slap.Measure (Offset(..), Length(..), FileSize(..),
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
-- Block placement classifier
----------------------------------------------------------------------------

-- | Where a UPS block's declared span sits relative to the active
-- output buffer. UPS blocks have a fixed declared stride
-- (@skipLen + xorDataLength + 1@) and the canonical encoder walks a
-- block stream that covers @max sourceSize targetSize@ bytes' worth
-- of output, so the stream can extend past whichever of
-- @source_size@ / @target_size@ the current direction is writing
-- to. The walker ('runUPSXorWalk') is direction-blind — it knows
-- only its own 'outputSize', supplied by 'applyUPS' or 'undoUPS' —
-- and classifies each block against it.
--
-- The two out-of-bounds arms — 'BlockPartiallyOvershoots' and
-- 'BlockEntirelyPhantom' — are direction-symmetric by algorithm.
-- Both are reachable from both directions; which arm fires depends
-- on the patch's shape (growth vs shrink, terminator placement),
-- not on whether the user invoked apply or undo. See each
-- constructor's docs for the dominant empirical case the current
-- corpus exhibits, but bear in mind those are observations of one
-- corpus, not properties of the format.
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
    -- boundary. The dominant empirical case is the +1-terminator
    -- quirk many UPS creation tools (NUPS, Tsukuyomi) emit: a
    -- final block whose terminator lands at @output_size@ rather
    -- than @output_size - 1@, so its trailing byte clips. The
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
    -- Reachable whenever a direction writes the smaller of the two
    -- declared sizes ('upsSourceSize' and 'upsTargetSize') and the
    -- block stream continues past that smaller size. The canonical
    -- encoder walks the larger of the two sizes, so the direction
    -- writing the larger size sees no phantom blocks, while the
    -- direction writing the smaller size sees a phantom tail.
    -- Growth patches put the phantom tail on 'undoUPS' (which
    -- writes the smaller source); shrink patches put it on
    -- 'applyUPS' (which writes the smaller target). The walker
    -- itself is direction-blind, so either entry point may reach
    -- this arm.
  deriving (Show, Eq)

-- | Classify a UPS block's placement against the active output
-- buffer. Pure function of three typed arguments: the block's start
-- position, its full declared span (@skipLen + xorDataLength + 1@),
-- and the size of the buffer being written. Performs no I/O and
-- reads no shared state.
classifyBlockPlacement :: Offset -> Length -> FileSize -> BlockPlacement
classifyBlockPlacement blockStart totalBlockLen outputSize
  | fitsWithin blockStart totalBlockLen outputSize = BlockFitsWithinOutput
  | offsetToFileSize blockStart >= outputSize      = BlockEntirelyPhantom
  | otherwise =
      BlockPartiallyOvershoots (remainingFromOffset blockStart outputSize)

----------------------------------------------------------------------------
-- applyUPS / undoUPS
----------------------------------------------------------------------------

-- | Apply a parsed UPS patch to a source ByteString. Walks the
-- block stream against @source@ and writes the result into a
-- target-sized output buffer. The reverse-direction sibling is
-- 'undoUPS'; both go through the same internal walker
-- ('runUPSXorWalk') which is parameterised on the output buffer
-- size — the direction choice lives in these two thin wrappers,
-- not threaded through the walker.
--
-- Returns 'Left' with a structured error if the declared target
-- size is negative (unreachable by construction but defensively
-- guarded). Blocks whose span exceeds the output size are clipped
-- to its bounds — the in-bounds portion is written and the
-- out-of-bounds portion is silently skipped. This tolerates the
-- common creation-tool artifact where the final block's terminator
-- byte lands 1 past the declared output size. The returned
-- 'Outcome' carries an 'ApplyOOBBlocksSkipped' advisory measured
-- against the apply-direction output size ('upsTargetSize') so the
-- caller sees a direction-correct summary of any clipping.
--
-- Source-shorter-than-target is legal (spec-mandated zero-fill past
-- source end) and is handled inline by the helper functions, not as
-- an error. The caller is still responsible for CRC validation
-- before calling.
applyUPS :: UPSPatch -> InputFileContents -> Either SlapError (Outcome OutputFileContents)
applyUPS patch (InputFileContents source) = do
  bytes <- runUPSXorWalk patch source outputSize
  pure (Outcome (OutputFileContents bytes) (detectOOBBlocks patch Forward outputSize))
  where
    outputSize = upsTargetSize patch

-- | Reverse-direction sibling to 'applyUPS'. UPS XOR is self-inverse,
-- so reconstructing the source from the target uses the same block
-- stream walked the same way — only the output buffer size differs
-- (@source_size@ instead of @target_size@). Same OOB-clipping rules
-- apply: blocks whose span exceeds the new (source-side) output
-- size get clipped against it, which is the typical situation for
-- growth patches where the block stream covers the larger target
-- but undo writes only the smaller source. The returned 'Outcome'
-- carries an 'ApplyOOBBlocksSkipped' advisory measured against the
-- undo-direction output size ('upsSourceSize'), which for growth
-- patches reports many more blocks and many more bytes than the
-- apply-direction advisory does on the same patch.
undoUPS :: UPSPatch -> OutputFileContents -> Either SlapError (Outcome InputFileContents)
undoUPS patch (OutputFileContents modified) = do
  bytes <- runUPSXorWalk patch modified outputSize
  pure (Outcome (InputFileContents bytes) (detectOOBBlocks patch Reverse outputSize))
  where
    outputSize = upsSourceSize patch

-- | Internal: walks a UPS patch's block stream against @inputBytes@,
-- writing an output buffer of @outputSize@ bytes. The two public
-- entry points ('applyUPS' and 'undoUPS') differ only in which
-- declared size they pass here. Renders 'NegativeTargetSize' for a
-- defensively-checked negative output size — the variant is named
-- after the apply direction's "target" but covers both directions
-- (a negative declared size is unreachable from a well-parsed patch
-- in either case).
runUPSXorWalk :: UPSPatch -> ByteString -> FileSize -> Either SlapError ByteString
runUPSXorWalk patch source outputSize
  | unFileSize outputSize < 0 =
      Left (NegativeTargetSize LabelUPS outputSize)
  | unFileSize outputSize == 0 =
      Right ByteString.empty
  | otherwise = Right $ unsafePerformIO $
      create (unFileSize outputSize) $ \outputPointer ->
        unsafeUseAsCStringLen source $ \(sourcePointerCString, _) ->
          let sourcePointer = castPtr sourcePointerCString :: Ptr Word8
          in runApply outputPointer sourcePointer
  where
    sourceSize     = byteFileSize source
    blocks         = upsBlocks patch
    blockStreamEnd = streamEndIndex blocks

    runApply outputPointer sourcePointer =
      let
        -- | Copy bytes from source to output at the given position,
        -- zero-filling past source end (spec-mandated for source-
        -- shorter-than-target). The caller is responsible for ensuring
        -- the copy fits within target bounds — this helper does not
        -- clip to target.
        copySourceSlice :: Offset -> Length -> IO ()
        copySourceSlice outputPosition copyLength = do
          let availableInSource = remainingFromOffset outputPosition sourceSize
              inBoundsLength    = minLength copyLength availableInSource
              zeroFillLength    = subtractLength copyLength inBoundsLength
              zeroFillStart     = advance outputPosition inBoundsLength
          when (unLength inBoundsLength > 0) $
            copyBytes
              (plusOffset outputPointer outputPosition)
              (sourcePointer `plusPtr` unOffset outputPosition)
              (unLength inBoundsLength)
          when (unLength zeroFillLength > 0) $
            fillBytes
              (plusOffset outputPointer zeroFillStart)
              0
              (unLength zeroFillLength)

        -- | XOR source bytes with xorData, writing result to output.
        -- Past source end, source bytes are treated as 0x00 (so
        -- xorData bytes are written verbatim — x XOR 0 == x). The
        -- caller is responsible for ensuring the write fits within
        -- target bounds — this helper does not clip to target.
        --
        -- Two-phase loop: a tight in-bounds phase reads source via
        -- the raw pinned pointer and XORs against xorData; a tight
        -- zero-fill phase writes xorData verbatim. This mirrors
        -- copySourceSlice's split-phase structure and BPS's
        -- generalOverlapLoop hoisted-base-pointer style.
        xorSourceSlice :: Offset -> Length -> ByteString -> IO ()
        xorSourceSlice outputPosition xorDataLength xorData = do
          let availableInSource = remainingFromOffset outputPosition sourceSize
              inBoundsLength    = minLength xorDataLength availableInSource
              readBase          = sourcePointer `plusPtr` unOffset outputPosition
              writeBase         = plusOffset outputPointer outputPosition
              inBoundsBytes     = unLength inBoundsLength
              totalBytes        = unLength xorDataLength

              -- Phase 1: source is in bounds. Read source, XOR with
              -- xorData, poke result.
              inBoundsLoop !byteOffset
                | byteOffset >= inBoundsBytes = pure ()
                | otherwise = do
                    sourceByte <- peekByteOff readBase byteOffset :: IO Word8
                    let xorByte = unsafeIndex xorData byteOffset
                    pokeByteOff writeBase byteOffset
                      (sourceByte `xor` xorByte :: Word8)
                    inBoundsLoop (byteOffset + 1)

              -- Phase 2: source is past end. Source byte is virtually
              -- 0, so the result is just xorData[byteOffset].
              zeroFillLoop !byteOffset
                | byteOffset >= totalBytes = pure ()
                | otherwise = do
                    let xorByte = unsafeIndex xorData byteOffset
                    pokeByteOff writeBase byteOffset xorByte
                    zeroFillLoop (byteOffset + 1)
          inBoundsLoop 0
          zeroFillLoop inBoundsBytes

        -- | Write a block whose declared span crosses the output
        -- boundary. Divides the in-bounds prefix sequentially across
        -- the block's three sub-operations (skip, xor, terminator) —
        -- each takes as much as is left, the next picks up whatever
        -- remains, and the trailing OOB bytes drop. The block-stride
        -- cursor advance is the caller's responsibility and fires
        -- regardless of how the prefix divides.
        writeStraddlingBlock :: Length
                             -> Offset -> Length
                             -> Offset -> Length -> ByteString
                             -> Offset
                             -> IO ()
        writeStraddlingBlock inBoundsPrefix
                             skipStart skipLen
                             xorStart  xorLen xorData
                             terminatorPos = do
          let clippedSkipLen = minLength skipLen inBoundsPrefix
              afterSkip      = subtractLength inBoundsPrefix clippedSkipLen
              clippedXorLen  = minLength xorLen afterSkip
              afterXor       = subtractLength afterSkip clippedXorLen
              clippedTermLen = minLength upsTerminatorByteLength afterXor
          when (unLength clippedSkipLen > 0) $
            copySourceSlice skipStart clippedSkipLen
          when (unLength clippedXorLen > 0) $
            xorSourceSlice xorStart clippedXorLen
              (ByteString.take (unLength clippedXorLen) xorData)
          when (unLength clippedTermLen > 0) $
            copySourceSlice terminatorPos clippedTermLen

        -- | The single cursor transition done after every block.
        -- The output cursor advances by the block's full declared
        -- span regardless of which 'BlockPlacement' arm classified
        -- the block: the patch was authored with that stride, and
        -- any subsequent blocks (rare past an OOB block, but legal)
        -- depend on it.
        advanceOutputByBlock :: Length -> UPSApply ()
        advanceOutputByBlock stride =
          modify (\outputPosition -> advance outputPosition stride)

        -- | Tail-recursive walk over the block vector. The output
        -- cursor lives in 'UPSApply' state, so each step needs only
        -- the running block index. End-of-stream issues the tail
        -- copy that fills any output bytes the block stream didn't
        -- name — no underfill check, because UPS's tail copy
        -- structurally guarantees the buffer ends exactly filled.
        applyBlockStream :: ActionIndex -> UPSApply ()
        applyBlockStream !blockIndex
          | blockIndex >= blockStreamEnd = do
              outputPosition <- get
              let tailLength = remainingFromOffset outputPosition outputSize
              liftIO (copySourceSlice outputPosition tailLength)
          | otherwise =
              handleBlock blockIndex
                (Vector.unsafeIndex blocks (unActionIndex blockIndex))

        -- | Per-block dispatch. Classify the block's placement once,
        -- run the placement-appropriate write (or nothing, for a
        -- phantom block), then advance the cursor by the full
        -- declared span and recurse. The three arms read top-to-
        -- bottom in order of decreasing in-bounds payload: fits
        -- writes all three sub-ops, straddles writes a clipped
        -- prefix of them, phantom writes nothing.
        handleBlock :: ActionIndex -> UPSBlock -> UPSApply ()
        handleBlock blockIndex (UPSBlock skipLen xorData) = do
          outputPosition <- get
          let xorLen        = byteLength xorData
              totalBlockLen = skipLen <> xorLen <> upsTerminatorByteLength
              skipStart     = outputPosition
              xorStart      = advance skipStart skipLen
              terminatorPos = advance xorStart xorLen
              placement     = classifyBlockPlacement
                                outputPosition totalBlockLen outputSize
          case placement of
            BlockFitsWithinOutput -> liftIO $ do
              copySourceSlice skipStart skipLen
              xorSourceSlice  xorStart  xorLen xorData
              copySourceSlice terminatorPos upsTerminatorByteLength
            BlockPartiallyOvershoots inBoundsPrefix -> liftIO $
              writeStraddlingBlock inBoundsPrefix
                skipStart skipLen
                xorStart  xorLen xorData
                terminatorPos
            BlockEntirelyPhantom -> pure ()
          advanceOutputByBlock totalBlockLen
          applyBlockStream (nextAction blockIndex)

      in evalStateT (applyBlockStream firstAction) (Offset 0)

----------------------------------------------------------------------------
-- Cursor state
----------------------------------------------------------------------------

-- | Strict 'StateT' over 'IO'. The state slot carries the output
-- cursor — the apply's only threaded value, advanced by one block's
-- full declared span ('advanceOutputByBlock') after every block,
-- regardless of how that block was classified. Kept as a bare
-- 'Offset' rather than a one-field record because there is nothing
-- else to bundle with it; UPS's apply has a single piece of state.
-- Mirrors 'Slap.XDelta1.Apply.XDelta1Apply'.
type UPSApply = StateT Offset IO

----------------------------------------------------------------------------
-- OOB block detection
----------------------------------------------------------------------------

-- | Per-block walk state for 'detectOOBBlocks'. Threaded through
-- 'Vector.ifoldl'' over the patch's blocks; each block either falls
-- entirely within the declared target (cursor advances; counts
-- unchanged) or extends past it (cursor still advances, counts
-- update). Module-internal; not exported.
data OOBWalkState = OOBWalkState
  { oobPosition   :: !Offset
  , oobCount      :: !OOBBlockCount
  , oobFirstIndex :: !(Maybe ActionIndex)
  , oobOvershoot  :: !OOBOvershootBytes
  }

-- | Walk the block stream and detect blocks whose declared span
-- exceeds the supplied @outputSize@. Returns a single summary
-- advisory if any OOB blocks exist, or an empty list if all blocks
-- fit. The output_size parameter is direction-dependent: apply
-- supplies 'upsTargetSize', undo supplies 'upsSourceSize'. Same
-- block stream, different output sizes, different OOB profiles —
-- a growth patch typically has a handful of OOB blocks (often just
-- one, from the terminator quirk) in the apply direction and many
-- in the undo direction, because the block stream covers the
-- larger target while undo writes the smaller source.
--
-- The direction parameter tags the advisory with which operation
-- produced it ('Forward' for apply, 'Reverse' for undo), so the
-- rendered text matches the operation the user invoked.
--
-- Called from 'applyUPS' and 'undoUPS' against their respective
-- output sizes; the resulting advisory is carried in the returned
-- 'Outcome' so the user always sees a summary measured against the
-- operation that actually ran.
detectOOBBlocks :: UPSPatch -> ApplyDirection -> FileSize -> [SlapAdvisory]
detectOOBBlocks patch direction outputSize = case oobFirstIndex finalState of
  Nothing       -> []
  Just firstIdx ->
    [ApplyOOBBlocksSkipped LabelUPS direction
      (oobCount finalState) firstIdx
      (oobOvershoot finalState) outputSize]
  where
    initialState = OOBWalkState
      { oobPosition   = Offset 0
      , oobCount      = OOBBlockCount 0
      , oobFirstIndex = Nothing
      , oobOvershoot  = mempty
      }

    finalState = Vector.ifoldl' walkBlock initialState (upsBlocks patch)

    walkBlock state blockIdx (UPSBlock skipLen xorData) =
      let xorLen        = byteLength xorData
          totalBlockLen = skipLen <> xorLen <> upsTerminatorByteLength
          nextPosition  = advance (oobPosition state) totalBlockLen
      in if fitsWithin (oobPosition state) totalBlockLen outputSize
           then state { oobPosition = nextPosition }
           else let remaining      = remainingFromOffset (oobPosition state) outputSize
                    blockOvershoot = subtractLength totalBlockLen remaining
                    OOBBlockCount currentCount = oobCount state
                in state
                  { oobPosition   = nextPosition
                  , oobCount      = OOBBlockCount (currentCount + 1)
                  , oobFirstIndex = case oobFirstIndex state of
                      Just _  -> oobFirstIndex state
                      Nothing -> Just (actionAtPosition blockIdx)
                  , oobOvershoot  = oobOvershoot state <> OOBOvershootBytes blockOvershoot
                  }
