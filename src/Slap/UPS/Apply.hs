module Slap.UPS.Apply
  ( applyUPS
  , undoUPS
  , detectOOBBlocks
  ) where

import Slap.UPS.Types (UPSPatch(..), UPSBlock(..), upsTerminatorByteLength)
import Slap.Error (SlapError(..), SlapWarning(..),
                   OOBBlockCount(..), OOBOvershootBytes(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.Measure (Offset(..), Length(..), FileSize(..),
                     ActionIndex(unActionIndex),
                     Cursor(..), fitsWithin, remainingFromOffset,
                     subtractLength, minLength,
                     byteFileSize, byteLength,
                     firstAction, nextAction,
                     streamEndIndex, actionAtPosition, plusOffset)
import Slap.FileContents (InputFileContents(..), OutputFileContents(..))

import Control.Monad (when)
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
-- byte lands 1 past the declared output size. Use 'detectOOBBlocks'
-- at parse time to surface these as warnings to the user.
--
-- Source-shorter-than-target is legal (spec-mandated zero-fill past
-- source end) and is handled inline by the helper functions, not as
-- an error. The caller is still responsible for CRC validation
-- before calling.
applyUPS :: UPSPatch -> InputFileContents -> Either SlapError OutputFileContents
applyUPS patch (InputFileContents source) =
  OutputFileContents <$> runUPSXorWalk patch source (upsTargetSize patch)

-- | Reverse-direction sibling to 'applyUPS'. UPS XOR is self-inverse,
-- so reconstructing the source from the target uses the same block
-- stream walked the same way — only the output buffer size differs
-- (@source_size@ instead of @target_size@). Same OOB-clipping rules
-- apply: blocks whose span exceeds the new (source-side) output
-- size get clipped against it, which is the typical situation for
-- growth patches where the block stream covers the larger target
-- but undo writes only the smaller source.
undoUPS :: UPSPatch -> OutputFileContents -> Either SlapError InputFileContents
undoUPS patch (OutputFileContents modified) =
  InputFileContents <$> runUPSXorWalk patch modified (upsSourceSize patch)

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

        applyBlockStream :: ActionIndex -> Offset -> IO ()
        applyBlockStream !blockIndex !outputPosition
          | blockIndex >= blockStreamEnd = do
              -- End of stream: tail copy from source to output,
              -- zero-filling past source end. No ApplyTargetUnderfilled
              -- check — the tail copy always fills the output exactly.
              let tailLength = remainingFromOffset outputPosition outputSize
              copySourceSlice outputPosition tailLength
          | otherwise =
              handleBlock blockIndex outputPosition
                (Vector.unsafeIndex blocks (unActionIndex blockIndex))

        handleBlock :: ActionIndex -> Offset -> UPSBlock -> IO ()
        handleBlock blockIndex outputPosition (UPSBlock skipLen xorData) =
          let xorLen         = byteLength xorData
              totalBlockLen  = skipLen <> xorLen <> upsTerminatorByteLength
              skipStart      = outputPosition
              xorStart       = advance skipStart skipLen
              terminatorPos  = advance xorStart xorLen
              nextPosition   = advance terminatorPos upsTerminatorByteLength
          in if fitsWithin outputPosition totalBlockLen outputSize
               then do
                 -- Fast path: entire block fits within the output buffer.
                 copySourceSlice skipStart skipLen
                 xorSourceSlice xorStart xorLen xorData
                 copySourceSlice terminatorPos upsTerminatorByteLength
                 applyBlockStream (nextAction blockIndex) nextPosition
               else do
                 -- OOB path: clip each sub-operation to remaining
                 -- output space. The cursor advances by the full
                 -- block span regardless — the patch was authored
                 -- with that stride, and any subsequent blocks (rare
                 -- but legal) depend on it. In the apply direction
                 -- this fires for the typical "terminator at target
                 -- end" tail block; in the undo direction it can
                 -- fire much earlier for growth patches (block
                 -- stream covers the larger target; undo writes the
                 -- smaller source).
                 let available      = remainingFromOffset outputPosition outputSize
                     clippedSkipLen = minLength skipLen available
                     afterSkip      = subtractLength available clippedSkipLen
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
                 applyBlockStream (nextAction blockIndex) nextPosition

      in applyBlockStream firstAction (Offset 0)

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

-- | Walk the block stream and detect blocks whose span exceeds the
-- declared target size. Returns a single summary warning if any OOB
-- blocks exist, or an empty list if all blocks fit. Called at parse
-- time from 'Slap.SomePatch' to populate 'patchWarnings' — the
-- user sees the diagnostic before apply runs, and 'applyUPS' clips
-- the writes silently.
detectOOBBlocks :: UPSPatch -> [SlapWarning]
detectOOBBlocks patch = case oobFirstIndex finalState of
  Nothing       -> []
  Just firstIdx ->
    [ApplyOOBBlocksSkipped LabelUPS
      (oobCount finalState) firstIdx
      (oobOvershoot finalState) targetFileSize]
  where
    targetFileSize = upsTargetSize patch

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
      in if fitsWithin (oobPosition state) totalBlockLen targetFileSize
           then state { oobPosition = nextPosition }
           else let remaining      = remainingFromOffset (oobPosition state) targetFileSize
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
