{-# LANGUAGE OverloadedStrings #-}

module Slap.APSGBA.Apply
  ( applyAPSGBA
  ) where

import Slap.APSGBA.Types
import Slap.Binary (copyByteStringRange, fillNewBuffer)
import Slap.Status (SlapError(..), ApplyError(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.Measure (Offset(..), Length(..), FileSize(..),
                     ActionIndex, RequestedLength(..),
                     offsetToFileSize, firstAction, nextAction)

import Slap.FileContents (InputFileContents(..), OutputFileContents(..))

import qualified Data.ByteString as ByteString
import Data.Bits (xor)
import Data.Word (Word8)
import Control.Monad (when)
import Foreign.Marshal.Utils (fillBytes)
import Foreign.Ptr (Ptr, plusPtr)
import Foreign.Storable (peekByteOff, pokeByteOff)
import System.IO.Unsafe (unsafePerformIO)

----------------------------------------------------------------------------
-- applyAPSGBA
----------------------------------------------------------------------------

-- | Apply a parsed APS-GBA patch. Each record names an absolute
-- 64KB-aligned offset and carries a full 'apsGbaBlockSize'-byte XOR
-- payload; the apply XORs each payload into the seeded output
-- buffer at its declared offset.
--
-- A record whose start offset is past the patch's natural block
-- reach (the byte count covered by @max(sourceSize, targetSize)@
-- rounded up to whole blocks — equivalent here to
-- @max(sourceSize, targetSize)@ since block ends are skipped
-- per-byte anyway) is malformed and surfaces as
-- 'ApplyAbsoluteWritePastTarget' naming the record's index, offset,
-- block size, and the target size.
--
-- The natural-reach check is strictly looser than "blockOffset must
-- fit inside the declared target size", because 'Slap.APSGBA.Create'
-- legitimately emits records past the target end when the patch is
-- shrinking — source blocks that have no target equivalent still
-- generate a record because the source-vs-(zero-padded-target) XOR
-- is non-zero. Those records contribute no bytes to the output (the
-- per-byte 'positionWithinTarget' guard skips them) but their
-- presence in the record stream is normal. A record whose start
-- exceeds @max(sourceSize, targetSize)@, by contrast, cannot have
-- been emitted by any well-formed creator: nothing in either input
-- would have produced a non-zero block at that index.
--
-- For the block's *tail* extending past the target end: that is the
-- non-64KB-aligned-target case and remains legitimate even when the
-- block start is in-range. The per-byte loop's
-- 'positionWithinTarget' guard skips those bytes; no error is
-- raised.
applyAPSGBA :: APSGBAPatch -> InputFileContents -> Either SlapError OutputFileContents
applyAPSGBA (APSGBAPatch header records) (InputFileContents source)
  | targetSize < 0 =
      Left (NegativeTargetSize LabelAPSGBA targetFileSize)
  | otherwise = unsafePerformIO $ do
      (result, maybeErr) <- fillNewBuffer targetFileSize runApply
      pure $ case maybeErr of
        Just applyErr -> Left (ApplyFailed LabelAPSGBA applyErr)
        Nothing       -> Right (OutputFileContents result)
  where
    sourceLength   = ByteString.length source
    targetFileSize = apsGbaTargetSize header
    targetSize     = unFileSize targetFileSize
    -- | The largest legitimate block-start offset's upper bound,
    -- derived as @max(sourceSize, targetSize)@. See the
    -- function-level comment for why this is the right bound and
    -- not @targetSize@ alone.
    naturalBlockReach :: FileSize
    naturalBlockReach =
      FileSize (max sourceLength targetSize)

    -- | Initial buffer state: copy source bytes (clipped at target
    -- length if shrinking) and zero-fill any tail past the source.
    seedBuffer :: Ptr Word8 -> IO ()
    seedBuffer targetPointer = do
      copyByteStringRange targetPointer 0 source 0 (min sourceLength targetSize)
      when (targetSize > sourceLength) $
        fillBytes (targetPointer `plusPtr` sourceLength)
                  (0 :: Word8)
                  (targetSize - sourceLength)

    -- | Per-record guard: the record's write *start* must lie
    -- within the patch's natural block reach (see 'naturalBlockReach').
    -- The trailing bytes of a block whose start is in-range may
    -- legitimately extend past the target end (a non-aligned last
    -- block, or a source-shrinking patch); those bytes are skipped
    -- by 'executeXorBlock', not flagged here.
    checkRecordStartsWithinReach :: ActionIndex -> Offset
                                 -> Either ApplyError ()
    checkRecordStartsWithinReach actionIndex blockOffset
      | offsetToFileSize blockOffset >= naturalBlockReach =
          Left (ApplyAbsoluteWritePastTarget actionIndex
                 blockOffset
                 (RequestedLength (Length apsGbaBlockSize))
                 targetFileSize)
      | otherwise = Right ()

    -- | Materialise one 64KB block into the output buffer. Each
    -- byte position is checked against 'targetSize'; positions past
    -- the target end are skipped (the legitimate non-aligned
    -- last-block case — see the function-level comment).
    executeXorBlock :: Ptr Word8 -> Offset -> ByteString.ByteString -> IO ()
    executeXorBlock targetPointer blockOffset xorPayload =
        writeRemainingBytes 0
      where
        blockBase     = unOffset blockOffset
        writeBase     = targetPointer `plusPtr` blockBase
        writeRemainingBytes !byteOffset
          | byteOffset >= apsGbaBlockSize = pure ()
          | otherwise = do
              let positionWithinTarget = blockBase + byteOffset
              when (positionWithinTarget < targetSize) $ do
                original <- peekByteOff writeBase byteOffset :: IO Word8
                pokeByteOff writeBase byteOffset
                  (original `xor` ByteString.index xorPayload byteOffset)
              writeRemainingBytes (byteOffset + 1)

    -- | Tail-recursive walk over the record list. End-of-stream
    -- finishes apply with no error; a malformed-record start
    -- returns immediately with the structured error.
    applyRecords :: Ptr Word8 -> ActionIndex -> [APSGBARecord]
                 -> IO (Maybe ApplyError)
    applyRecords _targetPointer _actionIndex [] = pure Nothing
    applyRecords targetPointer !actionIndex
                 (APSGBARecord blockOffset _ _ xorPayload : remainingRecords) =
      case checkRecordStartsWithinReach actionIndex blockOffset of
        Left err -> pure (Just err)
        Right () -> do
          executeXorBlock targetPointer blockOffset xorPayload
          applyRecords targetPointer (nextAction actionIndex) remainingRecords

    runApply targetPointer = do
      seedBuffer targetPointer
      applyRecords targetPointer firstAction records
