module Slap.NINJA2.Apply
  ( applyNINJA2
  ) where

import Slap.NINJA2.Types
import Slap.Status (SlapError(..), ApplyError(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.Binary (copyByteStringRange, fillNewBuffer)
import Slap.Measure (Offset(..), Length(..), FileSize(..),
                     ActionIndex, RequestedLength(..),
                     byteLength, fitsWithin,
                     firstAction, nextAction, streamEndIndex)

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
-- applyNINJA2
----------------------------------------------------------------------------

-- | Apply a parsed NINJA2 patch to a source ByteString. Walks two
-- write streams: the XOR record list and (when present) the
-- append-mode overflow payload. Both carry absolute wire offsets, so
-- a malformed patch can name a write that extends past the declared
-- target end; every such write is bounds-checked at its boundary and
-- the apply returns 'Left' with 'ApplyAbsoluteWritePastTarget'
-- naming which write went out of bounds and by how much.
--
-- Truncate-mode overflow is silent: its payload is the discarded
-- source tail preserved for round-trip and is *not* applied — the
-- smaller output buffer already encodes the truncation. Only
-- append-mode overflow drives a write, so only append-mode overflow
-- needs a bounds check.
--
-- The action-index space covers the XOR record stream
-- (@0 ..  length records - 1@); the overflow-append step, when
-- present, takes the index immediately after the last record
-- (@length records@), so an OOB on the append shows up at one index
-- past the last record and is unambiguous against an OOB on a
-- specific record.
applyNINJA2 :: NINJA2Patch -> InputFileContents -> Either SlapError OutputFileContents
applyNINJA2 patch (InputFileContents source)
  | outputLength < 0 =
      Left (NegativeTargetSize LabelNINJA2 outputFileSize)
  | otherwise = unsafePerformIO $ do
      (result, maybeErr) <- fillNewBuffer outputFileSize runApply
      pure $ case maybeErr of
        Just applyErr -> Left (ApplyFailed LabelNINJA2 applyErr)
        Nothing       -> Right (OutputFileContents result)
  where
    sourceLength   = ByteString.length source
    outputLength   = case ninja2OpenNewFile patch of
      Just openNewFile -> unFileSize (openNewFileTargetSize openNewFile)
      Nothing          -> sourceLength
    outputFileSize = FileSize outputLength
    records        = ninja2Records patch
    overflowActionIndex = streamEndIndex records

    -- | Initial buffer state: copy the source bytes (clipped at the
    -- output length, in case the patch is shrinking) and zero-fill
    -- any tail past the source. After this call the buffer is fully
    -- populated; subsequent record writes overlay it.
    seedBuffer :: Ptr Word8 -> IO ()
    seedBuffer outputPointer = do
      copyByteStringRange outputPointer 0 source 0 (min sourceLength outputLength)
      when (outputLength > sourceLength) $
        fillBytes (outputPointer `plusPtr` sourceLength)
                  (0 :: Word8)
                  (outputLength - sourceLength)

    -- | Per-record guard: the XOR record's write region must fit
    -- within the output buffer. Reports the record's start offset
    -- and payload length so the renderer can name the exact violation.
    checkRecordFits :: ActionIndex -> Offset -> Length
                    -> Either ApplyError ()
    checkRecordFits actionIndex writePosition recordLength
      | not (fitsWithin writePosition recordLength outputFileSize) =
          Left (ApplyAbsoluteWritePastTarget actionIndex
                 writePosition
                 (RequestedLength recordLength)
                 outputFileSize)
      | otherwise = Right ()

    -- | Materialise one XOR record into the output buffer:
    -- @output[writePosition+i] = output[writePosition+i] XOR payload[i]@
    -- for @i@ in @[0, recordLength)@. Bounds are the caller's
    -- responsibility; 'checkRecordFits' ran upstream of this call.
    executeXorRecord :: Ptr Word8 -> Offset -> ByteString.ByteString -> IO ()
    executeXorRecord outputPointer writePosition xorPayload =
        writeRemainingBytes 0
      where
        recordLength = ByteString.length xorPayload
        writeBase    = outputPointer `plusPtr` unOffset writePosition
        writeRemainingBytes !byteOffset
          | byteOffset >= recordLength = pure ()
          | otherwise = do
              original <- peekByteOff writeBase byteOffset :: IO Word8
              pokeByteOff writeBase byteOffset
                (original `xor` ByteString.index xorPayload byteOffset)
              writeRemainingBytes (byteOffset + 1)

    -- | Tail-recursive walk over the record list. End-of-stream
    -- hands control to 'applyOverflowAppend'; a per-record bounds
    -- failure returns immediately with the structured error.
    applyRecords :: Ptr Word8 -> ActionIndex -> [NINJA2Record]
                 -> IO (Maybe ApplyError)
    applyRecords outputPointer _actionIndex [] =
      applyOverflowAppend outputPointer
    applyRecords outputPointer !actionIndex
                 (NINJA2Record writePosition xorPayload : remainingRecords) =
      case checkRecordFits actionIndex writePosition (byteLength xorPayload) of
        Left err -> pure (Just err)
        Right () -> do
          executeXorRecord outputPointer writePosition xorPayload
          applyRecords outputPointer (nextAction actionIndex) remainingRecords

    -- | Append-mode overflow: the payload is XOR'd with @0xFF@ on
    -- disk and is written at the source-size boundary (or at
    -- 'sourceLength' if 'OPEN_NEW_FILE' is absent). Truncate-mode
    -- overflow is a no-op here — see the function-level comment for
    -- why. Bounds-checked with the same shape as the per-record
    -- check; the synthetic action index is one past the last record.
    applyOverflowAppend :: Ptr Word8 -> IO (Maybe ApplyError)
    applyOverflowAppend outputPointer =
      case (ninja2OverflowType patch, ninja2Overflow patch) of
        (Just OverflowAppend, Just overflow) ->
          let appendPosition = Offset $ case ninja2OpenNewFile patch of
                Just openNewFile -> unFileSize (openNewFileSourceSize openNewFile)
                Nothing          -> sourceLength
              decoded        = ByteString.map (xor 0xFF) overflow
              decodedLength  = byteLength decoded
          in case checkRecordFits overflowActionIndex appendPosition decodedLength of
               Left err -> pure (Just err)
               Right () -> do
                 copyByteStringRange outputPointer (unOffset appendPosition)
                                     decoded 0 (ByteString.length decoded)
                 pure Nothing
        _ -> pure Nothing

    runApply outputPointer = do
      seedBuffer outputPointer
      applyRecords outputPointer firstAction records
