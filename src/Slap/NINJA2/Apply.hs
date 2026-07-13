module Slap.NINJA2.Apply
  ( applyNINJA2
  ) where

import Slap.NINJA2.Types
import Slap.Status (SlapError(..), ApplyError(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.Binary (copyRegion, fillNewBuffer, seedBufferFromSource)
import Slap.Measure (Offset(..), Length, FileSize(..),
                     ActionIndex, RequestedLength(..),
                     byteFileSize, byteLength, fileSizeToOffset, fitsWithin, plusOffset,
                     firstAction, nextAction, streamEndIndex)

import Slap.FileContents (InputFileContents(..), OutputFileContents(..))

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.Bits (xor)
import Data.Word (Word8)
import Foreign.Ptr (Ptr)
import Foreign.Storable (peekByteOff, pokeByteOff)
import System.IO.Unsafe (unsafePerformIO)

-- | Walks two write streams: the XOR record list and (when present) the append-mode overflow payload.
-- Both carry absolute wire offsets, so a malformed patch can name a write past the declared target end;
-- every such write is bounds-checked at its boundary,
-- and the apply returns 'Left' with 'ApplyAbsoluteWritePastTarget' naming which write went out of bounds and by how much.
--
-- Truncate-mode overflow is silent: its payload is the discarded source tail, preserved for round-trip and *not* applied.
-- The smaller output buffer already encodes the truncation.
-- Only append-mode overflow drives a write, so it alone needs a bounds check.
--
-- The action-index space covers the XOR record stream (@0 .. length records - 1@);
-- the overflow-append step, when present, takes the index immediately after the last record (@length records@).
-- So an OOB on the append shows up one index past the last record, unambiguous against an OOB on a specific record.
applyNINJA2 :: NINJA2Patch -> InputFileContents -> Either SlapError OutputFileContents
applyNINJA2 patch (InputFileContents source)
  | outputFileSize < FileSize 0 =
      Left (NegativeTargetSize LabelNINJA2 outputFileSize)
  | otherwise = unsafePerformIO $ do
      (result, maybeErr) <- fillNewBuffer outputFileSize runApply
      pure $ case maybeErr of
        Just applyErr -> Left (ApplyFailed LabelNINJA2 applyErr)
        Nothing       -> Right (OutputFileContents result)
  where
    outputFileSize = maybe (byteFileSize source) openNewFileTargetSize (ninja2OpenNewFile patch)
    records        = ninja2Records patch
    overflowActionIndex = streamEndIndex records

    -- | Per-record guard: the XOR record's write region must fit
    -- within the output buffer. Reports the record's start offset
    -- and payload length so the renderer can name the exact violation.
    checkRecordFits :: ActionIndex -> Offset -> Length
                    -> Either ApplyError ()
    checkRecordFits actionIndex writePosition recordLength
      | unOffset writePosition < 0 =
          Left (ApplyNegativeRecordOffset actionIndex writePosition)
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
    executeXorRecord :: Ptr Word8 -> Offset -> ByteString -> IO ()
    executeXorRecord outputPointer writePosition xorPayload =
        writeRemainingBytes 0
      where
        recordLength = ByteString.length xorPayload
        writeBase    = outputPointer `plusOffset` writePosition
        writeRemainingBytes !byteOffset
          | byteOffset >= recordLength = pure ()
          | otherwise = do
              original <- peekByteOff writeBase byteOffset :: IO Word8
              pokeByteOff writeBase byteOffset
                (original `xor` ByteString.index xorPayload byteOffset)
              writeRemainingBytes (byteOffset + 1)

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

    -- | Append-mode overflow: the payload is XOR'd with @0xFF@ on disk and written at the source-size boundary
    -- (or at the source's own size if 'OPEN_NEW_FILE' is absent).
    -- Truncate-mode overflow is a no-op here; see the function-level comment for why.
    applyOverflowAppend :: Ptr Word8 -> IO (Maybe ApplyError)
    applyOverflowAppend outputPointer =
      case (ninja2OverflowType patch, ninja2Overflow patch) of
        (Just OverflowAppend, Just overflow) ->
          let appendPosition = fileSizeToOffset $ case ninja2OpenNewFile patch of
                Just openNewFile -> openNewFileSourceSize openNewFile
                Nothing          -> byteFileSize source
              decoded        = ByteString.map (xor 0xFF) overflow
              decodedLength  = byteLength decoded
          in case checkRecordFits overflowActionIndex appendPosition decodedLength of
               Left err -> pure (Just err)
               Right () -> do
                 copyRegion outputPointer appendPosition
                            decoded (Offset 0) (byteLength decoded)
                 pure Nothing
        _ -> pure Nothing

    runApply outputPointer = do
      seedBufferFromSource outputPointer outputFileSize source
      applyRecords outputPointer firstAction records
