module Slap.DPS.Apply
  ( applyDPS
  ) where

import Slap.DPS.Types (DPSPatch(..), DPSRecord(..), dpsOutputExtent)
import Slap.Binary (copyRegion, fillNewBuffer, fillRegion)
import Slap.Status (SlapError(..), ApplyError(..), addressableByteCount)
import Slap.FormatLabel (FormatLabel(..))
import Slap.Measure (Offset(..), Length, FileSize(..),
                     ActionIndex,
                     RequestedLength(..), RemainingLength(..),
                     advance, fileSizeToLength, fitsWithin, remainingFromOffset,
                     byteLength, byteFileSize,
                     firstAction, nextAction)
import Slap.FileContents (InputFileContents(..), OutputFileContents(..))

import qualified Data.ByteString as ByteString
import Data.Word (Word8)
import Foreign.Ptr (Ptr)
import System.IO.Unsafe (unsafePerformIO)

-- | The output buffer is zero-filled and sized to the furthest record write extent.
-- Bytes not named by any record are zero, matching the reference implementation (dpspatcher.exe).
applyDPS :: DPSPatch -> InputFileContents -> Either SlapError OutputFileContents
applyDPS patch (InputFileContents source)
  | unFileSize outputSize == 0 =
      Right (OutputFileContents ByteString.empty)
  | otherwise = case addressableByteCount LabelDPS outputSize of
      Left refusal          -> Left refusal
      Right addressableSize -> unsafePerformIO $ do
        (result, maybeErr) <- fillNewBuffer addressableSize runApply
        pure $ case maybeErr of
          Just applyErr -> Left (ApplyFailed LabelDPS applyErr)
          Nothing       -> Right (OutputFileContents result)
  where
    records    = dpsRecords patch
    sourceSize = byteFileSize source
    outputSize = dpsOutputExtent records

    -- | Per-record guards for a CopyFromROM record: the source
    -- read must fit in the source ROM, and the resulting write
    -- must fit in the output buffer.
    checkCopyFromRomPreconditions :: ActionIndex -> Offset -> Offset -> Length
                                  -> Either ApplyError ()
    checkCopyFromRomPreconditions recordIndex outputOffset sourceOffset copyLength
      | not (fitsWithin sourceOffset copyLength sourceSize) =
          Left (ApplySourceReadOutOfBounds recordIndex
                 (advance sourceOffset copyLength) sourceSize)
      | not (fitsWithin outputOffset copyLength outputSize) =
          Left (ApplyWritesPastTarget recordIndex
                 (RequestedLength copyLength)
                 (RemainingLength (remainingFromOffset outputOffset outputSize)))
      | otherwise = Right ()

    runApply :: Ptr Word8 -> IO (Maybe ApplyError)
    runApply outputPointer = do
      -- DPS names only the bytes its records write, and 'fillNewBuffer' does not zero the rest.
      fillRegion outputPointer (Offset 0) 0x00 (fileSizeToLength outputSize)
      applyRecordStream firstAction records
      where
        applyRecordStream :: ActionIndex -> [DPSRecord] -> IO (Maybe ApplyError)
        applyRecordStream !_recordIndex [] = pure Nothing
        applyRecordStream recordIndex (record : remainingRecords) =
          handleRecord recordIndex record remainingRecords

        handleRecord :: ActionIndex -> DPSRecord -> [DPSRecord] -> IO (Maybe ApplyError)

        handleRecord recordIndex (DPSCopyFromROM outputOffset sourceOffset copyLength) remainingRecords =
          case checkCopyFromRomPreconditions recordIndex outputOffset sourceOffset copyLength of
            Left err -> pure (Just err)
            Right () -> do
              copyRegion outputPointer outputOffset source sourceOffset copyLength
              applyRecordStream (nextAction recordIndex) remainingRecords

        handleRecord recordIndex (DPSEnclosedData outputOffset payload) remainingRecords =
          let writeLength    = byteLength payload
              remainingSpace = remainingFromOffset outputOffset outputSize
          in if not (fitsWithin outputOffset writeLength outputSize)
               then pure (Just (ApplyWritesPastTarget recordIndex
                                  (RequestedLength writeLength)
                                  (RemainingLength remainingSpace)))
               else do
                 copyRegion outputPointer outputOffset payload (Offset 0) writeLength
                 applyRecordStream (nextAction recordIndex) remainingRecords
