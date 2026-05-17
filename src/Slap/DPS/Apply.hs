module Slap.DPS.Apply
  ( applyDPS
  ) where

import Slap.DPS.Types (DPSPatch(..), DPSRecord(..), dpsOutputExtent)
import Slap.Binary (copyRegion)
import Slap.Status (SlapError(..), ApplyError(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.Measure (Offset(..), FileSize(..),
                     ActionIndex,
                     RequestedLength(..), RemainingLength(..),
                     advance, fitsWithin, remainingFromOffset,
                     byteLength, byteFileSize,
                     firstAction, nextAction)
import Slap.FileContents (InputFileContents(..), OutputFileContents(..))

import qualified Data.ByteString as ByteString
import Data.ByteString.Internal (createAndTrim')
import Data.Word (Word8)
import Foreign.Ptr (Ptr)
import System.IO.Unsafe (unsafePerformIO)

----------------------------------------------------------------------------
-- applyDPS
----------------------------------------------------------------------------

-- | Apply a parsed DPS patch to a source ByteString. The output buffer
-- is zero-filled and sized to the furthest record write extent — bytes
-- not named by any record are zero, matching the reference
-- implementation (dpspatcher.exe). Returns 'Left' with a structured
-- error if a CopyFromROM record references bytes past the end of the
-- source or if a record's write region exceeds the computed output
-- extent.
applyDPS :: DPSPatch -> InputFileContents -> Either SlapError OutputFileContents
applyDPS patch (InputFileContents source)
  | unFileSize outputSize < 0 =
      Left (NegativeTargetSize LabelDPS outputSize)
  | unFileSize outputSize == 0 =
      Right (OutputFileContents ByteString.empty)
  | otherwise = unsafePerformIO $ do
      (result, outcome) <- createAndTrim' (unFileSize outputSize) $ \outputPointer -> do
        maybeErr <- runApply outputPointer
        pure (0, unFileSize outputSize, maybeErr)
      pure $ case outcome of
        Just applyErr -> Left (ApplyFailed LabelDPS applyErr)
        Nothing       -> Right (OutputFileContents result)
  where
    records    = dpsRecords patch
    sourceSize = byteFileSize source
    outputSize = dpsOutputExtent records

    runApply :: Ptr Word8 -> IO (Maybe ApplyError)
    runApply outputPointer =
      let
        applyRecordStream :: ActionIndex -> [DPSRecord] -> IO (Maybe ApplyError)
        applyRecordStream !_recordIndex [] = pure Nothing
        applyRecordStream !recordIndex (record : remaining) =
          handleRecord recordIndex record remaining

        handleRecord :: ActionIndex -> DPSRecord -> [DPSRecord] -> IO (Maybe ApplyError)

        handleRecord recordIndex (DPSCopyFromROM outputOffset sourceOffset copyLength) remaining =
          let readEnd        = advance sourceOffset copyLength
              writeLength    = copyLength
              remainingSpace = remainingFromOffset outputOffset outputSize
          in if not (fitsWithin sourceOffset copyLength sourceSize)
               then pure (Just (ApplySourceReadOutOfBounds recordIndex readEnd sourceSize))
               else if not (fitsWithin outputOffset writeLength outputSize)
               then pure (Just (ApplyWritesPastTarget recordIndex
                                  (RequestedLength writeLength)
                                  (RemainingLength remainingSpace)))
               else do
                 copyRegion outputPointer outputOffset source sourceOffset copyLength
                 applyRecordStream (nextAction recordIndex) remaining

        handleRecord recordIndex (DPSEnclosedData outputOffset payload) remaining =
          let writeLength    = byteLength payload
              remainingSpace = remainingFromOffset outputOffset outputSize
          in if not (fitsWithin outputOffset writeLength outputSize)
               then pure (Just (ApplyWritesPastTarget recordIndex
                                  (RequestedLength writeLength)
                                  (RemainingLength remainingSpace)))
               else do
                 copyRegion outputPointer outputOffset payload (Offset 0) writeLength
                 applyRecordStream (nextAction recordIndex) remaining

      in applyRecordStream firstAction records
