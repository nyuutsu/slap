module Slap.DPS.Apply
  ( applyDPS
  ) where

import Slap.DPS.Types (DPSPatch(..), DPSRecord(..), dpsOutputExtent)
import Slap.Binary (copyRegion)
import Slap.Error (SlapError(..), ApplyError(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.Measure (Offset(..), FileSize(..),
                     ActionIndex,
                     RequestedLength(..), RemainingLength(..),
                     advance, fitsWithin, remainingFromOffset,
                     byteLength, byteFileSize,
                     firstAction, nextAction)
import Slap.FileContents (SourceFileContents(..), TargetFileContents(..))

import qualified Data.ByteString as ByteString
import Data.ByteString.Internal (create)
import Data.IORef (IORef, newIORef, readIORef, writeIORef)
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
applyDPS :: DPSPatch -> SourceFileContents -> Either SlapError TargetFileContents
applyDPS patch (SourceFileContents source)
  | unFileSize outputSize < 0 =
      Left (NegativeTargetSize LabelDPS outputSize)
  | unFileSize outputSize == 0 =
      Right (TargetFileContents ByteString.empty)
  | otherwise = unsafePerformIO $ do
      errorRef <- newIORef Nothing
      result <- create (unFileSize outputSize) $ \outputPointer ->
        runApply outputPointer errorRef
      errorState <- readIORef errorRef
      pure $ case errorState of
        Just applyErr -> Left (ApplyFailed LabelDPS applyErr)
        Nothing       -> Right (TargetFileContents result)
  where
    records    = dpsRecords patch
    sourceSize = byteFileSize source
    outputSize = dpsOutputExtent records

    runApply :: Ptr Word8 -> IORef (Maybe ApplyError) -> IO ()
    runApply outputPointer errorRef =
      let
        abort :: ApplyError -> IO ()
        abort applyErr = writeIORef errorRef (Just applyErr)

        applyRecordStream :: ActionIndex -> [DPSRecord] -> IO ()
        applyRecordStream !_recordIndex [] = pure ()
        applyRecordStream !recordIndex (record : remaining) =
          handleRecord recordIndex record remaining

        handleRecord :: ActionIndex -> DPSRecord -> [DPSRecord] -> IO ()

        handleRecord recordIndex (DPSCopyFromROM outputOffset sourceOffset copyLength) remaining =
          let readEnd        = advance sourceOffset copyLength
              writeLength    = copyLength
              remainingSpace = remainingFromOffset outputOffset outputSize
          in if not (fitsWithin sourceOffset copyLength sourceSize)
               then abort (ApplySourceReadOutOfBounds recordIndex readEnd sourceSize)
               else if not (fitsWithin outputOffset writeLength outputSize)
               then abort (ApplyWritesPastTarget recordIndex
                            (RequestedLength writeLength)
                            (RemainingLength remainingSpace))
               else do
                 copyRegion outputPointer outputOffset source sourceOffset copyLength
                 applyRecordStream (nextAction recordIndex) remaining

        handleRecord recordIndex (DPSEnclosedData outputOffset payload) remaining =
          let writeLength    = byteLength payload
              remainingSpace = remainingFromOffset outputOffset outputSize
          in if not (fitsWithin outputOffset writeLength outputSize)
               then abort (ApplyWritesPastTarget recordIndex
                            (RequestedLength writeLength)
                            (RemainingLength remainingSpace))
               else do
                 copyRegion outputPointer outputOffset payload (Offset 0) writeLength
                 applyRecordStream (nextAction recordIndex) remaining

      in applyRecordStream firstAction records
