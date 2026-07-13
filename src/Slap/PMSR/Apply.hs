module Slap.PMSR.Apply
  ( applyPMSR
  ) where

import Slap.PMSR.Types (PMSRPatch(..), PMSRRecord(..))
import Slap.Binary (copyRegion, filledBufferOfSize, seedBufferFromSource)
import Slap.Status (SlapError)
import Slap.Measure (Offset(..), advance, byteFileSize, byteLength, offsetToFileSize,
                     ActionIndex(unActionIndex),
                     firstAction, nextAction, streamEndIndex)

import Slap.FileContents (InputFileContents(..), OutputFileContents(..))

import qualified Data.Vector as Vector

-- | Copy source, then overwrite at offsets.
applyPMSR :: PMSRPatch -> InputFileContents -> Either SlapError OutputFileContents
applyPMSR patch (InputFileContents source) = Right $ OutputFileContents $ filledBufferOfSize outputSize $ \targetPointer -> do
    seedBufferFromSource targetPointer outputSize source
    let applyRecordStream !recordIndex
          | recordIndex >= recordStreamEnd = pure ()
          | otherwise = do
              let record = Vector.unsafeIndex records (unActionIndex recordIndex)
              copyRegion targetPointer
                (pmsrOffset record)
                (pmsrData record) (Offset 0)
                (byteLength (pmsrData record))
              applyRecordStream (nextAction recordIndex)
    applyRecordStream firstAction
  where
    records         = pmsrRecords patch
    recordStreamEnd = streamEndIndex records
    outputSize      = Vector.foldl' extendOutputBoundary (byteFileSize source) records

    extendOutputBoundary boundarySoFar record =
      max boundarySoFar (recordEndPosition record)

    recordEndPosition record =
      offsetToFileSize (advance (pmsrOffset record) (byteLength (pmsrData record)))
