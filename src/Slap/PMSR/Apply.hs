module Slap.PMSR.Apply
  ( applyPMSR
  ) where

import Slap.PMSR.Types (PMSRPatch(..), PMSRRecord(..))
import Slap.Binary (copyRegion)
import Slap.Status (SlapError)
import Slap.Measure (Offset(..), Length(..), offsetToInt, byteLength,
                     ActionIndex(unActionIndex),
                     firstAction, nextAction, streamEndIndex)

import Slap.FileContents (InputFileContents(..), OutputFileContents(..))

import qualified Data.ByteString as ByteString
import Data.ByteString.Internal (unsafeCreate)
import qualified Data.Vector as Vector
import Data.Word (Word8)
import Control.Monad (when)
import Foreign.Marshal.Utils (fillBytes)
import Foreign.Ptr (plusPtr)

-- | Apply a PMSR patch in memory: copy source, then overwrite at offsets.
applyPMSR :: PMSRPatch -> InputFileContents -> Either SlapError OutputFileContents
applyPMSR patch (InputFileContents source) = Right $ OutputFileContents $ unsafeCreate outputSize $ \targetPointer -> do
    copyRegion targetPointer (Offset 0) source (Offset 0) (Length (min sourceLength outputSize))
    when (outputSize > sourceLength) $
      fillBytes (targetPointer `plusPtr` sourceLength) (0 :: Word8) (outputSize - sourceLength)
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
    sourceLength    = ByteString.length source
    outputSize      = Vector.foldl' extendOutputBoundary sourceLength records

    extendOutputBoundary boundarySoFar record =
      max boundarySoFar (recordEndPosition record)

    recordEndPosition record =
      offsetToInt (pmsrOffset record) + ByteString.length (pmsrData record)
