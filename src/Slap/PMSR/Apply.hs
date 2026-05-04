module Slap.PMSR.Apply
  ( applyPMSR
  ) where

import Slap.PMSR.Types (PMSRPatch(..), PMSRRecord(..))
import Slap.Binary (copyByteStringRange)
import Slap.Error (SlapError)
import Slap.Measure (offsetToInt,
                     ActionIndex(unActionIndex),
                     firstAction, nextAction, streamEndIndex)

import Slap.FileContents (SourceFileContents(..), TargetFileContents(..))

import qualified Data.ByteString as ByteString
import Data.ByteString.Internal (unsafeCreate)
import qualified Data.Vector as Vector
import Data.Word (Word8)
import Control.Monad (when)
import Foreign.Marshal.Utils (fillBytes)
import Foreign.Ptr (plusPtr)

-- | Apply a PMSR patch in memory: copy source, then overwrite at offsets.
applyPMSR :: PMSRPatch -> SourceFileContents -> Either SlapError TargetFileContents
applyPMSR patch (SourceFileContents source) = Right $ TargetFileContents $ unsafeCreate outputSize $ \targetPointer -> do
    copyByteStringRange targetPointer 0 source 0 (min sourceLength outputSize)
    when (outputSize > sourceLength) $
      fillBytes (targetPointer `plusPtr` sourceLength) (0 :: Word8) (outputSize - sourceLength)
    let applyRecordStream !recordIndex
          | recordIndex >= recordStreamEnd = pure ()
          | otherwise = do
              let record = Vector.unsafeIndex records (unActionIndex recordIndex)
              copyByteStringRange targetPointer
                (offsetToInt (pmsrOffset record))
                (pmsrData record) 0
                (ByteString.length (pmsrData record))
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
