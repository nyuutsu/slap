module Slap.PMSR.Apply
  ( applyPMSRMemory
  ) where

import Slap.PMSR.Types (PMSRPatch(..), PMSRRecord(..))
import Slap.Binary (copyByteStringRange)
import Slap.Error (SlapError)
import Slap.Measure (offsetToInt)

import Slap.FileContents (SourceFileContents(..), TargetFileContents(..))

import qualified Data.ByteString as ByteString
import Data.ByteString.Internal (unsafeCreate)
import Data.Word (Word8)
import Control.Monad (forM_, when)
import Foreign.Marshal.Utils (fillBytes)
import Foreign.Ptr (plusPtr)

-- | Apply a PMSR patch in memory: copy source, then overwrite at offsets.
applyPMSRMemory :: PMSRPatch -> SourceFileContents -> Either SlapError TargetFileContents
applyPMSRMemory patch (SourceFileContents source) = Right $ TargetFileContents $ unsafeCreate outputSize $ \targetPointer -> do
    copyByteStringRange targetPointer 0 source 0 (min sourceLength outputSize)
    when (outputSize > sourceLength) $
      fillBytes (targetPointer `plusPtr` sourceLength) (0 :: Word8) (outputSize - sourceLength)
    forM_ (pmsrRecords patch) $ \record ->
      copyByteStringRange targetPointer (offsetToInt (pmsrOffset record)) (pmsrData record) 0 (ByteString.length (pmsrData record))
  where
    sourceLength = ByteString.length source
    outputSize = foldl' max sourceLength
      [ offsetToInt (pmsrOffset record) + ByteString.length (pmsrData record) | record <- pmsrRecords patch ]
