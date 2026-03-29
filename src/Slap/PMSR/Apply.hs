module Slap.PMSR.Apply
  ( applyPMSR
  , applyPMSRMemory
  ) where

import Slap.PMSR.Types (PMSRPatch(..), PMSRRecord(..))
import Slap.Binary (copyByteStringRange)
import Slap.Measure (seekTo, offsetToInt)

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.ByteString.Internal (unsafeCreate)
import Data.Word (Word8)
import Control.Monad (forM_, when)
import Foreign.Marshal.Utils (fillBytes)
import Foreign.Ptr (plusPtr)
import System.IO

applyPMSR :: PMSRPatch -> FilePath -> IO Int
applyPMSR patch target = withBinaryFile target ReadWriteMode $ \handle -> do
  mapM_ (applyRecord handle) (pmsrRecords patch)
  pure (length (pmsrRecords patch))
  where
    applyRecord handle record = do
      seekTo handle (pmsrOffset record)
      ByteString.hPut handle (pmsrData record)

-- | Apply a PMSR patch in memory: copy source, then overwrite at offsets.
applyPMSRMemory :: PMSRPatch -> ByteString -> ByteString
applyPMSRMemory patch source = unsafeCreate outputSize $ \targetPointer -> do
    copyByteStringRange targetPointer 0 source 0 (min sourceLength outputSize)
    when (outputSize > sourceLength) $
      fillBytes (targetPointer `plusPtr` sourceLength) (0 :: Word8) (outputSize - sourceLength)
    forM_ (pmsrRecords patch) $ \record ->
      copyByteStringRange targetPointer (offsetToInt (pmsrOffset record)) (pmsrData record) 0 (ByteString.length (pmsrData record))
  where
    sourceLength = ByteString.length source
    outputSize = foldl' max sourceLength
      [ offsetToInt (pmsrOffset record) + ByteString.length (pmsrData record) | record <- pmsrRecords patch ]
