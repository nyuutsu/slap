module Slap.IPS.Apply
  ( applyIPS
  , applyRecords
  , applyIPSMemory
  ) where

import Slap.IPS.Types (IPSRecord(..), IPSPatch(..))
import Slap.Binary (copyByteStringRange)
import Slap.Measure (Offset(..), Length(..), FileSize(..), seekTo, offsetToInt)

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.ByteString.Internal (unsafeCreate)
import Data.Word (Word8)
import Control.Monad (forM_, when)
import Foreign.Marshal.Utils (fillBytes)
import Foreign.Ptr (plusPtr)
import System.IO

-- | Apply an IPS patch to a target file (seek-and-write).
applyIPS :: IPSPatch -> FilePath -> IO Int
applyIPS patch target = withBinaryFile target ReadWriteMode $ \handle -> do
  written <- applyRecords handle (ipsRecords patch)
  case ipsTruncate patch of
    Just truncSize -> hSetFileSize handle (fromIntegral (unFileSize truncSize))
    Nothing        -> pure ()
  pure written

applyRecords :: Handle -> [IPSRecord] -> IO Int
applyRecords handle records = do
  mapM_ applyOne records
  pure (length records)
  where
    applyOne (IPSRecord writeOffset writePayload) = do
      seekTo handle writeOffset
      ByteString.hPut handle writePayload
    applyOne (IPSRecordRLE writeOffset fillCount fillValue) = do
      seekTo handle writeOffset
      ByteString.hPut handle (ByteString.replicate (unLength fillCount) fillValue)

-- | Apply an IPS patch in memory. Supports truncation (ipsTruncate) and
-- RLE records -- both are optional IPS features that many patchers omit.
applyIPSMemory :: IPSPatch -> ByteString -> ByteString
applyIPSMemory patch source = unsafeCreate outputLength $ \outputPointer -> do
    copyByteStringRange outputPointer 0 source 0 (min sourceLength outputLength)
    when (outputLength > sourceLength) $
      fillBytes (outputPointer `plusPtr` sourceLength) (0 :: Word8) (outputLength - sourceLength)
    forM_ (ipsRecords patch) $ \case
      IPSRecord writeOffset writePayload ->
        copyByteStringRange outputPointer (offsetToInt writeOffset) writePayload 0 (ByteString.length writePayload)
      IPSRecordRLE writeOffset fillCount fillValue ->
        fillBytes (outputPointer `plusPtr` offsetToInt writeOffset) fillValue (unLength fillCount)
  where
    sourceLength = ByteString.length source
    recordEnd (IPSRecord recordOffset recordPayload) = offsetToInt recordOffset + ByteString.length recordPayload
    recordEnd (IPSRecordRLE recordOffset fillCount _) = offsetToInt recordOffset + unLength fillCount
    maxRecordEnd = foldl' max sourceLength (map recordEnd (ipsRecords patch))
    outputLength = case ipsTruncate patch of
      Just truncSize -> fromIntegral (unFileSize truncSize)
      Nothing        -> maxRecordEnd
