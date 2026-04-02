module Slap.APSN64.Apply
  ( applyAPSN64
  , applyN64Record
  , applyAPSN64Memory
  ) where

import Slap.APSN64.Types
import Slap.Measure (offsetToInt, seekTo)
import Slap.Binary (copyByteStringRange)

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.ByteString.Internal (unsafeCreate)
import Data.Word (Word8)
import Control.Monad (forM_, when)
import Foreign.Marshal.Utils (fillBytes)
import Foreign.Ptr (plusPtr)
import System.IO

applyAPSN64 :: APSN64Patch -> FilePath -> IO Int
applyAPSN64 (APSN64Patch _ records) target = withBinaryFile target ReadWriteMode $ \handle -> do
  mapM_ (applyN64Record handle) records
  pure (length records)

applyN64Record :: Handle -> APSN64Record -> IO ()
applyN64Record handle (APSN64Normal writeOffset writePayload) = do
  seekTo handle writeOffset
  ByteString.hPut handle writePayload
applyN64Record handle (APSN64RLE rle) = do
  seekTo handle (apsN64RLEOffset rle)
  ByteString.hPut handle (ByteString.replicate (fromIntegral (apsN64RLERepeatCount rle)) (apsN64RLEFillValue rle))

applyAPSN64Memory :: APSN64Patch -> ByteString -> ByteString
applyAPSN64Memory (APSN64Patch _ records) source = unsafeCreate outputLength $ \targetPointer -> do
    copyByteStringRange targetPointer 0 source 0 (min sourceLength outputLength)
    when (outputLength > sourceLength) $
      fillBytes (targetPointer `plusPtr` sourceLength) (0 :: Word8) (outputLength - sourceLength)
    forM_ records $ \case
      APSN64Normal writeOffset writePayload ->
        copyByteStringRange targetPointer (offsetToInt writeOffset) writePayload 0 (ByteString.length writePayload)
      APSN64RLE rle ->
        fillBytes (targetPointer `plusPtr` offsetToInt (apsN64RLEOffset rle)) (apsN64RLEFillValue rle) (fromIntegral (apsN64RLERepeatCount rle))
  where
    sourceLength = ByteString.length source
    recordEnd (APSN64Normal recordOffset recordPayload) = offsetToInt recordOffset + ByteString.length recordPayload
    recordEnd (APSN64RLE rle)     = offsetToInt (apsN64RLEOffset rle) + fromIntegral (apsN64RLERepeatCount rle)
    outputLength = foldl' max sourceLength (map recordEnd records)

