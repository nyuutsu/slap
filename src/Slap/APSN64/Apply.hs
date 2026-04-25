module Slap.APSN64.Apply
  ( applyAPSN64
  , applyN64Record
  , applyAPSN64Memory
  ) where

import Slap.APSN64.Types
import Slap.Measure (offsetToInt, seekTo)
import Slap.Binary (copyByteStringRange)

import Slap.FileContents (SourceFileContents(..), TargetFileContents(..))

import qualified Data.ByteString as ByteString
import Data.ByteString.Internal (unsafeCreate)
import qualified Data.Foldable as Foldable
import Data.Word (Word8)
import Control.Monad (forM_, when)
import Foreign.Marshal.Utils (fillBytes)
import Foreign.Ptr (plusPtr)
import System.IO

applyAPSN64 :: APSN64Patch -> FilePath -> IO Int
applyAPSN64 (APSN64Patch _ records) target = withBinaryFile target ReadWriteMode $ \handle -> do
  mapM_ (applyN64Record handle) records
  pure (Foldable.length records)

applyN64Record :: Handle -> APSN64Record -> IO ()
applyN64Record handle (APSN64Normal writeOffset writePayload) = do
  seekTo handle writeOffset
  ByteString.hPut handle writePayload
applyN64Record handle (APSN64RLE writeOffset fillValue fillCount) = do
  seekTo handle writeOffset
  ByteString.hPut handle (ByteString.replicate (fromIntegral fillCount) fillValue)

applyAPSN64Memory :: APSN64Patch -> SourceFileContents -> TargetFileContents
applyAPSN64Memory (APSN64Patch _ records) (SourceFileContents source) = TargetFileContents $ unsafeCreate outputLength $ \targetPointer -> do
    copyByteStringRange targetPointer 0 source 0 (min sourceLength outputLength)
    when (outputLength > sourceLength) $
      fillBytes (targetPointer `plusPtr` sourceLength) (0 :: Word8) (outputLength - sourceLength)
    forM_ records $ \case
      APSN64Normal writeOffset writePayload ->
        copyByteStringRange targetPointer (offsetToInt writeOffset) writePayload 0 (ByteString.length writePayload)
      APSN64RLE writeOffset fillValue fillCount ->
        fillBytes (targetPointer `plusPtr` offsetToInt writeOffset) fillValue (fromIntegral fillCount)
  where
    sourceLength = ByteString.length source
    recordEnd (APSN64Normal recordOffset recordPayload) = offsetToInt recordOffset + ByteString.length recordPayload
    recordEnd (APSN64RLE recordOffset _ recordCount) = offsetToInt recordOffset + fromIntegral recordCount
    outputLength = Foldable.foldl' max sourceLength (fmap recordEnd records)

