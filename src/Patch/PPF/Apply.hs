module Patch.PPF.Apply (applyPatch, applyPatchMemory, undoPatch) where

import Patch.PPF.Types
import Patch.Binary (copyByteStringRange)
import Patch.Measure (seekTo, offsetToInt)

import qualified Data.ByteString as ByteString
import Data.ByteString (ByteString)
import Data.ByteString.Internal (unsafeCreate)
import Data.Maybe (fromMaybe)
import Control.Monad (foldM, foldM_, when)
import Foreign.Marshal.Utils (fillBytes)
import Foreign.Ptr (plusPtr)
import Data.Word (Word8)
import System.IO

-- | Apply a parsed PPF patch to a target file.
applyPatch :: Patch -> FilePath -> IO ([String], Int)
applyPatch patch target = withBinaryFile target ReadWriteMode $ \handle -> do
  written <- writeRecords handle (ppfRecords patch) recordData
  pure ([], written)

-- | Undo a parsed PPF3 patch (requires undo data).
undoPatch :: Patch -> FilePath -> IO (Either String Int)
undoPatch patch target
  | not (ppfHasUndo patch) = pure (Left "PPF: patch has no undo data")
  | otherwise = withBinaryFile target ReadWriteMode $ \handle ->
      Right <$> writeRecords handle (ppfRecords patch) (fromMaybe ByteString.empty . recordUndo)

-- Write records to a handle, selecting the data or undo payload per record.
writeRecords :: Handle -> [Record] -> (Record -> ByteString) -> IO Int
writeRecords handle records selector = foldM step 0 records
  where
    step written record
      | ByteString.null payload = pure written
      | otherwise = do
          case recordCommand record of
            Append  -> hSeek handle SeekFromEnd 0
            Replace -> seekTo handle (recordOffset record)
          ByteString.hPut handle payload
          pure (written + 1)
      where payload = selector record

-- | Apply a PPF patch in memory.
-- Simulates file-size tracking for Append records (PPF4).
applyPatchMemory :: Patch -> ByteString -> ByteString
applyPatchMemory patch source = unsafeCreate outputLength $ \outputPointer -> do
    copyByteStringRange outputPointer 0 source 0 (min sourceLength outputLength)
    when (outputLength > sourceLength) $
      fillBytes (outputPointer `plusPtr` sourceLength) (0 :: Word8) (outputLength - sourceLength)
    -- Track current end-of-file position for Append records
    foldM_ (applyRecord outputPointer) sourceLength (ppfRecords patch)
  where
    sourceLength = ByteString.length source
    -- Compute output size: simulate file growth from Replace and Append
    outputLength = foldl' accumulateSize sourceLength (ppfRecords patch)
    accumulateSize currentSize record = case recordCommand record of
      Replace -> max currentSize (offsetToInt (recordOffset record) + ByteString.length (recordData record))
      Append  -> currentSize + ByteString.length (recordData record)
    applyRecord outputPointer currentEnd record
      | ByteString.null (recordData record) = pure currentEnd
      | otherwise = case recordCommand record of
          Replace -> do
            let writePosition = offsetToInt (recordOffset record)
            copyByteStringRange outputPointer writePosition (recordData record) 0 (ByteString.length (recordData record))
            pure (max currentEnd (writePosition + ByteString.length (recordData record)))
          Append -> do
            copyByteStringRange outputPointer currentEnd (recordData record) 0 (ByteString.length (recordData record))
            pure (currentEnd + ByteString.length (recordData record))
