module Patch.PPF.Apply (applyPatch, applyPatchMemory, undoPatch) where

import Patch.PPF.Types
import Patch.Binary (copyBSRange)

import qualified Data.ByteString as BS
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
applyPatch patch target = withBinaryFile target ReadWriteMode $ \h -> do
  n <- writeRecords h (patchRecords patch) recData
  pure ([], n)

-- | Undo a parsed PPF3 patch (requires undo data).
undoPatch :: Patch -> FilePath -> IO (Either String Int)
undoPatch patch target
  | not (patchHasUndo patch) = pure (Left "PPF: patch has no undo data")
  | otherwise = withBinaryFile target ReadWriteMode $ \h ->
      Right <$> writeRecords h (patchRecords patch) (fromMaybe BS.empty . recUndo)

-- Write records to a handle, selecting the data or undo payload per record.
writeRecords :: Handle -> [Record] -> (Record -> ByteString) -> IO Int
writeRecords h recs selector = foldM step 0 recs
  where
    step n r
      | BS.null dat = pure n
      | otherwise = do
          case recCmd r of
            Append  -> hSeek h SeekFromEnd 0
            Replace -> hSeek h AbsoluteSeek (fromIntegral (recOffset r))
          BS.hPut h dat
          pure (n + 1)
      where dat = selector r

-- | Apply a PPF patch in memory.
-- Simulates file-size tracking for Append records (PPF4).
applyPatchMemory :: Patch -> ByteString -> ByteString
applyPatchMemory patch source = unsafeCreate outLen $ \ptr -> do
    copyBSRange ptr 0 source 0 (min srcLen outLen)
    when (outLen > srcLen) $
      fillBytes (ptr `plusPtr` srcLen) (0 :: Word8) (outLen - srcLen)
    -- Track current end-of-file position for Append records
    foldM_ (applyRec ptr) srcLen (patchRecords patch)
  where
    srcLen = BS.length source
    -- Compute output size: simulate file growth from Replace and Append
    outLen = foldl' step srcLen (patchRecords patch)
    step curSize r = case recCmd r of
      Replace -> max curSize (fromIntegral (recOffset r) + BS.length (recData r))
      Append  -> curSize + BS.length (recData r)
    applyRec ptr curEnd r
      | BS.null (recData r) = pure curEnd
      | otherwise = case recCmd r of
          Replace -> do
            let off = fromIntegral (recOffset r) :: Int
            copyBSRange ptr off (recData r) 0 (BS.length (recData r))
            pure (max curEnd (off + BS.length (recData r)))
          Append -> do
            copyBSRange ptr curEnd (recData r) 0 (BS.length (recData r))
            pure (curEnd + BS.length (recData r))

