module Patch.PPF.Apply (applyPatch, undoPatch) where

import Patch.PPF.Types

import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.Maybe (fromMaybe)
import Control.Monad (foldM)
import System.IO

-- | Apply a parsed PPF patch to a target file.
-- Returns warnings (if any) and the number of records applied.
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

-- Write records to a handle using a selector function (recData for apply, recUndo for undo).
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

