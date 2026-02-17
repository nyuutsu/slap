module Patch.PPF.Apply (applyPatch, undoPatch, validateTarget) where

import Patch.PPF.Types

import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.Int (Int64)
import Data.Maybe (fromMaybe)
import Data.Word (Word64)
import Control.Monad (foldM)
import Numeric (showHex)
import System.IO

-- | Apply a parsed PPF patch to a target file.
-- Returns warnings (if any) and the number of records applied.
applyPatch :: Patch -> FilePath -> IO ([String], Int)
applyPatch patch target = withBinaryFile target ReadWriteMode $ \h -> do
  warnings <- validateTarget patch h
  n <- writeRecords h (patchRecords patch) recData
  pure (warnings, n)

-- | Undo a parsed PPF3 patch (requires undo data).
undoPatch :: Patch -> FilePath -> IO (Either String Int)
undoPatch patch target
  | not (patchHasUndo patch) = pure (Left "patch has no undo data")
  | otherwise = withBinaryFile target ReadWriteMode $ \h ->
      Right <$> writeRecords h (patchRecords patch) (fromMaybe BS.empty . recUndo)

-- | Validate the target file against the patch's embedded checks.
-- Returns a list of warnings (empty = all good).
validateTarget :: Patch -> Handle -> IO [String]
validateTarget patch h = do
  sizeWarns <- case patchFileSize patch of
    Nothing -> pure []
    Just expected -> do
      actual <- hFileSize h
      pure [ "warning: file size mismatch (expected "
             ++ show expected ++ ", got " ++ show actual ++ ")"
           | fromIntegral expected /= actual ]
  blockWarns <- case patchValidation patch of
    Nothing -> pure []
    Just val -> do
      let off = validationOffset (valImageType val)
      actual <- readAt h off validationSize
      pure [ "warning: validation block mismatch at 0x"
             ++ showHex (fromIntegral off :: Word64) ""
           | actual /= valBlock val ]
  pure (sizeWarns ++ blockWarns)

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

-- Read n bytes from a handle at a given offset.
readAt :: Handle -> Int64 -> Int -> IO ByteString
readAt h off n = do
  hSeek h AbsoluteSeek (fromIntegral off)
  BS.hGet h n
