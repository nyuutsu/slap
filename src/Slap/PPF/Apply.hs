module Slap.PPF.Apply (applyPatchMemory, undoPatchMemory) where

import Slap.PPF.Types (PPFPatch(..), PPFRecord(..), PPFRecordCommand(..))
import Slap.Binary (copyByteStringRange)
import Slap.Measure (offsetToInt)

import qualified Data.ByteString as ByteString
import Data.ByteString (ByteString)
import Data.ByteString.Internal (unsafeCreate)
import Data.Maybe (fromMaybe)
import Control.Monad (foldM_, when, unless)
import Foreign.Marshal.Utils (fillBytes)
import Foreign.Ptr (plusPtr)
import Data.Word (Word8)

-- | Apply a PPF patch in memory.
-- Simulates file-size tracking for Append records (PPF4).
applyPatchMemory :: PPFPatch -> ByteString -> ByteString
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

-- | Undo a PPF patch in memory.
-- Restores original bytes at each record offset using stored undo data.
undoPatchMemory :: PPFPatch -> ByteString -> ByteString
undoPatchMemory patch input = unsafeCreate inputLength $ \outputPointer -> do
    copyByteStringRange outputPointer 0 input 0 inputLength
    mapM_ (undoRecord outputPointer) (ppfRecords patch)
  where
    inputLength = ByteString.length input
    undoRecord outputPointer record = case recordCommand record of
      Replace ->
        let undoPayload = fromMaybe ByteString.empty (recordUndo record)
        in unless (ByteString.null undoPayload) $
             copyByteStringRange outputPointer (offsetToInt (recordOffset record))
               undoPayload 0 (ByteString.length undoPayload)
      Append -> pure ()
