module Slap.PPF.Apply (applyPatchMemory, undoPatchMemory) where

import Slap.PPF.Types (PPFPatch(..), PPFRecord(..), PPFRecordCommand(..),
                        ppfVersionLabel)
import Slap.Binary (copyByteStringRange, copyRegion)
import Slap.Error (SlapError(..), ApplyError(..))
import Slap.Measure (Offset(..), Length(..), FileSize(..),
                     ActionIndex(..),
                     RequestedLength(..), RemainingLength(..),
                     fitsWithin, remainingFromOffset, minLength,
                     advance, byteLength, offsetToInt,
                     firstAction, nextAction, plusOffset)

import Slap.FileContents (SourceFileContents(..), TargetFileContents(..))

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.ByteString.Internal (create, unsafeCreate)
import Data.IORef (IORef, newIORef, readIORef, writeIORef)
import Data.Maybe (fromMaybe)
import Control.Monad (when, unless)
import Foreign.Marshal.Utils (fillBytes)
import Foreign.Ptr (Ptr)
import Data.Word (Word8)
import System.IO.Unsafe (unsafePerformIO)

-- | Apply a PPF patch in memory.
-- Validates every record write against the output buffer bounds.
-- Returns 'Left' on malformed patches (negative offsets, writes past
-- the buffer); returns 'Right' with byte-identical output on success.
applyPatchMemory :: PPFPatch -> SourceFileContents -> Either SlapError TargetFileContents
applyPatchMemory patch (SourceFileContents source)
  | unFileSize outputFileSize < 0 =
      Left (NegativeTargetSize label outputFileSize)
  | unFileSize outputFileSize == 0 =
      Right (TargetFileContents ByteString.empty)
  | otherwise = unsafePerformIO $ do
      errorRef <- newIORef Nothing
      result <- create (unFileSize outputFileSize) $ \outputPointer -> do
        -- Copy source bytes to output buffer
        copyRegion outputPointer (Offset 0) source (Offset 0) initialCopyLength
        -- Zero-fill any growth past source end
        when (unFileSize outputFileSize > unFileSize sourceFileSize) $
          fillBytes (plusOffset outputPointer (Offset (unFileSize sourceFileSize)))
                    (0 :: Word8)
                    (unFileSize outputFileSize - unFileSize sourceFileSize)
        -- Apply records with bounds checking
        applyRecordStream outputPointer errorRef firstAction
                          (Offset (unFileSize sourceFileSize))
                          (ppfRecords patch)
      errorState <- readIORef errorRef
      pure $ case errorState of
        Just applyErr -> Left (ApplyFailed label applyErr)
        Nothing       -> Right (TargetFileContents result)
  where
    label          = ppfVersionLabel (ppfVersion patch)
    sourceFileSize = FileSize (ByteString.length source)
    outputFileSize = computeOutputFileSize sourceFileSize (ppfRecords patch)
    initialCopyLength = minLength
                          (remainingFromOffset (Offset 0) sourceFileSize)
                          (remainingFromOffset (Offset 0) outputFileSize)

    computeOutputFileSize :: FileSize -> [PPFRecord] -> FileSize
    computeOutputFileSize sourceSize records = foldl' accumulateSize sourceSize records
      where
        accumulateSize :: FileSize -> PPFRecord -> FileSize
        accumulateSize currentSize record = case recordCommand record of
          Replace ->
            let writeEnd = advance (recordOffset record) (byteLength (recordData record))
            in FileSize (max (unFileSize currentSize) (unOffset writeEnd))
          Append ->
            FileSize (unFileSize currentSize + unLength (byteLength (recordData record)))

    applyRecordStream :: Ptr Word8 -> IORef (Maybe ApplyError)
                      -> ActionIndex -> Offset -> [PPFRecord] -> IO ()
    applyRecordStream _ _ _ _ [] = pure ()
    applyRecordStream outputPointer errorRef recordIndex currentEnd (record : rest) =
      case recordCommand record of
        Replace -> handleReplace outputPointer errorRef recordIndex currentEnd record rest
        Append  -> handleAppend outputPointer errorRef recordIndex currentEnd record rest

    handleReplace outputPointer errorRef recordIndex currentEnd record rest
      | unOffset writeOffset < 0 =
          abort errorRef (ApplyNegativeRecordOffset recordIndex writeOffset)
      | not (fitsWithin writeOffset payloadLength outputFileSize) =
          abort errorRef (ApplyWritesPastTarget recordIndex
                           (RequestedLength payloadLength)
                           (RemainingLength (remainingFromOffset writeOffset outputFileSize)))
      | otherwise = do
          copyRegion outputPointer writeOffset (recordData record) (Offset 0) payloadLength
          let writeEnd = Offset (max (unOffset currentEnd)
                                     (unOffset writeOffset + unLength payloadLength))
          applyRecordStream outputPointer errorRef
            (nextAction recordIndex) writeEnd rest
      where
        writeOffset   = recordOffset record
        payloadLength = byteLength (recordData record)

    handleAppend outputPointer errorRef recordIndex currentEnd record rest
      | not (fitsWithin currentEnd payloadLength outputFileSize) =
          abort errorRef (ApplyWritesPastTarget recordIndex
                           (RequestedLength payloadLength)
                           (RemainingLength (remainingFromOffset currentEnd outputFileSize)))
      | otherwise = do
          copyRegion outputPointer currentEnd (recordData record) (Offset 0) payloadLength
          applyRecordStream outputPointer errorRef
            (nextAction recordIndex) (advance currentEnd payloadLength) rest
      where
        payloadLength = byteLength (recordData record)

    abort :: IORef (Maybe ApplyError) -> ApplyError -> IO ()
    abort errorRef applyErr = writeIORef errorRef (Just applyErr)

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
