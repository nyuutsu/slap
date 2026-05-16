{-# LANGUAGE OverloadedStrings #-}

-- | Apply (and undo) a PPF3 patch in memory. Forward apply walks
-- the record stream the same way PPF1/PPF2 do; undo walks the
-- record stream in input order writing the per-record undo
-- payload back. Undo is only meaningful when the patch carries
-- undo data — by construction the parser sets 'ppf3RecordUndo'
-- to 'Just' on every record exactly when the patch's undo flag
-- is set, so 'undoPPF3' returns @Right input@ unchanged on a
-- non-undo patch.
module Slap.PPF3.Apply (applyPPF3, undoPPF3) where

import Slap.PPF3.Types (PPF3Patch(..), PPF3Record(..))
import Slap.Binary (copyRegion)
import Slap.Error (SlapError(..), ApplyError(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.Measure (Offset(..), Length(..), FileSize(..),
                     ActionIndex,
                     RequestedLength(..), RemainingLength(..),
                     fitsWithin, remainingFromOffset, minLength,
                     advance, byteLength, distance, offsetToFileSize,
                     firstAction, nextAction, plusOffset)
import Slap.FileContents (InputFileContents(..), OutputFileContents(..))

import qualified Data.ByteString as ByteString
import Data.ByteString.Internal (createAndTrim')
import Data.Maybe (fromMaybe)
import Control.Monad (when)
import Foreign.Marshal.Utils (fillBytes)
import Foreign.Ptr (Ptr)
import Data.Word (Word8)
import System.IO.Unsafe (unsafePerformIO)

applyPPF3 :: PPF3Patch -> InputFileContents -> Either SlapError OutputFileContents
applyPPF3 patch (InputFileContents source)
  | unFileSize outputFileSize < 0 =
      Left (NegativeTargetSize LabelPPF3 outputFileSize)
  | unFileSize outputFileSize == 0 =
      Right (OutputFileContents ByteString.empty)
  | otherwise = unsafePerformIO $ do
      (result, outcome) <- createAndTrim' (unFileSize outputFileSize) $ \outputPointer -> do
        copyRegion outputPointer (Offset 0) source (Offset 0) initialCopyLength
        when (outputEnd > sourceEnd) $
          fillBytes (plusOffset outputPointer sourceEnd)
                    (0 :: Word8)
                    (unLength (distance sourceEnd outputEnd))
        maybeErr <- applyRecordStream outputPointer firstAction (ppf3Records patch)
        pure (0, unFileSize outputFileSize, maybeErr)
      pure $ case outcome of
        Just applyErr -> Left (ApplyFailed LabelPPF3 applyErr)
        Nothing       -> Right (OutputFileContents result)
  where
    sourceEnd      = Offset (ByteString.length source)
    outputEnd      = computeOutputEnd sourceEnd (ppf3Records patch)
    outputFileSize = offsetToFileSize outputEnd
    initialCopyLength = minLength
                          (distance (Offset 0) sourceEnd)
                          (distance (Offset 0) outputEnd)

    computeOutputEnd :: Offset -> [PPF3Record] -> Offset
    computeOutputEnd sourceBufferEnd = foldl' accumulateEnd sourceBufferEnd
      where
        accumulateEnd currentEnd record =
          let writeEnd = advance (ppf3RecordOffset record)
                                 (byteLength (ppf3RecordPayload record))
          in max currentEnd writeEnd

    applyRecordStream :: Ptr Word8
                      -> ActionIndex -> [PPF3Record] -> IO (Maybe ApplyError)
    applyRecordStream _ _ [] = pure Nothing
    applyRecordStream outputPointer recordIndex (record : rest)
      | unOffset writeOffset < 0 =
          pure (Just (ApplyNegativeRecordOffset recordIndex writeOffset))
      | not (fitsWithin writeOffset payloadLength outputFileSize) =
          pure (Just (ApplyWritesPastTarget recordIndex
                       (RequestedLength payloadLength)
                       (RemainingLength
                          (remainingFromOffset writeOffset outputFileSize))))
      | otherwise = do
          copyRegion outputPointer writeOffset (ppf3RecordPayload record) (Offset 0) payloadLength
          applyRecordStream outputPointer (nextAction recordIndex) rest
      where
        writeOffset   = ppf3RecordOffset record
        payloadLength = byteLength (ppf3RecordPayload record)

undoPPF3 :: PPF3Patch -> OutputFileContents -> Either SlapError InputFileContents
undoPPF3 patch (OutputFileContents input)
  | inputLength == 0 =
      Right (InputFileContents ByteString.empty)
  | otherwise = unsafePerformIO $ do
      (result, outcome) <- createAndTrim' inputLength $ \outputPointer -> do
        copyRegion outputPointer (Offset 0) input (Offset 0) (Length inputLength)
        maybeErr <- undoRecordStream outputPointer firstAction (ppf3Records patch)
        pure (0, inputLength, maybeErr)
      pure $ case outcome of
        Just applyErr -> Left (UndoFailed LabelPPF3 applyErr)
        Nothing       -> Right (InputFileContents result)
  where
    inputLength = ByteString.length input

    undoRecordStream :: Ptr Word8
                     -> ActionIndex -> [PPF3Record] -> IO (Maybe ApplyError)
    undoRecordStream _ _ [] = pure Nothing
    undoRecordStream outputPointer recordIndex (record : rest)
      | ByteString.null undoPayload =
          undoRecordStream outputPointer (nextAction recordIndex) rest
      | unOffset writeOffset < 0 =
          pure (Just (ApplyNegativeRecordOffset recordIndex writeOffset))
      | not (fitsWithin writeOffset payloadLength (FileSize inputLength)) =
          pure (Just (ApplyWritesPastTarget recordIndex
                       (RequestedLength payloadLength)
                       (RemainingLength
                          (remainingFromOffset writeOffset (FileSize inputLength)))))
      | otherwise = do
          copyRegion outputPointer writeOffset undoPayload (Offset 0) payloadLength
          undoRecordStream outputPointer (nextAction recordIndex) rest
      where
        writeOffset   = ppf3RecordOffset record
        undoPayload   = fromMaybe ByteString.empty (ppf3RecordUndo record)
        payloadLength = byteLength undoPayload
