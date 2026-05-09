{-# LANGUAGE OverloadedStrings #-}

-- | Apply a PPF1 patch in memory. PPF1 has no validation block and
-- no undo data, so apply is a straight write-records-into-output
-- walk: copy the source bytes, then overwrite each record's
-- payload at its offset.
module Slap.PPF1.Apply (applyPPF1) where

import Slap.PPF1.Types (PPF1Patch(..), PPF1Record(..))
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
import Data.ByteString.Internal (create)
import Data.IORef (IORef, newIORef, readIORef, writeIORef)
import Control.Monad (when)
import Foreign.Marshal.Utils (fillBytes)
import Foreign.Ptr (Ptr)
import Data.Word (Word8)
import System.IO.Unsafe (unsafePerformIO)

applyPPF1 :: PPF1Patch -> InputFileContents -> Either SlapError OutputFileContents
applyPPF1 patch (InputFileContents source)
  | unFileSize outputFileSize < 0 =
      Left (NegativeTargetSize LabelPPF1 outputFileSize)
  | unFileSize outputFileSize == 0 =
      Right (OutputFileContents ByteString.empty)
  | otherwise = unsafePerformIO $ do
      errorRef <- newIORef Nothing
      result <- create (unFileSize outputFileSize) $ \outputPointer -> do
        copyRegion outputPointer (Offset 0) source (Offset 0) initialCopyLength
        when (outputEnd > sourceEnd) $
          fillBytes (plusOffset outputPointer sourceEnd)
                    (0 :: Word8)
                    (unLength (distance sourceEnd outputEnd))
        applyRecordStream outputPointer errorRef firstAction (ppf1Records patch)
      errorState <- readIORef errorRef
      pure $ case errorState of
        Just applyErr -> Left (ApplyFailed LabelPPF1 applyErr)
        Nothing       -> Right (OutputFileContents result)
  where
    sourceEnd      = Offset (ByteString.length source)
    outputEnd      = computeOutputEnd sourceEnd (ppf1Records patch)
    outputFileSize = offsetToFileSize outputEnd
    initialCopyLength = minLength
                          (distance (Offset 0) sourceEnd)
                          (distance (Offset 0) outputEnd)

    computeOutputEnd :: Offset -> [PPF1Record] -> Offset
    computeOutputEnd sourceBufferEnd = foldl' accumulateEnd sourceBufferEnd
      where
        accumulateEnd currentEnd (PPF1Record writeOffset payload) =
          max currentEnd (advance writeOffset (byteLength payload))

    applyRecordStream :: Ptr Word8 -> IORef (Maybe ApplyError)
                      -> ActionIndex -> [PPF1Record] -> IO ()
    applyRecordStream _ _ _ [] = pure ()
    applyRecordStream outputPointer errorRef recordIndex (PPF1Record writeOffset payload : rest)
      | unOffset writeOffset < 0 =
          writeIORef errorRef (Just (ApplyNegativeRecordOffset recordIndex writeOffset))
      | not (fitsWithin writeOffset payloadLength outputFileSize) =
          writeIORef errorRef (Just (ApplyWritesPastTarget recordIndex
                                       (RequestedLength payloadLength)
                                       (RemainingLength
                                          (remainingFromOffset writeOffset outputFileSize))))
      | otherwise = do
          copyRegion outputPointer writeOffset payload (Offset 0) payloadLength
          applyRecordStream outputPointer errorRef
            (nextAction recordIndex) rest
      where
        payloadLength = byteLength payload
