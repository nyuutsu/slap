{-# LANGUAGE OverloadedStrings #-}

-- | Apply a PPF2 patch in memory. Same record-stream walk as PPF1
-- (PPF2's records are wire-compatible) — the validation-block and
-- file-size fields parsed from the header don't enter into the
-- byte-walk itself; verifying source identity against them is the
-- caller's job, not this module's. Apply just produces output bytes.
module Slap.PPF2.Apply (applyPPF2) where

import Slap.PPF2.Types (PPF2Patch(..), PPF2Record(..))
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

applyPPF2 :: PPF2Patch -> InputFileContents -> Either SlapError OutputFileContents
applyPPF2 patch (InputFileContents source)
  | unFileSize outputFileSize < 0 =
      Left (NegativeTargetSize LabelPPF2 outputFileSize)
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
        applyRecordStream outputPointer errorRef firstAction (ppf2Records patch)
      errorState <- readIORef errorRef
      pure $ case errorState of
        Just applyErr -> Left (ApplyFailed LabelPPF2 applyErr)
        Nothing       -> Right (OutputFileContents result)
  where
    sourceEnd      = Offset (ByteString.length source)
    outputEnd      = computeOutputEnd sourceEnd (ppf2Records patch)
    outputFileSize = offsetToFileSize outputEnd
    initialCopyLength = minLength
                          (distance (Offset 0) sourceEnd)
                          (distance (Offset 0) outputEnd)

    computeOutputEnd :: Offset -> [PPF2Record] -> Offset
    computeOutputEnd sourceBufferEnd = foldl' accumulateEnd sourceBufferEnd
      where
        accumulateEnd currentEnd (PPF2Record writeOffset payload) =
          max currentEnd (advance writeOffset (byteLength payload))

    applyRecordStream :: Ptr Word8 -> IORef (Maybe ApplyError)
                      -> ActionIndex -> [PPF2Record] -> IO ()
    applyRecordStream _ _ _ [] = pure ()
    applyRecordStream outputPointer errorRef recordIndex (PPF2Record writeOffset payload : rest)
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
