{-# LANGUAGE OverloadedStrings #-}

-- | Apply a PPF2 patch.
-- Same record-stream walk as PPF1 (PPF2's records are wire-compatible).
-- The validation-block and file-size fields parsed from the header don't enter into the byte-walk itself;
-- verifying source identity against them is the caller's job, not this module's.
module Slap.PPF2.Apply (applyPPF2) where

import Slap.PPF2.Types (PPF2Patch(..), PPF2Record(..))
import Slap.Binary (copyRegion, fillNewBuffer, fillRegion)
import Slap.Status (SlapError(..), addressableByteCount, SlapAdvisory(..), ApplyError(..),
                    Outcome(..), noAdvisories)
import Slap.FormatLabel (FormatLabel(..))
import Slap.Measure (Offset(..), FileSize(..),
                     ActionIndex,
                     RequestedLength(..), RemainingLength(..),
                     fitsWithin, remainingFromOffset, minLength,
                     advance, byteLength, distance, offsetToFileSize,
                     firstAction, nextAction)
import Slap.FileContents (InputFileContents(..), OutputFileContents(..))

import qualified Data.ByteString as ByteString
import Control.Monad (when)
import Foreign.Ptr (Ptr)
import Data.Word (Word8)
import System.IO.Unsafe (unsafePerformIO)

applyPPF2 :: PPF2Patch -> InputFileContents -> Either SlapError (Outcome OutputFileContents)
applyPPF2 patch (InputFileContents source)
  | unFileSize outputFileSize == 0 =
      Right (noAdvisories (OutputFileContents ByteString.empty))
  | otherwise = case addressableByteCount LabelPPF2 outputFileSize of
      Left refusal          -> Left refusal
      Right addressableSize -> unsafePerformIO $ do
        (result, maybeErr) <- fillNewBuffer addressableSize $ \outputPointer -> do
          copyRegion outputPointer (Offset 0) source (Offset 0) initialCopyLength
          when (outputEnd > sourceEnd) $
            fillRegion outputPointer sourceEnd 0x00 (distance sourceEnd outputEnd)
          applyRecordStream outputPointer firstAction (ppf2Records patch)
        pure $ case maybeErr of
          Just applyErr -> Left (ApplyFailed LabelPPF2 applyErr)
          Nothing       -> Right (Outcome (OutputFileContents result) growthAdvisories)
  where
    sourceEnd      = Offset (fromIntegral (ByteString.length source))
    outputEnd      = computeOutputEnd sourceEnd (ppf2Records patch)
    outputFileSize = offsetToFileSize outputEnd
    initialCopyLength = minLength
                          (distance (Offset 0) sourceEnd)
                          (distance (Offset 0) outputEnd)

    growthAdvisories
      | outputEnd > sourceEnd =
          [PPFApplyGrewPastSource LabelPPF2
             (offsetToFileSize sourceEnd)
             (distance sourceEnd outputEnd)]
      | otherwise = []

    computeOutputEnd :: Offset -> [PPF2Record] -> Offset
    computeOutputEnd sourceBufferEnd = foldl' accumulateEnd sourceBufferEnd
      where
        accumulateEnd currentEnd (PPF2Record writeOffset payload) =
          max currentEnd (advance writeOffset (byteLength payload))

    applyRecordStream :: Ptr Word8
                      -> ActionIndex -> [PPF2Record] -> IO (Maybe ApplyError)
    applyRecordStream _ _ [] = pure Nothing
    applyRecordStream outputPointer recordIndex (PPF2Record writeOffset payload : rest)
      | unOffset writeOffset < 0 =
          pure (Just (ApplyNegativeRecordOffset recordIndex writeOffset))
      | not (fitsWithin writeOffset payloadLength outputFileSize) =
          pure (Just (ApplyWritesPastTarget recordIndex
                       (RequestedLength payloadLength)
                       (RemainingLength
                          (remainingFromOffset writeOffset outputFileSize))))
      | otherwise = do
          copyRegion outputPointer writeOffset payload (Offset 0) payloadLength
          applyRecordStream outputPointer (nextAction recordIndex) rest
      where
        payloadLength = byteLength payload
