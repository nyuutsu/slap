{-# LANGUAGE OverloadedStrings #-}

module Slap.APSGBA.Apply
  ( applyAPSGBA
  ) where

import Slap.APSGBA.Types
import Slap.Binary (fillNewBuffer, seedBufferFromSource)
import Slap.Status (SlapError(..), ApplyError(..), addressableByteCount)
import Slap.FormatLabel (FormatLabel(..))
import Slap.Measure (Offset(..), Length(..), FileSize(..),
                     ActionIndex, RequestedLength(..),
                     byteFileSize, offsetToFileSize, plusOffset, firstAction, nextAction)

import Slap.FileContents (InputFileContents(..), OutputFileContents(..))

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.Bits (xor)
import Data.Word (Word8)
import Foreign.Ptr (Ptr)
import Foreign.Storable (peekByteOff, pokeByteOff)
import System.IO.Unsafe (unsafePerformIO)

-- | XOR each record's 'apsGbaBlockSize'-byte payload into the seeded output buffer at the record's absolute offset.
--
-- A record whose start lies at or past @max(sourceSize, targetSize)@ is malformed and surfaces as 'ApplyAbsoluteWritePastTarget'.
-- The bound is @max@, not @targetSize@ alone, because a shrinking patch legitimately emits records past the target end:
-- a source block with no target equivalent still XORs non-zero against the zero-padded target.
-- 'executeXorBlock' then handles any record that reaches the boundary, with two different outcomes:
-- a record starting past the target writes nothing at all,
-- while one starting in range with an overrunning tail writes its in-range bytes and drops only the overhang.
applyAPSGBA :: APSGBAPatch -> InputFileContents -> Either SlapError OutputFileContents
applyAPSGBA (APSGBAPatch header records) (InputFileContents source) =
  case addressableByteCount LabelAPSGBA targetFileSize of
    Left refusal          -> Left refusal
    Right addressableSize -> unsafePerformIO $ do
      (result, maybeErr) <- fillNewBuffer addressableSize runApply
      pure $ case maybeErr of
        Just applyErr -> Left (ApplyFailed LabelAPSGBA applyErr)
        Nothing       -> Right (OutputFileContents result)
  where
    targetFileSize = apsGbaTargetSize header
    -- | Exclusive upper bound on a legitimate block start. See 'applyAPSGBA' for why this is @max@ and not 'targetFileSize' alone.
    naturalBlockReach :: FileSize
    naturalBlockReach = max (byteFileSize source) targetFileSize

    -- | Flag a record whose write start sits at or past 'naturalBlockReach'.
    -- Only the start is checked here; a tail that overruns the target is handled in 'executeXorBlock'.
    checkRecordStartsWithinReach :: ActionIndex -> Offset
                                 -> Either ApplyError ()
    checkRecordStartsWithinReach actionIndex blockOffset
      | offsetToFileSize blockOffset >= naturalBlockReach =
          Left (ApplyAbsoluteWritePastTarget actionIndex
                 blockOffset
                 (RequestedLength (Length (fromIntegral apsGbaBlockSize)))
                 targetFileSize)
      | otherwise = Right ()

    -- | Materialise one block into the output buffer, writing only the byte positions that land before the target end.
    executeXorBlock :: Ptr Word8 -> Offset -> ByteString -> IO ()
    executeXorBlock targetPointer blockOffset xorPayload =
        writeRemainingBytes 0
      where
        writeBase = targetPointer `plusOffset` blockOffset
        -- | How many of the block's bytes precede the target end; a block starting at or past the end writes none.
        writableByteCount :: Int
        writableByteCount =
          fromIntegral (min (fromIntegral apsGbaBlockSize)
                            (max 0 (unFileSize targetFileSize - unOffset blockOffset)))
        writeRemainingBytes !byteOffset
          | byteOffset >= writableByteCount = pure ()
          | otherwise = do
              original <- peekByteOff writeBase byteOffset :: IO Word8
              pokeByteOff writeBase byteOffset
                (original `xor` ByteString.index xorPayload byteOffset)
              writeRemainingBytes (byteOffset + 1)

    applyRecords :: Ptr Word8 -> ActionIndex -> [APSGBARecord]
                 -> IO (Maybe ApplyError)
    applyRecords _targetPointer _actionIndex [] = pure Nothing
    applyRecords targetPointer !actionIndex
                 (APSGBARecord blockOffset _ _ xorPayload : remainingRecords) =
      case checkRecordStartsWithinReach actionIndex blockOffset of
        Left err -> pure (Just err)
        Right () -> do
          executeXorBlock targetPointer blockOffset xorPayload
          applyRecords targetPointer (nextAction actionIndex) remainingRecords

    runApply targetPointer = do
      seedBufferFromSource targetPointer targetFileSize source
      applyRecords targetPointer firstAction records
