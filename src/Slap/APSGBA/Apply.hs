{-# LANGUAGE OverloadedStrings #-}

module Slap.APSGBA.Apply
  ( applyAPSGBA
  ) where

import Slap.APSGBA.Types
import Slap.Binary (copyRegion, fillNewBuffer)
import Slap.Status (SlapError(..), ApplyError(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.Measure (Offset(..), Length(..), FileSize(..),
                     ActionIndex, RequestedLength(..),
                     offsetToFileSize, firstAction, nextAction)

import Slap.FileContents (InputFileContents(..), OutputFileContents(..))

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.Bits (xor)
import Data.Word (Word8)
import Control.Monad (when)
import Foreign.Marshal.Utils (fillBytes)
import Foreign.Ptr (Ptr, plusPtr)
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
applyAPSGBA (APSGBAPatch header records) (InputFileContents source)
  | targetSize < 0 =
      Left (NegativeTargetSize LabelAPSGBA targetFileSize)
  | otherwise = unsafePerformIO $ do
      (result, maybeErr) <- fillNewBuffer targetFileSize runApply
      pure $ case maybeErr of
        Just applyErr -> Left (ApplyFailed LabelAPSGBA applyErr)
        Nothing       -> Right (OutputFileContents result)
  where
    sourceLength   = ByteString.length source
    targetFileSize = apsGbaTargetSize header
    targetSize     = unFileSize targetFileSize
    -- | Exclusive upper bound on a legitimate block start. See
    -- 'applyAPSGBA' for why this is @max@ and not @targetSize@ alone.
    naturalBlockReach :: FileSize
    naturalBlockReach =
      FileSize (max sourceLength targetSize)

    -- | Initial buffer state: copy source bytes (clipped at target
    -- length if shrinking) and zero-fill any tail past the source.
    seedBuffer :: Ptr Word8 -> IO ()
    seedBuffer targetPointer = do
      copyRegion targetPointer (Offset 0) source (Offset 0) (Length (min sourceLength targetSize))
      when (targetSize > sourceLength) $
        fillBytes (targetPointer `plusPtr` sourceLength)
                  (0 :: Word8)
                  (targetSize - sourceLength)

    -- | Flag a record whose write start sits at or past 'naturalBlockReach'.
    -- Only the start is checked here; a tail that overruns the target is handled in 'executeXorBlock'.
    checkRecordStartsWithinReach :: ActionIndex -> Offset
                                 -> Either ApplyError ()
    checkRecordStartsWithinReach actionIndex blockOffset
      | offsetToFileSize blockOffset >= naturalBlockReach =
          Left (ApplyAbsoluteWritePastTarget actionIndex
                 blockOffset
                 (RequestedLength (Length apsGbaBlockSize))
                 targetFileSize)
      | otherwise = Right ()

    -- | Materialise one block into the output buffer, skipping any byte position at or past 'targetSize'.
    executeXorBlock :: Ptr Word8 -> Offset -> ByteString -> IO ()
    executeXorBlock targetPointer blockOffset xorPayload =
        writeRemainingBytes 0
      where
        blockBase     = unOffset blockOffset
        writeBase     = targetPointer `plusPtr` blockBase
        writeRemainingBytes !byteOffset
          | byteOffset >= apsGbaBlockSize = pure ()
          | otherwise = do
              let positionWithinTarget = blockBase + byteOffset
              when (positionWithinTarget < targetSize) $ do
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
      seedBuffer targetPointer
      applyRecords targetPointer firstAction records
