module Slap.PPF4.Apply (applyPPF4) where

import Slap.PPF4.Types (PPF4Patch(..), PPF4Replace(..), PPF4Append(..))
import Slap.Binary (copyRegion)
import Slap.Error (SlapError(..), ApplyError(..))
import Slap.Measure (Offset(..), Length(..), FileSize(..),
                     ActionIndex,
                     RequestedLength(..), RemainingLength(..),
                     fitsWithin, remainingFromOffset, minLength,
                     advance, byteLength, distance, offsetToFileSize,
                     firstAction, nextAction, plusOffset)
import Slap.FileContents (SourceFileContents(..), TargetFileContents(..))
import Slap.FormatLabel (FormatLabel(LabelPPF4))

import qualified Data.ByteString as ByteString
import Data.ByteString.Internal (create)
import Data.IORef (IORef, newIORef, readIORef, writeIORef)
import Control.Monad (when)
import Foreign.Marshal.Utils (fillBytes)
import Foreign.Ptr (Ptr)
import Data.Word (Word8)
import System.IO.Unsafe (unsafePerformIO)

-- | Apply a PPF4 patch in memory.
--
-- PPF4 is a two-phase format. Replace records run first, each writing
-- at its declared offset within the source bounds (Replaces that
-- would write past source EOF fail with 'ApplyReplaceGrowsFile').
-- Append records run second, each writing sequentially starting at
-- the snapshot of @sourceFileSize@ taken before any Replace runs.
applyPPF4 :: PPF4Patch -> SourceFileContents -> Either SlapError TargetFileContents
applyPPF4 patch (SourceFileContents source)
  | unFileSize outputFileSize < 0 =
      Left (NegativeTargetSize LabelPPF4 outputFileSize)
  | unFileSize outputFileSize == 0 =
      Right (TargetFileContents ByteString.empty)
  | otherwise = unsafePerformIO $ do
      errorRef <- newIORef Nothing
      result <- create (unFileSize outputFileSize) $ \outputPointer -> do
        copyRegion outputPointer (Offset 0) source (Offset 0) initialCopyLength
        when (outputEnd > sourceEnd) $
          fillBytes (plusOffset outputPointer sourceEnd)
                    (0 :: Word8)
                    (unLength (distance sourceEnd outputEnd))
        appendStartIndex <- applyReplaces outputPointer errorRef firstAction (ppf4Replaces patch)
        -- Skip the Append phase if the Replace phase already errored,
        -- so the first failure wins (an Append-phase failure on a
        -- buffer corrupted by a failed Replace would otherwise
        -- overwrite the more useful diagnostic).
        afterReplaces <- readIORef errorRef
        case afterReplaces of
          Just _  -> pure ()
          Nothing ->
            applyAppends outputPointer errorRef
                         appendStartIndex
                         appendStartOffset (ppf4Appends patch)
      errorState <- readIORef errorRef
      pure $ case errorState of
        Just applyErr -> Left (ApplyFailed LabelPPF4 applyErr)
        Nothing       -> Right (TargetFileContents result)
  where
    sourceEnd         = Offset (ByteString.length source)
    sourceFileSize    = offsetToFileSize sourceEnd
    outputEnd         = computeOutputEnd sourceEnd patch
    outputFileSize    = offsetToFileSize outputEnd
    initialCopyLength = minLength
                          (distance (Offset 0) sourceEnd)
                          (distance (Offset 0) outputEnd)
    -- The Append phase starts at the original source's end, taken
    -- from the snapshot before any Replace runs. Replaces cannot
    -- extend past it (enforced in 'applyReplaces'), so this offset
    -- is the exact final start of the Append region.
    appendStartOffset = sourceEnd

    applyReplaces :: Ptr Word8 -> IORef (Maybe ApplyError)
                  -> ActionIndex -> [PPF4Replace] -> IO ActionIndex
    applyReplaces _ _ recordIndex [] = pure recordIndex
    applyReplaces outputPointer errorRef recordIndex (replace : rest)
      | unOffset writeOffset < 0 = do
          writeIORef errorRef (Just (ApplyNegativeRecordOffset recordIndex writeOffset))
          pure recordIndex
      | not (fitsWithin writeOffset payloadLength sourceFileSize) = do
          writeIORef errorRef (Just (ApplyReplaceGrowsFile recordIndex writeOffset
                                       (RequestedLength payloadLength)
                                       sourceFileSize))
          pure recordIndex
      | otherwise = do
          copyRegion outputPointer writeOffset (replaceData replace) (Offset 0) payloadLength
          applyReplaces outputPointer errorRef (nextAction recordIndex) rest
      where
        writeOffset   = replaceOffset replace
        payloadLength = byteLength (replaceData replace)

    applyAppends :: Ptr Word8 -> IORef (Maybe ApplyError)
                 -> ActionIndex -> Offset -> [PPF4Append] -> IO ()
    applyAppends _ _ _ _ [] = pure ()
    applyAppends outputPointer errorRef recordIndex currentEnd (PPF4Append payloadBytes : rest)
      | not (fitsWithin currentEnd payloadLength outputFileSize) =
          writeIORef errorRef (Just (ApplyWritesPastTarget recordIndex
                                       (RequestedLength payloadLength)
                                       (RemainingLength (remainingFromOffset currentEnd outputFileSize))))
      | otherwise = do
          copyRegion outputPointer currentEnd payloadBytes (Offset 0) payloadLength
          applyAppends outputPointer errorRef (nextAction recordIndex)
                       (advance currentEnd payloadLength) rest
      where
        payloadLength = byteLength payloadBytes

computeOutputEnd :: Offset -> PPF4Patch -> Offset
computeOutputEnd sourceBufferEnd patch =
  let appendsTotal = foldMap (byteLength . appendData) (ppf4Appends patch)
  in advance sourceBufferEnd appendsTotal
