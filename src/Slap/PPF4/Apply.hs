module Slap.PPF4.Apply (applyPPF4) where

import Slap.PPF4.Types (PPF4Patch(..), PPF4Replace(..), PPF4Append(..))
import Slap.Binary (copyRegion, fillNewBuffer, fillRegion)
import Slap.Status (SlapError(..), ApplyError(..))
import Slap.Measure (Offset(..), FileSize(..),
                     ActionIndex,
                     RequestedLength(..), RemainingLength(..),
                     fitsWithin, remainingFromOffset, minLength,
                     advance, byteLength, distance, offsetToFileSize,
                     firstAction, nextAction)
import Slap.FileContents (InputFileContents(..), OutputFileContents(..))
import Slap.FormatLabel (FormatLabel(LabelPPF4))

import qualified Data.ByteString as ByteString
import Control.Monad (when)
import Foreign.Ptr (Ptr)
import Data.Word (Word8)
import System.IO.Unsafe (unsafePerformIO)

-- | PPF4 is a two-phase format.
-- Replace records run first, each writing at its declared offset within the source bounds
-- (Replaces that would write past source EOF fail with 'ApplyReplaceGrowsFile').
-- Append records run second, each writing sequentially starting at the snapshot of @sourceFileSize@ taken before any Replace runs.
applyPPF4 :: PPF4Patch -> InputFileContents -> Either SlapError OutputFileContents
applyPPF4 patch (InputFileContents source)
  | unFileSize outputFileSize < 0 =
      Left (NegativeTargetSize LabelPPF4 outputFileSize)
  | unFileSize outputFileSize == 0 =
      Right (OutputFileContents ByteString.empty)
  | otherwise = unsafePerformIO $ do
      (result, finalOutcome) <- fillNewBuffer outputFileSize $ \outputPointer -> do
        copyRegion outputPointer (Offset 0) source (Offset 0) initialCopyLength
        when (outputEnd > sourceEnd) $
          fillRegion outputPointer sourceEnd 0x00 (distance sourceEnd outputEnd)
        replaceOutcome <- applyReplaces outputPointer firstAction (ppf4Replaces patch)
        -- First failure wins: a Replace-phase error short-circuits the
        -- Append phase, so an Append-phase failure on a buffer corrupted
        -- by a failed Replace can't overwrite the more useful diagnostic.
        case replaceOutcome of
          Left applyErr -> pure (Just applyErr)
          Right appendStartIndex ->
            applyAppends outputPointer
                         appendStartIndex
                         appendStartOffset (ppf4Appends patch)
      pure $ case finalOutcome of
        Just applyErr -> Left (ApplyFailed LabelPPF4 applyErr)
        Nothing       -> Right (OutputFileContents result)
  where
    sourceEnd         = Offset (fromIntegral (ByteString.length source))
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

    applyReplaces :: Ptr Word8
                  -> ActionIndex -> [PPF4Replace] -> IO (Either ApplyError ActionIndex)
    applyReplaces _ recordIndex [] = pure (Right recordIndex)
    applyReplaces outputPointer recordIndex (replace : rest)
      | unOffset writeOffset < 0 =
          pure (Left (ApplyNegativeRecordOffset recordIndex writeOffset))
      | not (fitsWithin writeOffset payloadLength sourceFileSize) =
          pure (Left (ApplyReplaceGrowsFile recordIndex writeOffset
                       (RequestedLength payloadLength)
                       sourceFileSize))
      | otherwise = do
          copyRegion outputPointer writeOffset (replaceData replace) (Offset 0) payloadLength
          applyReplaces outputPointer (nextAction recordIndex) rest
      where
        writeOffset   = replaceOffset replace
        payloadLength = byteLength (replaceData replace)

    applyAppends :: Ptr Word8
                 -> ActionIndex -> Offset -> [PPF4Append] -> IO (Maybe ApplyError)
    applyAppends _ _ _ [] = pure Nothing
    applyAppends outputPointer recordIndex currentEnd (PPF4Append payloadBytes : rest)
      | not (fitsWithin currentEnd payloadLength outputFileSize) =
          pure (Just (ApplyWritesPastTarget recordIndex
                       (RequestedLength payloadLength)
                       (RemainingLength (remainingFromOffset currentEnd outputFileSize))))
      | otherwise = do
          copyRegion outputPointer currentEnd payloadBytes (Offset 0) payloadLength
          applyAppends outputPointer (nextAction recordIndex)
                       (advance currentEnd payloadLength) rest
      where
        payloadLength = byteLength payloadBytes

computeOutputEnd :: Offset -> PPF4Patch -> Offset
computeOutputEnd sourceBufferEnd patch =
  let appendsTotal = foldMap (byteLength . appendData) (ppf4Appends patch)
  in advance sourceBufferEnd appendsTotal
