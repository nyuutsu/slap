module Slap.APSN64.Apply
  ( applyAPSN64
  ) where

import Slap.APSN64.Types
import Slap.Status (SlapError(..), ApplyError(..), addressableByteCount)
import Slap.FormatLabel (FormatLabel(..))
import Slap.Binary (copyRegion, fillNewBuffer, fillRegion, seedBufferFromSource)
import Slap.Measure (Offset(..), Length(..),
                     ActionIndex, RequestedLength(..),
                     byteLength, fitsWithin,
                     firstAction, nextAction)

import Slap.FileContents (InputFileContents(..), OutputFileContents(..))

import qualified Data.Vector as Vector
import Data.Word (Word8)
import Foreign.Ptr (Ptr)
import System.IO.Unsafe (unsafePerformIO)

-- | Apply an APS-N64 patch, sizing the output to the header's destination-size field — not to the records —
-- to match the reference @n64aps@, which truncates or zero-pads the source to that size before writing.
-- A record past that size is refused ('ApplyAbsoluteWritePastTarget'), never grown into.
applyAPSN64 :: APSN64Patch -> InputFileContents -> Either SlapError OutputFileContents
applyAPSN64 (APSN64Patch header records) (InputFileContents source) =
  case addressableByteCount LabelAPSN64 outputFileSize of
    Left refusal          -> Left refusal
    Right addressableSize -> unsafePerformIO $ do
      (result, maybeErr) <- fillNewBuffer addressableSize runApply
      pure $ case maybeErr of
        Just applyErr -> Left (ApplyFailed LabelAPSN64 applyErr)
        Nothing       -> Right (OutputFileContents result)
  where
    outputFileSize = apsN64DestinationSizeAsFileSize (apsN64DestinationSize header)

    checkWriteFitsTarget :: ActionIndex -> Offset -> Length
                         -> Either ApplyError ()
    checkWriteFitsTarget actionIndex writeOffset writeLength
      | fitsWithin writeOffset writeLength outputFileSize = Right ()
      | otherwise =
          Left (ApplyAbsoluteWritePastTarget actionIndex
                 writeOffset
                 (RequestedLength writeLength)
                 outputFileSize)

    runApply :: Ptr Word8 -> IO (Maybe ApplyError)
    runApply targetPointer = do
      seedBufferFromSource targetPointer outputFileSize source
      applyRecords firstAction (Vector.toList records)
      where
        applyRecords :: ActionIndex -> [APSN64Record] -> IO (Maybe ApplyError)
        applyRecords !_actionIndex [] = pure Nothing
        applyRecords actionIndex (record : remainingRecords) =
          case record of
            APSN64Normal writeOffset writePayload ->
              let writeLength = byteLength writePayload
              in case checkWriteFitsTarget actionIndex writeOffset writeLength of
                   Left err -> pure (Just err)
                   Right () -> do
                     copyRegion targetPointer writeOffset writePayload (Offset 0) writeLength
                     applyRecords (nextAction actionIndex) remainingRecords
            APSN64RLE writeOffset fillValue fillCount ->
              let writeLength = Length (fromIntegral fillCount)
              in case checkWriteFitsTarget actionIndex writeOffset writeLength of
                   Left err -> pure (Just err)
                   Right () -> do
                     fillRegion targetPointer writeOffset fillValue writeLength
                     applyRecords (nextAction actionIndex) remainingRecords
