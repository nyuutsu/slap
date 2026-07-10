module Slap.APSN64.Apply
  ( applyAPSN64
  ) where

import Slap.APSN64.Types
import Slap.Status (SlapError(..), ApplyError(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.Binary (copyRegion, fillNewBuffer)
import Slap.Measure (Offset(..), Length(..), FileSize(..),
                     ActionIndex, RequestedLength(..), RemainingLength(..),
                     byteLength, offsetToInt, fitsWithin, remainingFromOffset,
                     firstAction, nextAction)

import Slap.FileContents (InputFileContents(..), OutputFileContents(..))

import qualified Data.ByteString as ByteString
import qualified Data.Vector as Vector
import Data.Word (Word8)
import Control.Monad (when)
import Foreign.Marshal.Utils (fillBytes)
import Foreign.Ptr (Ptr, plusPtr)
import System.IO.Unsafe (unsafePerformIO)

-- | Apply an APS-N64 patch. The output is sized to the header's destination-size field, matching the reference @n64aps@,
-- whose @ReadSizeHeader@ truncates or zero-pads the source to that size before any record is written.
-- A record whose write would fall past the declared destination is malformed, surfacing as 'ApplyWritesPastTarget'
-- rather than silently growing the output.
applyAPSN64 :: APSN64Patch -> InputFileContents -> Either SlapError OutputFileContents
applyAPSN64 (APSN64Patch header records) (InputFileContents source) =
  unsafePerformIO $ do
    (result, maybeErr) <- fillNewBuffer outputFileSize runApply
    pure $ case maybeErr of
      Just applyErr -> Left (ApplyFailed LabelAPSN64 applyErr)
      Nothing       -> Right (OutputFileContents result)
  where
    sourceLength   = ByteString.length source
    outputFileSize = apsN64DestinationSizeAsFileSize (apsN64DestinationSize header)
    outputSize     = unFileSize outputFileSize

    -- | The initial buffer: the source bytes, clipped to the destination size when shrinking and zero-padded when growing.
    seedBuffer :: Ptr Word8 -> IO ()
    seedBuffer targetPointer = do
      copyRegion targetPointer (Offset 0) source (Offset 0)
                 (Length (min sourceLength outputSize))
      when (outputSize > sourceLength) $
        fillBytes (targetPointer `plusPtr` sourceLength)
                  (0 :: Word8)
                  (outputSize - sourceLength)

    checkWriteFitsTarget :: ActionIndex -> Offset -> Length
                         -> Either ApplyError ()
    checkWriteFitsTarget actionIndex writeOffset writeLength
      | fitsWithin writeOffset writeLength outputFileSize = Right ()
      | otherwise =
          Left (ApplyWritesPastTarget actionIndex
                 (RequestedLength writeLength)
                 (RemainingLength (remainingFromOffset writeOffset outputFileSize)))

    runApply :: Ptr Word8 -> IO (Maybe ApplyError)
    runApply targetPointer = do
      seedBuffer targetPointer
      applyRecords firstAction (Vector.toList records)
      where
        applyRecords :: ActionIndex -> [APSN64Record] -> IO (Maybe ApplyError)
        applyRecords !_actionIndex [] = pure Nothing
        applyRecords !actionIndex (record : remainingRecords) =
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
                     fillBytes (targetPointer `plusPtr` offsetToInt writeOffset)
                               fillValue (fromIntegral fillCount)
                     applyRecords (nextAction actionIndex) remainingRecords
