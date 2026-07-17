module Slap.NINJA1.Apply
  ( applyNINJA1
  ) where

import Slap.NINJA1.Types (NINJA1Patch(..), NINJA1Record(..))
import Slap.FormatLabel (FormatLabel(LabelNINJA1))
import Slap.Status (SlapError, addressableByteCount)
import Slap.Measure (Offset(..), advance, byteFileSize, byteLength, offsetToFileSize)
import Slap.Binary (copyRegion, filledBufferOfSize, seedBufferFromSource)

import Slap.FileContents (InputFileContents(..), OutputFileContents(..))

import Control.Monad (forM_)

-- | Copy source, then overwrite at offsets.
-- The writes and the 'outputSize' fold add offsets and lengths unchecked:
-- parse already refused any record reaching past 'Int' ('Slap.NINJA1.Parse.rejectUnaddressableRecordEnds'), so the arithmetic here cannot wrap.
applyNINJA1 :: NINJA1Patch -> InputFileContents -> Either SlapError OutputFileContents
applyNINJA1 patch (InputFileContents source) =
  case addressableByteCount LabelNINJA1 outputSize of
    Left refusal          -> Left refusal
    Right addressableSize -> Right $ OutputFileContents $ filledBufferOfSize addressableSize $ \outputPointer -> do
      seedBufferFromSource outputPointer outputSize source
      forM_ (ninja1Records patch) $ \(NINJA1Record writeOffset writePayload) ->
        copyRegion outputPointer writeOffset writePayload (Offset 0) (byteLength writePayload)
  where
    outputSize = foldl' max (byteFileSize source)
      [ offsetToFileSize (advance (ninja1RecordOffset record) (byteLength (ninja1RecordData record))) | record <- ninja1Records patch ]
