module Slap.APSN64.Apply
  ( applyAPSN64
  ) where

import Slap.APSN64.Types
import Slap.Status (SlapError)
import Slap.Measure (Offset(..), Length(..), offsetToInt, byteLength)
import Slap.Binary (copyRegion)

import Slap.FileContents (InputFileContents(..), OutputFileContents(..))

import qualified Data.ByteString as ByteString
import Data.ByteString.Internal (unsafeCreate)
import qualified Data.Foldable as Foldable
import Data.Word (Word8)
import Control.Monad (forM_, when)
import Foreign.Marshal.Utils (fillBytes)
import Foreign.Ptr (plusPtr)

applyAPSN64 :: APSN64Patch -> InputFileContents -> Either SlapError OutputFileContents
applyAPSN64 (APSN64Patch _ records) (InputFileContents source) =
  Right (OutputFileContents (unsafeCreate outputLength runApply))
  where
    sourceLength = ByteString.length source
    recordEnd (APSN64Normal recordOffset recordPayload) = offsetToInt recordOffset + ByteString.length recordPayload
    recordEnd (APSN64RLE recordOffset _ fillCount) = offsetToInt recordOffset + fromIntegral fillCount
    outputLength = Foldable.foldl' max sourceLength (fmap recordEnd records)

    runApply targetPointer = do
        seedFromSource
        forM_ records writeRecord
      where
        -- | Seed with the source bytes, zero-filling any tail past source end.
        seedFromSource = do
          copyRegion targetPointer (Offset 0) source (Offset 0) (Length (min sourceLength outputLength))
          when (outputLength > sourceLength) $
            fillBytes (targetPointer `plusPtr` sourceLength) (0 :: Word8) (outputLength - sourceLength)
        -- | Overlay one record onto the seeded buffer.
        writeRecord = \case
          APSN64Normal writeOffset writePayload ->
            copyRegion targetPointer writeOffset writePayload (Offset 0) (byteLength writePayload)
          APSN64RLE writeOffset fillValue fillCount ->
            fillBytes (targetPointer `plusPtr` offsetToInt writeOffset) fillValue (fromIntegral fillCount)
