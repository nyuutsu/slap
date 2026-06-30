module Slap.NINJA1.Apply
  ( applyNINJA1
  ) where

import Slap.NINJA1.Types (NINJA1Patch(..), NINJA1Record(..))
import Slap.Status (SlapError)
import Slap.Measure (Offset(..), Length(..), offsetToInt, byteLength)
import Slap.Binary (copyRegion)

import Slap.FileContents (InputFileContents(..), OutputFileContents(..))

import qualified Data.ByteString as ByteString
import Data.ByteString.Internal (unsafeCreate)
import Control.Monad (forM_, when)
import Foreign.Marshal.Utils (fillBytes)
import Foreign.Ptr (plusPtr)
import Data.Word (Word8)

-- | Copy source, then overwrite at offsets.
applyNINJA1 :: NINJA1Patch -> InputFileContents -> Either SlapError OutputFileContents
applyNINJA1 patch (InputFileContents source) = Right $ OutputFileContents $ unsafeCreate outputSize $ \outputPointer -> do
    copyRegion outputPointer (Offset 0) source (Offset 0) (Length (min sourceLength outputSize))
    when (outputSize > sourceLength) $
      fillBytes (outputPointer `plusPtr` sourceLength) (0 :: Word8) (outputSize - sourceLength)
    forM_ (ninja1Records patch) $ \(NINJA1Record writeOffset writePayload) ->
      copyRegion outputPointer writeOffset writePayload (Offset 0) (byteLength writePayload)
  where
    sourceLength = ByteString.length source
    outputSize = foldl' max sourceLength
      [ offsetToInt (ninja1RecordOffset record) + ByteString.length (ninja1RecordData record) | record <- ninja1Records patch ]
