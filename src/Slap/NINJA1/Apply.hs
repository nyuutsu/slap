module Slap.NINJA1.Apply
  ( applyNINJA1
  , applyRecord
  , applyNINJA1Memory
  ) where

import Slap.NINJA1.Types (NINJA1Patch(..), NINJA1Record(..))
import Slap.Measure (seekTo, offsetToInt)
import Slap.Binary (copyByteStringRange)

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.ByteString.Internal (unsafeCreate)
import Control.Monad (forM_, when)
import Foreign.Marshal.Utils (fillBytes)
import Foreign.Ptr (plusPtr)
import Data.Word (Word8)
import System.IO

----------------------------------------------------------------------------
-- Apply (raw overwrite, like IPS)
----------------------------------------------------------------------------

applyNINJA1 :: NINJA1Patch -> FilePath -> IO Int
applyNINJA1 patch target = withBinaryFile target ReadWriteMode $ \handle -> do
  mapM_ (applyRecord handle) (ninja1Records patch)
  pure (length (ninja1Records patch))

applyRecord :: Handle -> NINJA1Record -> IO ()
applyRecord handle (NINJA1Record writeOffset writePayload) = do
  seekTo handle writeOffset
  ByteString.hPut handle writePayload

-- | Apply a NINJA1 patch in memory: copy source, then overwrite at offsets.
applyNINJA1Memory :: NINJA1Patch -> ByteString -> ByteString
applyNINJA1Memory patch source = unsafeCreate outputSize $ \outputPointer -> do
    copyByteStringRange outputPointer 0 source 0 (min sourceLength outputSize)
    when (outputSize > sourceLength) $
      fillBytes (outputPointer `plusPtr` sourceLength) (0 :: Word8) (outputSize - sourceLength)
    forM_ (ninja1Records patch) $ \(NINJA1Record writeOffset writePayload) ->
      copyByteStringRange outputPointer (offsetToInt writeOffset) writePayload 0 (ByteString.length writePayload)
  where
    sourceLength = ByteString.length source
    outputSize = foldl' max sourceLength
      [ offsetToInt (ninja1RecordOffset record) + ByteString.length (ninja1RecordData record) | record <- ninja1Records patch ]
