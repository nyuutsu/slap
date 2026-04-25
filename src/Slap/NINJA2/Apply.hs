module Slap.NINJA2.Apply
  ( applyNINJA2Memory
  ) where

import Slap.NINJA2.Types
import Slap.Measure (FileSize(..), offsetToInt)
import Slap.Binary (copyByteStringRange)

import Slap.FileContents (SourceFileContents(..), TargetFileContents(..))

import qualified Data.ByteString as ByteString
import Data.ByteString.Internal (unsafeCreate)
import Data.Bits (xor)
import Data.Word (Word8)
import Control.Monad (forM_, when)
import Foreign.Marshal.Utils (fillBytes)
import Foreign.Ptr (plusPtr)
import Foreign.Storable (peekByteOff, pokeByteOff)

-- | Apply a NINJA2 patch in memory: XOR records + overflow handling.
applyNINJA2Memory :: NINJA2Patch -> SourceFileContents -> TargetFileContents
applyNINJA2Memory patch (SourceFileContents source) = TargetFileContents $ unsafeCreate outputLength $ \outputPointer -> do
    -- Copy source, zero-fill any extension
    copyByteStringRange outputPointer 0 source 0 (min sourceLength outputLength)
    when (outputLength > sourceLength) $
      fillBytes (outputPointer `plusPtr` sourceLength) (0 :: Word8) (outputLength - sourceLength)
    -- XOR records: read from buffer, XOR, write back
    forM_ (ninja2Records patch) $ \(NINJA2Record writeOffset xorPayload) -> do
      let writePosition = offsetToInt writeOffset
          recordLength = ByteString.length xorPayload
      forM_ [0..recordLength-1] $ \position -> do
        let bytePosition = writePosition + position
        original <- peekByteOff outputPointer bytePosition :: IO Word8
        pokeByteOff outputPointer bytePosition (original `xor` ByteString.index xorPayload position)
    -- Overflow: decoded data (XOR'd with 0xFF on disk) written at source end
    case ninja2Overflow patch of
      Nothing -> pure ()
      Just overflow -> do
        let appendPosition = unFileSize (ninja2SourceSize patch)
            decoded = ByteString.map (xor 0xFF) overflow
        copyByteStringRange outputPointer appendPosition decoded 0 (ByteString.length decoded)
  where
    sourceLength = ByteString.length source
    -- 'ninja2SourceMD5' is 'Just' iff the patch contained an OPEN_NEW_FILE
    -- command, which is the only place 'ninja2TargetSize' gets a real value.
    -- Without the header we have no declared target size, so fall back to the
    -- source length; with it, trust the declared size — including zero, which
    -- a target-less-than-source patch will legitimately produce.
    outputLength = case ninja2SourceMD5 patch of
      Just _  -> unFileSize (ninja2TargetSize patch)
      Nothing -> sourceLength
