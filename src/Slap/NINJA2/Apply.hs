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
    -- Overflow: append-mode payload is the new tail bytes (XOR'd with 0xFF
    -- on disk) and is written at sourceSize; truncate-mode payload is the
    -- discarded tail bytes preserved for round-trip and is *not* applied —
    -- the smaller output buffer already encodes the truncation.
    case (ninja2OverflowType patch, ninja2Overflow patch) of
      (Just OverflowAppend, Just overflow) -> do
        let appendPosition = case ninja2OpenNewFile patch of
              Just openNewFile -> unFileSize (openNewFileSourceSize openNewFile)
              Nothing          -> sourceLength
            decoded = ByteString.map (xor 0xFF) overflow
        copyByteStringRange outputPointer appendPosition decoded 0 (ByteString.length decoded)
      _ -> pure ()
  where
    sourceLength = ByteString.length source
    outputLength = case ninja2OpenNewFile patch of
      Just openNewFile -> unFileSize (openNewFileTargetSize openNewFile)
      Nothing          -> sourceLength
