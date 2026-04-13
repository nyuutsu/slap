module Slap.NINJA2.Apply
  ( applyNINJA2
  , applyRecord
  , applyNINJA2Memory
  ) where

import Slap.NINJA2.Types
import Slap.Measure (Offset(..), FileSize(..), offsetToInt)
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
import System.IO

applyNINJA2 :: NINJA2Patch -> FilePath -> IO Int
applyNINJA2 patch target = do
  withBinaryFile target ReadWriteMode $ \handle -> do
    mapM_ (applyRecord handle) (ninja2Records patch)
    -- Handle overflow (append data for file size changes).
    -- On-disk overflow is XOR'd with 0xFF; decode before writing.
    case ninja2Overflow patch of
      Nothing -> pure ()
      Just overflow -> do
        hSeek handle AbsoluteSeek (fromIntegral (unFileSize (ninja2SourceSize patch)))
        ByteString.hPut handle (ByteString.map (xor 0xFF) overflow)
    -- Handle truncation (if target is smaller than source)
    when (ninja2TargetSize patch < ninja2SourceSize patch) $
      hSetFileSize handle (fromIntegral (unFileSize (ninja2TargetSize patch)))
  pure (length (ninja2Records patch))

applyRecord :: Handle -> NINJA2Record -> IO ()
applyRecord handle (NINJA2Record writeOffset xorPayload) = do
  hSeek handle AbsoluteSeek (fromIntegral (unOffset writeOffset))
  sourceBytes <- ByteString.hGet handle (ByteString.length xorPayload)
  let padded = if ByteString.length sourceBytes < ByteString.length xorPayload
               then sourceBytes <> ByteString.replicate (ByteString.length xorPayload - ByteString.length sourceBytes) 0
               else sourceBytes
      result = ByteString.packZipWith xor padded xorPayload
  hSeek handle AbsoluteSeek (fromIntegral (unOffset writeOffset))
  ByteString.hPut handle result

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
    targetLength = unFileSize (ninja2TargetSize patch)
    outputLength = if targetLength > 0 then targetLength else sourceLength
