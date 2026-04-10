module Slap.RUP.Apply
  ( applyRUP
  , applyRecord
  , applyRUPMemory
  ) where

import Slap.RUP.Types
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

applyRUP :: RUPPatch -> FilePath -> IO Int
applyRUP patch target = do
  withBinaryFile target ReadWriteMode $ \handle -> do
    mapM_ (applyRecord handle) (rupRecords patch)
    -- Handle overflow (append data for file size changes).
    -- On-disk overflow is XOR'd with 0xFF; decode before writing.
    case rupOverflow patch of
      Nothing -> pure ()
      Just overflow -> do
        hSeek handle AbsoluteSeek (fromIntegral (unFileSize (rupSourceSize patch)))
        ByteString.hPut handle (ByteString.map (xor 0xFF) overflow)
    -- Handle truncation (if target is smaller than source)
    when (rupTargetSize patch < rupSourceSize patch) $
      hSetFileSize handle (fromIntegral (unFileSize (rupTargetSize patch)))
  pure (length (rupRecords patch))

applyRecord :: Handle -> RUPRecord -> IO ()
applyRecord handle (RUPRecord writeOffset xorPayload) = do
  hSeek handle AbsoluteSeek (fromIntegral (unOffset writeOffset))
  sourceBytes <- ByteString.hGet handle (ByteString.length xorPayload)
  let padded = if ByteString.length sourceBytes < ByteString.length xorPayload
               then sourceBytes <> ByteString.replicate (ByteString.length xorPayload - ByteString.length sourceBytes) 0
               else sourceBytes
      result = ByteString.packZipWith xor padded xorPayload
  hSeek handle AbsoluteSeek (fromIntegral (unOffset writeOffset))
  ByteString.hPut handle result

-- | Apply a RUP patch in memory: XOR records + overflow handling.
applyRUPMemory :: RUPPatch -> SourceFileContents -> TargetFileContents
applyRUPMemory patch (SourceFileContents source) = TargetFileContents $ unsafeCreate outputLength $ \outputPointer -> do
    -- Copy source, zero-fill any extension
    copyByteStringRange outputPointer 0 source 0 (min sourceLength outputLength)
    when (outputLength > sourceLength) $
      fillBytes (outputPointer `plusPtr` sourceLength) (0 :: Word8) (outputLength - sourceLength)
    -- XOR records: read from buffer, XOR, write back
    forM_ (rupRecords patch) $ \(RUPRecord writeOffset xorPayload) -> do
      let writePosition = offsetToInt writeOffset
          recordLength = ByteString.length xorPayload
      forM_ [0..recordLength-1] $ \position -> do
        let bytePosition = writePosition + position
        original <- peekByteOff outputPointer bytePosition :: IO Word8
        pokeByteOff outputPointer bytePosition (original `xor` ByteString.index xorPayload position)
    -- Overflow: decoded data (XOR'd with 0xFF on disk) written at source end
    case rupOverflow patch of
      Nothing -> pure ()
      Just overflow -> do
        let appendPosition = unFileSize (rupSourceSize patch)
            decoded = ByteString.map (xor 0xFF) overflow
        copyByteStringRange outputPointer appendPosition decoded 0 (ByteString.length decoded)
  where
    sourceLength = ByteString.length source
    targetLength = unFileSize (rupTargetSize patch)
    outputLength = if targetLength > 0 then targetLength else sourceLength
