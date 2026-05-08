module Slap.FFI (rustyCRC32, rustyAdler32, rustyBpsDiff) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Unsafe as UnsafeByteString
import Data.Word (Word8, Word32)
import Foreign.C.Types (CSize(..))
import Foreign.Marshal.Alloc (alloca)
import Foreign.Ptr (Ptr, castPtr, nullPtr)
import Foreign.Storable (peek)
import Slap.Checksum (CRC32(..), Adler32(..))
import Slap.FileContents (InputFileContents(..), OutputFileContents(..))
import System.IO.Unsafe (unsafeDupablePerformIO)

foreign import ccall unsafe "rusty_crc32"
  c_rustyCRC32 :: Ptr () -> CSize -> Word32

foreign import ccall unsafe "rusty_adler32"
  c_rustyAdler32 :: Ptr () -> CSize -> Word32

foreign import ccall unsafe "rusty_bps_diff"
  c_bpsDiff :: Ptr Word8 -> CSize -> Ptr Word8 -> CSize
            -> Ptr (Ptr Word8) -> Ptr CSize -> IO ()

foreign import ccall unsafe "rusty_free"
  c_free :: Ptr Word8 -> CSize -> IO ()

-- | CRC-32 via rusty-slap (hardware-accelerated crc32fast).
rustyCRC32 :: ByteString -> CRC32
rustyCRC32 input = CRC32 $ unsafeDupablePerformIO $
  UnsafeByteString.unsafeUseAsCStringLen input $ \(dataPointer, dataLength) ->
    pure $ c_rustyCRC32 (castPtr dataPointer) (fromIntegral dataLength)

-- | Adler-32 via rusty-slap (RFC 1950).
rustyAdler32 :: ByteString -> Adler32
rustyAdler32 input = Adler32 $ unsafeDupablePerformIO $
  UnsafeByteString.unsafeUseAsCStringLen input $ \(dataPointer, dataLength) ->
    pure $ c_rustyAdler32 (castPtr dataPointer) (fromIntegral dataLength)

-- | BPS diff via rusty-slap (suffix-array algorithm, after Alcaro's Flips).
-- Returns the raw encoded action byte stream.
rustyBpsDiff :: InputFileContents -> OutputFileContents -> ByteString
rustyBpsDiff (InputFileContents source) (OutputFileContents target) = unsafeDupablePerformIO $
  UnsafeByteString.unsafeUseAsCStringLen source $ \(sourcePointer, sourceLength) ->
    UnsafeByteString.unsafeUseAsCStringLen target $ \(targetPointer, targetLength) ->
      alloca $ \resultAddressPointer ->
        alloca $ \resultLengthPointer -> do
          c_bpsDiff (castPtr sourcePointer) (fromIntegral sourceLength)
                    (castPtr targetPointer) (fromIntegral targetLength)
                    resultAddressPointer resultLengthPointer
          resultPointer <- peek resultAddressPointer
          resultLength <- peek resultLengthPointer
          if resultPointer == nullPtr
            then pure ByteString.empty
            else do
              result <- ByteString.packCStringLen (castPtr resultPointer, fromIntegral resultLength)
              c_free resultPointer resultLength
              pure result
