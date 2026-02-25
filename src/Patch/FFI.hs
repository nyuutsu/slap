module Patch.FFI (rustyCRC32, rustyAdler32, rustyBpsDiff) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Unsafe as BSU
import Data.Word (Word8, Word32)
import Foreign.C.Types (CSize(..))
import Foreign.Marshal.Alloc (alloca)
import Foreign.Ptr (Ptr, castPtr, nullPtr)
import Foreign.Storable (peek)
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
rustyCRC32 :: ByteString -> Word32
rustyCRC32 bs = unsafeDupablePerformIO $
  BSU.unsafeUseAsCStringLen bs $ \(ptr, len) ->
    pure $ c_rustyCRC32 (castPtr ptr) (fromIntegral len)

-- | Adler-32 via rusty-slap (RFC 1950).
rustyAdler32 :: ByteString -> Word32
rustyAdler32 bs = unsafeDupablePerformIO $
  BSU.unsafeUseAsCStringLen bs $ \(ptr, len) ->
    pure $ c_rustyAdler32 (castPtr ptr) (fromIntegral len)

-- | BPS diff via rusty-slap (suffix-array Flips algorithm).
-- Returns the raw encoded action byte stream.
rustyBpsDiff :: ByteString -> ByteString -> ByteString
rustyBpsDiff src tgt = unsafeDupablePerformIO $
  BSU.unsafeUseAsCStringLen src $ \(srcPtr, srcLen) ->
    BSU.unsafeUseAsCStringLen tgt $ \(tgtPtr, tgtLen) ->
      alloca $ \outPtrPtr ->
        alloca $ \outLenPtr -> do
          c_bpsDiff (castPtr srcPtr) (fromIntegral srcLen)
                    (castPtr tgtPtr) (fromIntegral tgtLen)
                    outPtrPtr outLenPtr
          outPtr <- peek outPtrPtr
          outLen <- peek outLenPtr
          if outPtr == nullPtr
            then pure BS.empty
            else do
              result <- BS.packCStringLen (castPtr outPtr, fromIntegral outLen)
              c_free outPtr outLen
              pure result
