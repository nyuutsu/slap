-- | Compression and decompression via rusty-slap (flate2 + bzip2-rs, pure Rust).
module Slap.Compress
  ( zlibInflate
  , zlibDeflate
  , gzipInflate
  , bz2Decompress
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Unsafe as UnsafeByteString
import Data.Word (Word8)
import Foreign.C.Types (CSize(..), CInt(..))
import Foreign.Marshal.Alloc (alloca)
import Foreign.Ptr (Ptr, castPtr, nullPtr)
import Foreign.Storable (peek)
import System.IO.Unsafe (unsafeDupablePerformIO)

foreign import ccall unsafe "rusty_zlib_inflate"
  c_zlibInflate :: Ptr Word8 -> CSize -> Ptr (Ptr Word8) -> Ptr CSize -> IO CInt

foreign import ccall unsafe "rusty_zlib_deflate"
  c_zlibDeflate :: Ptr Word8 -> CSize -> CInt -> Ptr (Ptr Word8) -> Ptr CSize -> IO CInt

foreign import ccall unsafe "rusty_gzip_inflate"
  c_gzipInflate :: Ptr Word8 -> CSize -> Ptr (Ptr Word8) -> Ptr CSize -> IO CInt

foreign import ccall unsafe "rusty_bz2_decompress"
  c_bz2Decompress :: Ptr Word8 -> CSize -> Ptr (Ptr Word8) -> Ptr CSize -> IO CInt

foreign import ccall unsafe "rusty_free"
  c_free :: Ptr Word8 -> CSize -> IO ()

----------------------------------------------------------------------------
-- Helpers
----------------------------------------------------------------------------

-- | Call a Rust decompression function that allocates its own output buffer.
-- Returns Left on error, Right on success.  Empty input → empty output.
{-# INLINE callRustyDecompress #-}
callRustyDecompress
  :: String                                                         -- error label
  -> (Ptr Word8 -> CSize -> Ptr (Ptr Word8) -> Ptr CSize -> IO CInt) -- FFI fn
  -> ByteString -> Either String ByteString
callRustyDecompress _     _          input | ByteString.null input = Right ByteString.empty
callRustyDecompress label decompress input = unsafeDupablePerformIO $
  UnsafeByteString.unsafeUseAsCStringLen input $ \(dataPointer, dataLength) ->
    alloca $ \resultAddressPointer ->
      alloca $ \resultLengthPointer -> do
        returnCode <- decompress (castPtr dataPointer) (fromIntegral dataLength) resultAddressPointer resultLengthPointer
        if returnCode /= 0
          then pure $ Left (label ++ " decompression failed")
          else do
            resultPointer <- peek resultAddressPointer
            resultLength <- peek resultLengthPointer
            if resultPointer == nullPtr
              then pure $ Right ByteString.empty
              else do
                result <- ByteString.packCStringLen (castPtr resultPointer, fromIntegral resultLength)
                c_free resultPointer resultLength
                pure $ Right result

----------------------------------------------------------------------------
-- Public API
----------------------------------------------------------------------------

-- | Zlib (RFC 1950) inflate.
zlibInflate :: ByteString -> Either String ByteString
zlibInflate = callRustyDecompress "zlib" c_zlibInflate

-- | Zlib (RFC 1950) deflate (hardcoded compression level 6).
-- Compression cannot fail for valid input; crashes on internal error.
zlibDeflate :: ByteString -> ByteString
zlibDeflate input
  | ByteString.null input = ByteString.empty
  | otherwise = unsafeDupablePerformIO $
      UnsafeByteString.unsafeUseAsCStringLen input $ \(dataPointer, dataLength) ->
        alloca $ \resultAddressPointer ->
          alloca $ \resultLengthPointer -> do
            returnCode <- c_zlibDeflate (castPtr dataPointer) (fromIntegral dataLength) 6 resultAddressPointer resultLengthPointer
            if returnCode /= 0
              then error "zlibDeflate: internal error (flate2 compression failed)"
              else do
                resultPointer <- peek resultAddressPointer
                resultLength <- peek resultLengthPointer
                if resultPointer == nullPtr
                  then pure ByteString.empty
                  else do
                    result <- ByteString.packCStringLen (castPtr resultPointer, fromIntegral resultLength)
                    c_free resultPointer resultLength
                    pure result

-- | Gzip (RFC 1952) inflate.
gzipInflate :: ByteString -> Either String ByteString
gzipInflate = callRustyDecompress "gzip" c_gzipInflate

-- | Bzip2 decompress.
bz2Decompress :: ByteString -> Either String ByteString
bz2Decompress = callRustyDecompress "bzip2" c_bz2Decompress
