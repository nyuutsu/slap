-- | Compression via rusty-slap (flate2 + bzip2-rs, pure Rust).
module Patch.Compress
  ( zlibInflate
  , zlibDeflate
  , gzipInflate
  , bz2Decompress
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Unsafe as BSU
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
callRustyDecompress _     _   bs | BS.null bs = Right BS.empty
callRustyDecompress label ffi bs = unsafeDupablePerformIO $
  BSU.unsafeUseAsCStringLen bs $ \(ptr, len) ->
    alloca $ \outPtrPtr ->
      alloca $ \outLenPtr -> do
        rc <- ffi (castPtr ptr) (fromIntegral len) outPtrPtr outLenPtr
        if rc /= 0
          then pure $ Left (label ++ " decompression failed")
          else do
            outPtr <- peek outPtrPtr
            outLen <- peek outLenPtr
            if outPtr == nullPtr
              then pure $ Right BS.empty
              else do
                result <- BS.packCStringLen (castPtr outPtr, fromIntegral outLen)
                c_free outPtr outLen
                pure $ Right result

----------------------------------------------------------------------------
-- Public API
----------------------------------------------------------------------------

-- | Zlib (RFC 1950) inflate.
zlibInflate :: ByteString -> Either String ByteString
zlibInflate = callRustyDecompress "zlib" c_zlibInflate

-- | Zlib (RFC 1950) deflate (default compression level 6).
-- Compression cannot fail for valid input; crashes on internal error.
zlibDeflate :: ByteString -> ByteString
zlibDeflate bs
  | BS.null bs = BS.empty
  | otherwise = unsafeDupablePerformIO $
      BSU.unsafeUseAsCStringLen bs $ \(ptr, len) ->
        alloca $ \outPtrPtr ->
          alloca $ \outLenPtr -> do
            rc <- c_zlibDeflate (castPtr ptr) (fromIntegral len) 6 outPtrPtr outLenPtr
            if rc /= 0
              then error "zlibDeflate: internal error (flate2 compression failed)"
              else do
                outPtr <- peek outPtrPtr
                outLen <- peek outLenPtr
                if outPtr == nullPtr
                  then pure BS.empty
                  else do
                    result <- BS.packCStringLen (castPtr outPtr, fromIntegral outLen)
                    c_free outPtr outLen
                    pure result

-- | Gzip (RFC 1952) inflate.
gzipInflate :: ByteString -> Either String ByteString
gzipInflate = callRustyDecompress "gzip" c_gzipInflate

-- | Bzip2 decompress.
bz2Decompress :: ByteString -> Either String ByteString
bz2Decompress = callRustyDecompress "bzip2" c_bz2Decompress
