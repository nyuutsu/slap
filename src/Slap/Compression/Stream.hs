-- | Compression and decompression via rusty-slap (flate2 + bzip2-rs, pure Rust).
module Slap.Compression.Stream
  ( zlibInflate
  , zlibDeflate
  , gzipInflate
  , bzip2Decompress
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Unsafe as UnsafeByteString
import Data.Word (Word8)
import Foreign.C.Types (CSize(..), CInt(..))
import Foreign.Marshal.Alloc (alloca)
import Foreign.Ptr (Ptr, castPtr)
import System.IO.Unsafe (unsafeDupablePerformIO)

import Slap.Error (DecompressionCause(..))
import Slap.FFI (readByteString, readString)

foreign import ccall unsafe "rusty_zlib_inflate"
  rustyZlibInflate
    :: Ptr Word8 -> CSize
    -> Ptr (Ptr Word8) -> Ptr CSize     -- success buffer
    -> Ptr (Ptr Word8) -> Ptr CSize     -- error message buffer
    -> IO CInt

foreign import ccall unsafe "rusty_zlib_deflate"
  rustyZlibDeflate
    :: Ptr Word8 -> CSize
    -> Ptr (Ptr Word8) -> Ptr CSize     -- success buffer
    -> Ptr (Ptr Word8) -> Ptr CSize     -- error message buffer
    -> IO CInt

foreign import ccall unsafe "rusty_gzip_inflate"
  rustyGzipInflate
    :: Ptr Word8 -> CSize
    -> Ptr (Ptr Word8) -> Ptr CSize
    -> Ptr (Ptr Word8) -> Ptr CSize
    -> IO CInt

foreign import ccall unsafe "rusty_bzip2_decompress"
  rustyBzip2Decompress
    :: Ptr Word8 -> CSize
    -> Ptr (Ptr Word8) -> Ptr CSize
    -> Ptr (Ptr Word8) -> Ptr CSize
    -> IO CInt

----------------------------------------------------------------------------
-- Helpers
----------------------------------------------------------------------------

-- | Call a Rust decompression function that allocates its own output buffer.
-- Returns Left on error, Right on success.  Empty input → empty output.
{-# INLINE callDecompressor #-}
callDecompressor
  :: ( Ptr Word8 -> CSize
    -> Ptr (Ptr Word8) -> Ptr CSize
    -> Ptr (Ptr Word8) -> Ptr CSize
    -> IO CInt )
  -> ByteString -> Either DecompressionCause ByteString
callDecompressor _          input | ByteString.null input = Right ByteString.empty
callDecompressor decompress input = unsafeDupablePerformIO $
  UnsafeByteString.unsafeUseAsCStringLen input $ \(dataPointer, dataLength) ->
    alloca $ \resultAddressPointer ->
    alloca $ \resultLengthPointer ->
    alloca $ \errorAddressPointer ->
    alloca $ \errorLengthPointer -> do
      returnCode <- decompress
        (castPtr dataPointer) (fromIntegral dataLength)
        resultAddressPointer resultLengthPointer
        errorAddressPointer  errorLengthPointer
      if returnCode /= 0
        then do
          rustMessage <- readString errorAddressPointer errorLengthPointer
          pure $ Left (DecompressionCause rustMessage)
        else
          Right <$> readByteString resultAddressPointer resultLengthPointer

----------------------------------------------------------------------------
-- Public API
----------------------------------------------------------------------------

-- | Zlib (RFC 1950) inflate.
zlibInflate :: ByteString -> Either DecompressionCause ByteString
zlibInflate = callDecompressor rustyZlibInflate

-- | Zlib (RFC 1950) deflate at the library's default compression level.
-- The NINJA1 spec is mute on level — any zlib-deflate output round-trips
-- through any decoder regardless — so the rusty side pins the default
-- rather than exposing a knob no caller currently turns. Compression
-- cannot fail for valid input; crashes on internal error.
zlibDeflate :: ByteString -> ByteString
zlibDeflate input
  | ByteString.null input = ByteString.empty
  | otherwise = unsafeDupablePerformIO $
      UnsafeByteString.unsafeUseAsCStringLen input $ \(dataPointer, dataLength) ->
        alloca $ \resultAddressPointer ->
        alloca $ \resultLengthPointer ->
        alloca $ \errorAddressPointer ->
        alloca $ \errorLengthPointer -> do
          returnCode <- rustyZlibDeflate
            (castPtr dataPointer) (fromIntegral dataLength)
            resultAddressPointer resultLengthPointer
            errorAddressPointer  errorLengthPointer
          if returnCode /= 0
            then do
              rustMessage <- readString errorAddressPointer errorLengthPointer
              error ("zlibDeflate: internal error: " ++ rustMessage)
            else
              readByteString resultAddressPointer resultLengthPointer

-- | Gzip (RFC 1952) inflate.
gzipInflate :: ByteString -> Either DecompressionCause ByteString
gzipInflate = callDecompressor rustyGzipInflate

-- | Bzip2 decompress.
bzip2Decompress :: ByteString -> Either DecompressionCause ByteString
bzip2Decompress = callDecompressor rustyBzip2Decompress
