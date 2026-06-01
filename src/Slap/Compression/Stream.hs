-- | Compression and decompression via rusty-slap.
module Slap.Compression.Stream
  ( zlibInflate
  , zlibDeflate
  , gzipInflate
  , gzipDeflate
  , bzip2Decompress
  , yay0Decompress
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.Word (Word8)
import Foreign.C.Types (CSize(..), CInt(..))
import Foreign.Marshal.Alloc (alloca)
import Foreign.Ptr (Ptr)
import System.IO.Unsafe (unsafeDupablePerformIO)

import Slap.Status (DecompressionCause(..))
import Slap.FFI (readByteString, readText, withByteString)

foreign import ccall unsafe "rusty_zlib_inflate"
  rustyZlibInflate
    :: Ptr Word8 -> CSize
    -> Ptr (Ptr Word8) -> Ptr CSize     -- success buffer
    -> Ptr (Ptr Word8) -> Ptr CSize     -- error message buffer
    -> IO CInt

foreign import ccall unsafe "rusty_zlib_deflate"
  rustyZlibDeflate
    :: Ptr Word8 -> CSize
    -> Ptr (Ptr Word8) -> Ptr CSize
    -> IO ()

foreign import ccall unsafe "rusty_gzip_inflate"
  rustyGzipInflate
    :: Ptr Word8 -> CSize
    -> Ptr (Ptr Word8) -> Ptr CSize
    -> Ptr (Ptr Word8) -> Ptr CSize
    -> IO CInt

foreign import ccall unsafe "rusty_gzip_deflate"
  rustyGzipDeflate
    :: Ptr Word8 -> CSize
    -> Ptr (Ptr Word8) -> Ptr CSize
    -> IO ()

foreign import ccall unsafe "rusty_bzip2_decompress"
  rustyBzip2Decompress
    :: Ptr Word8 -> CSize
    -> Ptr (Ptr Word8) -> Ptr CSize
    -> Ptr (Ptr Word8) -> Ptr CSize
    -> IO CInt

foreign import ccall unsafe "rusty_yay0_decompress"
  rustyYay0Decompress
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
  withByteString input $ \dataPointer dataLength ->
    alloca $ \resultAddressPointer ->
    alloca $ \resultLengthPointer ->
    alloca $ \errorAddressPointer ->
    alloca $ \errorLengthPointer -> do
      returnCode <- decompress
        dataPointer dataLength
        resultAddressPointer resultLengthPointer
        errorAddressPointer  errorLengthPointer
      if returnCode /= 0
        then do
          rustMessage <- readText errorAddressPointer errorLengthPointer
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
-- rather than exposing a knob no caller currently turns. Pure, and total
-- at the algorithm level for the same reason as 'gzipDeflate': in-memory
-- deflate's only fail-shaped event is allocation failure, which Rust's
-- allocator handles by aborting before any error reaches us.
--
-- The empty-input guard is deliberate and wire-affecting: NINJA1's
-- compressed-binary payload round-trips an empty payload as empty bytes
-- (paired with 'callDecompressor''s matching empty guard), rather than as
-- the header+checksum a real deflate of empty would emit.
zlibDeflate :: ByteString -> ByteString
zlibDeflate input
  | ByteString.null input = ByteString.empty
  | otherwise = unsafeDupablePerformIO $
      withByteString input $ \dataPointer dataLength ->
        alloca $ \resultAddressPointer ->
        alloca $ \resultLengthPointer -> do
          rustyZlibDeflate dataPointer dataLength
                           resultAddressPointer resultLengthPointer
          readByteString   resultAddressPointer resultLengthPointer

-- | Gzip (RFC 1952) inflate.
gzipInflate :: ByteString -> Either DecompressionCause ByteString
gzipInflate = callDecompressor rustyGzipInflate

-- | Gzip (RFC 1952) deflate via rusty-slap (flate2's gzip encoder, default
-- compression level, @mtime = 0@ pinned for deterministic output). Pure:
-- gzip-deflate of arbitrary input is total at the algorithm level; the only
-- fail-shaped event is allocation failure, which Rust's default allocator
-- handles by aborting before any error value reaches us. Round-trip partner
-- of 'gzipInflate'.
gzipDeflate :: ByteString -> ByteString
gzipDeflate input = unsafeDupablePerformIO $
  withByteString input $ \dataPointer dataLength ->
  alloca $ \resultAddressPointer ->
  alloca $ \resultLengthPointer -> do
    rustyGzipDeflate dataPointer dataLength
                     resultAddressPointer resultLengthPointer
    readByteString   resultAddressPointer resultLengthPointer

-- | Bzip2 decompress.
bzip2Decompress :: ByteString -> Either DecompressionCause ByteString
bzip2Decompress = callDecompressor rustyBzip2Decompress

-- | Yay0 (Nintendo LZSS) decompression.
yay0Decompress :: ByteString -> Either DecompressionCause ByteString
yay0Decompress = callDecompressor rustyYay0Decompress
