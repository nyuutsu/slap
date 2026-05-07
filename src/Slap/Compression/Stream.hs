-- | Compression and decompression via rusty-slap (flate2 + bzip2-rs, pure Rust).
module Slap.Compression.Stream
  ( zlibInflate
  , zlibDeflate
  , gzipInflate
  , bz2Decompress
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Unsafe as UnsafeByteString
import qualified Data.Text as Text
import qualified Data.Text.Encoding as TextEncoding
import Data.Word (Word8)
import Foreign.C.Types (CSize(..), CInt(..))
import Foreign.Marshal.Alloc (alloca)
import Foreign.Ptr (Ptr, castPtr, nullPtr)
import Foreign.Storable (peek)
import System.IO.Unsafe (unsafeDupablePerformIO)

import Slap.Error (DecompressionCause(..))

foreign import ccall unsafe "rusty_zlib_inflate"
  c_zlibInflate
    :: Ptr Word8 -> CSize
    -> Ptr (Ptr Word8) -> Ptr CSize     -- success buffer
    -> Ptr (Ptr Word8) -> Ptr CSize     -- error message buffer
    -> IO CInt

foreign import ccall unsafe "rusty_zlib_deflate"
  c_zlibDeflate
    :: Ptr Word8 -> CSize -> CInt
    -> Ptr (Ptr Word8) -> Ptr CSize     -- success buffer
    -> Ptr (Ptr Word8) -> Ptr CSize     -- error message buffer
    -> IO CInt

foreign import ccall unsafe "rusty_gzip_inflate"
  c_gzipInflate
    :: Ptr Word8 -> CSize
    -> Ptr (Ptr Word8) -> Ptr CSize
    -> Ptr (Ptr Word8) -> Ptr CSize
    -> IO CInt

foreign import ccall unsafe "rusty_bz2_decompress"
  c_bz2Decompress
    :: Ptr Word8 -> CSize
    -> Ptr (Ptr Word8) -> Ptr CSize
    -> Ptr (Ptr Word8) -> Ptr CSize
    -> IO CInt

foreign import ccall unsafe "rusty_free"
  c_free :: Ptr Word8 -> CSize -> IO ()

----------------------------------------------------------------------------
-- Helpers
----------------------------------------------------------------------------

-- | Pack the bytes at @(addressPointer, lengthPointer)@ into a 'String',
-- freeing the underlying buffer.  Returns @""@ if the pointer is null.
--
-- The bytes are guaranteed to be valid UTF-8 (Rust's 'String' is UTF-8
-- by construction at the type level, so every diagnostic that reaches
-- this helper is well-formed).  Decoded leniently nonetheless — any
-- structurally-invalid byte sequence is replaced with U+FFFD rather
-- than raising — so a corrupt-bytes-from-FFI event cannot throw during
-- the rendering of an unrelated error.  The resulting 'String' carries
-- real Unicode code points: an em-dash arrives as 'Char' U+2014, not
-- three garbage 'Char's.
readRustString :: Ptr (Ptr Word8) -> Ptr CSize -> IO String
readRustString addressPointer lengthPointer = do
  bufferPointer <- peek addressPointer
  bufferLength  <- peek lengthPointer
  if bufferPointer == nullPtr
    then pure ""
    else do
      messageBytes <- ByteString.packCStringLen (castPtr bufferPointer, fromIntegral bufferLength)
      c_free bufferPointer bufferLength
      pure (Text.unpack (TextEncoding.decodeUtf8Lenient messageBytes))

-- | Call a Rust decompression function that allocates its own output buffer.
-- Returns Left on error, Right on success.  Empty input → empty output.
{-# INLINE callRustyDecompress #-}
callRustyDecompress
  :: ( Ptr Word8 -> CSize
    -> Ptr (Ptr Word8) -> Ptr CSize
    -> Ptr (Ptr Word8) -> Ptr CSize
    -> IO CInt )
  -> ByteString -> Either DecompressionCause ByteString
callRustyDecompress _          input | ByteString.null input = Right ByteString.empty
callRustyDecompress decompress input = unsafeDupablePerformIO $
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
          rustMessage <- readRustString errorAddressPointer errorLengthPointer
          pure $ Left (DecompressionCause rustMessage)
        else do
          resultPointer <- peek resultAddressPointer
          resultLength  <- peek resultLengthPointer
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
zlibInflate :: ByteString -> Either DecompressionCause ByteString
zlibInflate = callRustyDecompress c_zlibInflate

-- | Zlib (RFC 1950) deflate (hardcoded compression level 6).
-- Compression cannot fail for valid input; crashes on internal error.
zlibDeflate :: ByteString -> ByteString
zlibDeflate input
  | ByteString.null input = ByteString.empty
  | otherwise = unsafeDupablePerformIO $
      UnsafeByteString.unsafeUseAsCStringLen input $ \(dataPointer, dataLength) ->
        alloca $ \resultAddressPointer ->
        alloca $ \resultLengthPointer ->
        alloca $ \errorAddressPointer ->
        alloca $ \errorLengthPointer -> do
          returnCode <- c_zlibDeflate
            (castPtr dataPointer) (fromIntegral dataLength) 6
            resultAddressPointer resultLengthPointer
            errorAddressPointer  errorLengthPointer
          if returnCode /= 0
            then do
              rustMessage <- readRustString errorAddressPointer errorLengthPointer
              error ("zlibDeflate: internal error: " ++ rustMessage)
            else do
              resultPointer <- peek resultAddressPointer
              resultLength  <- peek resultLengthPointer
              if resultPointer == nullPtr
                then pure ByteString.empty
                else do
                  result <- ByteString.packCStringLen (castPtr resultPointer, fromIntegral resultLength)
                  c_free resultPointer resultLength
                  pure result

-- | Gzip (RFC 1952) inflate.
gzipInflate :: ByteString -> Either DecompressionCause ByteString
gzipInflate = callRustyDecompress c_gzipInflate

-- | Bzip2 decompress.
bz2Decompress :: ByteString -> Either DecompressionCause ByteString
bz2Decompress = callRustyDecompress c_bz2Decompress
