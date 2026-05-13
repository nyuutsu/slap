-- | Cross-format math primitives via rusty-slap, plus the shared
-- buffer-handling helpers every rusty-slap binding reaches back
-- into. The math kernels are used by more than one format family
-- ('crc32' lands in BPS, IPS32, PCHTXT, …; 'adler32' is the UPS
-- footer); one-format-uses-this differs live next to their format
-- ('Slap.BPS.FFI', 'Slap.XDelta1.FFI'), but they all marshal Rust-
-- allocated buffers home through 'readByteString' and 'readString'.
module Slap.FFI
  ( crc32
  , adler32
  , readByteString
  , readString
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Unsafe as UnsafeByteString
import qualified Data.Text as Text
import qualified Data.Text.Encoding as TextEncoding
import Data.Word (Word8, Word32)
import Foreign.C.Types (CSize(..))
import Foreign.Ptr (Ptr, castPtr, nullPtr)
import Foreign.Storable (peek)
import Slap.Checksum (CRC32(..), Adler32(..))
import System.IO.Unsafe (unsafeDupablePerformIO)

foreign import ccall unsafe "rusty_crc32"
  rustyCRC32 :: Ptr () -> CSize -> Word32

foreign import ccall unsafe "rusty_adler32"
  rustyAdler32 :: Ptr () -> CSize -> Word32

foreign import ccall unsafe "rusty_free"
  rustyFree :: Ptr Word8 -> CSize -> IO ()

-- | CRC-32 via rusty-slap (hardware-accelerated crc32fast).
crc32 :: ByteString -> CRC32
crc32 input = CRC32 $ unsafeDupablePerformIO $
  UnsafeByteString.unsafeUseAsCStringLen input $ \(dataPointer, dataLength) ->
    pure $ rustyCRC32 (castPtr dataPointer) (fromIntegral dataLength)

-- | Adler-32 via rusty-slap (RFC 1950).
adler32 :: ByteString -> Adler32
adler32 input = Adler32 $ unsafeDupablePerformIO $
  UnsafeByteString.unsafeUseAsCStringLen input $ \(dataPointer, dataLength) ->
    pure $ rustyAdler32 (castPtr dataPointer) (fromIntegral dataLength)

-- | Pack a Rust-allocated buffer into a managed Haskell 'ByteString'
-- and free the underlying allocation via 'rustyFree'. Inputs are the
-- out-pointer pair (address pointer, length pointer) the FFI call
-- writes into. Returns 'ByteString.empty' for null pointers — the
-- canonical "no buffer" pair surfaced by @surface_buffer_to_caller@
-- on the Rust side.
readByteString :: Ptr (Ptr Word8) -> Ptr CSize -> IO ByteString
readByteString addressPointer lengthPointer = do
  bufferAddress <- peek addressPointer
  bufferLength  <- peek lengthPointer
  if bufferAddress == nullPtr
    then pure ByteString.empty
    else do
      bytes <- ByteString.packCStringLen
                 (castPtr bufferAddress, fromIntegral bufferLength)
      rustyFree bufferAddress bufferLength
      pure bytes

-- | Pack a Rust-allocated string (UTF-8 bytes) into a Haskell 'String',
-- decoded leniently — invalid byte sequences become U+FFFD rather
-- than throwing, so a corrupt-bytes-from-FFI event cannot raise
-- during the rendering of an unrelated error. Built on
-- 'readByteString'; same null-pointer semantics. Used for diagnostic
-- message channels.
readString :: Ptr (Ptr Word8) -> Ptr CSize -> IO String
readString addressPointer lengthPointer = do
  messageBytes <- readByteString addressPointer lengthPointer
  pure (Text.unpack (TextEncoding.decodeUtf8Lenient messageBytes))
