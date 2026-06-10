-- | Cross-format math primitives via rusty-slap, plus the shared
-- buffer-handling helpers every rusty-slap binding reaches back
-- into. The math kernels are used by more than one format family
-- ('crc32' lands in BPS and UPS; 'adler32' is VCDIFF's per-window
-- checksum, verified at the shared boundary);
-- one-format-uses-this differs live next to their format
-- ('Slap.BPS.FFI', 'Slap.XDelta1.FFI'), but they all marshal Rust-
-- allocated buffers home through 'readByteString' / 'readText'
-- and hand input bytes across through 'withByteString' — the FFI-
-- marshalling helper trio.
module Slap.FFI
  ( crc32
  , adler32
  , withByteString
  , readByteString
  , readText
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Unsafe as UnsafeByteString
import Data.Text (Text)
import qualified Data.Text.Encoding as TextEncoding
import Data.Word (Word8, Word32)
import Foreign.C.Types (CSize(..))
import Foreign.Ptr (Ptr, castPtr, nullPtr)
import Foreign.Storable (peek)
import Slap.Checksum (CRC32(..), Adler32(..))
import System.IO.Unsafe (unsafeDupablePerformIO)

foreign import ccall unsafe "rusty_crc32"
  rustyCRC32 :: Ptr Word8 -> CSize -> Word32

foreign import ccall unsafe "rusty_adler32"
  rustyAdler32 :: Ptr Word8 -> CSize -> Word32

foreign import ccall unsafe "rusty_free"
  rustyFree :: Ptr Word8 -> CSize -> IO ()

-- | CRC-32 via rusty-slap (hardware-accelerated crc32fast).
--
-- The @pure $!@ is load-bearing: 'rustyCRC32' is imported pure, so a
-- lazy @pure $@ would return an unevaluated thunk holding the raw
-- pointer past the end of 'withByteString''s keep-alive bracket —
-- and a force after the ByteString's buffer is collected would read
-- freed memory. Forcing inside the bracket pins the call to the
-- window where the pointer is guaranteed valid.
crc32 :: ByteString -> CRC32
crc32 input = CRC32 $ unsafeDupablePerformIO $
  withByteString input $ \dataPointer dataLength ->
    pure $! rustyCRC32 dataPointer dataLength

-- | Adler-32 via rusty-slap (RFC 1950). The @pure $!@ is load-bearing
-- for the same reason as in 'crc32'.
adler32 :: ByteString -> Adler32
adler32 input = Adler32 $ unsafeDupablePerformIO $
  withByteString input $ \dataPointer dataLength ->
    pure $! rustyAdler32 dataPointer dataLength

-- | Use a 'ByteString''s bytes as an FFI-compatible
-- ('Ptr' 'Word8', 'CSize') pair for the duration of a synchronous
-- FFI call. Bundles the 'UnsafeByteString.unsafeUseAsCStringLen'
-- bracket, the 'Ptr CChar' → 'Ptr Word8' relabel (ByteString stores
-- 'Ptr CChar' for historical reasons; the rusty-slap signatures want
-- 'Ptr Word8' to match Rust's @*const u8@ honestly), and the 'Int' →
-- 'CSize' conversion in one place. Input-side mirror of
-- 'readByteString'.
--
-- The unsafe (no-copy) variant of 'unsafeUseAsCStringLen' is
-- correct for synchronous FFI that consumes the bytes during the
-- call and doesn't retain a pointer after return — slap's current
-- shape. A future FFI that retains a pointer (async, callback, or
-- thread-keeping shape) would need a copying sibling; not present
-- today.
withByteString :: ByteString -> (Ptr Word8 -> CSize -> IO a) -> IO a
withByteString input action =
  UnsafeByteString.unsafeUseAsCStringLen input $ \(dataPointer, dataLength) ->
    action (castPtr dataPointer) (fromIntegral dataLength)

-- | Pack a Rust-allocated buffer into a managed Haskell 'ByteString'
-- and free the underlying allocation via 'rustyFree'. Inputs are the
-- out-pointer pair (address pointer, length pointer) the FFI call
-- writes into. Returns 'ByteString.empty' for null pointers — the
-- canonical "no buffer" pair surfaced by @surface_buffer_to_caller@
-- on the Rust side. Output-side mirror of 'withByteString'.
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

-- | Pack a Rust-allocated string (UTF-8 bytes) into a Haskell 'Text',
-- decoded leniently — invalid byte sequences become U+FFFD rather
-- than throwing, so a corrupt-bytes-from-FFI event cannot raise
-- during the rendering of an unrelated error. Built on
-- 'readByteString'; same null-pointer semantics. Used for diagnostic
-- message channels. Rust's 'String' is UTF-8 by language guarantee,
-- so the leniency is defense-in-depth: at this seam the bytes are
-- UTF-8 by Rust's contract, and a buffer-corruption event in the FFI
-- channel can't raise a decode exception during error rendering.
readText :: Ptr (Ptr Word8) -> Ptr CSize -> IO Text
readText addressPointer lengthPointer = do
  messageBytes <- readByteString addressPointer lengthPointer
  pure (TextEncoding.decodeUtf8Lenient messageBytes)
