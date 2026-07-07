-- | Cross-format math primitives via rusty-slap, plus the shared buffer-handling helpers every rusty-slap binding reaches back into.
--
-- The math kernels live here because more than one format family uses them ('crc32' in BPS and UPS, 'adler32' for VCDIFF's per-window checksum);
-- a kernel only one format uses lives next to that format ('Slap.BPS.FFI', 'Slap.XDelta1.FFI').
--
-- Every binding, here and elsewhere, marshals through the same trio:
-- 'withByteString' hands input bytes across, 'readByteString' / 'readText' bring Rust-allocated buffers home.
module Slap.FFI
  ( crc32
  , adler32
  , withByteString
  , readByteString
  , readText
  , readWord64LE
  ) where

import Data.Bits ((.|.), shiftL)
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Unsafe as UnsafeByteString
import Data.Text (Text)
import qualified Data.Text.Encoding as TextEncoding
import Data.Word (Word8, Word32, Word64)
import Foreign.C.Types (CSize(..))
import Foreign.Ptr (Ptr, castPtr, nullPtr)
import Foreign.Storable (peek)
import Slap.Checksum (CRC32(..), Adler32(..))
import System.IO.Unsafe (unsafePerformIO)

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
crc32 input = CRC32 $ unsafePerformIO $
  withByteString input $ \dataPointer dataLength ->
    pure $! rustyCRC32 dataPointer dataLength

-- | Adler-32 via rusty-slap (RFC 1950, runtime-SIMD simd-adler32).
-- The @pure $!@ is load-bearing for the same reason as in 'crc32'.
adler32 :: ByteString -> Adler32
adler32 input = Adler32 $ unsafePerformIO $
  withByteString input $ \dataPointer dataLength ->
    pure $! rustyAdler32 dataPointer dataLength

-- | Use a 'ByteString''s bytes as an FFI-compatible ('Ptr' 'Word8', 'CSize') pair for the duration of a synchronous FFI call.
-- Bundles the 'UnsafeByteString.unsafeUseAsCStringLen' bracket,
-- the 'Ptr CChar' → 'Ptr Word8' relabel (ByteString stores 'Ptr CChar'; the rusty-slap signatures want 'Ptr Word8' to match Rust's @*const u8@),
-- and the 'Int' → 'CSize' conversion in one place.
-- Input-side mirror of 'readByteString'.
--
-- The unsafe (no-copy) variant of 'unsafeUseAsCStringLen' is
-- correct here because the FFI call is synchronous: it consumes the
-- bytes during the call and doesn't retain a pointer after return.
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
-- message channels.
readText :: Ptr (Ptr Word8) -> Ptr CSize -> IO Text
readText addressPointer lengthPointer = do
  messageBytes <- readByteString addressPointer lengthPointer
  pure (TextEncoding.decodeUtf8Lenient messageBytes)

-- | Read a little-endian 'Word64' from @offset@ in a buffer — the
-- decode side of an @x.to_le_bytes()@ element in a rusty-slap parallel
-- u64 array. The bindings that unmarshal those arrays
-- ('Slap.XDelta1.FFI', 'Slap.VCDIFF.FFI') share this rather than each
-- re-spelling the eight shifts.
readWord64LE :: ByteString -> Int -> Word64
readWord64LE buffer offset =
  let byteAt index = fromIntegral (ByteString.index buffer (offset + index)) :: Word64
  in       byteAt 0
    .|. (byteAt 1 `shiftL` 8)
    .|. (byteAt 2 `shiftL` 16)
    .|. (byteAt 3 `shiftL` 24)
    .|. (byteAt 4 `shiftL` 32)
    .|. (byteAt 5 `shiftL` 40)
    .|. (byteAt 6 `shiftL` 48)
    .|. (byteAt 7 `shiftL` 56)
