-- | Cross-format math primitives via rusty-slap. The kernels here
-- are used by more than one format family ('rustyCRC32' lands in
-- BPS, IPS32, PCHTXT, …; 'rustyAdler32' is the UPS footer); one-
-- format-uses-this differs live next to their format
-- ('Slap.BPS.FFI', 'Slap.XDelta1.FFI').
module Slap.FFI (rustyCRC32, rustyAdler32) where

import Data.ByteString (ByteString)
import qualified Data.ByteString.Unsafe as UnsafeByteString
import Data.Word (Word32)
import Foreign.C.Types (CSize(..))
import Foreign.Ptr (Ptr, castPtr)
import Slap.Checksum (CRC32(..), Adler32(..))
import System.IO.Unsafe (unsafeDupablePerformIO)

foreign import ccall unsafe "rusty_crc32"
  c_rustyCRC32 :: Ptr () -> CSize -> Word32

foreign import ccall unsafe "rusty_adler32"
  c_rustyAdler32 :: Ptr () -> CSize -> Word32

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
