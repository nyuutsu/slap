-- | BPS differ binding to rusty-slap. Sibling to the cross-format
-- primitives in "Slap.FFI": those are the math kernels shared
-- across formats (CRC-32, Adler-32); this is the one-format-uses-
-- this differ ('rusty-slap/src/bps_diff.rs') and lives next to the
-- rest of the BPS module family.
module Slap.BPS.FFI (bpsDiff) where

import Data.ByteString (ByteString)
import Data.Word (Word8)
import Foreign.C.Types (CSize(..))
import Foreign.Marshal.Alloc (alloca)
import Foreign.Ptr (Ptr)
import Slap.FFI (readByteString, withByteString)
import Slap.FileContents (InputFileContents(..), OutputFileContents(..))
import System.IO.Unsafe (unsafeDupablePerformIO)

foreign import ccall unsafe "rusty_bps_diff"
  rustyBpsDiff :: Ptr Word8 -> CSize -> Ptr Word8 -> CSize
               -> Ptr (Ptr Word8) -> Ptr CSize -> IO ()

-- | BPS diff via rusty-slap (suffix-array algorithm, after Alcaro's Flips).
-- Returns the raw encoded action byte stream.
bpsDiff :: InputFileContents -> OutputFileContents -> ByteString
bpsDiff (InputFileContents source) (OutputFileContents target) = unsafeDupablePerformIO $
  withByteString source $ \sourcePointer sourceLength ->
  withByteString target $ \targetPointer targetLength ->
  alloca $ \resultAddressPointer ->
  alloca $ \resultLengthPointer -> do
    rustyBpsDiff sourcePointer sourceLength
                 targetPointer targetLength
                 resultAddressPointer resultLengthPointer
    readByteString resultAddressPointer resultLengthPointer
