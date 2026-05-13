-- | BPS differ binding to rusty-slap. Sibling to the cross-format
-- primitives in "Slap.FFI": those are the math kernels shared
-- across formats (CRC-32, Adler-32); this is the one-format-uses-
-- this differ ('rusty-slap/src/bps_diff.rs') and lives next to the
-- rest of the BPS module family.
module Slap.BPS.FFI (rustyBpsDiff) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Unsafe as UnsafeByteString
import Data.Word (Word8)
import Foreign.C.Types (CSize(..))
import Foreign.Marshal.Alloc (alloca)
import Foreign.Ptr (Ptr, castPtr, nullPtr)
import Foreign.Storable (peek)
import Slap.FileContents (InputFileContents(..), OutputFileContents(..))
import System.IO.Unsafe (unsafeDupablePerformIO)

foreign import ccall unsafe "rusty_bps_diff"
  c_bpsDiff :: Ptr Word8 -> CSize -> Ptr Word8 -> CSize
            -> Ptr (Ptr Word8) -> Ptr CSize -> IO ()

foreign import ccall unsafe "rusty_free"
  c_free :: Ptr Word8 -> CSize -> IO ()

-- | BPS diff via rusty-slap (suffix-array algorithm, after Alcaro's Flips).
-- Returns the raw encoded action byte stream.
rustyBpsDiff :: InputFileContents -> OutputFileContents -> ByteString
rustyBpsDiff (InputFileContents source) (OutputFileContents target) = unsafeDupablePerformIO $
  UnsafeByteString.unsafeUseAsCStringLen source $ \(sourcePointer, sourceLength) ->
    UnsafeByteString.unsafeUseAsCStringLen target $ \(targetPointer, targetLength) ->
      alloca $ \resultAddressPointer ->
        alloca $ \resultLengthPointer -> do
          c_bpsDiff (castPtr sourcePointer) (fromIntegral sourceLength)
                    (castPtr targetPointer) (fromIntegral targetLength)
                    resultAddressPointer resultLengthPointer
          resultPointer <- peek resultAddressPointer
          resultLength <- peek resultLengthPointer
          if resultPointer == nullPtr
            then pure ByteString.empty
            else do
              result <- ByteString.packCStringLen (castPtr resultPointer, fromIntegral resultLength)
              c_free resultPointer resultLength
              pure result
