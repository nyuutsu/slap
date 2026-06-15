-- | Compression and decompression via rusty-slap.
module Slap.Compression.Stream
  ( zlibInflate
  , zlibDeflate
  , gzipInflate
  , gzipDeflate
  , bzip2Decompress
  , LzmaDecoded(..)
  , lzmaDecompress
  , DjwDecoded(..)
  , djwDecompress
  , FgkDecoded(..)
  , fgkDecompress
  , yay0Decompress
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.Word (Word8)
import Foreign.C.Types (CSize(..), CInt(..))
import Foreign.Marshal.Alloc (alloca)
import Foreign.Marshal.Array (withArray)
import Foreign.Ptr (Ptr)
import Foreign.Storable (peek)
import System.IO.Unsafe (unsafeDupablePerformIO)

import Slap.Measure (Length(..))
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

foreign import ccall unsafe "rusty_lzma_decompress"
  rustyLzmaDecompress
    :: Ptr Word8 -> CSize
    -> Ptr (Ptr Word8) -> Ptr CSize     -- decoded bytes
    -> Ptr CSize                        -- consumed input length
    -> Ptr (Ptr Word8) -> Ptr CSize     -- error message buffer
    -> IO CInt

foreign import ccall unsafe "rusty_djw_decompress"
  rustyDjwDecompress
    :: Ptr Word8 -> CSize
    -> CSize                            -- expected output length
    -> Ptr (Ptr Word8) -> Ptr CSize     -- decoded bytes
    -> Ptr CSize                        -- consumed input length
    -> Ptr (Ptr Word8) -> Ptr CSize     -- error message buffer
    -> IO CInt

foreign import ccall unsafe "rusty_fgk_decompress"
  rustyFgkDecompress
    :: Ptr Word8 -> CSize
    -> Ptr CSize -> CSize               -- per-section output lengths, count
    -> Ptr (Ptr Word8) -> Ptr CSize     -- decoded bytes
    -> Ptr CSize                        -- consumed input length
    -> Ptr (Ptr Word8) -> Ptr CSize     -- error message buffer
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
zlibDeflate :: ByteString -> ByteString
zlibDeflate input = unsafeDupablePerformIO $
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

-- | What one LZMA decompression reports back across the seam: the
-- decoded bytes, and how many input bytes the decoder consumed
-- before it finished. The consumed length is a fact only the decoder
-- can know; whether that fact honors the framing the stream was
-- carried under is a judgment this seam leaves to its caller.
data LzmaDecoded = LzmaDecoded
  { lzmaDecodedBytes        :: !ByteString
  , lzmaConsumedInputLength :: !Length
  }
  deriving (Show, Eq)

-- | LZMA decompression of one xdelta3-flavored stream (xz header,
-- raw LZMA2 chunks, no closing footer — see @rusty-slap/src/xdelta3_lzma.rs@
-- for the stream shape). Written longhand rather than through
-- 'callDecompressor': the consumed-input length is a third output
-- channel the helper's shape has no slot for, and the helper's
-- empty-input short-circuit would be wrong here — an empty input is
-- not an empty output, it is a stream with no xz header, and the
-- decoder's complaint to that effect is the honest answer.
lzmaDecompress :: ByteString -> Either DecompressionCause LzmaDecoded
lzmaDecompress input = unsafeDupablePerformIO $
  withByteString input $ \dataPointer dataLength ->
    alloca $ \resultAddressPointer ->
    alloca $ \resultLengthPointer ->
    alloca $ \consumedLengthPointer ->
    alloca $ \errorAddressPointer ->
    alloca $ \errorLengthPointer -> do
      returnCode <- rustyLzmaDecompress
        dataPointer dataLength
        resultAddressPointer resultLengthPointer
        consumedLengthPointer
        errorAddressPointer  errorLengthPointer
      if returnCode /= 0
        then do
          rustMessage <- readText errorAddressPointer errorLengthPointer
          pure $ Left (DecompressionCause rustMessage)
        else do
          decodedBytes   <- readByteString resultAddressPointer resultLengthPointer
          consumedLength <- peek consumedLengthPointer
          pure $ Right LzmaDecoded
            { lzmaDecodedBytes        = decodedBytes
            , lzmaConsumedInputLength = Length (fromIntegral consumedLength)
            }

-- | What one DJW decompression reports back across the seam: the
-- decoded bytes, and how many input bytes the decoder consumed
-- before its output budget filled. Sibling of 'LzmaDecoded', same
-- contract: the consumed length is a fact only the decoder can know,
-- and whether it honors the section's framing is the caller's
-- judgment.
data DjwDecoded = DjwDecoded
  { djwDecodedBytes        :: !ByteString
  , djwConsumedInputLength :: !Length
  }
  deriving (Show, Eq)

-- | DJW decompression of one xdelta3 secondary-compressed section
-- (xdelta3's own static multi-table Huffman — see
-- @rusty-slap/src/xdelta3_djw.rs@ for the stream shape). The 'Length' is the
-- section's declared output size, handed to the decoder as its loop
-- terminus — DJW's bit stream carries no output size of its own
-- (LZMA's chunk headers do), so the declaration must travel beside
-- the bytes; the asymmetry with 'lzmaDecompress' is real and stays
-- visible. Written longhand for the same reasons as 'lzmaDecompress':
-- the consumed-length channel, and an honest answer on empty input.
djwDecompress :: Length -> ByteString -> Either DecompressionCause DjwDecoded
djwDecompress expectedOutputLength input = unsafeDupablePerformIO $
  withByteString input $ \dataPointer dataLength ->
    alloca $ \resultAddressPointer ->
    alloca $ \resultLengthPointer ->
    alloca $ \consumedLengthPointer ->
    alloca $ \errorAddressPointer ->
    alloca $ \errorLengthPointer -> do
      returnCode <- rustyDjwDecompress
        dataPointer dataLength
        (fromIntegral (unLength expectedOutputLength))
        resultAddressPointer resultLengthPointer
        consumedLengthPointer
        errorAddressPointer  errorLengthPointer
      if returnCode /= 0
        then do
          rustMessage <- readText errorAddressPointer errorLengthPointer
          pure $ Left (DecompressionCause rustMessage)
        else do
          decodedBytes   <- readByteString resultAddressPointer resultLengthPointer
          consumedLength <- peek consumedLengthPointer
          pure $ Right DjwDecoded
            { djwDecodedBytes        = decodedBytes
            , djwConsumedInputLength = Length (fromIntegral consumedLength)
            }

-- | What one FGK kind-decode reports back across the seam: every
-- section's decoded bytes concatenated, and how many input bytes the
-- decoder consumed across all of them. Sibling of 'DjwDecoded' and
-- 'LzmaDecoded' in shape; the consumed length is a fact only the
-- decoder can know, and whether it honors the kind's gathered framing
-- is the caller's judgment.
data FgkDecoded = FgkDecoded
  { fgkDecodedBytes        :: !ByteString
  , fgkConsumedInputLength :: !Length
  }
  deriving (Show, Eq)

-- | FGK decompression of one kind's gathered sections (xdelta3's
-- adaptive Huffman — see @rusty-slap/src/xdelta3_fgk.rs@ for the stream
-- shape). The @['Length']@ is the declared output size of each section,
-- in window order, and the 'ByteString' is those sections' stream bytes
-- concatenated in the same order. FGK is gather-shaped like LZMA, not
-- per-section like DJW: a kind's sections share one adaptive tree, so
-- they must be decoded together. But unlike LZMA, FGK's bit stream
-- carries no output size of its own — each section's declared size
-- bounds its own decode and realigns the reader between sections — so
-- the sizes travel beside the bytes, the way 'djwDecompress' carries
-- its one section's size. Written longhand for the same reasons as
-- 'lzmaDecompress': the consumed-length channel, and an honest answer
-- on empty input.
fgkDecompress :: [Length] -> ByteString -> Either DecompressionCause FgkDecoded
fgkDecompress sectionOutputLengths input = unsafeDupablePerformIO $
  withByteString input $ \dataPointer dataLength ->
    withArray (map (fromIntegral . unLength) sectionOutputLengths) $ \sectionLengthsPointer ->
    alloca $ \resultAddressPointer ->
    alloca $ \resultLengthPointer ->
    alloca $ \consumedLengthPointer ->
    alloca $ \errorAddressPointer ->
    alloca $ \errorLengthPointer -> do
      returnCode <- rustyFgkDecompress
        dataPointer dataLength
        sectionLengthsPointer (fromIntegral (length sectionOutputLengths))
        resultAddressPointer resultLengthPointer
        consumedLengthPointer
        errorAddressPointer  errorLengthPointer
      if returnCode /= 0
        then do
          rustMessage <- readText errorAddressPointer errorLengthPointer
          pure $ Left (DecompressionCause rustMessage)
        else do
          decodedBytes   <- readByteString resultAddressPointer resultLengthPointer
          consumedLength <- peek consumedLengthPointer
          pure $ Right FgkDecoded
            { fgkDecodedBytes        = decodedBytes
            , fgkConsumedInputLength = Length (fromIntegral consumedLength)
            }

-- | Yay0 (Nintendo LZSS) decompression.
yay0Decompress :: ByteString -> Either DecompressionCause ByteString
yay0Decompress = callDecompressor rustyYay0Decompress
