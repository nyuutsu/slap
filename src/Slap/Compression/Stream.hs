-- | Compression and decompression via rusty-slap.
module Slap.Compression.Stream
  ( zlibInflate
  , zlibDeflate
  , gzipInflate
  , gzipDeflate
  , bzip2Decompress
  , LzmaDecoded(..)
  , lzmaDecompress
  , lzmaCompress
  , LzmaSectionStream(..)
  , lzmaCompressSections
  , DjwDecoded(..)
  , djwDecompress
  , djwCompress
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
import System.IO.Unsafe (unsafePerformIO)

import Slap.Measure (Length(..))
import Slap.Status (DecompressionCause(..))
import Slap.FFI (readByteString, readText, readWord64LE, withByteString)

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

foreign import ccall unsafe "rusty_lzma_compress"
  rustyLzmaCompress
    :: Ptr Word8 -> CSize
    -> Ptr (Ptr Word8) -> Ptr CSize
    -> IO ()

foreign import ccall unsafe "rusty_djw_decompress"
  rustyDjwDecompress
    :: Ptr Word8 -> CSize
    -> CSize                            -- expected output length
    -> Ptr (Ptr Word8) -> Ptr CSize     -- decoded bytes
    -> Ptr CSize                        -- consumed input length
    -> Ptr (Ptr Word8) -> Ptr CSize     -- error message buffer
    -> IO CInt

foreign import ccall unsafe "rusty_djw_compress"
  rustyDjwCompress
    :: Ptr Word8 -> CSize
    -> Ptr (Ptr Word8) -> Ptr CSize
    -> IO ()

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
-- Empty input → empty output.
{-# INLINE callDecompressor #-}
callDecompressor
  :: ( Ptr Word8 -> CSize
    -> Ptr (Ptr Word8) -> Ptr CSize
    -> Ptr (Ptr Word8) -> Ptr CSize
    -> IO CInt )
  -> ByteString -> Either DecompressionCause ByteString
callDecompressor _          input | ByteString.null input = Right ByteString.empty
callDecompressor decompress input = unsafePerformIO $
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

-- | Call a Rust compression function that allocates its own output buffer.
-- Pure: in-memory compression has no error to surface (allocation failure aborts).
-- No empty-input shortcut, unlike 'callDecompressor': a compressor may owe framing bytes
-- even for empty input ('lzmaCompress' does).
{-# INLINE callCompressor #-}
callCompressor
  :: ( Ptr Word8 -> CSize
    -> Ptr (Ptr Word8) -> Ptr CSize
    -> IO () )
  -> ByteString -> ByteString
callCompressor compress input = unsafePerformIO $
  withByteString input $ \dataPointer dataLength ->
    alloca $ \resultAddressPointer ->
    alloca $ \resultLengthPointer -> do
      compress dataPointer dataLength resultAddressPointer resultLengthPointer
      readByteString resultAddressPointer resultLengthPointer

----------------------------------------------------------------------------
-- Public API
----------------------------------------------------------------------------

-- | Zlib (RFC 1950) inflate.
zlibInflate :: ByteString -> Either DecompressionCause ByteString
zlibInflate = callDecompressor rustyZlibInflate

-- | Zlib (RFC 1950) deflate at the library's default compression level.
-- The NINJA1 spec is mute on level — any zlib-deflate output round-trips
-- through any decoder regardless — so the rusty side pins the default
-- rather than exposing a knob no caller currently turns.
zlibDeflate :: ByteString -> ByteString
zlibDeflate = callCompressor rustyZlibDeflate

-- | Gzip (RFC 1952) inflate.
gzipInflate :: ByteString -> Either DecompressionCause ByteString
gzipInflate = callDecompressor rustyGzipInflate

-- | Gzip (RFC 1952) deflate via rusty-slap (flate2's gzip encoder, default
-- compression level, @mtime = 0@ pinned for deterministic output).
-- Round-trip partner of 'gzipInflate'.
gzipDeflate :: ByteString -> ByteString
gzipDeflate = callCompressor rustyGzipDeflate

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
-- for the stream shape). Written longhand rather than through 'callDecompressor':
-- the consumed-input length is a third output channel the helper's shape has no slot for,
-- and the helper's empty-input short-circuit would be wrong here: an empty input is not an empty output,
-- it is a stream with no xz header, and the decoder's complaint to that effect is the right answer.
lzmaDecompress :: ByteString -> Either DecompressionCause LzmaDecoded
lzmaDecompress input = unsafePerformIO $
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

-- | LZMA compression into one xdelta3-flavored stream: the xz header, then sync-flushed
-- raw LZMA2 chunks with no closing marker — exactly the shape 'lzmaDecompress' reads back
-- (see @rusty-slap/src/xdelta3_lzma.rs@ for why the stream must end unfinished).
-- Round-trip partner of 'lzmaDecompress'.
lzmaCompress :: ByteString -> ByteString
lzmaCompress = callCompressor rustyLzmaCompress

foreign import ccall unsafe "rusty_lzma_compress_sections"
  rustyLzmaCompressSections
    :: Ptr Word8 -> CSize               -- concatenated sections
    -> Ptr CSize -> CSize               -- per-section lengths, section count
    -> Ptr (Ptr Word8) -> Ptr CSize     -- stream bytes
    -> Ptr (Ptr Word8) -> Ptr CSize     -- piece-end offsets, one u64 LE per section
    -> IO ()

-- | One kind's sections compressed as a single continuous stream, with the cut positions that split it back into per-section pieces.
-- The first piece begins at offset zero and carries the xz framing; every later piece is a bare continuation slice —
-- exactly the carriage shape the decode side gathers back together.
data LzmaSectionStream = LzmaSectionStream
  { lzmaStreamBytes     :: !ByteString
  , lzmaPieceEndOffsets :: ![Int]
  }
  deriving (Show, Eq)

-- | LZMA compression of one kind's sections, in window order, into one continuous xdelta3-flavored stream:
-- one encoder runs the whole stream, sync-flushed at every section boundary, the dictionary carrying across —
-- so a later window's section compresses against everything before it.
-- The gathered partner of 'lzmaCompress'; 'lzmaDecompress' reads the whole stream back.
lzmaCompressSections :: [ByteString] -> LzmaSectionStream
lzmaCompressSections sections = unsafePerformIO $
  withByteString (ByteString.concat sections) $ \sectionsPointer sectionsLength ->
    withArray (map (fromIntegral . ByteString.length) sections) $ \sectionLengthsPointer ->
      alloca $ \streamAddressPointer ->
        alloca $ \streamLengthPointer ->
          alloca $ \cutsAddressPointer ->
            alloca $ \cutsLengthPointer -> do
              rustyLzmaCompressSections
                sectionsPointer sectionsLength
                sectionLengthsPointer (fromIntegral (length sections))
                streamAddressPointer streamLengthPointer
                cutsAddressPointer   cutsLengthPointer
              streamBytes <- readByteString streamAddressPointer streamLengthPointer
              cutBytes    <- readByteString cutsAddressPointer   cutsLengthPointer
              pure LzmaSectionStream
                { lzmaStreamBytes     = streamBytes
                , lzmaPieceEndOffsets =
                    [ fromIntegral (readWord64LE cutBytes (8 * pieceIndex))
                    | pieceIndex <- [0 .. length sections - 1] ]
                }

-- | What one DJW decompression reports back across the seam:
-- the decoded bytes, and how many input bytes the decoder consumed before its output budget filled.
-- Sibling of 'LzmaDecoded', same consumed-length contract.
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
-- the consumed-length channel, and the right answer on empty input.
djwDecompress :: Length -> ByteString -> Either DecompressionCause DjwDecoded
djwDecompress expectedOutputLength input = unsafePerformIO $
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

-- | DJW compression of one section: the bit stream 'djwDecompress' reads back
-- (see @rusty-slap/src/xdelta3_djw.rs@ for the table and grouping choices).
-- Round-trip partner of 'djwDecompress'.
djwCompress :: ByteString -> ByteString
djwCompress = callCompressor rustyDjwCompress

-- | What one FGK kind-decode reports back across the seam:
-- every section's decoded bytes concatenated, and how many input bytes the decoder consumed across all of them.
-- Sibling of 'DjwDecoded' and 'LzmaDecoded', same consumed-length contract.
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
-- 'lzmaDecompress': the consumed-length channel, and the right answer on empty input.
fgkDecompress :: [Length] -> ByteString -> Either DecompressionCause FgkDecoded
fgkDecompress sectionOutputLengths input = unsafePerformIO $
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
