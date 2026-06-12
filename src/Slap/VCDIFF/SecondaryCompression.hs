-- | Secondary compression, the xdelta3 way: the catalog that gives
-- compressor ids their names, and the gather-decode-split machine
-- that turns a section kind's compressed pieces back into plain
-- sections.
--
-- The RFC defines none of this — §6 waves at "assuming that any such
-- compressed data has been decompressed" — so the shapes here are
-- xdelta3 convention, recovered from its source and from real patches
-- (docs/vcdiff/xdelta3/spec.md "Secondary compression",
-- docs/vcdiff/xdelta3/questions.md). The two facts that shape the
-- module:
--
--   * A compressed section's on-wire bytes are a decompressed-size
--     varint followed by a slice of compressor-native stream.
--
--   * The three section kinds — data, instructions, addresses — are
--     independent of each other, but within a kind the compressed
--     stream is continuous across windows: a compressed data section
--     in window 7 is not a self-contained unit, it is a slice of the
--     data kind's one ongoing stream. The compressor's header appears
--     only in the first window that compresses the kind; later
--     sections are bare continuation slices.
--
-- Continuity is why the machine gathers: collect a kind's slices in
-- window order, decode the kind once, and split the output back into
-- per-section pieces by their declared sizes. Being in-memory makes
-- this equivalent to xd3's persistent-decoder streaming, without any
-- decoder state crossing the FFI — the Rust side receives bytes and
-- returns bytes plus how much input it consumed, and the verdicts on
-- those facts (xd3's "finished with unused input" and "short output",
-- kept distinct here as they are there) are typed on this side, where
-- the wire framing is known.
module Slap.VCDIFF.SecondaryCompression
  ( -- * The catalog
    XDelta3SecondaryCompressor(..)
  , secondaryCompressorCatalog
    -- * The gather-decode-split machine
  , SectionCarriage(..)
  , decodeLZMACompressedKind
  ) where

import Slap.Binary (getVcdiffVarint, VarintResult(..))
import Slap.Compression.Stream (LzmaDecoded(..), lzmaDecompress)
import Slap.Measure (Length(..), byteLength, lengthToFileSize, subtractLength,
                     ExpectedSize(..), ActualSize(..))
import Slap.Status
  ( SlapError(..), VCDIFFMalformation(..), VCDIFFSection(..)
  , DecompressionFailure(..), CompressionAlgorithm(..) )

import Control.Monad (when)
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.List (mapAccumL)
import Data.Word (Word8)

----------------------------------------------------------------------------
-- The catalog
----------------------------------------------------------------------------

-- | The compressors xdelta3's catalog names. A closed sum of exactly
-- three, distinct from the broader 'CompressionAlgorithm' so that
-- catalog dispatch is total over the algorithms a VCDIFF patch can
-- actually declare — a VCDIFF patch claiming gzip is unrepresentable.
data XDelta3SecondaryCompressor
  = SecondaryDJW   -- ^ xdelta3's own static multi-table Huffman.
  | SecondaryLZMA  -- ^ xz\/LZMA2 as liblzma emits it.
  | SecondaryFGK   -- ^ Adaptive Huffman, "demonstration purposes only".
  deriving (Eq, Show)

-- | The id-to-algorithm mapping (docs/vcdiff/xdelta3/spec.md
-- "Catalog"). The ids are not IANA-registered — this table is the
-- only registry there is — and xd3 rejects any other id, so a
-- 'Nothing' here becomes the 'VCDIFFUnknownSecondaryCompressor'
-- decline at the caller.
secondaryCompressorCatalog :: Word8 -> Maybe XDelta3SecondaryCompressor
secondaryCompressorCatalog 1  = Just SecondaryDJW
secondaryCompressorCatalog 2  = Just SecondaryLZMA
secondaryCompressorCatalog 16 = Just SecondaryFGK
secondaryCompressorCatalog _  = Nothing

----------------------------------------------------------------------------
-- The gather-decode-split machine
----------------------------------------------------------------------------

-- | How one window carries its section of a given kind on the wire:
-- as plain bytes, or as a compressed piece of the kind's continuous
-- stream (still wearing its decompressed-size prefix). The caller
-- reads each window's Delta_Indicator bit for the kind and builds one
-- carriage per window, in window order.
data SectionCarriage
  = CarriedPlain !ByteString
  | CarriedCompressed !ByteString

-- | One window's contribution to a kind, after the per-section
-- framing has been read: either the plain bytes themselves, or a
-- compressed piece whose declared output size and stream slice have
-- been separated.
data KindContribution
  = PlainContribution !ByteString
  | CompressedContribution !CompressedPiece

-- | A compressed section with its framing peeled: the size its slice
-- must decode to, and the slice of the kind's stream it carries.
data CompressedPiece = CompressedPiece
  { pieceDeclaredOutputSize :: !Length
  , pieceStreamSlice        :: !ByteString
  }

-- | Decode one section kind across a patch's windows: validate each
-- compressed section's framing, gather the stream slices in window
-- order, decode the kind's stream once through the LZMA seam, hold
-- the decoder's facts to the framing's claims, and hand back one
-- plain section per window. Plain carriages pass through untouched;
-- a kind no window compresses comes back exactly as it went in.
--
-- LZMA-specific by name and by signature: 'lzmaDecompress' sizes its
-- own output, so this machine needs no expected-size loop bound. The
-- DJW and FGK decoders, when they land, will take the declared total
-- as theirs — that asymmetry is real, and their entry points will
-- wear it rather than hide behind a unified shape.
decodeLZMACompressedKind
  :: VCDIFFSection      -- ^ which kind, naming any refusal
  -> [SectionCarriage]  -- ^ one per window, in window order
  -> Either SlapError [ByteString]
decodeLZMACompressedKind kind carriages = do
  contributions <- traverse (readContribution kind) carriages
  case [piece | CompressedContribution piece <- contributions] of
    -- Total: the empty scrutinee just proved every contribution is
    -- plain, so this comprehension drops nothing and hands back one
    -- section per window.
    []     -> pure [bytes | PlainContribution bytes <- contributions]
    pieces -> do
      let gatheredStream = ByteString.concat (map pieceStreamSlice pieces)
          declaredTotal  = foldMap pieceDeclaredOutputSize pieces
      decoderFacts <- runLZMADecoder kind gatheredStream
      holdDecoderToFraming kind gatheredStream declaredTotal decoderFacts
      pure (handOutDecodedSlices (lzmaDecodedBytes decoderFacts) contributions)

-- | Read one carriage's framing. A compressed section must begin
-- with a readable decompressed-size varint (the zero-length section
-- has no bytes to read one from), and that size must be positive —
-- compressing nothing yields framing bytes, never zero, so a
-- declared size of zero is a category error, not a no-op
-- (docs/vcdiff/xdelta3/questions.md, "compressed-but-empty section").
readContribution :: VCDIFFSection -> SectionCarriage -> Either SlapError KindContribution
readContribution _ (CarriedPlain sectionBytes) =
  Right (PlainContribution sectionBytes)
readContribution kind (CarriedCompressed sectionBytes) =
  case getVcdiffVarint 0 sectionBytes of
    Left _ ->
      Left (MalformedVCDIFF (VCDIFFCompressedSectionWithoutDeclaredSize kind))
    Right (VarintResult declaredSize consumed)
      | declaredSize == 0 ->
          Left (MalformedVCDIFF (VCDIFFCompressedSectionDeclaresEmptyOutput kind))
      | otherwise ->
          Right (CompressedContribution CompressedPiece
            { pieceDeclaredOutputSize = Length (fromIntegral declaredSize)
            , pieceStreamSlice        = ByteString.drop consumed sectionBytes
            })

-- | Run the kind's gathered stream through the LZMA seam, lifting a
-- decoder fault — a broken chunk, a missing xz header — into the
-- 'DecompressionFailed' lane with the kind and algorithm named.
runLZMADecoder :: VCDIFFSection -> ByteString -> Either SlapError LzmaDecoded
runLZMADecoder kind gatheredStream =
  case lzmaDecompress gatheredStream of
    Left cause         -> Left (DecompressionFailed (VCDIFFSectionFailed kind LZMA cause))
    Right decoderFacts -> Right decoderFacts

-- | The two framing verdicts, made here from the decoder's surfaced
-- facts — never by parsing its message text. The decoder must consume
-- the whole gathered stream, and must produce exactly the sum of the
-- sections' declared sizes; each shortfall is its own malformation,
-- mirroring xd3's two distinct complaints.
holdDecoderToFraming
  :: VCDIFFSection -> ByteString -> Length -> LzmaDecoded -> Either SlapError ()
holdDecoderToFraming kind gatheredStream declaredTotal decoderFacts = do
  let unconsumedInput =
        subtractLength (byteLength gatheredStream) (lzmaConsumedInputLength decoderFacts)
      producedTotal = byteLength (lzmaDecodedBytes decoderFacts)
  when (unconsumedInput /= Length 0) $
    Left (MalformedVCDIFF
           (VCDIFFSecondaryStreamUnconsumedInput kind LZMA unconsumedInput))
  when (producedTotal /= declaredTotal) $
    Left (MalformedVCDIFF
           (VCDIFFSecondaryStreamOutputSizeMismatch kind LZMA
             (ExpectedSize (lengthToFileSize declaredTotal))
             (ActualSize   (lengthToFileSize producedTotal))))

-- | Split the decoded stream back into per-window sections: each
-- compressed contribution takes its declared size off the front, and
-- each plain contribution passes its own bytes through. Total by the
-- time it runs — 'holdDecoderToFraming' has already proven the
-- decoded length equals the declared sum, so the slices come out
-- exact and the stream comes out empty.
handOutDecodedSlices :: ByteString -> [KindContribution] -> [ByteString]
handOutDecodedSlices decodedStream contributions =
  snd (mapAccumL handOneContribution decodedStream contributions)
  where
    handOneContribution remainingDecoded (PlainContribution sectionBytes) =
      (remainingDecoded, sectionBytes)
    handOneContribution remainingDecoded (CompressedContribution piece) =
      let (slice, restDecoded) =
            ByteString.splitAt (unLength (pieceDeclaredOutputSize piece)) remainingDecoded
      in (restDecoded, slice)
