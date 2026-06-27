-- | Secondary compression, the xdelta3 way: the catalog that gives compressor ids their names, and the per-kind decode paths that turn compressed sections back into plain ones.
--
-- The RFC defines none of this (§6 waves at "assuming that any such compressed data has been decompressed"), so the shapes here are xdelta3 convention, recovered from its source (docs/vcdiff/xdelta3/secondary-compression.md, docs/vcdiff/xdelta3/questions.md).
-- One framing fact is shared: a compressed section's on-wire bytes are a decompressed-size varint followed by compressor-native stream bytes. What that stream /is/ differs per compressor, and the three decode paths wear the difference:
--
--   * LZMA's stream is continuous within a kind: a window's section is a slice of the kind's one ongoing stream, the xz header in the first window only.
--     So the LZMA path gathers: collect a kind's slices in window order, decode once, split the output by declared sizes.
--   * DJW is fresh per section: each carries its own table headers and bit stream, so the DJW path decodes each piece independently, no gathering, its verdicts at per-section granularity.
--   * FGK also gathers, but its sections share the adaptive /tree/, not a bitstream: each is byte-flushed, yet a section's first byte decodes against the tree the earlier sections left.
--     So the path gathers the slices and threads one tree through them, each section bounded by its declared size with the reader realigned between sections.
--
-- In every path the Rust side receives bytes and returns bytes plus how much input it consumed; the verdicts on those facts (xd3's "finished with unused input" and "short output", kept distinct here as there) are typed on this side, where the wire framing is known.
module Slap.VCDIFF.SecondaryCompression
  ( -- * The catalog
    XDelta3SecondaryCompressor(..)
  , secondaryCompressorCatalog
    -- * The per-kind decode paths
  , SectionCarriage(..)
  , decodeLZMACompressedKind
  , decodeDJWCompressedKind
  , decodeFGKCompressedKind
  ) where

import Slap.Binary (getVcdiffVarint, VarintResult(..))
import Slap.Compression.Stream (LzmaDecoded(..), lzmaDecompress,
                                DjwDecoded(..), djwDecompress,
                                FgkDecoded(..), fgkDecompress)
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

-- | The compressors xdelta3's catalog names. A closed sum of exactly three, distinct from the broader 'CompressionAlgorithm' so catalog dispatch is total over the algorithms a VCDIFF patch can declare: a VCDIFF patch claiming gzip is unrepresentable.
data XDelta3SecondaryCompressor
  = SecondaryDJW   -- ^ xdelta3's own static multi-table Huffman.
  | SecondaryLZMA  -- ^ xz\/LZMA2 as liblzma emits it.
  | SecondaryFGK   -- ^ Adaptive Huffman; xd3's own demonstration codec.
  deriving (Eq, Show)

-- | The id-to-algorithm mapping (docs/vcdiff/xdelta3/secondary-compression.md "Catalog").
-- The ids are not IANA-registered, this table being the only registry there is, and xd3 rejects any other id, so a 'Nothing' here becomes the 'VCDIFFUnknownSecondaryCompressor' decline at the caller.
secondaryCompressorCatalog :: Word8 -> Maybe XDelta3SecondaryCompressor
secondaryCompressorCatalog 1  = Just SecondaryDJW
secondaryCompressorCatalog 2  = Just SecondaryLZMA
secondaryCompressorCatalog 16 = Just SecondaryFGK
secondaryCompressorCatalog _  = Nothing

----------------------------------------------------------------------------
-- The gather-decode-split machine
----------------------------------------------------------------------------

-- | How one window carries its section of a given kind on the wire: plain bytes, or a compressed piece of the kind's continuous stream (still wearing its decompressed-size prefix).
-- The caller reads each window's Delta_Indicator bit for the kind and builds one carriage per window, in window order.
data SectionCarriage
  = CarriedPlain !ByteString
  | CarriedCompressed !ByteString

-- | One window's contribution to a kind, after the per-section framing has been read: the plain bytes themselves, or a compressed piece whose declared output size and stream slice have been separated.
data KindContribution
  = PlainContribution !ByteString
  | CompressedContribution !CompressedPiece

-- | A compressed section with its framing peeled: the size its slice must decode to, and the slice of the kind's stream it carries.
data CompressedPiece = CompressedPiece
  { pieceDeclaredOutputSize :: !Length
  , pieceStreamSlice        :: !ByteString
  }

-- | Decode one section kind across a patch's windows, the LZMA way: validate each compressed section's framing, gather the stream slices in window order, decode the kind's stream once through the LZMA seam, hold the decoder's facts to the framing's claims, and hand back one plain section per window.
-- Plain carriages pass through untouched; a kind no window compresses comes back exactly as it went in.
--
-- LZMA-specific by name and shape: the gathering exists because LZMA's stream is continuous within a kind, and 'lzmaDecompress' sizes its own output from the chunk headers, so no expected-size bound crosses the seam. 'decodeDJWCompressedKind' is the per-section sibling.
decodeLZMACompressedKind
  :: VCDIFFSection      -- ^ which kind, naming any refusal
  -> [SectionCarriage]  -- ^ one per window, in window order
  -> Either SlapError [ByteString]
decodeLZMACompressedKind kind carriages = do
  contributions <- traverse (readContribution kind) carriages
  case [piece | CompressedContribution piece <- contributions] of
    -- The empty case: every contribution is plain, so hand back one section per window.
    []     -> pure [bytes | PlainContribution bytes <- contributions]
    pieces -> do
      let gatheredStream = ByteString.concat (map pieceStreamSlice pieces)
          declaredTotal  = foldMap pieceDeclaredOutputSize pieces
      decoded <- runLZMADecoder kind gatheredStream
      holdDecoderToFraming kind LZMA gatheredStream declaredTotal
        (lzmaDecoderFacts decoded)
      pure (handOutDecodedSlices (lzmaDecodedBytes decoded) contributions)

-- | Decode one section kind across a patch's windows, the DJW way: every compressed section is self-contained (its own table headers, its own bit stream, decoded to exactly its declared size), so there is nothing to gather.
-- Each piece decodes independently through the same framing 'readContribution' peels, and the verdicts land at per-section granularity, sharper than LZMA's per-kind and exactly xd3's own. Plain carriages pass through untouched.
decodeDJWCompressedKind
  :: VCDIFFSection      -- ^ which kind, naming any refusal
  -> [SectionCarriage]  -- ^ one per window, in window order
  -> Either SlapError [ByteString]
decodeDJWCompressedKind kind carriages = do
  contributions <- traverse (readContribution kind) carriages
  traverse decodeContribution contributions
  where
    decodeContribution (PlainContribution sectionBytes) = Right sectionBytes
    decodeContribution (CompressedContribution piece) = do
      decoded <- runDJWDecoder kind piece
      holdDecoderToFraming kind DJW (pieceStreamSlice piece)
        (pieceDeclaredOutputSize piece)
        (djwDecoderFacts decoded)
      Right (djwDecodedBytes decoded)

-- | Decode one section kind across a patch's windows, the FGK way: gather, like LZMA, not per-section like DJW.
-- A kind's compressed sections share one adaptive tree, so they cannot be decoded apart: the slices gather in window order, the decoder threads one tree through them all, and its facts are held to the gathered framing's claims. Plain carriages pass through untouched.
--
-- The gather is LZMA's shape, but the asymmetry differs: LZMA's bytes are one continuous stream that sizes its own output, while FGK's are byte-flushed per section and carry no sizes, so each section's declared output size crosses the seam to bound its decode and realign the reader between sections.
decodeFGKCompressedKind
  :: VCDIFFSection      -- ^ which kind, naming any refusal
  -> [SectionCarriage]  -- ^ one per window, in window order
  -> Either SlapError [ByteString]
decodeFGKCompressedKind kind carriages = do
  contributions <- traverse (readContribution kind) carriages
  case [piece | CompressedContribution piece <- contributions] of
    -- The empty case: every contribution is plain (as in the LZMA path).
    []     -> pure [bytes | PlainContribution bytes <- contributions]
    pieces -> do
      let gatheredStream     = ByteString.concat (map pieceStreamSlice pieces)
          sectionOutputSizes = map pieceDeclaredOutputSize pieces
          declaredTotal      = foldMap pieceDeclaredOutputSize pieces
      decoded <- runFGKDecoder kind sectionOutputSizes gatheredStream
      holdDecoderToFraming kind FGK gatheredStream declaredTotal
        (fgkDecoderFacts decoded)
      pure (handOutDecodedSlices (fgkDecodedBytes decoded) contributions)

-- | Read one carriage's framing. A compressed section must begin with a readable decompressed-size varint (the zero-length section has none to read), and that size must be positive: a declared size of zero is damage, not an empty section (docs/vcdiff/xdelta3/questions.md, "compressed-but-empty section").
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

-- | Run the kind's gathered stream through the LZMA seam, lifting a decoder fault (a broken chunk, a missing xz header) into the 'DecompressionFailed' lane with the kind and algorithm named.
runLZMADecoder :: VCDIFFSection -> ByteString -> Either SlapError LzmaDecoded
runLZMADecoder kind gatheredStream =
  case lzmaDecompress gatheredStream of
    Left cause         -> Left (DecompressionFailed (VCDIFFSectionFailed kind LZMA cause))
    Right decoderFacts -> Right decoderFacts

-- | Run one section's stream through the DJW seam, lifting a decoder fault (an exhausted bit stream, a code outside its table) into the 'DecompressionFailed' lane with the kind and algorithm named.
-- The section's declared output size crosses as the decoder's budget.
runDJWDecoder :: VCDIFFSection -> CompressedPiece -> Either SlapError DjwDecoded
runDJWDecoder kind piece =
  case djwDecompress (pieceDeclaredOutputSize piece) (pieceStreamSlice piece) of
    Left cause         -> Left (DecompressionFailed (VCDIFFSectionFailed kind DJW cause))
    Right decoderFacts -> Right decoderFacts

-- | Run a kind's gathered stream through the FGK seam, lifting a decoder fault (an exhausted bit stream, an escape past the unseen list) into the 'DecompressionFailed' lane with the kind and algorithm named.
-- The per-section declared output sizes cross alongside the bytes, bounding each section's decode against the shared tree and realigning the reader between sections.
runFGKDecoder :: VCDIFFSection -> [Length] -> ByteString -> Either SlapError FgkDecoded
runFGKDecoder kind sectionOutputLengths gatheredStream =
  case fgkDecompress sectionOutputLengths gatheredStream of
    Left cause         -> Left (DecompressionFailed (VCDIFFSectionFailed kind FGK cause))
    Right decoderFacts -> Right decoderFacts

-- | The two facts every secondary decoder surfaces: how much input it consumed, and how much output it produced.
-- One record with named fields, not two positional 'Length's, so the roles are fixed at the only construction sites (the per-decoder projections below) and cannot transpose on the way to the verdicts.
data SecondaryDecoderFacts = SecondaryDecoderFacts
  { factsConsumedInput  :: !Length
  , factsProducedOutput :: !Length
  }

-- | The LZMA seam's decoded form, projected onto the shared facts.
lzmaDecoderFacts :: LzmaDecoded -> SecondaryDecoderFacts
lzmaDecoderFacts decoded = SecondaryDecoderFacts
  { factsConsumedInput  = lzmaConsumedInputLength decoded
  , factsProducedOutput = byteLength (lzmaDecodedBytes decoded)
  }

-- | The DJW seam's decoded form, projected onto the shared facts.
djwDecoderFacts :: DjwDecoded -> SecondaryDecoderFacts
djwDecoderFacts decoded = SecondaryDecoderFacts
  { factsConsumedInput  = djwConsumedInputLength decoded
  , factsProducedOutput = byteLength (djwDecodedBytes decoded)
  }

-- | The FGK seam's decoded form, projected onto the shared facts.
fgkDecoderFacts :: FgkDecoded -> SecondaryDecoderFacts
fgkDecoderFacts decoded = SecondaryDecoderFacts
  { factsConsumedInput  = fgkConsumedInputLength decoded
  , factsProducedOutput = byteLength (fgkDecodedBytes decoded)
  }

-- | The two framing verdicts, made here from a decoder's surfaced facts, never by parsing its message text.
-- The decoder must consume the whole stream it was handed and produce exactly the declared size; each shortfall is its own malformation, mirroring xd3's two distinct complaints.
-- Called at both granularities, a kind's gathered stream and a single section's.
holdDecoderToFraming
  :: VCDIFFSection -> CompressionAlgorithm
  -> ByteString             -- ^ the stream the decoder was handed
  -> Length                 -- ^ the output size its framing declared
  -> SecondaryDecoderFacts  -- ^ what the decoder reported back
  -> Either SlapError ()
holdDecoderToFraming kind algorithm decoderInput declaredOutput decoderFacts = do
  let unconsumedInput =
        subtractLength (byteLength decoderInput) (factsConsumedInput decoderFacts)
  when (unconsumedInput /= Length 0) $
    Left (MalformedVCDIFF
           (VCDIFFSecondaryStreamUnconsumedInput kind algorithm unconsumedInput))
  when (factsProducedOutput decoderFacts /= declaredOutput) $
    Left (MalformedVCDIFF
           (VCDIFFSecondaryStreamOutputSizeMismatch kind algorithm
             (ExpectedSize (lengthToFileSize declaredOutput))
             (ActualSize   (lengthToFileSize (factsProducedOutput decoderFacts)))))

-- | Split the decoded stream back into per-window sections: each compressed contribution takes its declared size off the front, each plain contribution passes its own bytes through.
-- Total by the time it runs: 'holdDecoderToFraming' has already proven the decoded length equals the declared sum, so the slices come out exact and the stream comes out empty.
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
