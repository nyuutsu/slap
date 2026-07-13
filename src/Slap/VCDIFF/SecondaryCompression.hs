-- | xdelta3's secondary compression: the compressor-id catalog, the per-compressor
-- decode paths that turn compressed sections back into plain bytes, and the emission
-- paths that produce such sections
-- (the RFC leaves this undefined in §6; the shapes follow docs/vcdiff/xdelta3/secondary-compression.md).
--
-- A section is one of a window's three — data, instructions, addresses. Each compressor
-- needs its own path because a section's compressed bytes span the windows differently:
-- LZMA one continuous stream, DJW independent per window, FGK per window over a shared tree.
module Slap.VCDIFF.SecondaryCompression
  ( -- * The catalog
    XDelta3SecondaryCompressor(..)
  , secondaryCompressorCatalog
  , secondaryCompressorId
  , secondaryCompressorTokens
  , compressionAlgorithmOf
    -- * The decode paths
  , SectionCarriage(..)
  , carriageBytes
  , decodeLZMACompressedKind
  , decodeDJWCompressedKind
  , decodeFGKCompressedKind
    -- * The emission paths
  , SectionCompressor
  , sectionCompressorAlgorithm
  , sectionCompressorKindCarriages
  , encodableSectionCompressor
  , lzmaSectionCompressor
  , djwSectionCompressor
  ) where

import Slap.Binary (getVcdiffVarint, VarintResult(..), putVcdiffVarint)
import Slap.Compression.Stream (LzmaDecoded(..), lzmaDecompress,
                                LzmaSectionStream(..), lzmaCompressSections,
                                DjwDecoded(..), djwDecompress, djwCompress,
                                FgkDecoded(..), fgkDecompress)
import Slap.Measure (lengthToInt, Length(..), byteLength, lengthToFileSize, subtractLength,
                     ExpectedSize(..), ActualSize(..))
import Slap.Status
  ( SlapError(..), VCDIFFMalformation(..), VCDIFFSection(..)
  , DecompressionFailure(..), CompressionAlgorithm(..) )

import Control.Monad (when)
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.ByteString.Builder (toLazyByteString)
import qualified Data.ByteString.Lazy as LazyByteString
import Data.List (mapAccumL)
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Word (Word8)

----------------------------------------------------------------------------
-- The catalog
----------------------------------------------------------------------------

-- | The three compressors xdelta3 defines, a separate sum from the broader 'CompressionAlgorithm'
-- so a VCDIFF patch can declare only one of these three — a patch claiming gzip is unrepresentable.
data XDelta3SecondaryCompressor
  = SecondaryDJW   -- ^ xdelta3's own static multi-table Huffman.
  | SecondaryLZMA  -- ^ xz\/LZMA2 as liblzma emits it.
  | SecondaryFGK   -- ^ Adaptive Huffman; xd3's own demonstration codec.
  deriving (Eq, Show)

-- | Maps a compressor id to its algorithm (docs/vcdiff/xdelta3/secondary-compression.md "Catalog").
-- The ids are registered nowhere but here, so an unknown id is 'Nothing' —
-- the caller's 'VCDIFFUnknownSecondaryCompressor' decline.
secondaryCompressorCatalog :: Word8 -> Maybe XDelta3SecondaryCompressor
secondaryCompressorCatalog 1  = Just SecondaryDJW
secondaryCompressorCatalog 2  = Just SecondaryLZMA
secondaryCompressorCatalog 16 = Just SecondaryFGK
secondaryCompressorCatalog _  = Nothing

-- | The id a compressor declares itself by on the wire: the catalog's inverse,
-- kept beside it; the @xdelta3: compressor ids round-trip through the catalog@ case
-- in "Props.RoundTrip" holds the two readings of the registry to agreement.
secondaryCompressorId :: XDelta3SecondaryCompressor -> Word8
secondaryCompressorId SecondaryDJW  = 1
secondaryCompressorId SecondaryLZMA = 2
secondaryCompressorId SecondaryFGK  = 16

-- | The @--compress-with@ token for each catalog entry, beside the wire-id registry it
-- parallels. fgk is a real token: selecting it is a request slap understands and declines
-- by name ('encodableSectionCompressor' is what the decline consults), never an unknown word.
secondaryCompressorTokens :: [(String, XDelta3SecondaryCompressor)]
secondaryCompressorTokens =
  [ ("lzma", SecondaryLZMA)
  , ("djw",  SecondaryDJW)
  , ("fgk",  SecondaryFGK)
  ]

-- | Each catalog entry under 'Slap.Status''s broader compression vocabulary, for the
-- error arms that carry an algorithm name across module layers.
compressionAlgorithmOf :: XDelta3SecondaryCompressor -> CompressionAlgorithm
compressionAlgorithmOf SecondaryDJW  = DJW
compressionAlgorithmOf SecondaryLZMA = LZMA
compressionAlgorithmOf SecondaryFGK  = FGK

----------------------------------------------------------------------------
-- The gather-decode-split machine
----------------------------------------------------------------------------

-- | How one window carries a section on the wire: plain bytes, or a compressed piece
-- of the section's stream, still prefixed with its decompressed size.
-- The read side builds one carriage per window (in window order) from each window's
-- Delta_Indicator bit; the write side chooses one through its compressor's
-- 'sectionCompressorCarriage' and composes the bit from the choice.
data SectionCarriage
  = CarriedPlain !ByteString
  | CarriedCompressed !ByteString

-- | The bytes a carriage puts on (or found on) the wire, whichever form they ride in.
carriageBytes :: SectionCarriage -> ByteString
carriageBytes (CarriedPlain sectionBytes)      = sectionBytes
carriageBytes (CarriedCompressed sectionBytes) = sectionBytes

-- | One window's contribution to a section, after its framing has been read: the plain bytes,
-- or a compressed piece with its declared output size and stream slice split apart.
data KindContribution
  = PlainContribution !ByteString
  | CompressedContribution !CompressedPiece

-- | A compressed section with its framing peeled: the size its slice must decode to,
-- and the slice of the section's stream it carries.
data CompressedPiece = CompressedPiece
  { pieceDeclaredOutputSize :: !Length
  , pieceStreamSlice        :: !ByteString
  }

-- | Decode one section (data, instructions, or addresses) across every window, for an LZMA patch.
-- LZMA is one continuous stream: gather the slices, decode once, split the output by declared size.
-- 'lzmaDecompress' sizes its own output, so no expected size crosses the seam.
decodeLZMACompressedKind
  :: VCDIFFSection      -- ^ which section, named in any refusal
  -> [SectionCarriage]  -- ^ one per window, in window order
  -> Either SlapError [ByteString]
decodeLZMACompressedKind kind carriages = do
  contributions <- traverse (readContribution kind) carriages
  case [piece | CompressedContribution piece <- contributions] of
    -- No compressed pieces: return each window's plain bytes.
    []     -> pure [bytes | PlainContribution bytes <- contributions]
    pieces -> do
      let gatheredStream = ByteString.concat (map pieceStreamSlice pieces)
          declaredTotal  = foldMap pieceDeclaredOutputSize pieces
      decoded <- runLZMADecoder kind gatheredStream
      holdDecoderToFraming kind LZMA gatheredStream declaredTotal
        (lzmaDecoderFacts decoded)
      pure (handOutDecodedSlices (lzmaDecodedBytes decoded) contributions)

-- | Decode one section across every window, for a DJW patch.
-- Each DJW section is self-contained (own headers, own bit stream, own declared size), so decode each on its own.
decodeDJWCompressedKind
  :: VCDIFFSection      -- ^ which section, named in any refusal
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

-- | Decode one section across every window, for an FGK patch.
-- FGK sections share one adaptive tree, so gather them like LZMA but decode under the shared tree;
-- each is byte-flushed with no size of its own, so its declared size bounds the decode, resetting the read position between sections.
decodeFGKCompressedKind
  :: VCDIFFSection      -- ^ which section, named in any refusal
  -> [SectionCarriage]  -- ^ one per window, in window order
  -> Either SlapError [ByteString]
decodeFGKCompressedKind kind carriages = do
  contributions <- traverse (readContribution kind) carriages
  case [piece | CompressedContribution piece <- contributions] of
    -- No compressed pieces (as in the LZMA path).
    []     -> pure [bytes | PlainContribution bytes <- contributions]
    pieces -> do
      let gatheredStream     = ByteString.concat (map pieceStreamSlice pieces)
          sectionOutputSizes = map pieceDeclaredOutputSize pieces
          declaredTotal      = foldMap pieceDeclaredOutputSize pieces
      decoded <- runFGKDecoder kind sectionOutputSizes gatheredStream
      holdDecoderToFraming kind FGK gatheredStream declaredTotal
        (fgkDecoderFacts decoded)
      pure (handOutDecodedSlices (fgkDecodedBytes decoded) contributions)

-- | Read one carriage's framing. A compressed section starts with a decompressed-size varint,
-- and that size must be positive — a declared zero is damage, not an empty section
-- (docs/vcdiff/xdelta3/questions.md, "compressed-but-empty section").
readContribution :: VCDIFFSection -> SectionCarriage -> Either SlapError KindContribution
readContribution _ (CarriedPlain sectionBytes) =
  Right (PlainContribution sectionBytes)
readContribution kind (CarriedCompressed sectionBytes) =
  case getVcdiffVarint 0 sectionBytes of
    Left varintFailure ->
      Left (MalformedVCDIFF (VCDIFFCompressedSectionWithoutDeclaredSize kind varintFailure))
    Right (VarintResult declaredSize consumed)
      | declaredSize == 0 ->
          Left (MalformedVCDIFF (VCDIFFCompressedSectionDeclaresEmptyOutput kind))
      | otherwise ->
          Right (CompressedContribution CompressedPiece
            { pieceDeclaredOutputSize = Length (fromIntegral declaredSize)
            , pieceStreamSlice        = ByteString.drop consumed sectionBytes
            })

-- | Run the gathered stream through the LZMA seam; a fault (a broken chunk, a missing xz header)
-- becomes a 'DecompressionFailed'.
runLZMADecoder :: VCDIFFSection -> ByteString -> Either SlapError LzmaDecoded
runLZMADecoder kind gatheredStream =
  case lzmaDecompress gatheredStream of
    Left cause         -> Left (DecompressionFailed (VCDIFFSectionFailed kind LZMA cause))
    Right decoderFacts -> Right decoderFacts

-- | Run one section's stream through the DJW seam; a fault (an exhausted bit stream, a code outside its table)
-- becomes a 'DecompressionFailed'. The section's declared size is the decoder's budget.
runDJWDecoder :: VCDIFFSection -> CompressedPiece -> Either SlapError DjwDecoded
runDJWDecoder kind piece =
  case djwDecompress (pieceDeclaredOutputSize piece) (pieceStreamSlice piece) of
    Left cause         -> Left (DecompressionFailed (VCDIFFSectionFailed kind DJW cause))
    Right decoderFacts -> Right decoderFacts

-- | Run the gathered stream through the FGK seam; a fault (an exhausted bit stream, an escape past the unseen list)
-- becomes a 'DecompressionFailed'. The per-section sizes are the decoder's budgets.
runFGKDecoder :: VCDIFFSection -> [Length] -> ByteString -> Either SlapError FgkDecoded
runFGKDecoder kind sectionOutputLengths gatheredStream =
  case fgkDecompress sectionOutputLengths gatheredStream of
    Left cause         -> Left (DecompressionFailed (VCDIFFSectionFailed kind FGK cause))
    Right decoderFacts -> Right decoderFacts

-- | What every secondary decoder surfaces: how much input it consumed, and how much output it produced.
-- Named fields, not two positional 'Length's, so the two cannot transpose before the verdicts.
data SecondaryDecoderFacts = SecondaryDecoderFacts
  { factsConsumedInput  :: !Length
  , factsProducedOutput :: !Length
  }

lzmaDecoderFacts :: LzmaDecoded -> SecondaryDecoderFacts
lzmaDecoderFacts decoded = SecondaryDecoderFacts
  { factsConsumedInput  = lzmaConsumedInputLength decoded
  , factsProducedOutput = byteLength (lzmaDecodedBytes decoded)
  }

djwDecoderFacts :: DjwDecoded -> SecondaryDecoderFacts
djwDecoderFacts decoded = SecondaryDecoderFacts
  { factsConsumedInput  = djwConsumedInputLength decoded
  , factsProducedOutput = byteLength (djwDecodedBytes decoded)
  }

fgkDecoderFacts :: FgkDecoded -> SecondaryDecoderFacts
fgkDecoderFacts decoded = SecondaryDecoderFacts
  { factsConsumedInput  = fgkConsumedInputLength decoded
  , factsProducedOutput = byteLength (fgkDecodedBytes decoded)
  }

-- | The two framing verdicts, read off the decoder's surfaced facts, never by parsing its message text:
-- it must consume the whole stream and produce exactly the declared size, each shortfall its own malformation.
-- Used for both a gathered stream and a single section.
holdDecoderToFraming
  :: VCDIFFSection -> CompressionAlgorithm
  -> ByteString             -- ^ the stream the decoder was handed
  -> Length                 -- ^ the output size its framing declared
  -> SecondaryDecoderFacts  -- ^ what the decoder handed back
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

-- | Split the decoded stream back into per-window sections: each compressed contribution takes its
-- declared size off the front, each plain contribution keeps its own bytes.
-- 'holdDecoderToFraming' has already checked the decoded length equals the declared sum, so the split is exact.
handOutDecodedSlices :: ByteString -> [KindContribution] -> [ByteString]
handOutDecodedSlices decodedStream contributions =
  snd (mapAccumL handOneContribution decodedStream contributions)
  where
    handOneContribution remainingDecoded (PlainContribution sectionBytes) =
      (remainingDecoded, sectionBytes)
    handOneContribution remainingDecoded (CompressedContribution piece) =
      let (slice, restDecoded) =
            ByteString.splitAt (lengthToInt (pieceDeclaredOutputSize piece)) remainingDecoded
      in (restDecoded, slice)

----------------------------------------------------------------------------
-- The emission paths
----------------------------------------------------------------------------

-- | A compressor the create path can encode with: the algorithm the patch header declares,
-- and the carriage run one kind's sections ride out on — one plain section per window in,
-- one carriage per window out, the write-side mirror of the decode paths above.
-- The two travel together because the header's declaration and the sections' encoding must name the same algorithm.
-- The constructor stays private and only 'encodableSectionCompressor' mints values,
-- so an emission compressing with FGK is unrepresentable, not merely refused.
data SectionCompressor = SectionCompressor
  { sectionCompressorAlgorithm     :: !XDelta3SecondaryCompressor
  , sectionCompressorKindCarriages :: [ByteString] -> [SectionCarriage]
  }

-- | The compressors slap can encode with today: LZMA and DJW.
-- FGK slap decodes but does not yet encode;
-- its 'Nothing' is the fact 'Slap.Status.XDelta3CompressorEncodingUnsupported' reports at the create door.
encodableSectionCompressor :: XDelta3SecondaryCompressor -> Maybe SectionCompressor
encodableSectionCompressor SecondaryLZMA = Just lzmaSectionCompressor
encodableSectionCompressor SecondaryDJW  = Just djwSectionCompressor
encodableSectionCompressor SecondaryFGK  = Nothing

lzmaSectionCompressor :: SectionCompressor
lzmaSectionCompressor = SectionCompressor SecondaryLZMA lzmaKindCarriages

-- | DJW sections stand alone (each carries its own tables and bit stream), so the kind's carriage run is the per-section choice, window by window.
djwSectionCompressor :: SectionCompressor
djwSectionCompressor = SectionCompressor SecondaryDJW (map (carriageKeepingSmaller djwCompress))

-- | The carriages one kind's sections ride out on under LZMA: the non-empty sections compressed as one continuous stream
-- ('Slap.Compression.Stream.lzmaCompressSections'), each window's piece framed behind its decompressed-size varint.
-- The kind keeps or drops the compression whole, judged by the run's total framed bytes against its total plain bytes:
-- the gathered stream shares one dictionary, so the early piece that fails to shrink on its own
-- is often what makes the later, near-identical pieces nearly free —
-- judging pieces one by one would drop the dictionary's teacher, and with it, piece by piece, the whole run.
-- The encoder emits each flush's tail — a section's final lookahead-sized stretch — as blind literals,
-- so a section shorter than that lookahead shares nothing across the flush and its kind simply rides plain through the whole-kind gate;
-- the sharing pays on the sections long enough to match past their own tail.
-- An empty section never participates: nothing compresses to nothing, and the read side refuses a compressed section declaring zero output.
lzmaKindCarriages :: [ByteString] -> [SectionCarriage]
lzmaKindCarriages plainSections
  | null participants = map CarriedPlain plainSections
  | kindPaysWhole =
      [ maybe (CarriedPlain plainBytes) CarriedCompressed (Map.lookup windowIndex framedByWindow)
      | (windowIndex, plainBytes) <- numberedSections ]
  | otherwise = map CarriedPlain plainSections
  where
    numberedSections = zip [0 :: Int ..] plainSections
    participants     = [ numbered | numbered@(_, sectionBytes) <- numberedSections
                                  , not (ByteString.null sectionBytes) ]

    kindPaysWhole =
      sum (map ByteString.length (Map.elems framedByWindow))
        < sum [ ByteString.length plainBytes | (_, plainBytes) <- participants ]

    framedByWindow :: Map Int ByteString
    framedByWindow =
      let sectionStream = lzmaCompressSections (map snd participants)
          pieceBounds   = zip (0 : lzmaPieceEndOffsets sectionStream) (lzmaPieceEndOffsets sectionStream)
          pieceAt (pieceStart, pieceEnd) =
            ByteString.take (pieceEnd - pieceStart)
                            (ByteString.drop pieceStart (lzmaStreamBytes sectionStream))
      in Map.fromList
           [ (windowIndex, framedCompressedSection (byteLength plainBytes) (pieceAt bounds))
           | ((windowIndex, plainBytes), bounds) <- zip participants pieceBounds ]

-- | The carriage one section rides out under a per-section compressor: the compressed piece — its
-- decompressed-size varint, then the compressor's stream — when that is smaller than the
-- plain bytes, the plain bytes otherwise (docs/vcdiff/xdelta3/questions.md: a section is kept compressed only where it shrinks).
-- The write-side partner of 'readContribution', producing exactly the framing it peels;
-- the caller composes the window's Delta_Indicator bit from the choice.
-- An empty section always rides plain: nothing compresses to nothing,
-- and the read side refuses a compressed section declaring zero output ('VCDIFFCompressedSectionDeclaresEmptyOutput').
carriageKeepingSmaller :: (ByteString -> ByteString) -> ByteString -> SectionCarriage
carriageKeepingSmaller compress plainSection
  | ByteString.null plainSection = CarriedPlain plainSection
  | ByteString.length compressedSection < ByteString.length plainSection =
      CarriedCompressed compressedSection
  | otherwise = CarriedPlain plainSection
  where
    compressedSection = framedCompressedSection (byteLength plainSection) (compress plainSection)

-- | A compressed section's wire bytes: the decompressed-size varint, then the compressor's stream piece —
-- exactly the framing 'readContribution' peels.
framedCompressedSection :: Length -> ByteString -> ByteString
framedCompressedSection declaredOutputLength streamPiece =
  LazyByteString.toStrict
    (toLazyByteString (putVcdiffVarint (fromIntegral (unLength declaredOutputLength))))
    <> streamPiece
