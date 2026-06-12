-- | Read a VCDIFF patch into the 'Slap.VCDIFF.Types' vocabulary,
-- source-free. Scoped to the core plus the xdelta3 arc as far as
-- LZMA: the default code table, the application header (carried
-- opaque), the per-window Adler32 (carried for the verification
-- boundary), and LZMA-compressed sections (decoded here, before
-- instruction decode, through 'Slap.VCDIFF.SecondaryCompression'). A
-- patch that reaches further — DJW or FGK compression, a custom code
-- table, a VCD_TARGET window — is classified and declined cleanly: a
-- deferred feature as 'VCDIFFFeatureNotYetSupported', a reserved
-- indicator bit or an uncataloged compressor id as the decline shapes
-- 'VCDIFFReservedIndicatorBits' \/ 'VCDIFFUnknownSecondaryCompressor'
-- — never mishandled.
--
-- Parsing is two passes with one clean seam. 'parseRawPatch' is the
-- byte-level walk: it reads the header and frames each window into its
-- indicator bytes, source segment, sizes, checksum, and three raw
-- section slices, surfacing only truncation ('ParseError').
-- 'classifyAndDecode' is the semantic pass, in stages: it vets every
-- window's framing ('vetWindowFraming'), resolves secondary
-- compression so each window holds plain sections
-- ('resolveSecondaryCompression'), decodes each window's instruction
-- stream ('decodeWindow') — enforcing the three core invariants
-- (docs/vcdiff/core/spec.md "Core invariants") so a patch this module
-- returns has them guaranteed — and names the flavor.
--
-- The address cache lives here, as decode mechanism: it is reset per
-- window, updated after every COPY, and gone once the window's
-- absolute offsets are in hand. 'decodeCopyAddress' — the cache decode
-- — is exported so a property test can exercise its round-robin and
-- modulo-slotted updates in isolation; it is the most error-prone
-- piece.
module Slap.VCDIFF.Parse
  ( parseVCDIFF
    -- * Address cache (exported for testing)
  , AddressCache(..)
  , NearSlots(..)
  , NearSlot(..)
  , SameBlock(..)
  , freshAddressCache
  , decodeCopyAddress
  , CopyAddressReading(..)
  , AddressDecodeFailure(..)
  , nearCacheSize
  , sameCacheSize
  ) where

import Slap.VCDIFF.Types
  ( VCDIFFPatch(..), Window(..), VCDIFFInstruction(..)
  , XDelta3Header(..), XDelta3Window(..)
  , SourceSegment(..), SegmentOrigin(..), vcdiffMagicBytes )
-- Qualified: 'InstructionTemplate' shares the constructor names Add /
-- Run / Copy with 'VCDIFFInstruction'. The template (code-table) side
-- is qualified; the decoded-instruction side stays unqualified, so the
-- two are visibly distinct at every use.
import qualified Slap.VCDIFF.CodeTable as Table
import Slap.VCDIFF.SecondaryCompression
  ( XDelta3SecondaryCompressor(..), secondaryCompressorCatalog
  , SectionCarriage(..), decodeLZMACompressedKind )
import Slap.Binary (getVcdiffVarint, VarintResult(..), viewBytesInRange)
import Slap.ByteParser
  ( ByteParser, runByteParser, getByte, getBytes, skip, lookAhead
  , vcdiffVarint, word32BE, remaining, atEnd )
import Slap.Checksum (Adler32(..))
import Slap.Status
  ( SlapError(..), SlapAdvisory(..), Parsed(..)
  , VCDIFFUnsupportedFeature(..), VCDIFFMalformation(..)
  , VCDIFFIndicatorKind(..), VCDIFFSection(..) )
import Slap.FormatLabel (FormatLabel(..))
import Slap.FileContents (PatchFileContents(..))
import Slap.Measure
  ( Offset(..), Length(..), FileSize(..)
  , ActualOffset(..), MaxOffset(..), ExpectedSize(..), ActualSize(..)
  , ActionIndex, firstAction, nextAction
  , Cursor(..), fitsWithin, remainingFromOffset, lengthToFileSize
  , subtractLength
  , RequiredLength(..), ActualLength(..), ActualMagic(..)
  , FoundVersion(..), byteLength, byteFileSize )

import Control.Monad (when, unless)
import Control.Monad.Trans.Class (lift)
import Control.Monad.Trans.State.Strict (StateT, evalStateT, gets, modify)
import Data.Bits (testBit, bit, complement, (.&.), (.|.))
import Data.Foldable (traverse_)
import Data.List (zipWith4)
import Data.Maybe (isJust, listToMaybe)
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.IntMap.Strict (IntMap)
import qualified Data.IntMap.Strict as IntMap
import Data.Vector (Vector)
import qualified Data.Vector as Vector
import Data.Word (Word8)

----------------------------------------------------------------------------
-- Entry point
----------------------------------------------------------------------------

parseVCDIFF :: PatchFileContents -> Either SlapError (Parsed VCDIFFPatch)
parseVCDIFF (PatchFileContents input)
  | ByteString.length input < magicLength =
      Left (InputTooShort LabelVCDIFF
              (RequiredLength (Length magicLength))
              (ActualLength (byteLength input)))
  | ByteString.take magicLength input /= vcdiffMagicBytes =
      Left (BadMagic LabelVCDIFF (ActualMagic (ByteString.take magicLength input)))
  | otherwise =
      case runByteParser parseRawPatch (ByteString.drop magicLength input) of
        Left parserError -> Left (ParseError LabelVCDIFF parserError)
        Right rawPatch   ->
          (\patch -> Parsed patch (trailingRemnantNotes rawPatch))
            <$> classifyAndDecode rawPatch
  where
    magicLength = ByteString.length vcdiffMagicBytes

-- | The advisory the framer's trailing-remnant recognition surfaces,
-- when it consumed one (see 'isTrailingRemnant'). The remnant is the
-- whole of what the patch says about itself here — its bytes are not
-- patch semantics and go no further than this note.
trailingRemnantNotes :: RawPatch -> [SlapAdvisory]
trailingRemnantNotes rawPatch = case rawTrailingRemnant rawPatch of
  Nothing            -> []
  Just remnantLength -> [VCDIFFTrailingRemnant remnantLength]

----------------------------------------------------------------------------
-- Byte-level framing
----------------------------------------------------------------------------

-- | The header plus a framed-but-not-yet-interpreted window list. The
-- indicator bytes are carried verbatim so 'classifyAndDecode' can read
-- their bits; the compressor id is carried as read, looked up against
-- the catalog only during classification; the application header is
-- opaque by definition and is carried as read; the sections are raw
-- slices, decoded only for a window that survives classification.
data RawPatch = RawPatch
  { rawVersion         :: !Word8
  , rawHeaderIndicator :: !Word8
  , rawCompressorId    :: !(Maybe Word8)
  , rawAppHeader       :: !(Maybe ByteString)
  , rawWindows         :: ![RawWindow]
  , rawTrailingRemnant :: !(Maybe Length)
    -- ^ The byte count of the recognized trailing remnant the framer
    -- consumed after the last window, when one was present (see
    -- 'isTrailingRemnant'). Carried for the advisory channel only:
    -- the bytes are not patch semantics, so they reach neither the
    -- decoded 'VCDIFFPatch' nor anything downstream of it.
  }

data RawWindow = RawWindow
  { rawWindowIndicator :: !Word8
  , rawSourceSegment   :: !(Maybe RawSegment)
    -- | The delta-encoding length the window declares: the byte span
    -- of everything after the length field itself, through the end of
    -- the address section. The boundary a reader navigates windows
    -- by, so 'classifyWindow' holds it against
    -- 'rawMeasuredEncodingLength' (docs/vcdiff/core/questions.md,
    -- "delta-encoding-length").
  , rawDeclaredEncodingLength :: !Length
    -- | The span the framer actually consumed over the same fields.
  , rawMeasuredEncodingLength :: !Length
  , rawTargetSize      :: !FileSize
  , rawDeltaIndicator  :: !Word8
  , rawWindowAdler     :: !(Maybe Adler32)
  , rawDataSection     :: !ByteString
  , rawInstSection     :: !ByteString
  , rawAddrSection     :: !ByteString
  }

-- | A window's source-segment position and length as read off the wire.
-- Which side it is cut from is decided in 'classifyAndDecode' from the
-- window indicator bits, not here.
data RawSegment = RawSegment
  { rawSegmentPosition :: !Offset
  , rawSegmentLength   :: !Length
  }

-- | The byte-level walk. Reads the version and header indicator, then
-- frames the windows — but only when the header is one this parser
-- knows how to walk: version zero, with no header feature beyond the
-- secondary-compressor id (a single byte) and the application header
-- (whose varint-length-plus-bytes shape is read here). A custom code
-- table changes what follows in ways slap refuses anyway, so such a
-- header leaves the window list empty; 'classifyAndDecode' refuses on
-- the header before it would look at windows whose framing it could
-- not trust.
parseRawPatch :: ByteParser RawPatch
parseRawPatch = do
  version          <- getByte
  headerIndicator  <- getByte
  if version == 0 && headerOnlyUsesFramableFeatures headerIndicator
    then do
      compressorId <- if testBit headerIndicator vcdDecompressBit
                        then Just <$> getByte
                        else pure Nothing
      appHeader    <- if testBit headerIndicator vcdAppHeaderBit
                        then Just <$> parseApplicationHeader
                        else pure Nothing
      (windows, trailingRemnant) <- parseRawWindows
      pure (RawPatch version headerIndicator compressorId appHeader windows trailingRemnant)
    else pure (RawPatch version headerIndicator Nothing Nothing [] Nothing)

-- | Whether every set bit of a header indicator names a feature whose
-- bytes the framer knows how to walk past — VCD_DECOMPRESS (one
-- compressor-id byte) and VCD_APPHEADER (the varint-length-plus-bytes
-- shape 'parseApplicationHeader' reads). Any other set bit means the
-- bytes that follow have a shape framing cannot trust.
headerOnlyUsesFramableFeatures :: Word8 -> Bool
headerOnlyUsesFramableFeatures headerIndicator =
  headerIndicator .&. complement (bit vcdDecompressBit .|. bit vcdAppHeaderBit) == 0

-- | The application header's wire shape: a varint length, then that
-- many opaque bytes (docs/vcdiff/xdelta3/spec.md "Application
-- header"). On the wire the field follows the compressor-id byte
-- (read by 'parseRawPatch' when declared) and the code-table data
-- (never framed — a code-table header bails out before any field is
-- walked), so here it follows whichever of those preceded it.
parseApplicationHeader :: ByteParser ByteString
parseApplicationHeader = do
  declaredLength <- vcdiffVarint
  getBytes (Length (fromIntegral declaredLength))

-- | What 'parseRawWindows' finds where the next window would begin:
-- input spent, the one trailing shape slap recognizes, or another
-- window to frame. The collect loop's three outcomes as data, in the
-- house classify-then-dispatch shape, so the loop reads as policy
-- and the looking lives in 'peekWindowStreamHead'.
data WindowStreamHead
  = StreamSpent
  | RemnantToEnd !Length
  | WindowAhead

-- | Collect windows until the input ends — or until what sits where
-- the next window would begin is the one trailing shape slap
-- recognizes instead ('isTrailingRemnant'). A recognized remnant is
-- consumed whole and reported by its byte count. The peek classifies
-- uniformly on every iteration, so a zero-window patch wearing the
-- tail gets the same recognition as a many-window one.
parseRawWindows :: ByteParser ([RawWindow], Maybe Length)
parseRawWindows = collect []
  where
    collect accumulatedReversed = do
      streamHead <- peekWindowStreamHead
      case streamHead of
        StreamSpent -> pure (reverse accumulatedReversed, Nothing)
        RemnantToEnd remnantLength -> do
          skip remnantLength
          pure (reverse accumulatedReversed, Just remnantLength)
        WindowAhead -> do
          window <- parseRawWindow
          collect (window : accumulatedReversed)

-- | Classify the rest of the input without moving the cursor;
-- 'parseRawWindows' performs whatever consumption the verdict calls
-- for.
peekWindowStreamHead :: ByteParser WindowStreamHead
peekWindowStreamHead = do
  done <- atEnd
  if done
    then pure StreamSpent
    else do
      bytesLeft   <- remaining
      restOfInput <- lookAhead (getBytes bytesLeft)
      pure $ if isTrailingRemnant restOfInput
               then RemnantToEnd bytesLeft
               else WindowAhead

-- | The one trailing shape slap recognizes after the last window:
-- the four marker bytes, then nothing but zero padding (none
-- included) to end of input. Exactly the tail LODModS-made patches
-- carry, and the tolerance extends exactly as far as that evidence
-- (docs/vcdiff/questions.md, "How does a decoder know the patch is
-- over"): any other trailing bytes keep framing as a window and
-- failing as one, and a second recognized shape earns its place the
-- way this one did — by existing in the wild, not by widening this
-- predicate.
isTrailingRemnant :: ByteString -> Bool
isTrailingRemnant trailingBytes =
  ByteString.take markerLength trailingBytes == trailingRemnantMarker
    && ByteString.all (== 0x00) (ByteString.drop markerLength trailingBytes)
  where
    markerLength = ByteString.length trailingRemnantMarker

-- | The four bytes that open the recognized trailing remnant.
trailingRemnantMarker :: ByteString
trailingRemnantMarker = ByteString.pack [0xFF, 0xFF, 0xFF, 0xFF]

parseRawWindow :: ByteParser RawWindow
parseRawWindow = do
  windowIndicator <- getByte
  sourceSegment   <- if testBit windowIndicator vcdSourceBit
                        || testBit windowIndicator vcdTargetBit
                       then do
                         segmentLength   <- vcdiffVarint
                         segmentPosition <- vcdiffVarint
                         pure (Just (RawSegment
                                       (Offset (fromIntegral segmentPosition))
                                       (Length (fromIntegral segmentLength))))
                       else pure Nothing
  declaredEncodingLength   <- Length . fromIntegral <$> vcdiffVarint
  remainingAtEncodingStart <- remaining
  targetSize           <- vcdiffVarint
  deltaIndicator       <- getByte
  dataLength <- vcdiffVarint
  instLength <- vcdiffVarint
  addrLength <- vcdiffVarint
  -- The per-window checksum, when present, sits between the section
  -- lengths and the data section: four bytes, big-endian, presence
  -- decided by the indicator bit alone (docs/vcdiff/xdelta3/spec.md
  -- "Per-window Adler32").
  adlerChecksum <- if testBit windowIndicator vcdAdler32Bit
                     then Just . Adler32 <$> word32BE
                     else pure Nothing
  dataSection <- getBytes (Length (fromIntegral dataLength))
  instSection <- getBytes (Length (fromIntegral instLength))
  addrSection <- getBytes (Length (fromIntegral addrLength))
  remainingAtWindowEnd <- remaining
  pure RawWindow
    { rawWindowIndicator        = windowIndicator
    , rawSourceSegment          = sourceSegment
    , rawDeclaredEncodingLength = declaredEncodingLength
    , rawMeasuredEncodingLength =
        subtractLength remainingAtEncodingStart remainingAtWindowEnd
    , rawTargetSize             = FileSize (fromIntegral targetSize)
    , rawDeltaIndicator         = deltaIndicator
    , rawWindowAdler            = adlerChecksum
    , rawDataSection            = dataSection
    , rawInstSection            = instSection
    , rawAddrSection            = addrSection
    }

----------------------------------------------------------------------------
-- Indicator bits
----------------------------------------------------------------------------

-- Header indicator (Hdr_Indicator)
vcdDecompressBit, vcdCodeTableBit, vcdAppHeaderBit :: Int
vcdDecompressBit = 0   -- VCD_DECOMPRESS: a secondary compressor is declared
vcdCodeTableBit  = 1   -- VCD_CODETABLE:  a custom code table follows
vcdAppHeaderBit  = 2   -- VCD_APPHEADER:  application data follows

-- Window indicator (Win_Indicator)
vcdSourceBit, vcdTargetBit, vcdAdler32Bit :: Int
vcdSourceBit  = 0   -- VCD_SOURCE:  copies address a segment of the source file
vcdTargetBit  = 1   -- VCD_TARGET:  copies address a segment of produced target
vcdAdler32Bit = 2   -- VCD_ADLER32: a per-window Adler32 follows the section lengths

-- Delta indicator (Delta_Indicator): one bit per section kind,
-- marking that kind's section of this window as a compressed piece
-- of the kind's continuous secondary stream.
vcdDataCompBit, vcdInstCompBit, vcdAddrCompBit :: Int
vcdDataCompBit = 0   -- VCD_DATACOMP: the data section is compressed
vcdInstCompBit = 1   -- VCD_INSTCOMP: the instruction section is compressed
vcdAddrCompBit = 2   -- VCD_ADDRCOMP: the address section is compressed

-- | The three Delta_Indicator compression bits, each paired with the
-- section kind it governs. The single place the bit-to-kind pairing
-- lives; both the carriage builder and the compressed-kind scans
-- below read it.
sectionCompressionBits :: [(Int, VCDIFFSection)]
sectionCompressionBits =
  [ (vcdDataCompBit, VCDIFFDataSection)
  , (vcdInstCompBit, VCDIFFInstructionSection)
  , (vcdAddrCompBit, VCDIFFAddressSection)
  ]

-- | Mask of the bits each indicator byte leaves undefined in the core.
-- A set bit here is reserved for future definition: slap cannot
-- interpret it, so the patch is declined as unreadable
-- ('VCDIFFReservedIndicatorBits'), not called malformed.
reservedIndicatorMask :: Word8
reservedIndicatorMask = 0xF8

----------------------------------------------------------------------------
-- Semantic classification and decode
----------------------------------------------------------------------------

-- | Interpret a framed patch: refuse an unreadable version or header,
-- vet every window's framing, resolve secondary compression so each
-- window holds plain sections, decode each window, then name the
-- flavor.
--
-- Vetting runs before resolution on purpose: a window whose delta
-- indicator carries reserved bits is declined before its compression
-- bits are believed, because slap cannot claim to interpret three
-- bits of a byte it does not understand the rest of.
classifyAndDecode :: RawPatch -> Either SlapError VCDIFFPatch
classifyAndDecode rawPatch
  | rawVersion rawPatch /= 0 =
      Left (BadVersion LabelVCDIFF (FoundVersion (rawVersion rawPatch)))
  | headerIndicator .&. reservedIndicatorMask /= 0 =
      Left (VCDIFFReservedIndicatorBits HeaderIndicator headerIndicator)
  | testBit headerIndicator vcdCodeTableBit =
      Left (VCDIFFFeatureNotYetSupported VCDIFFCustomCodeTable)
  | otherwise = do
      declaredCompressor <- lookupDeclaredCompressor (rawCompressorId rawPatch)
      traverse_ vetWindowFraming (rawWindows rawPatch)
      resolvedWindows <- resolveSecondaryCompression declaredCompressor (rawWindows rawPatch)
      decodedWindows  <- traverse decodeWindow resolvedWindows
      pure (classifyFlavor declaredCompressor (rawAppHeader rawPatch)
              (Vector.fromList decodedWindows))
  where
    headerIndicator = rawHeaderIndicator rawPatch

-- | Resolve a framed compressor id against the catalog. An id the
-- catalog does not name is the decline shape — slap does not know
-- what algorithm such a patch is asking for, so it cannot call the
-- patch malformed (see 'VCDIFFUnknownSecondaryCompressor').
lookupDeclaredCompressor
  :: Maybe Word8 -> Either SlapError (Maybe XDelta3SecondaryCompressor)
lookupDeclaredCompressor Nothing = Right Nothing
lookupDeclaredCompressor (Just compressorId) =
  case secondaryCompressorCatalog compressorId of
    Nothing         -> Left (VCDIFFUnknownSecondaryCompressor compressorId)
    Just compressor -> Right (Just compressor)

-- | One decoded window, before the patch-level flavor verdict: the
-- shared 'Window', plus the checksum it carried if any. A VCDIFF
-- window and nothing more — which flavor it belongs to is a fact
-- about the whole patch, rendered by 'classifyFlavor' after every
-- window is decoded, and only then do these become 'XDelta3Window's
-- (or shed their absent checksums and stay plain 'Window's).
data DecodedWindow = DecodedWindow
  { decodedWindowBody     :: !Window
  , decodedWindowChecksum :: !(Maybe Adler32)
  }

-- | Name the decoded patch for what it is. Any xdelta3-arc feature —
-- a declared secondary compressor (an xdelta3 signal even when no
-- window exercises it, because xdelta3's catalog is the only registry
-- of compressor ids there is), an application header, or any window
-- carrying an Adler32 — makes the patch 'PatchXDelta3'; a patch using
-- none decodes identically under either flavor and keeps the
-- first-class 'PatchCoreOnly' verdict (docs/vcdiff/xdelta3/spec.md
-- "Classification").
classifyFlavor
  :: Maybe XDelta3SecondaryCompressor -> Maybe ByteString
  -> Vector DecodedWindow -> VCDIFFPatch
classifyFlavor declaredCompressor maybeAppHeader decodedWindows
  | isJust declaredCompressor
      || isJust maybeAppHeader
      || Vector.any (isJust . decodedWindowChecksum) decodedWindows =
      PatchXDelta3 (XDelta3Header maybeAppHeader) (fmap toXDelta3Window decodedWindows)
  | otherwise = PatchCoreOnly (fmap decodedWindowBody decodedWindows)
  where
    toXDelta3Window decodedWindow =
      XDelta3Window (decodedWindowBody decodedWindow)
                    (decodedWindowChecksum decodedWindow)

-- | Vet one framed window's framing: refuse any unlanded feature on
-- its indicator bytes, and hold the window to its own declared
-- length. Runs over every window before secondary compression is
-- resolved, so the resolution pass reads compression bits only out
-- of indicator bytes this vetting has fully accounted for.
vetWindowFraming :: RawWindow -> Either SlapError ()
vetWindowFraming rawWindow
  | windowIndicator .&. reservedIndicatorMask /= 0 =
      Left (VCDIFFReservedIndicatorBits WindowIndicator windowIndicator)
  | testBit windowIndicator vcdSourceBit && testBit windowIndicator vcdTargetBit =
      Left (MalformedVCDIFF VCDIFFBothSourceAndTargetWindowBits)
  | testBit windowIndicator vcdTargetBit =
      Left (VCDIFFFeatureNotYetSupported VCDIFFTargetWindow)
  | rawDeltaIndicator rawWindow .&. reservedIndicatorMask /= 0 =
      Left (VCDIFFReservedIndicatorBits DeltaIndicator (rawDeltaIndicator rawWindow))
  | rawDeclaredEncodingLength rawWindow /= rawMeasuredEncodingLength rawWindow =
      Left (MalformedVCDIFF (VCDIFFDeltaEncodingLengthMismatch
              (ExpectedSize (lengthToFileSize (rawDeclaredEncodingLength rawWindow)))
              (ActualSize   (lengthToFileSize (rawMeasuredEncodingLength rawWindow)))))
  | otherwise = Right ()
  where
    windowIndicator = rawWindowIndicator rawWindow

-- | Decode one resolved window's instruction stream. The
-- 'ResolvedWindow' proof is what lets the body read the sections as
-- plain bytes without checking — the instruction decode never learns
-- that compression existed.
decodeWindow :: ResolvedWindow -> Either SlapError DecodedWindow
decodeWindow (ResolvedWindow rawWindow) = do
  let sourceSegment =
        (\segment -> SourceSegment
                       FromSourceFile
                       (rawSegmentPosition segment)
                       (rawSegmentLength segment))
        <$> rawSourceSegment rawWindow
      segmentLength = maybe mempty rawSegmentLength (rawSourceSegment rawWindow)
  instructions <- decodeWindowInstructions
                    segmentLength
                    (rawTargetSize rawWindow)
                    (rawDataSection rawWindow)
                    (rawInstSection rawWindow)
                    (rawAddrSection rawWindow)
  Right DecodedWindow
    { decodedWindowBody = Window
        { windowSourceSegment = sourceSegment
        , windowTargetSize    = rawTargetSize rawWindow
        , windowInstructions  = instructions
        }
    , decodedWindowChecksum = rawWindowAdler rawWindow
    }

----------------------------------------------------------------------------
-- Secondary-compression resolution
----------------------------------------------------------------------------

-- | The proof that 'resolveSecondaryCompression' has run: a window
-- whose sections are plain bytes, whatever the wire carried. Its
-- still-set Delta_Indicator compression bits are history, not
-- instruction — they record what the wire did; the type says it has
-- been dealt with. 'decodeWindow' accepts only this, so decoding an
-- unresolved window is a compile error.
newtype ResolvedWindow = ResolvedWindow RawWindow

-- | Resolve every window's compressed sections into plain ones, or
-- refuse. The four dispositions, decided by the declared compressor
-- and whether any window actually compresses a section:
--
--   * No compressor declared: any compression-flagged section is a
--     wire self-contradiction ('VCDIFFCompressedSectionWithoutCompressor').
--   * DJW or FGK declared and exercised: refused by name — slap
--     recognizes the catalog entry but does not decode it yet.
--   * LZMA declared and exercised: each kind's stream is gathered,
--     decoded, and split back; every window comes out holding plain
--     sections.
--   * Any compressor declared but exercised by no window: the patch
--     is fully decodable and passes through untouched — a
--     declared-but-unused compressor is valid
--     (docs/vcdiff/xdelta3/spec.md "Catalog").
--
-- The DJW and FGK arms are deliberate shape-twins, kept explicit
-- rather than factored through a shared refusal projection: the
-- dispositions above appear one-to-one in the code, and a compressor
-- graduating into decode support — or a new catalog entry — fires
-- '-Wincomplete-patterns' here, at the decision point.
resolveSecondaryCompression
  :: Maybe XDelta3SecondaryCompressor -> [RawWindow]
  -> Either SlapError [ResolvedWindow]
resolveSecondaryCompression declaredCompressor rawWindows =
  map ResolvedWindow <$> case declaredCompressor of
    Nothing -> case listToMaybe (concatMap compressedKindsOf rawWindows) of
      Just orphanedKind ->
        Left (MalformedVCDIFF (VCDIFFCompressedSectionWithoutCompressor orphanedKind))
      Nothing -> Right rawWindows
    Just SecondaryDJW
      | anyWindowCompresses ->
          Left (VCDIFFFeatureNotYetSupported VCDIFFDJWSecondaryCompression)
      | otherwise -> Right rawWindows
    Just SecondaryFGK
      | anyWindowCompresses ->
          Left (VCDIFFFeatureNotYetSupported VCDIFFFGKSecondaryCompression)
      | otherwise -> Right rawWindows
    Just SecondaryLZMA -> decompressLZMASections rawWindows
  where
    anyWindowCompresses = any (not . null . compressedKindsOf) rawWindows

-- | The section kinds a window's Delta_Indicator flags as
-- compressed, in kind order.
compressedKindsOf :: RawWindow -> [VCDIFFSection]
compressedKindsOf rawWindow =
  [ kind
  | (compressionBit, kind) <- sectionCompressionBits
  , testBit (rawDeltaIndicator rawWindow) compressionBit
  ]

-- | Run each of the three kinds through the gather-decode-split
-- machine and hand every window back with plain sections. Each kind
-- is its own continuous stream, decoded independently; a kind no
-- window compresses passes through the machine untouched.
decompressLZMASections :: [RawWindow] -> Either SlapError [RawWindow]
decompressLZMASections rawWindows = do
  plainDataSections <- decodeKind VCDIFFDataSection        vcdDataCompBit rawDataSection
  plainInstSections <- decodeKind VCDIFFInstructionSection vcdInstCompBit rawInstSection
  plainAddrSections <- decodeKind VCDIFFAddressSection     vcdAddrCompBit rawAddrSection
  pure (zipWith4 windowWithPlainSections
          rawWindows plainDataSections plainInstSections plainAddrSections)
  where
    decodeKind :: VCDIFFSection -> Int -> (RawWindow -> ByteString)
               -> Either SlapError [ByteString]
    decodeKind kind compressionBit sectionOf =
      decodeLZMACompressedKind kind
        [ if testBit (rawDeltaIndicator rawWindow) compressionBit
            then CarriedCompressed (sectionOf rawWindow)
            else CarriedPlain      (sectionOf rawWindow)
        | rawWindow <- rawWindows
        ]

    -- The three plain sections arrive positionally in data, inst,
    -- addr order — the same order the 'do' block above binds them in,
    -- so a transposition is visible at the 'zipWith4' call site.
    windowWithPlainSections :: RawWindow -> ByteString -> ByteString -> ByteString
                            -> RawWindow
    windowWithPlainSections rawWindow dataSection instSection addrSection =
      rawWindow
        { rawDataSection = dataSection
        , rawInstSection = instSection
        , rawAddrSection = addrSection
        }

----------------------------------------------------------------------------
-- Instruction-stream decode
----------------------------------------------------------------------------

-- | Cursors into one window's three sections. Role-wrapped so a
-- transition meant for one section cannot compile against another —
-- the same reason 'Slap.BPS.Apply' role-wraps its two relative
-- cursors — and 'Offset'-backed: each names a byte position in its
-- section slice, squarely inside 'Offset''s charter of byte positions
-- in zero-indexed buffers. The walk's byte-level primitives
-- ('ByteString.index', 'getVcdiffVarint') peel both layers at their
-- call sites; everywhere else the cursors move only through the
-- named transitions below.
newtype InstructionSectionCursor = InstructionSectionCursor Offset
  deriving (Eq, Ord, Show)

-- | See 'InstructionSectionCursor'.
newtype DataSectionCursor = DataSectionCursor Offset
  deriving (Eq, Ord, Show)

-- | See 'InstructionSectionCursor'. The address cursor has no
-- 'Cursor' instance: it never advances by a stride — the address
-- kernel returns its absolute post-position, adopted whole by
-- 'adoptCopyAddressReading'.
newtype AddressSectionCursor = AddressSectionCursor Offset
  deriving (Eq, Ord, Show)

instance Cursor InstructionSectionCursor where
  advance  (InstructionSectionCursor position) stride = InstructionSectionCursor (advance  position stride)
  displace (InstructionSectionCursor position) delta  = InstructionSectionCursor (displace position delta)

instance Cursor DataSectionCursor where
  advance  (DataSectionCursor position) stride = DataSectionCursor (advance  position stride)
  displace (DataSectionCursor position) delta  = DataSectionCursor (displace position delta)

-- | Cursors and accumulators carried through one window's decode by
-- 'WindowDecode'. The three sections each have their own role-typed
-- cursor; 'producedBytes' tracks how much of the target this window
-- has emitted, which fixes @here@ for the next COPY; and
-- 'instructionIndex' numbers the decoded instructions for error
-- reporting — deliberately instructions, not instruction-section
-- bytes: one code byte can carry two instructions, and an inline
-- size varint widens others, so an error's index counts what the
-- stream means rather than where it sits.
data DecodeState = DecodeState
  { instCursor       :: !InstructionSectionCursor
  , dataCursor       :: !DataSectionCursor
  , addrCursor       :: !AddressSectionCursor
  , addressCache     :: !AddressCache
  , producedBytes    :: !Length
  , instructionIndex :: !ActionIndex
  , emittedReversed  :: ![VCDIFFInstruction]
  }

-- | The window-decode monad: 'DecodeState' threaded over the same
-- 'Either' the rest of parse answers in, the way 'Slap.BPS.Apply'
-- threads its cursors over 'IO'.
type WindowDecode = StateT DecodeState (Either SlapError)

-- | Refuse the window with a malformation verdict. Every refusal the
-- instruction walk raises is a 'VCDIFFMalformation'; this is the one
-- door into the 'Left' lane.
failDecode :: VCDIFFMalformation -> WindowDecode a
failDecode = lift . Left . MalformedVCDIFF

-- | Refuse the window: an instruction demanded more bytes than the
-- named section holds.
sectionExhausted :: VCDIFFSection -> WindowDecode a
sectionExhausted section = do
  failingInstruction <- gets instructionIndex
  failDecode (VCDIFFSectionExhausted section failingInstruction)

-- | Advance the instruction-section cursor past a consumed code byte
-- or inline size varint.
advanceInstCursor :: Length -> DecodeState -> DecodeState
advanceInstCursor consumed decodeState =
  decodeState { instCursor = advance (instCursor decodeState) consumed }

-- | Advance the data-section cursor past consumed ADD literal bytes
-- or a RUN fill byte.
advanceDataCursor :: Length -> DecodeState -> DecodeState
advanceDataCursor consumed decodeState =
  decodeState { dataCursor = advance (dataCursor decodeState) consumed }

-- | Move the state to a 'CopyAddressReading''s post-state: the cache
-- with the address recorded, the address-section cursor past the
-- consumed bytes. The address kernel answers in 'Int' (see
-- 'CopyAddressReading'); its post-state re-enters the typed walk
-- here.
adoptCopyAddressReading :: CopyAddressReading -> DecodeState -> DecodeState
adoptCopyAddressReading reading decodeState = decodeState
  { addrCursor   = AddressSectionCursor (Offset (copyAddressCursorAfter reading))
  , addressCache = copyAddressCacheAfter reading
  }

-- | Account for an emitted instruction: the produced-byte count grows
-- by the instruction's output size, the instruction counter steps,
-- and the instruction joins the reversed accumulator.
emitInstruction :: VCDIFFInstruction -> Length -> DecodeState -> DecodeState
emitInstruction instruction outputSize decodeState = decodeState
  { producedBytes    = producedBytes decodeState <> outputSize
  , instructionIndex = nextAction (instructionIndex decodeState)
  , emittedReversed  = instruction : emittedReversed decodeState
  }

-- | Decode one window's instruction stream into already-resolved
-- 'VCDIFFInstruction's, enforcing the three core invariants. Each
-- instruction byte indexes the default code table for up to two
-- templates; a deferred (zero) size is read inline from the
-- instruction section; ADD slices its literal bytes from the data
-- section; RUN takes its fill byte; COPY decodes its absolute
-- superstring offset through the address cache.
decodeWindowInstructions
  :: Length       -- ^ source-segment length, @len(S)@
  -> FileSize     -- ^ declared target-window size
  -> ByteString   -- ^ data section
  -> ByteString   -- ^ instruction section
  -> ByteString   -- ^ address section
  -> Either SlapError (Vector VCDIFFInstruction)
decodeWindowInstructions segmentLength targetWindowSize dataSection instSection addrSection =
  evalStateT walkInstructionSection initialState
  where
    initialState = DecodeState
      { instCursor       = InstructionSectionCursor (Offset 0)
      , dataCursor       = DataSectionCursor (Offset 0)
      , addrCursor       = AddressSectionCursor (Offset 0)
      , addressCache     = freshAddressCache
      , producedBytes    = mempty
      , instructionIndex = firstAction
      , emittedReversed  = []
      }

    -- | The sections measured as the whole spaces their cursors
    -- address. 'FileSize' is the role 'fitsWithin' and
    -- 'remainingFromOffset' read their last argument in — the total
    -- extent a region is checked against — and within this walk each
    -- section is exactly that whole, even though one layer up it is a
    -- region of the patch file.
    instructionSectionSize, dataSectionSize :: FileSize
    instructionSectionSize = byteFileSize instSection
    dataSectionSize        = byteFileSize dataSection

    -- | @len(S)@ in the address kernel's 'Int' domain (see
    -- 'CopyAddressReading' for why the kernel speaks 'Int'); the
    -- typed segment length unwraps once, here.
    segmentEnd :: Int
    segmentEnd = unLength segmentLength

    -- | The current write position in the superstring @U = S + T@:
    -- @len(S)@ plus the target bytes produced so far. In the kernel's
    -- 'Int' domain for the same reason as 'segmentEnd'.
    superstringWriteHead :: DecodeState -> Int
    superstringWriteHead decodeState =
      unLength (segmentLength <> producedBytes decodeState)

    -- | Decode table entries until the instruction section is spent,
    -- then close the window out.
    walkInstructionSection :: WindowDecode (Vector VCDIFFInstruction)
    walkInstructionSection = do
      sectionSpent <- gets (instructionSectionSpent . instCursor)
      if sectionSpent
        then finishWindow
        else decodeTableEntry >> walkInstructionSection

    -- | Whether the instruction section has no bytes left to decode.
    instructionSectionSpent :: InstructionSectionCursor -> Bool
    instructionSectionSpent (InstructionSectionCursor position) =
      remainingFromOffset position instructionSectionSize == Length 0

    -- | Core invariant 3 — the instructions must produce exactly the
    -- declared target size — then the reversed accumulator
    -- materialises as the decoded stream.
    finishWindow :: WindowDecode (Vector VCDIFFInstruction)
    finishWindow = do
      producedSize <- gets (lengthToFileSize . producedBytes)
      when (producedSize /= targetWindowSize) $
        failDecode (VCDIFFWindowSizeMismatch
                      (ExpectedSize targetWindowSize)
                      (ActualSize producedSize))
      gets (Vector.fromList . reverse . emittedReversed)

    -- | Read one code byte and apply both of its templates ('Noop'
    -- fills the unused slot of a single-instruction entry).
    decodeTableEntry :: WindowDecode ()
    decodeTableEntry = do
      codeByte <- nextInstructionByte
      let entry = Table.codeTableEntries Table.defaultCodeTable
                    Vector.! fromIntegral codeByte
      applyTemplate (Table.firstTemplate entry)
      applyTemplate (Table.secondTemplate entry)

    -- | The next byte of the instruction section. Total:
    -- 'walkInstructionSection' only descends here when the cursor is
    -- strictly inside the section.
    nextInstructionByte :: WindowDecode Word8
    nextInstructionByte = do
      InstructionSectionCursor (Offset codeBytePosition) <- gets instCursor
      modify (advanceInstCursor (Length 1))
      pure (ByteString.index instSection codeBytePosition)

    applyTemplate :: Table.InstructionTemplate -> WindowDecode ()
    applyTemplate Table.Noop = pure ()
    applyTemplate (Table.Add sizeTemplate) = do
      size <- resolveSize sizeTemplate
      DataSectionCursor literalStart <- gets dataCursor
      unless (fitsWithin literalStart size dataSectionSize) $
        sectionExhausted VCDIFFDataSection
      modify (advanceDataCursor size)
      modify (emitInstruction
                (Add (viewBytesInRange literalStart size dataSection))
                size)
    applyTemplate (Table.Run sizeTemplate) = do
      size <- resolveSize sizeTemplate
      DataSectionCursor fillStart <- gets dataCursor
      unless (fitsWithin fillStart (Length 1) dataSectionSize) $
        sectionExhausted VCDIFFDataSection
      modify (advanceDataCursor (Length 1))
      modify (emitInstruction
                (Run size (ByteString.index dataSection (unOffset fillStart)))
                size)
    applyTemplate (Table.Copy sizeTemplate (Table.CopyAddressMode mode)) = do
      size            <- resolveSize sizeTemplate
      here            <- gets superstringWriteHead
      reading         <- readCopyAddress here mode
      thisInstruction <- gets instructionIndex
      let address = copyAddressDecoded reading
          copyEnd = address + unLength size
      when (address < 0 || address >= here) $
        failDecode (VCDIFFCopyAddressOutOfRange thisInstruction
                      (ActualOffset (Offset address))
                      (MaxOffset (Offset here)))
      when (address < segmentEnd && copyEnd > segmentEnd) $
        failDecode (VCDIFFCopyCrossesSourceSegmentEnd thisInstruction)
      modify (adoptCopyAddressReading reading)
      modify (emitInstruction (Copy size (Offset address)) size)

    -- | Resolve an instruction's size: a fixed table size as-is, or a
    -- deferred (zero) size read inline from the instruction section.
    resolveSize :: Table.InstructionSize -> WindowDecode Length
    resolveSize (Table.SizeIs (Table.FixedInstructionSize fixed)) =
      pure (Length (fromIntegral fixed))
    resolveSize Table.SizeCodedSeparately = do
      InstructionSectionCursor (Offset sizePosition) <- gets instCursor
      case getVcdiffVarint sizePosition instSection of
        Left _ -> sectionExhausted VCDIFFInstructionSection
        Right (VarintResult value consumed) -> do
          modify (advanceInstCursor (Length consumed))
          pure (Length (fromIntegral value))

    -- | Decode one COPY address through the cache, mapping the
    -- kernel's failures onto the malformation vocabulary.
    readCopyAddress :: Int -> Word8 -> WindowDecode CopyAddressReading
    readCopyAddress here mode = do
      AddressSectionCursor (Offset cursor) <- gets addrCursor
      cache <- gets addressCache
      case decodeCopyAddress cache here mode addrSection cursor of
        Left AddressSectionExhausted ->
          sectionExhausted VCDIFFAddressSection
        Left (UnknownAddressMode modeByte) ->
          failDecode (VCDIFFInvalidCopyAddressMode modeByte)
        Right reading -> pure reading

----------------------------------------------------------------------------
-- Address cache
----------------------------------------------------------------------------

-- | The two address caches a VCDIFF decoder maintains in lockstep with
-- the encoder (docs/vcdiff/core/spec.md "Address cache"), holding the
-- decoded addresses themselves. Both reset to zero at the start of
-- every window and update after every COPY.
--
-- The cache is threaded linearly through the decode — each value is
-- consumed once to produce the next, no old version is revisited — so
-- the representations are chosen for cheap single-slot updates: a
-- five-word 'NearSlots' record and an 'IntMap' path-copy per COPY,
-- where array cloning would copy every slot to change one.
data AddressCache = AddressCache
  { nearAddresses :: !NearSlots
    -- ^ The near cache, written round-robin at 'nearWriteSlot'.
  , sameAddresses :: !(IntMap Int)
    -- ^ The same cache, keyed by @address mod 'sameSlotCount'@. A
    -- slot never written reads as zero ('readSameSlot'): xd3
    -- initializes both caches to zero, and a same-mode read of an
    -- untouched slot legitimately decodes address 0 — so the empty
    -- map with a zero default is the semantics itself, not 768
    -- stored zeroes that happen not to be overwritten yet.
  , nearWriteSlot :: !NearSlot
    -- ^ The next near slot to overwrite.
  }
  deriving (Eq, Show)

-- | The near cache of the default code table's configuration: four
-- slots, as one strict record, so a write allocates one fresh record
-- where a vector would clone an array. Four is the default table's
-- fact, not a format universal — a custom code table (RFC arc)
-- chooses its own cache sizes and reshapes this type when it lands.
data NearSlots = NearSlots !Int !Int !Int !Int
  deriving (Eq, Show)

-- | A position in 'NearSlots'. A four-arm sum rather than an 'Int'
-- index, so an out-of-range slot is unrepresentable and the
-- round-robin advance ('nextNearSlot') wraps by construction, with
-- no modulus.
data NearSlot = NearSlot0 | NearSlot1 | NearSlot2 | NearSlot3
  deriving (Eq, Show)

-- | The round-robin successor: each slot steps to the next, the
-- last wraps to the first.
nextNearSlot :: NearSlot -> NearSlot
nextNearSlot NearSlot0 = NearSlot1
nextNearSlot NearSlot1 = NearSlot2
nextNearSlot NearSlot2 = NearSlot3
nextNearSlot NearSlot3 = NearSlot0

-- | The address held in one near slot.
readNearSlot :: NearSlot -> NearSlots -> Int
readNearSlot NearSlot0 (NearSlots slot0 _ _ _) = slot0
readNearSlot NearSlot1 (NearSlots _ slot1 _ _) = slot1
readNearSlot NearSlot2 (NearSlots _ _ slot2 _) = slot2
readNearSlot NearSlot3 (NearSlots _ _ _ slot3) = slot3

-- | One near slot overwritten, the other three carried.
writeNearSlot :: NearSlot -> Int -> NearSlots -> NearSlots
writeNearSlot NearSlot0 address (NearSlots _ slot1 slot2 slot3) = NearSlots address slot1 slot2 slot3
writeNearSlot NearSlot1 address (NearSlots slot0 _ slot2 slot3) = NearSlots slot0 address slot2 slot3
writeNearSlot NearSlot2 address (NearSlots slot0 slot1 _ slot3) = NearSlots slot0 slot1 address slot3
writeNearSlot NearSlot3 address (NearSlots slot0 slot1 slot2 _) = NearSlots slot0 slot1 slot2 address

-- | One of the default configuration's three same-cache blocks. A
-- same-mode COPY names a block; the one-byte operand picks a slot
-- within the block's 256-slot span ('sameBlockBase'). Three is the
-- default table's fact, with the same custom-table caveat as
-- 'NearSlots'.
data SameBlock = SameBlock0 | SameBlock1 | SameBlock2
  deriving (Eq, Show)

-- | The first slot of a same block's 256-slot span.
sameBlockBase :: SameBlock -> Int
sameBlockBase SameBlock0 = 0
sameBlockBase SameBlock1 = 256
sameBlockBase SameBlock2 = 512

-- | The address held in one same slot; an untouched slot holds zero
-- (see 'sameAddresses').
readSameSlot :: SameBlock -> Int -> IntMap Int -> Int
readSameSlot sameBlock slotByte sameMap =
  IntMap.findWithDefault 0 (sameBlockBase sameBlock + slotByte) sameMap

-- | The default-code-table cache configuration: four near slots and
-- three same blocks, giving nine address modes (0–8). A custom code
-- table could change these (RFC-arc); the core uses these. The
-- structural mirrors are 'NearSlots' and 'SameBlock'; these 'Int'
-- projections remain for arithmetic against wire values.
nearCacheSize, sameCacheSize :: Int
nearCacheSize = 4
sameCacheSize = 3

-- | The same cache's slot count: 'sameCacheSize' blocks of 256 slots.
sameSlotCount :: Int
sameSlotCount = sameCacheSize * 256

-- | A zeroed cache, as at the start of each window.
freshAddressCache :: AddressCache
freshAddressCache = AddressCache
  { nearAddresses = NearSlots 0 0 0 0
  , sameAddresses = IntMap.empty
  , nearWriteSlot = NearSlot0
  }

-- | Why 'decodeCopyAddress' could not produce an address. Mapped to a
-- 'VCDIFFMalformation' by the caller, which holds the instruction
-- index these are free of.
data AddressDecodeFailure
  = AddressSectionExhausted
  | UnknownAddressMode !Word8
  deriving (Eq, Show)

-- | The product of one COPY-address decode: the absolute address into
-- the superstring, plus the post-state the decode leaves behind — the
-- cache with the address recorded, and the address-section cursor
-- advanced past the consumed bytes. Named so callers read the three
-- by name rather than by tuple position, in the manner of
-- 'Slap.Binary.VarintResult'.
data CopyAddressReading = CopyAddressReading
  { copyAddressDecoded     :: !Int
    -- ^ The absolute superstring address. Bare 'Int' on purpose: this
    -- is the cache kernel's arithmetic domain; the address becomes an
    -- 'Offset' when the validated COPY is emitted.
  , copyAddressCacheAfter  :: !AddressCache
  , copyAddressCursorAfter :: !Int
  }
  deriving (Eq, Show)

-- | What a COPY address mode byte asks for, classified before any
-- bytes are read: one of the two varint modes, a read of a near
-- slot, or a read of a same block. The wire's mode arithmetic
-- (RFC 3284 §5.3's @2 + s_near + s_same@ bands) is collapsed into
-- the classifier; everything after it dispatches on named cases.
data AddressModeFamily
  = SelfAddress
    -- ^ Mode 0 (SELF): the address is a varint, read directly.
  | HereAddress
    -- ^ Mode 1 (HERE): the address is @here@ minus a varint.
  | NearAddress !NearSlot
    -- ^ Near modes: a varint added to the slot's cached address.
  | SameAddress !SameBlock
    -- ^ Same modes: a single byte indexing the block's 256 slots.

-- | Name a mode byte's family — the nine modes of the default cache
-- configuration, enumerated ('nearCacheSize' near slots after the
-- two fixed modes, 'sameCacheSize' same blocks after those).
-- 'Nothing' is a mode byte past the catalog, the
-- 'UnknownAddressMode' decline at the caller.
classifyAddressMode :: Word8 -> Maybe AddressModeFamily
classifyAddressMode 0 = Just SelfAddress
classifyAddressMode 1 = Just HereAddress
classifyAddressMode 2 = Just (NearAddress NearSlot0)
classifyAddressMode 3 = Just (NearAddress NearSlot1)
classifyAddressMode 4 = Just (NearAddress NearSlot2)
classifyAddressMode 5 = Just (NearAddress NearSlot3)
classifyAddressMode 6 = Just (SameAddress SameBlock0)
classifyAddressMode 7 = Just (SameAddress SameBlock1)
classifyAddressMode 8 = Just (SameAddress SameBlock2)
classifyAddressMode _ = Nothing

-- | Decode one COPY address from the address section, given the cache,
-- the current @here@ position in the superstring, and the address
-- mode. The mode families are classified by 'classifyAddressMode'
-- (docs/vcdiff/core/spec.md "Address cache").
--
-- Both caches are updated after the address is decoded, regardless of
-- the mode it came through — the round-robin near write and the
-- modulo-slotted same write that keep decoder and encoder in step.
--
-- The upstream half of a two-stage pipeline: the absolute @U@ offset
-- decoded here is what 'Slap.VCDIFF.Apply.resolveCopyAddress' later
-- resolves into a physical read against the source file or the output
-- buffer.
decodeCopyAddress
  :: AddressCache -> Int -> Word8 -> ByteString -> Int
  -> Either AddressDecodeFailure CopyAddressReading
decodeCopyAddress cache here mode addrSection cursor =
  case classifyAddressMode mode of
    Nothing -> Left (UnknownAddressMode mode)
    Just SelfAddress -> fromVarint id
    Just HereAddress -> fromVarint (\delta -> here - delta)
    Just (NearAddress nearSlot) ->
      fromVarint (\delta -> readNearSlot nearSlot (nearAddresses cache) + delta)
    Just (SameAddress sameBlock) -> fromSameByte sameBlock
  where
    fromVarint computeAddress =
      case getVcdiffVarint cursor addrSection of
        Left _ -> Left AddressSectionExhausted
        Right (VarintResult value consumed) ->
          Right (readingOf (computeAddress (fromIntegral value)) (cursor + consumed))

    fromSameByte sameBlock
      | cursor >= ByteString.length addrSection = Left AddressSectionExhausted
      | otherwise =
          let slotByte = fromIntegral (ByteString.index addrSection cursor)
          in Right (readingOf (readSameSlot sameBlock slotByte (sameAddresses cache))
                              (cursor + 1))

    readingOf address cursorAfter = CopyAddressReading
      { copyAddressDecoded     = address
      , copyAddressCacheAfter  = recordAddress cache address
      , copyAddressCursorAfter = cursorAfter
      }

-- | Write a freshly-decoded address into both caches: the next near
-- slot (advancing round-robin) and the same slot at
-- @address mod 'sameSlotCount'@.
recordAddress :: AddressCache -> Int -> AddressCache
recordAddress cache address = cache
  { nearAddresses = writeNearSlot (nearWriteSlot cache) address (nearAddresses cache)
  , nearWriteSlot = nextNearSlot (nearWriteSlot cache)
  , sameAddresses = IntMap.insert (address `mod` sameSlotCount) address (sameAddresses cache)
  }
