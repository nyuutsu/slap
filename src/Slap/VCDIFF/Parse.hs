-- | Read a VCDIFF patch into the 'Slap.VCDIFF.Types' vocabulary, source-free.
-- Reads the core (default table, framing, instructions), the xdelta3 arc (checksums and secondary compression), and the RFC arc (VCD_TARGET windows and custom code tables).
-- Each feature's read and each decline reason live where it is handled.
--
-- Parsing is two passes with one clean seam.
-- 'parseRawPatch' is the byte-level walk: it reads the header and frames each window, surfacing only truncation ('ParseError').
-- 'classifyAndDecode' is the semantic pass, in three stages:
--
--   * vet each window's framing ('vetWindowFraming')
--   * resolve secondary compression so each window holds plain sections ('resolveSecondaryCompression')
--   * decode each window's instruction stream ('decodeWindow'), enforcing the three core invariants (docs/vcdiff/core/spec.md "Core invariants")
--
-- and name the flavor.
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
  , AddressCacheConfig(..)
  , defaultAddressCacheConfig
  , firstSameMode
  , freshAddressCache
  , decodeCopyAddress
  , CopyAddressReading(..)
  , AddressDecodeFailure(..)
  ) where

import Slap.VCDIFF.Types
  ( VCDIFFPatch(..), Window(..), VCDIFFInstruction(..)
  , XDelta3Header(..), XDelta3Window(..), RFCHeader(..), CustomCodeTable(..)
  , SourceSegment(..), SegmentOrigin(..), vcdiffMagicBytes )
-- Qualified: 'InstructionTemplate' shares the constructor names Add /
-- Run / Copy with 'VCDIFFInstruction'. The template (code-table) side
-- is qualified; the decoded-instruction side stays unqualified, so the
-- two are visibly distinct at every use.
import qualified Slap.VCDIFF.CodeTable as Table
import Slap.VCDIFF.SecondaryCompression
  ( XDelta3SecondaryCompressor(..), secondaryCompressorCatalog
  , SectionCarriage(..), decodeLZMACompressedKind, decodeDJWCompressedKind
  , decodeFGKCompressedKind )
import Slap.VCDIFF.AddressCache
  ( AddressCache(..), AddressCacheConfig(..), NearSlotCount(..), SameBlockCount(..)
  , defaultAddressCacheConfig
  , freshAddressCache, classifyAddressMode, firstSameMode, modeCeiling
  , decodeCopyAddress, CopyAddressReading(..), AddressDecodeFailure(..) )
import Slap.Binary (getVcdiffVarint, VarintResult(..), viewBytesInRange)
import Slap.ByteParser
  ( ByteParser, runByteParser, getByte, getBytes, skip, lookAhead
  , vcdiffVarint, word32BE, remaining, atEnd )
import Slap.Checksum (Adler32(..))
import Slap.Status
  ( SlapError(..), SlapAdvisory(..), Parsed(..)
  , VCDIFFRFCFeature(..), VCDIFFXDelta3Feature(..), VCDIFFMalformation(..)
  , VCDIFFShapeViolation(..), VCDIFFCodeTableMalformation(..)
  , VCDIFFIndicatorKind(..), VCDIFFSection(..) )
import Slap.FormatLabel (FormatLabel(..))
import Slap.VCDIFF.Apply (applyVCDIFF)
import Slap.FileContents (PatchFileContents(..), InputFileContents(..), OutputFileContents(..))
import Slap.Measure
  ( Offset(..), Length(..), FileSize(..)
  , ActualOffset(..), MaxOffset(..), ExpectedSize(..), ActualSize(..)
  , ActionIndex, firstAction, nextAction, actionAtPosition
  , Cursor(..), fitsWithin, remainingFromOffset, lengthToFileSize
  , lengthToOffset
  , subtractLength
  , RequiredLength(..), ActualLength(..), ActualMagic(..)
  , FoundVersion(..), byteLength, byteFileSize )

import Control.Monad (when, unless)
import Control.Monad.Trans.Class (lift)
import Control.Monad.Trans.State.Strict (StateT, evalStateT, gets, modify)
import Data.Bits (testBit, (.&.))
import Data.Foldable (traverse_)
import Data.List (zipWith4)
import Data.Maybe (isJust, isNothing, listToMaybe)
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.Vector (Vector)
import qualified Data.Vector as Vector
import Data.Word (Word8)

----------------------------------------------------------------------------
-- Entry point
----------------------------------------------------------------------------

-- | Whether a patch being parsed may carry a custom code table. The
-- top-level parse permits it ('CustomTablesAllowed'); the inner delta a
-- custom table is built from is parsed with it forbidden
-- ('CustomTablesForbidden'), because RFC 3284 §7c requires that delta to
-- use the default table — a nested table would recurse with no base
-- case. The forbidden case is the one door to 'VCDIFFNestedCustomCodeTable'.
data CustomTablePolicy
  = CustomTablesAllowed
  | CustomTablesForbidden
  deriving (Eq, Show)

parseVCDIFF :: PatchFileContents -> Either SlapError (Parsed VCDIFFPatch)
parseVCDIFF = parseVCDIFFWith CustomTablesAllowed

-- | Parse a VCDIFF patch under a given custom-table policy. The public
-- 'parseVCDIFF' fixes 'CustomTablesAllowed'; 'buildCustomTable' reuses
-- this with 'CustomTablesForbidden' to decode a custom table's inner
-- delta, which is itself a self-contained VCDIFF patch.
parseVCDIFFWith :: CustomTablePolicy -> PatchFileContents -> Either SlapError (Parsed VCDIFFPatch)
parseVCDIFFWith tablePolicy (PatchFileContents input)
  | ByteString.length input < magicLength =
      Left (InputTooShort LabelVCDIFF
              (RequiredLength (Length magicLength))
              (ActualLength (byteLength input)))
  | ByteString.take magicLength input /= vcdiffMagicBytes =
      Left (BadMagic LabelVCDIFF (ActualMagic (ByteString.take magicLength input)))
  | otherwise =
      case runByteParser parseRawPatch (ByteString.drop magicLength input) of
        Left parserError -> Left (ParseError LabelVCDIFF parserError)
        Right rawPatch   -> do
          (patch, tableNotes) <- classifyAndDecode tablePolicy rawPatch
          pure (Parsed patch (parseNotes rawPatch ++ tableNotes))
  where
    magicLength = ByteString.length vcdiffMagicBytes

-- | The note-severity advisories a successfully-parsed patch carries:
-- the framer's trailing remnant, and any VCD_TARGET window that reaches
-- nothing. Both are pure readings of the framed patch, attached only on
-- a parse that succeeds.
parseNotes :: RawPatch -> [SlapAdvisory]
parseNotes rawPatch =
  trailingRemnantNotes rawPatch ++ emptyTargetSegmentNotes rawPatch

-- | The advisory the framer's trailing-remnant recognition surfaces,
-- when it consumed one (see 'isTrailingRemnant'). The remnant is the
-- whole of what the patch says about itself here — its bytes are not
-- patch semantics and go no further than this note.
trailingRemnantNotes :: RawPatch -> [SlapAdvisory]
trailingRemnantNotes rawPatch = case rawTrailingRemnant rawPatch of
  Nothing            -> []
  Just remnantLength -> [VCDIFFTrailingRemnant remnantLength]

-- | A note for each VCD_TARGET window whose declared source segment is
-- empty: it draws nothing from the produced target, the only legal
-- shape a first-window VCD_TARGET can take and a pointless one
-- anywhere. The window's position in the stream rides in the note.
emptyTargetSegmentNotes :: RawPatch -> [SlapAdvisory]
emptyTargetSegmentNotes rawPatch =
  [ VCDIFFEmptyTargetWindowSegment (actionAtPosition windowPosition)
  | (windowPosition, rawWindow) <- zip [0 ..] (rawWindows rawPatch)
  , declaresEmptyTargetSegment rawWindow
  ]
  where
    declaresEmptyTargetSegment rawWindow =
      testBit (rawWindowIndicator rawWindow) vcdTargetBit
        && maybe False ((== Length 0) . rawSegmentLength) (rawSourceSegment rawWindow)

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
  , rawCodeTableData   :: !(Maybe ByteString)
    -- ^ The custom code table's data section, as read: the two
    -- cache-size bytes followed by the inner delta, carried verbatim
    -- when VCD_CODETABLE was set. 'classifyAndDecode' hands it to
    -- 'buildCustomTable', which peels the cache sizes and decodes the
    -- inner delta; 'Nothing' means the default table is in force.
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
-- the optional header fields in wire order — the secondary-compressor
-- id, the custom-code-table data, the application header — and frames
-- the windows. It does this only when the header is built from bits
-- slap recognizes; a header carrying a reserved bit has a byte-shape
-- the framer cannot trust, so it leaves the window list empty and lets
-- 'classifyAndDecode' decline on the header before it would read
-- windows it could not have framed.
parseRawPatch :: ByteParser RawPatch
parseRawPatch = do
  version          <- getByte
  headerIndicator  <- getByte
  if version == 0 && headerUsesOnlyRecognizedBits headerIndicator
    then do
      compressorId  <- if testBit headerIndicator vcdDecompressBit
                         then Just <$> getByte
                         else pure Nothing
      codeTableData <- if testBit headerIndicator vcdCodeTableBit
                         then Just <$> parseCodeTableData
                         else pure Nothing
      appHeader     <- if testBit headerIndicator vcdAppHeaderBit
                         then Just <$> parseApplicationHeader
                         else pure Nothing
      (windows, trailingRemnant) <- parseRawWindows
      pure (RawPatch version headerIndicator compressorId codeTableData
                     appHeader windows trailingRemnant)
    else pure (RawPatch version headerIndicator Nothing Nothing Nothing [] Nothing)

-- | Whether the header indicator is built only from bits slap
-- recognizes — the three RFC-and-xdelta3 bits VCD_DECOMPRESS,
-- VCD_CODETABLE, and VCD_APPHEADER (bits 0–2), which are exactly the
-- complement of 'reservedIndicatorMask'. A set reserved bit (3–7)
-- names a feature from beyond what slap reads, belonging to neither
-- dialect; the framer cannot trust the byte-shape that follows such a
-- header, so it declines to frame and 'classifyAndDecode' surfaces the
-- honest 'VCDIFFReservedIndicatorBits' reason rather than failing as
-- framing garbage.
headerUsesOnlyRecognizedBits :: Word8 -> Bool
headerUsesOnlyRecognizedBits headerIndicator =
  headerIndicator .&. reservedIndicatorMask == 0

-- | The custom-code-table data's wire shape: a varint length, then that
-- many bytes (docs/vcdiff/rfc-vcdiff/spec.md "Custom code tables").
-- The bytes are carried verbatim — the cache-size header and the inner
-- delta within them are peeled by 'buildCustomTable', not here. On the
-- wire this field follows the compressor-id byte (RFC 3284 §4.1's
-- header order) and precedes the application header.
parseCodeTableData :: ByteParser ByteString
parseCodeTableData = do
  declaredLength <- vcdiffVarint
  getBytes (Length (fromIntegral declaredLength))

-- | The application header's wire shape: a varint length, then that
-- many opaque bytes (docs/vcdiff/xdelta3/spec.md "Application
-- header"). On the wire the field follows the compressor-id byte and
-- the code-table data (both read above when declared), so here it
-- follows whichever of those preceded it.
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
-- included) to end of input. Some patches carry this harmless
-- trailer, and slap lets it through rather than blocking them
-- (docs/vcdiff/questions.md, "How does a decoder know the patch is
-- over"). Any other trailing bytes keep framing as a window and
-- failing as one.
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
-- settle the code table the windows decode against, vet every window's
-- framing, resolve secondary compression so each window holds plain
-- sections, decode each window, then name the flavor. Returns the
-- decoded patch alongside any advisories the table-build raised (a
-- custom table's do-nothing entries).
--
-- Vetting runs before resolution on purpose: a window whose delta
-- indicator carries reserved bits is declined before its compression
-- bits are believed, because slap cannot claim to interpret three
-- bits of a byte it does not understand the rest of.
classifyAndDecode :: CustomTablePolicy -> RawPatch -> Either SlapError (VCDIFFPatch, [SlapAdvisory])
classifyAndDecode tablePolicy rawPatch
  | rawVersion rawPatch /= 0 =
      Left (BadVersion LabelVCDIFF (FoundVersion (rawVersion rawPatch)))
  | headerIndicator .&. reservedIndicatorMask /= 0 =
      Left (VCDIFFReservedIndicatorBits HeaderIndicator headerIndicator)
  | otherwise = do
      resolvedTable <- resolveActiveTable tablePolicy headerIndicator (rawCodeTableData rawPatch)
      declaredCompressor <- lookupDeclaredCompressor (rawCompressorId rawPatch)
      traverse_ vetWindowFraming (rawWindows rawPatch)
      resolvedWindows <- resolveSecondaryCompression declaredCompressor (rawWindows rawPatch)
      decodedWindows  <- traverse (decodeWindow (resolvedActiveTable resolvedTable)) resolvedWindows
      patch <- classifyFlavor (resolvedCustomTable resolvedTable) declaredCompressor
                 (rawAppHeader rawPatch) (Vector.fromList decodedWindows)
      pure (patch, resolvedTableNotes resolvedTable)
  where
    headerIndicator = rawHeaderIndicator rawPatch

-- | The code table a patch's windows decode against, plus how the
-- decode names it. 'resolvedActiveTable' is the table-and-cache-config
-- the instruction walk uses; 'resolvedCustomTable' is 'Just' only for a
-- patch that supplied its own table, with the cache geometry that table
-- declared (the classifier's RFC-exclusive signal, and what 'RFCHeader'
-- records); 'resolvedTableNotes' carries
-- any advisory building the table raised.
data ResolvedTable = ResolvedTable
  { resolvedActiveTable :: !ActiveTable
  , resolvedCustomTable :: !(Maybe CustomCodeTable)
  , resolvedTableNotes  :: ![SlapAdvisory]
  }

-- | The code table and address-cache configuration a window's
-- instruction walk decodes against — the default pair for an ordinary
-- patch, the built pair for one carrying a custom table. Bundled so the
-- two travel together and a window can never be decoded against one
-- patch's table and another's cache sizes.
data ActiveTable = ActiveTable
  { activeCodeTable   :: !Table.CodeTable
  , activeCacheConfig :: !AddressCacheConfig
  }

-- | The core's pairing: the RFC §5.6 default table with the default
-- four-near / three-same cache configuration. In force for every patch
-- that supplies no custom table.
defaultActiveTable :: ActiveTable
defaultActiveTable = ActiveTable Table.defaultCodeTable defaultAddressCacheConfig

-- | Settle which table the windows decode against. With VCD_CODETABLE
-- unset, the default pair. With it set, build the custom table from the
-- header's data section — unless custom tables are forbidden here (the
-- inner delta of a table being built), where the bit is the no-nesting
-- refusal pointing at the table declaration, not the inner body.
resolveActiveTable
  :: CustomTablePolicy -> Word8 -> Maybe ByteString -> Either SlapError ResolvedTable
resolveActiveTable tablePolicy headerIndicator maybeTableData
  | testBit headerIndicator vcdCodeTableBit =
      case tablePolicy of
        CustomTablesForbidden ->
          Left (UnsupportedVCDIFFShape VCDIFFNestedCustomCodeTable)
        CustomTablesAllowed -> buildCustomTable maybeTableData
  | otherwise =
      Right ResolvedTable
        { resolvedActiveTable = defaultActiveTable
        , resolvedCustomTable = Nothing
        , resolvedTableNotes  = []
        }

-- | Build a patch's custom code table from its data section (RFC 3284
-- §7): peel the two cache-size bytes, decode the inner delta — itself a
-- self-contained VCDIFF patch — against the serialized default table,
-- read the 1536-byte result back into a table, and check the one thing
-- the image alone could not (a COPY mode the declared caches do not
-- reach). Yields the 'ResolvedTable' the windows decode against — the
-- built table paired with its cache config, the same table as the
-- classifier's RFC signal, and any do-nothing-entry advisory. Everything
-- from the inner decode onward — the inner-delta parse and apply, the
-- read-back, the mode check — is wrapped with the custom-code-table
-- context so its precision survives; only the cache-size peel, which
-- fails before any of that, keeps its own bare error.
buildCustomTable :: Maybe ByteString -> Either SlapError ResolvedTable
buildCustomTable maybeTableData = do
  (config, innerDelta) <- peelCodeTableHeader maybeTableData
  image <- decodeInnerTableImage innerDelta
  table <- wrapTableDecode (Table.deserializeCodeTable image)
  wrapTableDecode (checkCustomTableCopyModes config table)
  Right ResolvedTable
    { resolvedActiveTable = ActiveTable table config
    , resolvedCustomTable = Just (CustomCodeTable table config)
    , resolvedTableNotes  = noopNoopAdvisories table
    }
  where
    wrapTableDecode = either (Left . VCDIFFCustomCodeTableDecodeFailed) Right

-- | Peel the two cache-size bytes (@s_near@, @s_same@) off the front of
-- the code-table data, leaving the inner delta. The data must hold at
-- least those two bytes (RFC 3284 §7); fewer cannot name a cache
-- configuration at all, so it is 'VCDIFFCodeTableHeaderTooShort'.
peelCodeTableHeader
  :: Maybe ByteString -> Either SlapError (AddressCacheConfig, ByteString)
peelCodeTableHeader (Just tableData)
  | ByteString.length tableData >= 2 =
      Right ( AddressCacheConfig
                (NearSlotCount  (fromIntegral (ByteString.index tableData 0)))
                (SameBlockCount (fromIntegral (ByteString.index tableData 1)))
            , ByteString.drop 2 tableData )
peelCodeTableHeader _ =
  Left (MalformedVCDIFFCodeTable VCDIFFCodeTableHeaderTooShort)

-- | Decode a custom table's inner delta against the serialized default
-- table, yielding the raw image 'Table.deserializeCodeTable' reads
-- back. The inner delta is a self-contained VCDIFF patch (RFC 3284 §7),
-- so this reuses slap's own parse and apply rather than a second
-- decoder — parsed with custom tables forbidden, so a nested table
-- surfaces as its own 'VCDIFFNestedCustomCodeTable' (pointing at the
-- header), while every other inner parse or apply failure is wrapped
-- with the custom-code-table context.
decodeInnerTableImage :: ByteString -> Either SlapError ByteString
decodeInnerTableImage innerDelta =
  case parseVCDIFFWith CustomTablesForbidden (PatchFileContents innerDelta) of
    Left nested@(UnsupportedVCDIFFShape VCDIFFNestedCustomCodeTable) -> Left nested
    Left innerError -> Left (VCDIFFCustomCodeTableDecodeFailed innerError)
    Right (Parsed innerPatch _innerNotes) ->
      case applyVCDIFF innerPatch (InputFileContents defaultTableImage) of
        Left innerError                  -> Left (VCDIFFCustomCodeTableDecodeFailed innerError)
        Right (OutputFileContents image) -> Right image
  where
    defaultTableImage = Table.serializeCodeTable Table.defaultCodeTable

-- | Reject any COPY template in the built table whose address mode the
-- declared caches do not reach — the cache-dependent check
-- 'Table.deserializeCodeTable' deliberately defers (it carries the mode
-- verbatim). The admissible band is exactly the one
-- 'classifyAddressMode' uses at decode, consulted here so the eager
-- check and the decode-time check cannot drift
-- (docs/vcdiff/rfc-vcdiff/questions.md, "invalid decoded-table entries").
checkCustomTableCopyModes
  :: AddressCacheConfig -> Table.CodeTable -> Either SlapError ()
checkCustomTableCopyModes config table =
  traverse_ checkTemplate
    (concatMap bothTemplates (Vector.toList (Table.codeTableEntries table)))
  where
    bothTemplates entry = [Table.firstTemplate entry, Table.secondTemplate entry]
    checkTemplate (Table.Copy _ (Table.CopyAddressMode mode))
      | isNothing (classifyAddressMode config mode) =
          Left (MalformedVCDIFFCodeTable
                  (VCDIFFCodeTableCopyModeOutOfRange mode (highestValidAddressMode config)))
    checkTemplate _ = Right ()

-- | The highest COPY address mode the caches reach: one below the layout's
-- mode ceiling. Reads that one boundary from 'modeCeiling' rather than
-- re-deriving the band arithmetic 'classifyAddressMode' steers by.
highestValidAddressMode :: AddressCacheConfig -> Int
highestValidAddressMode config = modeCeiling config - 1

-- | A presence advisory if the built table holds any do-nothing
-- (NOOP-then-NOOP) entry, or none. Legal but remarkable — the default
-- table has no such entry, so one means the table was deliberately
-- shaped to carry it (docs/vcdiff/rfc-vcdiff/questions.md, "invalid
-- decoded-table entries").
noopNoopAdvisories :: Table.CodeTable -> [SlapAdvisory]
noopNoopAdvisories table =
  [ VCDIFFCustomTableNoopNoopEntries doNothingCount | doNothingCount > 0 ]
  where
    doNothingCount =
      length [ () | entry <- Vector.toList (Table.codeTableEntries table)
                  , Table.firstTemplate  entry == Table.Noop
                  , Table.secondTemplate entry == Table.Noop ]

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

-- | Name the decoded patch for what it is, from two independent
-- readings of its windows: whether it carries an xdelta3 extension, and
-- whether it carries an RFC-exclusive feature. The four combinations
-- are exhaustive and each has one honest answer:
--
--   * an xdelta3 extension, no RFC-exclusive feature → 'PatchXDelta3'.
--     A declared secondary compressor (an xdelta3 signal even when no
--     window exercises it, because xdelta3's catalog is the only
--     registry of compressor ids there is), an application header, or
--     any window's Adler32 is enough.
--   * an RFC-exclusive feature, no xdelta3 extension → 'PatchRFC',
--     carrying the custom code table when there was one ('Nothing' for a
--     VCD_TARGET-only patch). Either a produced-target window or a custom
--     code table is that signal.
--   * neither → 'PatchCoreOnly', decoding identically under either
--     flavor (docs/vcdiff/xdelta3/spec.md "Classification").
--   * both → refused. The patch is neither dialect — RFC 3284 defines
--     no xdelta3 extension and xdelta3 refuses both RFC-exclusive
--     features — so slap, which reads only those two dialects, declines,
--     naming the RFC feature and the xdelta3 extension it found. The
--     Adler32 reaches this verdict read and used, never dropped: the
--     type forbids carrying it into a 'PatchRFC' at all.
--
-- The mixed case is an explicit 'Left' with no wildcard; both halves of
-- the two RFC-exclusive features are accounted for, so the compiler
-- points here if a third signal is ever added.
classifyFlavor
  :: Maybe CustomCodeTable -> Maybe XDelta3SecondaryCompressor -> Maybe ByteString
  -> Vector DecodedWindow -> Either SlapError VCDIFFPatch
classifyFlavor maybeCustomTable declaredCompressor maybeAppHeader decodedWindows =
  case (carriesXDelta3Extension, carriesRFCExclusiveFeature) of
    (True,  True)  -> Left (VCDIFFRFCFeatureWithXDelta3Feature presentRFCFeature presentXDelta3Feature)
    (True,  False) -> Right (PatchXDelta3 (XDelta3Header maybeAppHeader declaredCompressor)
                                          (fmap toXDelta3Window decodedWindows))
    (False, True)  -> Right (PatchRFC (RFCHeader maybeCustomTable) (fmap decodedWindowBody decodedWindows))
    (False, False) -> Right (PatchCoreOnly (fmap decodedWindowBody decodedWindows))
  where
    carriesXDelta3Extension =
      isJust declaredCompressor
        || isJust maybeAppHeader
        || Vector.any (isJust . decodedWindowChecksum) decodedWindows

    carriesRFCExclusiveFeature = isJust maybeCustomTable || hasTargetWindow
    hasTargetWindow = Vector.any windowDrawsOnProducedTarget decodedWindows
    windowDrawsOnProducedTarget decodedWindow =
      case windowSourceSegment (decodedWindowBody decodedWindow) of
        Just segment -> sourceSegmentOrigin segment == FromProducedTarget
        Nothing      -> False

    -- Which RFC feature to name in the refusal; reached only when
    -- 'carriesRFCExclusiveFeature' holds, so the final arm means the
    -- custom code table is what made it true.
    presentRFCFeature
      | hasTargetWindow = RFCFeatureTargetWindow
      | otherwise       = RFCFeatureCustomCodeTable

    -- Which extension to name in the refusal, in detection priority;
    -- reached only when 'carriesXDelta3Extension' holds, so the final
    -- arm means a window checksum is what made it true.
    presentXDelta3Feature
      | isJust declaredCompressor = XDelta3FeatureSecondaryCompressor
      | isJust maybeAppHeader     = XDelta3FeatureApplicationHeader
      | otherwise                 = XDelta3FeatureWindowChecksum

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
  | rawDeltaIndicator rawWindow .&. reservedIndicatorMask /= 0 =
      Left (VCDIFFReservedIndicatorBits DeltaIndicator (rawDeltaIndicator rawWindow))
  | rawDeclaredEncodingLength rawWindow /= rawMeasuredEncodingLength rawWindow =
      Left (MalformedVCDIFF (VCDIFFDeltaEncodingLengthMismatch
              (ExpectedSize (lengthToFileSize (rawDeclaredEncodingLength rawWindow)))
              (ActualSize   (lengthToFileSize (rawMeasuredEncodingLength rawWindow)))))
  | otherwise = Right ()
  where
    windowIndicator = rawWindowIndicator rawWindow

-- | Decode one resolved window's instruction stream against the active
-- code table — the default pair for an ordinary patch, the built pair
-- for one carrying a custom table. The 'ResolvedWindow' proof is what
-- lets the body read the sections as plain bytes without checking — the
-- instruction decode never learns that compression existed.
decodeWindow :: ActiveTable -> ResolvedWindow -> Either SlapError DecodedWindow
decodeWindow activeTable (ResolvedWindow rawWindow) = do
  let -- The window's two copy-source bits are mutually exclusive
      -- ('vetWindowFraming' rejects both at once), so the VCD_TARGET bit
      -- alone decides which side a present segment is cut from.
      segmentOrigin
        | testBit (rawWindowIndicator rawWindow) vcdTargetBit = FromProducedTarget
        | otherwise                                           = FromSourceFile
      sourceSegment =
        (\segment -> SourceSegment
                       segmentOrigin
                       (rawSegmentPosition segment)
                       (rawSegmentLength segment))
        <$> rawSourceSegment rawWindow
      segmentLength = maybe mempty rawSegmentLength (rawSourceSegment rawWindow)
  instructions <- decodeWindowInstructions
                    activeTable
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
-- refuse. The dispositions, decided by the declared compressor:
--
--   * No compressor declared: any compression-flagged section is a
--     wire self-contradiction ('VCDIFFCompressedSectionWithoutCompressor').
--   * A compressor declared: each kind runs through that compressor's
--     decode path — per-section for DJW and FGK, gathered for LZMA —
--     and every window comes out holding plain sections. A compressor
--     declared but exercised by no window passes every section through
--     untouched and arrives at the same place, which is the valid
--     declared-but-unused case (docs/vcdiff/xdelta3/secondary-
--     compression.md "Catalog").
--
-- The arms stay explicit rather than factored through a shared projection:
-- the dispositions above appear one-to-one in the code, and a new catalog entry fires '-Wincomplete-patterns' here, at the decision point.
-- The catalog refuses nothing here: all three compressors are decode paths.
resolveSecondaryCompression
  :: Maybe XDelta3SecondaryCompressor -> [RawWindow]
  -> Either SlapError [ResolvedWindow]
resolveSecondaryCompression declaredCompressor rawWindows =
  map ResolvedWindow <$> case declaredCompressor of
    Nothing -> case listToMaybe (concatMap compressedKindsOf rawWindows) of
      Just orphanedKind ->
        Left (MalformedVCDIFF (VCDIFFCompressedSectionWithoutCompressor orphanedKind))
      Nothing -> Right rawWindows
    Just SecondaryDJW  -> decompressSectionsThrough decodeDJWCompressedKind rawWindows
    Just SecondaryFGK  -> decompressSectionsThrough decodeFGKCompressedKind rawWindows
    Just SecondaryLZMA -> decompressSectionsThrough decodeLZMACompressedKind rawWindows

-- | The section kinds a window's Delta_Indicator flags as
-- compressed, in kind order.
compressedKindsOf :: RawWindow -> [VCDIFFSection]
compressedKindsOf rawWindow =
  [ kind
  | (compressionBit, kind) <- sectionCompressionBits
  , testBit (rawDeltaIndicator rawWindow) compressionBit
  ]

-- | Run each of the three kinds through a compressor's kind-decode
-- path and hand every window back with plain sections. Each kind is
-- decoded independently of the others; a kind no window compresses
-- passes through untouched. The argument is the per-compressor
-- machine — 'decodeLZMACompressedKind' gathers a kind's continuous
-- stream, 'decodeDJWCompressedKind' decodes each section on its own —
-- and this walker owns only what the compressors share: pairing each
-- window's Delta_Indicator bit with its section bytes on the way in,
-- and reassembling windows on the way out.
decompressSectionsThrough
  :: (VCDIFFSection -> [SectionCarriage] -> Either SlapError [ByteString])
  -> [RawWindow] -> Either SlapError [RawWindow]
decompressSectionsThrough decodeCompressedKind rawWindows = do
  plainDataSections <- decodeOneKind VCDIFFDataSection        vcdDataCompBit rawDataSection
  plainInstSections <- decodeOneKind VCDIFFInstructionSection vcdInstCompBit rawInstSection
  plainAddrSections <- decodeOneKind VCDIFFAddressSection     vcdAddrCompBit rawAddrSection
  pure (zipWith4 windowWithPlainSections
          rawWindows plainDataSections plainInstSections plainAddrSections)
  where
    decodeOneKind :: VCDIFFSection -> Int -> (RawWindow -> ByteString)
                  -> Either SlapError [ByteString]
    decodeOneKind kind compressionBit sectionOf =
      decodeCompressedKind kind
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
  { addrCursor   = AddressSectionCursor (copyAddressCursorAfter reading)
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
  :: ActiveTable  -- ^ the active code table and cache configuration
  -> Length       -- ^ source-segment length, @len(S)@
  -> FileSize     -- ^ declared target-window size
  -> ByteString   -- ^ data section
  -> ByteString   -- ^ instruction section
  -> ByteString   -- ^ address section
  -> Either SlapError (Vector VCDIFFInstruction)
decodeWindowInstructions activeTable segmentLength targetWindowSize dataSection instSection addrSection =
  evalStateT walkInstructionSection initialState
  where
    initialState = DecodeState
      { instCursor       = InstructionSectionCursor (Offset 0)
      , dataCursor       = DataSectionCursor (Offset 0)
      , addrCursor       = AddressSectionCursor (Offset 0)
      , addressCache     = freshAddressCache (activeCacheConfig activeTable)
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

    -- | @len(S)@ as the position where the source segment ends in the
    -- superstring @U = S + T@: a COPY address below it reads the segment,
    -- at or above it reads the produced target.
    segmentEnd :: Offset
    segmentEnd = lengthToOffset segmentLength

    -- | The current write position in the superstring @U = S + T@:
    -- @len(S)@ plus the target bytes produced so far.
    superstringWriteHead :: DecodeState -> Offset
    superstringWriteHead decodeState =
      lengthToOffset (segmentLength <> producedBytes decodeState)

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
      let entry = Table.codeTableEntry (activeCodeTable activeTable) codeByte
      applyTemplate (Table.firstTemplate entry)
      applyTemplate (Table.secondTemplate entry)

    -- | The next byte of the instruction section. Total:
    -- 'walkInstructionSection' only descends here when the cursor is
    -- strictly inside the section.
    nextInstructionByte :: WindowDecode Table.Opcode
    nextInstructionByte = do
      InstructionSectionCursor (Offset codeBytePosition) <- gets instCursor
      modify (advanceInstCursor (Length 1))
      pure (Table.Opcode (ByteString.index instSection codeBytePosition))

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
          copyEnd = advance address size
      when (address < Offset 0 || address >= here) $
        failDecode (VCDIFFCopyAddressOutOfRange thisInstruction
                      (ActualOffset address)
                      (MaxOffset here))
      when (address < segmentEnd && copyEnd > segmentEnd) $
        failDecode (VCDIFFCopyCrossesSourceSegmentEnd thisInstruction)
      modify (adoptCopyAddressReading reading)
      modify (emitInstruction (Copy size address) size)

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
    readCopyAddress :: Offset -> Word8 -> WindowDecode CopyAddressReading
    readCopyAddress here mode = do
      AddressSectionCursor cursor <- gets addrCursor
      cache <- gets addressCache
      case decodeCopyAddress cache here mode addrSection cursor of
        Left AddressSectionExhausted ->
          sectionExhausted VCDIFFAddressSection
        Left (UnknownAddressMode modeByte) ->
          failDecode (VCDIFFInvalidCopyAddressMode modeByte)
        Right reading -> pure reading

