-- | Read a VCDIFF patch into the 'Slap.VCDIFF.Types' vocabulary,
-- source-free. Scoped to the CoreOnly subset: the default code table,
-- no custom table, no application header, no per-window Adler32, no
-- secondary compression. A patch that reaches past the core is
-- classified and declined cleanly — a deferred feature as
-- 'VCDIFFFeatureNotYetSupported', a reserved indicator bit as
-- 'VCDIFFReservedIndicatorBits' — never mishandled.
--
-- Parsing is two passes with one clean seam. 'parseRawPatch' is the
-- byte-level walk: it reads the header and frames each window into its
-- indicator bytes, source segment, sizes, and three raw section
-- slices, surfacing only truncation ('ParseError'). 'classifyAndDecode'
-- is the semantic pass: it reads the indicator bits to decide flavor,
-- refuses anything past the core, and decodes each core window's
-- instruction stream — enforcing the three core invariants
-- (docs/vcdiff/core/spec.md "Core invariants") so a patch this module
-- returns has them guaranteed.
--
-- The address cache lives here, as decode mechanism: it is reset per
-- window, updated after every COPY, and gone once the window's
-- absolute offsets are in hand. 'decodeCopyAddress' — the cache decode
-- — is exported so a property test can exercise its round-robin and
-- mod-256 updates in isolation; it is the most error-prone piece.
module Slap.VCDIFF.Parse
  ( parseVCDIFF
    -- * Address cache (exported for testing)
  , AddressCache(..)
  , freshAddressCache
  , decodeCopyAddress
  , CopyAddressReading(..)
  , AddressDecodeFailure(..)
  , nearCacheSize
  , sameCacheSize
  ) where

import Slap.VCDIFF.Types
  ( VCDIFFPatch(..), Window(..), VCDIFFInstruction(..)
  , SourceSegment(..), SegmentOrigin(..), vcdiffMagicBytes )
-- Qualified: 'InstructionTemplate' shares the constructor names Add /
-- Run / Copy with 'VCDIFFInstruction'. The template (code-table) side
-- is qualified; the decoded-instruction side stays unqualified, so the
-- two are visibly distinct at every use.
import qualified Slap.VCDIFF.CodeTable as Table
import Slap.Binary (getVcdiffVarint, VarintResult(..), viewBytesInRange)
import Slap.ByteParser
  ( ByteParser, runByteParser, getByte, getBytes, vcdiffVarint, atEnd )
import Slap.Status
  ( SlapError(..), Parsed(..)
  , VCDIFFUnsupportedFeature(..), VCDIFFMalformation(..)
  , VCDIFFIndicatorKind(..), VCDIFFSection(..) )
import Slap.FormatLabel (FormatLabel(..))
import Slap.FileContents (PatchFileContents(..))
import Slap.Measure
  ( Offset(..), Length(..), FileSize(..)
  , ActualOffset(..), MaxOffset(..), ExpectedSize(..), ActualSize(..)
  , ActionIndex, firstAction, nextAction
  , Cursor(..), fitsWithin, remainingFromOffset, lengthToFileSize
  , RequiredLength(..), ActualLength(..), ActualMagic(..)
  , FoundVersion(..), byteLength, byteFileSize )

import Control.Monad (when, unless)
import Control.Monad.Trans.Class (lift)
import Control.Monad.Trans.State.Strict (StateT, evalStateT, gets, modify)
import Data.Bits (testBit, (.&.))
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
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
        Right rawPatch   -> (\patch -> Parsed patch []) <$> classifyAndDecode rawPatch
  where
    magicLength = ByteString.length vcdiffMagicBytes

----------------------------------------------------------------------------
-- Byte-level framing
----------------------------------------------------------------------------

-- | The header plus a framed-but-not-yet-interpreted window list. The
-- indicator bytes are carried verbatim so 'classifyAndDecode' can read
-- their bits; the sections are raw slices, decoded only for a window
-- that turns out to be core.
data RawPatch = RawPatch
  { rawVersion        :: !Word8
  , rawHeaderIndicator :: !Word8
  , rawWindows        :: ![RawWindow]
  }

data RawWindow = RawWindow
  { rawWindowIndicator :: !Word8
  , rawSourceSegment   :: !(Maybe RawSegment)
  , rawTargetSize      :: !FileSize
  , rawDeltaIndicator  :: !Word8
  , rawHasAdler        :: !Bool
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
-- frames the windows — but only when the header is core (version and
-- header indicator both zero). A non-core header leaves the window
-- list empty; 'classifyAndDecode' refuses on the header before it
-- would look at windows whose framing it could not trust.
parseRawPatch :: ByteParser RawPatch
parseRawPatch = do
  version          <- getByte
  headerIndicator  <- getByte
  windows <- if version == 0 && headerIndicator == 0
               then parseRawWindows
               else pure []
  pure (RawPatch version headerIndicator windows)

parseRawWindows :: ByteParser [RawWindow]
parseRawWindows = collect []
  where
    collect accumulatedReversed = do
      done <- atEnd
      if done
        then pure (reverse accumulatedReversed)
        else do
          window <- parseRawWindow
          collect (window : accumulatedReversed)

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
  _deltaEncodingLength <- vcdiffVarint
  targetSize           <- vcdiffVarint
  deltaIndicator       <- getByte
  dataLength <- vcdiffVarint
  instLength <- vcdiffVarint
  addrLength <- vcdiffVarint
  let hasAdler = testBit windowIndicator vcdAdler32Bit
  -- The per-window checksum, when present, sits between the section
  -- lengths and the data section; read past it so the section slices
  -- frame correctly even though a checksummed window is refused.
  _adler      <- if hasAdler then Just <$> getBytes vcdiffAdler32Length else pure Nothing
  dataSection <- getBytes (Length (fromIntegral dataLength))
  instSection <- getBytes (Length (fromIntegral instLength))
  addrSection <- getBytes (Length (fromIntegral addrLength))
  pure RawWindow
    { rawWindowIndicator = windowIndicator
    , rawSourceSegment   = sourceSegment
    , rawTargetSize      = FileSize (fromIntegral targetSize)
    , rawDeltaIndicator  = deltaIndicator
    , rawHasAdler        = hasAdler
    , rawDataSection     = dataSection
    , rawInstSection     = instSection
    , rawAddrSection     = addrSection
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

-- | Length of the per-window Adler32 checksum field (xdelta3's
-- VCD_ADLER32), sitting between the section lengths and the data
-- section when Win_Indicator bit 2 is set.
vcdiffAdler32Length :: Length
vcdiffAdler32Length = Length 4

-- | Mask of the bits each indicator byte leaves undefined in the core.
-- A set bit here is reserved for future definition: slap cannot
-- interpret it, so the patch is declined as unreadable
-- ('VCDIFFReservedIndicatorBits'), not called malformed.
reservedIndicatorMask :: Word8
reservedIndicatorMask = 0xF8

----------------------------------------------------------------------------
-- Semantic classification and decode
----------------------------------------------------------------------------

-- | Interpret a framed patch: refuse a non-core version or header,
-- then decode each window. Only 'PatchCoreOnly' is produced here; the
-- per-flavor constructors arrive with their flavors.
classifyAndDecode :: RawPatch -> Either SlapError VCDIFFPatch
classifyAndDecode rawPatch
  | rawVersion rawPatch /= 0 =
      Left (BadVersion LabelVCDIFF (FoundVersion (rawVersion rawPatch)))
  | headerIndicator .&. reservedIndicatorMask /= 0 =
      Left (VCDIFFReservedIndicatorBits HeaderIndicator headerIndicator)
  | testBit headerIndicator vcdDecompressBit =
      Left (VCDIFFFeatureNotYetSupported VCDIFFSecondaryCompressor)
  | testBit headerIndicator vcdCodeTableBit =
      Left (VCDIFFFeatureNotYetSupported VCDIFFCustomCodeTable)
  | testBit headerIndicator vcdAppHeaderBit =
      Left (VCDIFFFeatureNotYetSupported VCDIFFApplicationHeader)
  | otherwise =
      PatchCoreOnly . Vector.fromList <$> traverse classifyWindow (rawWindows rawPatch)
  where
    headerIndicator = rawHeaderIndicator rawPatch

-- | Interpret one framed window, refusing any non-core feature before
-- decoding its instruction stream.
classifyWindow :: RawWindow -> Either SlapError Window
classifyWindow rawWindow
  | windowIndicator .&. reservedIndicatorMask /= 0 =
      Left (VCDIFFReservedIndicatorBits WindowIndicator windowIndicator)
  | testBit windowIndicator vcdSourceBit && testBit windowIndicator vcdTargetBit =
      Left (MalformedVCDIFF VCDIFFBothSourceAndTargetWindowBits)
  | rawHasAdler rawWindow =
      Left (VCDIFFFeatureNotYetSupported VCDIFFPerWindowChecksum)
  | testBit windowIndicator vcdTargetBit =
      Left (VCDIFFFeatureNotYetSupported VCDIFFTargetWindow)
  | rawDeltaIndicator rawWindow .&. reservedIndicatorMask /= 0 =
      Left (VCDIFFReservedIndicatorBits DeltaIndicator (rawDeltaIndicator rawWindow))
  | rawDeltaIndicator rawWindow .&. secondaryCompressionMask /= 0 =
      Left (VCDIFFFeatureNotYetSupported VCDIFFSecondaryCompressedSection)
  | otherwise = do
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
      Right Window
        { windowSourceSegment = sourceSegment
        , windowTargetSize    = rawTargetSize rawWindow
        , windowInstructions  = instructions
        }
  where
    windowIndicator = rawWindowIndicator rawWindow
    -- VCD_DATACOMP | VCD_INSTCOMP | VCD_ADDRCOMP
    secondaryCompressionMask = 0x07

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
      applyTemplate (Table.firstInstruction entry)
      applyTemplate (Table.secondInstruction entry)

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
data AddressCache = AddressCache
  { nearAddresses :: !(Vector Int)
    -- ^ 'nearCacheSize' slots, written round-robin.
  , sameAddresses :: !(Vector Int)
    -- ^ @sameCacheSize * 256@ slots, written at @address mod (sameCacheSize * 256)@.
  , nearWriteSlot :: !Int
    -- ^ The next near slot to overwrite.
  }
  deriving (Eq, Show)

-- | The default-code-table cache configuration: four near slots and
-- three same blocks, giving nine address modes (0–8). A custom code
-- table could change these (RFC-arc); the core uses these.
nearCacheSize, sameCacheSize :: Int
nearCacheSize = 4
sameCacheSize = 3

-- | A zeroed cache, as at the start of each window.
freshAddressCache :: AddressCache
freshAddressCache = AddressCache
  { nearAddresses = Vector.replicate nearCacheSize 0
  , sameAddresses = Vector.replicate (sameCacheSize * 256) 0
  , nearWriteSlot = 0
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

-- | Decode one COPY address from the address section, given the cache,
-- the current @here@ position in the superstring, and the address
-- mode. The mode families (docs/vcdiff/core/spec.md "Address cache"):
--
--   * mode 0 (SELF): the address is a varint, read directly.
--   * mode 1 (HERE): the address is @here@ minus a varint.
--   * near modes: a varint added to a near-cache slot.
--   * same modes: a single byte indexing a same-cache block.
--
-- Both caches are updated after the address is decoded, regardless of
-- the mode it came through — the round-robin near write and the
-- @mod 256@ same write that keep decoder and encoder in step.
--
-- The upstream half of a two-stage pipeline: the absolute @U@ offset
-- decoded here is what 'Slap.VCDIFF.Apply.resolveCopyAddress' later
-- resolves into a physical read against the source file or the output
-- buffer.
decodeCopyAddress
  :: AddressCache -> Int -> Word8 -> ByteString -> Int
  -> Either AddressDecodeFailure CopyAddressReading
decodeCopyAddress cache here mode addrSection cursor
  | modeNumber == 0 = fromVarint id
  | modeNumber == 1 = fromVarint (\delta -> here - delta)
  | modeNumber >= 2 && modeNumber <= nearCacheSize + 1 =
      fromVarint (\delta -> (nearAddresses cache Vector.! (modeNumber - 2)) + delta)
  | modeNumber >= nearCacheSize + 2 && modeNumber <= nearCacheSize + sameCacheSize + 1 =
      fromSameByte (modeNumber - (nearCacheSize + 2))
  | otherwise = Left (UnknownAddressMode mode)
  where
    modeNumber = fromIntegral mode

    fromVarint computeAddress =
      case getVcdiffVarint cursor addrSection of
        Left _ -> Left AddressSectionExhausted
        Right (VarintResult value consumed) ->
          Right (readingOf (computeAddress (fromIntegral value)) (cursor + consumed))

    fromSameByte sameBlock
      | cursor >= ByteString.length addrSection = Left AddressSectionExhausted
      | otherwise =
          let slotByte = fromIntegral (ByteString.index addrSection cursor)
          in Right (readingOf (sameAddresses cache Vector.! (sameBlock * 256 + slotByte))
                              (cursor + 1))

    readingOf address cursorAfter = CopyAddressReading
      { copyAddressDecoded     = address
      , copyAddressCacheAfter  = recordAddress cache address
      , copyAddressCursorAfter = cursorAfter
      }

-- | Write a freshly-decoded address into both caches: the next near
-- slot (advancing round-robin) and the same slot at @address mod
-- (sameCacheSize * 256)@.
recordAddress :: AddressCache -> Int -> AddressCache
recordAddress cache address = cache
  { nearAddresses = nearAddresses cache Vector.// [(nearWriteSlot cache, address)]
  , nearWriteSlot = (nearWriteSlot cache + 1) `mod` nearCacheSize
  , sameAddresses = sameAddresses cache Vector.// [(address `mod` (sameCacheSize * 256), address)]
  }
