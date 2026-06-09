-- | Read a VCDIFF patch into the 'Slap.VCDIFF.Types' vocabulary,
-- source-free. Scoped to the CoreOnly subset: the default code table,
-- no custom table, no application header, no per-window Adler32, no
-- secondary compression. A patch that reaches past the core is
-- classified and refused cleanly ('VCDIFFFeatureNotYetSupported'),
-- never mishandled.
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
  , ActionIndex, actionAtPosition
  , RequiredLength(..), ActualLength(..), ActualMagic(..)
  , FoundVersion(..), byteLength )

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
  _adler      <- if hasAdler then Just <$> getBytes (Length 4) else pure Nothing
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

-- | Mask of the bits each indicator byte leaves undefined in the core.
-- A set bit outside the three the core names is malformed.
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
      Left (MalformedVCDIFF (VCDIFFUnknownIndicatorBits HeaderIndicator headerIndicator))
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
      Left (MalformedVCDIFF (VCDIFFUnknownIndicatorBits WindowIndicator windowIndicator))
  | testBit windowIndicator vcdSourceBit && testBit windowIndicator vcdTargetBit =
      Left (MalformedVCDIFF VCDIFFBothSourceAndTargetWindowBits)
  | rawHasAdler rawWindow =
      Left (VCDIFFFeatureNotYetSupported VCDIFFPerWindowChecksum)
  | testBit windowIndicator vcdTargetBit =
      Left (VCDIFFFeatureNotYetSupported VCDIFFTargetWindow)
  | rawDeltaIndicator rawWindow .&. reservedIndicatorMask /= 0 =
      Left (MalformedVCDIFF (VCDIFFUnknownIndicatorBits DeltaIndicator (rawDeltaIndicator rawWindow)))
  | rawDeltaIndicator rawWindow .&. secondaryCompressionMask /= 0 =
      Left (VCDIFFFeatureNotYetSupported VCDIFFSecondaryCompressedSection)
  | otherwise = do
      let sourceSegment =
            (\segment -> SourceSegment
                           FromSourceFile
                           (rawSegmentPosition segment)
                           (rawSegmentLength segment))
            <$> rawSourceSegment rawWindow
          segmentLength = maybe 0 (unLength . rawSegmentLength) (rawSourceSegment rawWindow)
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

-- | Cursors and accumulators threaded through one window's decode. The
-- three sections each carry their own cursor; 'producedBytes' tracks
-- how much of the target this window has emitted, which fixes @here@
-- for the next COPY; 'instructionIndex' numbers the emitted
-- instructions for error reporting.
data DecodeState = DecodeState
  { instCursor       :: !Int
  , dataCursor       :: !Int
  , addrCursor       :: !Int
  , addressCache     :: !AddressCache
  , producedBytes    :: !Int
  , instructionIndex :: !Int
  , emittedReversed  :: ![VCDIFFInstruction]
  }

-- | Decode one window's instruction stream into already-resolved
-- 'VCDIFFInstruction's, enforcing the three core invariants. Each
-- instruction byte indexes the default code table for up to two
-- templates; a deferred (zero) size is read inline from the
-- instruction section; ADD slices its literal bytes from the data
-- section; RUN takes its fill byte; COPY decodes its absolute
-- superstring offset through the address cache.
decodeWindowInstructions
  :: Int          -- ^ source-segment length, @len(S)@
  -> FileSize     -- ^ declared target-window size
  -> ByteString   -- ^ data section
  -> ByteString   -- ^ instruction section
  -> ByteString   -- ^ address section
  -> Either SlapError (Vector VCDIFFInstruction)
decodeWindowInstructions segmentLength targetWindowSize dataSection instSection addrSection =
  walk initialState
  where
    targetSize = unFileSize targetWindowSize
    instLength = ByteString.length instSection
    dataLength = ByteString.length dataSection

    initialState = DecodeState
      { instCursor       = 0
      , dataCursor       = 0
      , addrCursor       = 0
      , addressCache     = freshAddressCache
      , producedBytes    = 0
      , instructionIndex = 0
      , emittedReversed  = []
      }

    walk state
      | instCursor state >= instLength =
          if producedBytes state == targetSize
            then Right (Vector.fromList (reverse (emittedReversed state)))
            else Left (MalformedVCDIFF
                         (VCDIFFWindowSizeMismatch
                            (ExpectedSize targetWindowSize)
                            (ActualSize (FileSize (producedBytes state)))))
      | otherwise =
          let codeByte = ByteString.index instSection (instCursor state)
              entry    = Table.codeTableEntries Table.defaultCodeTable Vector.! fromIntegral codeByte
              advanced = state { instCursor = instCursor state + 1 }
          in do
            afterFirst  <- applyTemplate (Table.firstInstruction entry)  advanced
            afterSecond <- applyTemplate (Table.secondInstruction entry) afterFirst
            walk afterSecond

    applyTemplate :: Table.InstructionTemplate -> DecodeState -> Either SlapError DecodeState
    applyTemplate Table.Noop state = Right state
    applyTemplate (Table.Add sizeTemplate) state = do
      (size, afterSize) <- resolveSize sizeTemplate state
      if dataCursor afterSize + size > dataLength
        then sectionExhausted VCDIFFDataSection afterSize
        else
          let literal = viewBytesInRange (Offset (dataCursor afterSize)) (Length size) dataSection
          in Right (emit (Add literal) size afterSize
                      { dataCursor = dataCursor afterSize + size })
    applyTemplate (Table.Run sizeTemplate) state = do
      (size, afterSize) <- resolveSize sizeTemplate state
      if dataCursor afterSize >= dataLength
        then sectionExhausted VCDIFFDataSection afterSize
        else
          let fillByte = ByteString.index dataSection (dataCursor afterSize)
          in Right (emit (Run (Length size) fillByte) size afterSize
                      { dataCursor = dataCursor afterSize + 1 })
    applyTemplate (Table.Copy sizeTemplate (Table.CopyAddressMode mode)) state = do
      (size, afterSize) <- resolveSize sizeTemplate state
      let here = segmentLength + producedBytes afterSize
      case decodeCopyAddress (addressCache afterSize) here mode addrSection (addrCursor afterSize) of
        Left AddressSectionExhausted ->
          sectionExhausted VCDIFFAddressSection afterSize
        Left (UnknownAddressMode modeByte) ->
          Left (MalformedVCDIFF (VCDIFFInvalidCopyAddressMode modeByte))
        Right (address, updatedCache, nextAddrCursor)
          | address < 0 || address >= here ->
              Left (MalformedVCDIFF
                      (VCDIFFCopyAddressOutOfRange
                         (currentIndex afterSize)
                         (ActualOffset (Offset address))
                         (MaxOffset (Offset here))))
          | address < segmentLength && address + size > segmentLength ->
              Left (MalformedVCDIFF (VCDIFFCopyCrossesSourceSegmentEnd (currentIndex afterSize)))
          | otherwise ->
              Right (emit (Copy (Length size) (Offset address)) size afterSize
                       { addrCursor   = nextAddrCursor
                       , addressCache = updatedCache })

    -- | Resolve an instruction's size: a fixed table size as-is, or a
    -- deferred (zero) size read inline from the instruction section.
    resolveSize :: Table.InstructionSize -> DecodeState -> Either SlapError (Int, DecodeState)
    resolveSize (Table.SizeIs (Table.FixedInstructionSize fixed)) state =
      Right (fromIntegral fixed, state)
    resolveSize Table.SizeCodedSeparately state =
      case getVcdiffVarint (instCursor state) instSection of
        Left _ -> Left (MalformedVCDIFF (VCDIFFSectionExhausted VCDIFFInstructionSection (currentIndex state)))
        Right (VarintResult value consumed) ->
          Right (fromIntegral value, state { instCursor = instCursor state + consumed })

    -- | Append an emitted instruction and advance the produced-byte and
    -- instruction counters.
    emit :: VCDIFFInstruction -> Int -> DecodeState -> DecodeState
    emit instruction size state = state
      { producedBytes    = producedBytes state + size
      , instructionIndex = instructionIndex state + 1
      , emittedReversed  = instruction : emittedReversed state
      }

    sectionExhausted :: VCDIFFSection -> DecodeState -> Either SlapError a
    sectionExhausted section state =
      Left (MalformedVCDIFF (VCDIFFSectionExhausted section (currentIndex state)))

    currentIndex :: DecodeState -> ActionIndex
    currentIndex state = actionAtPosition (instructionIndex state)

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

-- | Decode one COPY address from the address section, given the cache,
-- the current @here@ position in the superstring, and the address
-- mode. Returns the absolute address, the cache updated with it, and
-- the advanced address-section cursor. The mode families
-- (docs/vcdiff/core/spec.md "Address cache"):
--
--   * mode 0 (SELF): the address is a varint, read directly.
--   * mode 1 (HERE): the address is @here@ minus a varint.
--   * near modes: a varint added to a near-cache slot.
--   * same modes: a single byte indexing a same-cache block.
--
-- Both caches are updated after the address is decoded, regardless of
-- the mode it came through — the round-robin near write and the
-- @mod 256@ same write that keep decoder and encoder in step.
decodeCopyAddress
  :: AddressCache -> Int -> Word8 -> ByteString -> Int
  -> Either AddressDecodeFailure (Int, AddressCache, Int)
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
          let address = computeAddress (fromIntegral value)
          in Right (address, recordAddress cache address, cursor + consumed)

    fromSameByte sameBlock
      | cursor >= ByteString.length addrSection = Left AddressSectionExhausted
      | otherwise =
          let slotByte = fromIntegral (ByteString.index addrSection cursor)
              address  = sameAddresses cache Vector.! (sameBlock * 256 + slotByte)
          in Right (address, recordAddress cache address, cursor + 1)

-- | Write a freshly-decoded address into both caches: the next near
-- slot (advancing round-robin) and the same slot at @address mod
-- (sameCacheSize * 256)@.
recordAddress :: AddressCache -> Int -> AddressCache
recordAddress cache address = cache
  { nearAddresses = nearAddresses cache Vector.// [(nearWriteSlot cache, address)]
  , nearWriteSlot = (nearWriteSlot cache + 1) `mod` nearCacheSize
  , sameAddresses = sameAddresses cache Vector.// [(address `mod` (sameCacheSize * 256), address)]
  }
