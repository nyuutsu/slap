{-# LANGUAGE LambdaCase #-}

-- | VCDIFF patch creation: a cover of the target serialized to wire
-- bytes.
--
-- Creation has two halves. A /matcher/ ('Slap.VCDIFF.FFI.vcdiffCover',
-- Rust-backed) segments the target into copies and literals — a
-- 'Cover'. This module is the other half: it turns a cover into a
-- VCDIFF patch. 'createRFCVCDIFF' runs the matcher and serializes its
-- cover; when the matcher finds nothing the cover is all-literal and
-- the bytes are the bedrock floor's exactly. Tests also feed
-- 'createFromCover' hand-built covers directly, exercising the full
-- COPY/ADD/RUN path independently of what the matcher happens to find.
--
-- The emitted patch reaches for no flavor-distinguishing feature, so it
-- parses back as 'Slap.VCDIFF.Types.PatchCoreOnly', not @PatchRFC@. That
-- is right, not a gap: the RFC arc's parameterless default genuinely
-- uses only core features (docs/vcdiff/core/spec.md, "A patch that
-- happens to use only the features described here is valid as either
-- flavor"). The @rfc-vcdiff@ token names the arc the user asked for;
-- these bytes happen to be core-shaped because nothing RFC-specific is
-- reached for.
--
-- Instruction selection stays uniform: a literal becomes a 'Run' only
-- when it is a single byte repeated (length ≥ 2), an 'Add' otherwise; a
-- copy passes straight through. Every opcode is still the coded-size
-- single-instruction default-table entry (no inline-size or combined
-- rows), and there is still one window. What is no longer uniform is the
-- COPY address: rather than always SELF (the absolute @U@ offset), the
-- encoder chooses the cheapest mode the address cache admits per COPY —
-- SAME (one byte), NEAR (a short delta off a recent address), HERE (a
-- short distance back from the write head), or SELF — through the shared
-- 'Slap.VCDIFF.AddressCache.selectCopyAddressMode', running the same
-- 'Slap.VCDIFF.AddressCache.recordAddress' the decoder runs so the two
-- caches stay one state. The address section, the fattest part of a
-- patch, shrinks accordingly.
module Slap.VCDIFF.Create
  ( createRFCVCDIFF
    -- * Cover-driven emission (exported for testing)
  , createFromCover
  , coverToInstructions
  ) where

import Slap.VCDIFF.Types (vcdiffMagicBytes, VCDIFFInstruction(..))
import Slap.VCDIFF.Cover (Cover(..), CoverSegment(..))
import Slap.VCDIFF.FFI (vcdiffCover)
import Slap.VCDIFF.AddressCache
  ( AddressCache, freshAddressCache, defaultAddressCacheConfig
  , selectCopyAddressMode, SelectedCopyAddress(..), CopyAddressOperand(..) )
import qualified Slap.VCDIFF.CodeTable as Table
import Slap.Binary (putVcdiffVarint, viewBytesInRange)
import Slap.Status (SlapError, CreateResult(..))
import Slap.Measure (Offset(..), Length(..), byteLength, Cursor(..), lengthToOffset)
import Slap.FileContents (InputFileContents(..), OutputFileContents(..), PatchFileContents(..))

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.ByteString.Builder (Builder, byteString, word8, toLazyByteString)
import qualified Data.ByteString.Lazy as LazyByteString
import Data.IntMap.Strict (IntMap)
import qualified Data.IntMap.Strict as IntMap
import Data.List (mapAccumL)
import qualified Data.Vector as Vector
import Data.Word (Word8)

-- | Create a VCDIFF patch reconstructing @target@. The cover comes from
-- the matcher ('Slap.VCDIFF.FFI.vcdiffCover'), so the patch copies
-- runs the target shares with the source or with itself. When the
-- matcher finds nothing — an unrelated source, a target shorter than
-- the minimum match — it returns an all-literal cover and the bytes are
-- the bedrock floor's exactly, so the degenerate case is still reached,
-- just no longer hard-coded. The 'Either' is shape-symmetry with the
-- other @create*@ entries, whose richer encoders can fail. No metadata,
-- no advisories.
createRFCVCDIFF :: InputFileContents -> OutputFileContents
                -> Either SlapError CreateResult
createRFCVCDIFF inputContents outputContents =
  Right (createFromCover inputContents outputContents (vcdiffCover inputContents outputContents))

-- | Serialize a cover of @target@ against @source@ into a VCDIFF patch.
-- Total: the cover is the contract, and a well-formed cover always
-- serializes — the 'CreateResult' carries no advisories.
createFromCover :: InputFileContents -> OutputFileContents -> Cover -> CreateResult
createFromCover (InputFileContents source) (OutputFileContents target) cover =
  CreateResult (PatchFileContents (emitPatch source target cover)) []

----------------------------------------------------------------------------
-- Cover -> instructions
----------------------------------------------------------------------------

-- | Choose an instruction for each cover segment. A copy passes straight
-- through to 'Copy'. A literal's bytes are sliced from the target and
-- become a 'Run' when they are a single byte repeated (strictly smaller
-- than the equivalent 'Add' once length ≥ 2), an 'Add' otherwise.
coverToInstructions :: ByteString -> Cover -> [VCDIFFInstruction]
coverToInstructions target (Cover segments) = map segmentToInstruction segments
  where
    segmentToInstruction = \case
      CoverCopy copyLength superstringOffset -> Copy copyLength superstringOffset
      CoverLiteral literalStart literalLength ->
        literalToInstruction (viewBytesInRange literalStart literalLength target)

-- | A literal run becomes a 'Run' of its single repeated byte, or an
-- 'Add' of its bytes verbatim.
literalToInstruction :: ByteString -> VCDIFFInstruction
literalToInstruction literalBytes
  | isSingleRepeatedByte literalBytes =
      Run (byteLength literalBytes) (ByteString.head literalBytes)
  | otherwise = Add literalBytes

-- | Whether a run is two or more copies of one byte — the case a 'Run'
-- encodes strictly smaller than an 'Add'. A length-1 (or empty) run is
-- not "repeated" and stays an 'Add', so 'ByteString.head' below it is
-- only reached on a non-empty run.
isSingleRepeatedByte :: ByteString -> Bool
isSingleRepeatedByte bytes =
  byteLength bytes >= Length 2 && ByteString.all (== ByteString.head bytes) bytes

----------------------------------------------------------------------------
-- Cover -> wire
----------------------------------------------------------------------------

-- | The three realized on-wire sections of a window.
data Sections = Sections
  { sectionData         :: !ByteString   -- ^ ADD literals and RUN fill bytes.
  , sectionInstructions :: !ByteString   -- ^ each opcode and its coded size.
  , sectionAddresses    :: !ByteString   -- ^ each COPY's chosen-mode operand.
  }

-- | The three section byte-streams under construction. One value is both
-- a single instruction's contribution and — the type being a 'Monoid'
-- that combines the streams componentwise — a whole window's
-- accumulation, so a window's sections are exactly the fold of its
-- instructions' pieces in order. A field is 'mempty' where an
-- instruction contributes nothing there (a COPY adds no data; an ADD or
-- RUN adds no address).
data SectionBuilders = SectionBuilders
  { dataStream        :: !Builder
  , instructionStream :: !Builder
  , addressStream     :: !Builder
  }

instance Semigroup SectionBuilders where
  SectionBuilders earlierData earlierInstructions earlierAddresses
    <> SectionBuilders laterData laterInstructions laterAddresses =
      SectionBuilders
        (earlierData         <> laterData)
        (earlierInstructions <> laterInstructions)
        (earlierAddresses    <> laterAddresses)

instance Monoid SectionBuilders where
  mempty = SectionBuilders mempty mempty mempty

-- | The encoder's running state as it walks a window's instructions: the
-- address cache, kept in lockstep with the decoder's, and the write head
-- @here@ in the superstring @U = S + T@ that the HERE mode measures back
-- from. Every instruction advances @here@ by its output length; only a
-- COPY touches the cache.
data EmitState = EmitState
  { emitCache :: !AddressCache
  , emitHere  :: !Offset
  }

-- | Emit one instruction: its three section contributions, and the state
-- left behind. ADD and RUN advance @here@ and leave the cache untouched;
-- a COPY chooses its address mode against the cache and @here@ through
-- the shared 'selectCopyAddressMode', emits the matching opcode and the
-- mode's operand, and adopts the cache the selection recorded into.
-- Exhaustive over the three kinds — no wildcard, so a fourth could not
-- slip through.
emitInstruction :: IntMap Word8 -> EmitState -> VCDIFFInstruction -> (EmitState, SectionBuilders)
emitInstruction opcodeForMode emitState = \case
  Add literal ->
    ( advanceWriteHead (byteLength literal)
    , SectionBuilders
        { dataStream        = byteString literal
        , instructionStream = word8 addOpcodeSizeCoded <> varintOfLength (byteLength literal)
        , addressStream     = mempty } )
  Run runLength fillByte ->
    ( advanceWriteHead runLength
    , SectionBuilders
        { dataStream        = word8 fillByte
        , instructionStream = word8 runOpcodeSizeCoded <> varintOfLength runLength
        , addressStream     = mempty } )
  Copy copyLength address ->
    let selected = selectCopyAddressMode (emitCache emitState) (emitHere emitState) address
        opcode   = singleCopyOpcode opcodeForMode (selectedAddressMode selected)
    in ( EmitState
           { emitCache = selectedAddressCacheAfter selected
           , emitHere  = advance (emitHere emitState) copyLength }
       , SectionBuilders
           { dataStream        = mempty
           , instructionStream = word8 opcode <> varintOfLength copyLength
           , addressStream     = renderOperand (selectedAddressOperand selected) } )
  where
    advanceWriteHead outputLength =
      emitState { emitHere = advance (emitHere emitState) outputLength }

-- | The address-section bytes a chosen mode's operand contributes: a
-- varint for SELF \/ HERE \/ NEAR, a single byte for SAME.
renderOperand :: CopyAddressOperand -> Builder
renderOperand (AddressVarint value) = putVcdiffVarint value
renderOperand (AddressSameByte byte) = word8 byte

-- | The instruction-stream opcode for a single COPY of coded size in a
-- given address mode. Total by construction: the selection chooses among
-- the default configuration's nine modes, and the default table provides
-- a coded-size single-COPY entry for every one — the same proof-by-
-- provenance as 'Slap.VCDIFF.CodeTable''s @Vector.!@ lookup.
singleCopyOpcode :: IntMap Word8 -> Word8 -> Word8
singleCopyOpcode opcodeForMode mode = opcodeForMode IntMap.! fromIntegral mode

-- | The opcode for a single coded-size COPY in each address mode the
-- table names, read out of the table itself rather than hard-coded — so
-- the modes the selection picks and the opcodes emitted come from one
-- source, the discipline the combined-opcode and custom-table layers
-- will extend. The default table provides all nine core modes.
copyOpcodeForMode :: Table.CodeTable -> IntMap Word8
copyOpcodeForMode table = IntMap.fromList
  [ (fromIntegral mode, fromIntegral index)
  | (index, entry) <- zip [0 :: Int ..] (Vector.toList (Table.codeTableEntries table))
  , Table.CodeTableEntry (Table.Copy Table.SizeCodedSeparately (Table.CopyAddressMode mode)) Table.Noop
      <- [entry]
  ]

-- | Walk a window's instructions through the emit state and render the
-- three accumulated streams to bytes. The fold threads the cache and the
-- write head so each COPY selects against the state its predecessors
-- left; section bytes are the ordered concatenation of the per-
-- instruction contributions.
layoutSections :: IntMap Word8 -> EmitState -> [VCDIFFInstruction] -> Sections
layoutSections opcodeForMode initialState instructions = Sections
  { sectionData         = builderBytes (dataStream combined)
  , sectionInstructions = builderBytes (instructionStream combined)
  , sectionAddresses    = builderBytes (addressStream combined)
  }
  where
    combined = mconcat (snd (mapAccumL (emitInstruction opcodeForMode) initialState instructions))

-- | Whether a window's instructions read from the superstring — i.e.
-- contain a COPY. A copying window declares its source segment; an
-- all-literal one is self-contained. Total over the three kinds.
hasCopy :: [VCDIFFInstruction] -> Bool
hasCopy = any $ \case
  Copy _ _ -> True
  Add _    -> False
  Run _ _  -> False

-- | Serialize a whole patch: the fixed header, then one window holding
-- the cover's instructions. When any instruction copies, the window
-- declares the entire source as its segment (so the COPY addresses can
-- reach into @U@); otherwise the window is self-contained and the two
-- segment varints are absent, reproducing the bedrock floor exactly.
emitPatch :: ByteString -> ByteString -> Cover -> ByteString
emitPatch source target cover = builderBytes
  (  byteString vcdiffMagicBytes
  <> word8 version0
  <> word8 noHeaderFeatures
  <> windowBuilder )
  where
    instructions = coverToInstructions target cover
    copying      = hasCopy instructions
    sections     = layoutSections (copyOpcodeForMode Table.defaultCodeTable)
                                  initialEmitState instructions

    -- The write head starts at @len(S)@: the source segment a copying
    -- window declares (the whole source), or zero for a self-contained
    -- window, which has no COPY to measure against it anyway.
    initialEmitState = EmitState
      { emitCache = freshAddressCache defaultAddressCacheConfig
      , emitHere  = if copying then lengthToOffset (byteLength source) else Offset 0
      }

    -- The Win_Indicator and (when copying) the source-segment varints,
    -- which precede the delta-encoding-length on the wire.
    windowIndicatorAndSegment
      | copying =
             word8 sourceSegmentWindow
          <> varintOfLength (byteLength source)   -- source-segment length
          <> putVcdiffVarint 0                    -- source-segment position
      | otherwise = word8 selfContainedWindow

    -- Everything the delta-encoding-length field measures: the target
    -- window size, the indicator, the three section lengths, then the
    -- three sections in order.
    deltaEncoding = builderBytes
      (  varintOfLength (byteLength target)
      <> word8 noSectionsCompressed
      <> varintOfLength (byteLength (sectionData sections))
      <> varintOfLength (byteLength (sectionInstructions sections))
      <> varintOfLength (byteLength (sectionAddresses sections))
      <> byteString (sectionData sections)
      <> byteString (sectionInstructions sections)
      <> byteString (sectionAddresses sections) )

    windowBuilder =
         windowIndicatorAndSegment
      <> varintOfLength (byteLength deltaEncoding)
      <> byteString deltaEncoding

----------------------------------------------------------------------------
-- Varint helpers and named wire constants
----------------------------------------------------------------------------

-- | A 'Length' as a VCDIFF varint.
varintOfLength :: Length -> Builder
varintOfLength (Length n) = putVcdiffVarint (fromIntegral n)

-- | Default code-table index 1: ADD with its size coded separately
-- (RFC 3284 §5.6).
addOpcodeSizeCoded :: Word8
addOpcodeSizeCoded = 0x01

-- | Default code-table index 0: RUN with its size coded separately
-- (RFC 3284 §5.6).
runOpcodeSizeCoded :: Word8
runOpcodeSizeCoded = 0x00

-- | Version byte: VCDIFF is at version 0 (RFC 3284 §4.1).
version0 :: Word8
version0 = 0x00

-- | Hdr_Indicator with no bits set: no secondary compressor, no custom
-- code table, no application header.
noHeaderFeatures :: Word8
noHeaderFeatures = 0x00

-- | Win_Indicator with no bits set: a self-contained window, no source
-- segment, so its two source-segment varints are absent.
selfContainedWindow :: Word8
selfContainedWindow = 0x00

-- | Win_Indicator with the VCD_SOURCE bit set: the window's COPYs may
-- address a segment of the source file, named by the two varints that
-- follow.
sourceSegmentWindow :: Word8
sourceSegmentWindow = 0x01

-- | Delta_Indicator with no bits set: none of the three sections is
-- secondary-compressed.
noSectionsCompressed :: Word8
noSectionsCompressed = 0x00

-- | Render a 'Builder' to a strict 'ByteString'.
builderBytes :: Builder -> ByteString
builderBytes = LazyByteString.toStrict . toLazyByteString
