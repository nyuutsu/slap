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
-- copy passes straight through. Each instruction is then emitted as the
-- densest entry the active table offers: a fixed-size single where the
-- size has its own opcode (dropping the out-of-line size varint), or a
-- combined opcode where an adjacent ADD+COPY or COPY+ADD pair shares one
-- — the coded-size single is the fallback, not the default. Both choices
-- only ever shrink the instruction section, the second-fattest part of a
-- patch, so the rule is mechanical — the most specific entry the table
-- has — with no cost comparison to get wrong. There is still one window.
-- The COPY address follows the same spirit: rather than always SELF (the
-- absolute @U@ offset), the encoder chooses the cheapest mode the address
-- cache admits per COPY —
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
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
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

-- | Walk a window's instructions, emitting each as the densest opcode
-- the active table offers and accumulating the three section streams. A
-- one-step lookahead packs an adjacent ADD+COPY or COPY+ADD into one
-- combined opcode whenever the table has an entry for the pair's sizes
-- and the COPY's selected mode; otherwise each instruction emits on its
-- own — fixed-size where the table names the size, coded-size where it
-- does not. RUN never combines. Greedy left-to-right takes a maximum set
-- of non-overlapping pairs, and each pairing saves exactly one opcode, so
-- the instruction section is byte-minimal under the active table.
--
-- The recursion threads 'EmitState' — the address cache and the write
-- head @here@ — consuming one or two instructions per step. Combinability
-- turns on the COPY's mode, which turns on the cache, so the cache lives
-- in this one walk; every COPY, combined or single, runs
-- 'selectCopyAddressMode' and so 'recordAddress', keeping the encoder's
-- cache in lockstep with the decoder's.
emitInstructions :: DenseOpcodes -> EmitState -> [VCDIFFInstruction] -> SectionBuilders
emitInstructions resolver = emitFrom
  where
    emitFrom _     []                                            = mempty
    emitFrom state (Add literal : Copy copyLength address : rest)
      | Just (opcode, selected) <- combineAddCopy resolver state literal copyLength address =
          combinedSections opcode literal selected
            <> emitFrom (afterCopy state selected (byteLength literal <> copyLength)) rest
    emitFrom state (Copy copyLength address : Add literal : rest)
      | Just (opcode, selected) <- combineCopyAdd resolver state copyLength address literal =
          combinedSections opcode literal selected
            <> emitFrom (afterCopy state selected (copyLength <> byteLength literal)) rest
    emitFrom state (instruction : rest) =
      let (nextState, sections) = emitSingle resolver state instruction
      in sections <> emitFrom nextState rest

    -- The state after a combined pair: the COPY's recorded cache, and
    -- @here@ advanced past the output of both halves.
    afterCopy state selected outputLength = EmitState
      { emitCache = selectedAddressCacheAfter selected
      , emitHere  = advance (emitHere state) outputLength }

-- | Try to pack an ADD immediately followed by a COPY into one combined
-- opcode. Succeeds only when both sizes name fixed-size entries and the
-- table holds a combined ADD+COPY opcode for those sizes and the COPY's
-- selected mode — so a combine never forces the COPY off the cheapest
-- mode the selection chose. The COPY is selected against @here@ advanced
-- past the ADD's output, the position it will occupy in the stream. When
-- either size is too large to sit inline, 'fixedSizeFor' short-circuits
-- before the selection runs, so an oversized copy costs no wasted work.
combineAddCopy
  :: DenseOpcodes -> EmitState -> ByteString -> Length -> Offset
  -> Maybe (Word8, SelectedCopyAddress)
combineAddCopy resolver state literal copyLength address = do
  addSize  <- fixedSizeFor (byteLength literal)
  copySize <- fixedSizeFor copyLength
  let copyHere = advance (emitHere state) (byteLength literal)
      selected = selectCopyAddressMode (emitCache state) copyHere address
      mode     = Table.CopyAddressMode (selectedAddressMode selected)
  opcode <- opcodeFor resolver
              (Table.CodeTableEntry (Table.Add addSize) (Table.Copy copySize mode))
  pure (opcode, selected)

-- | Try to pack a COPY immediately followed by an ADD into one combined
-- opcode — the mirror of 'combineAddCopy'. The COPY outputs first, so it
-- is selected against the current @here@, and the table must hold a
-- COPY+ADD opcode for the two sizes and the COPY's mode.
combineCopyAdd
  :: DenseOpcodes -> EmitState -> Length -> Offset -> ByteString
  -> Maybe (Word8, SelectedCopyAddress)
combineCopyAdd resolver state copyLength address literal = do
  copySize <- fixedSizeFor copyLength
  addSize  <- fixedSizeFor (byteLength literal)
  let selected = selectCopyAddressMode (emitCache state) (emitHere state) address
      mode     = Table.CopyAddressMode (selectedAddressMode selected)
  opcode <- opcodeFor resolver
              (Table.CodeTableEntry (Table.Copy copySize mode) (Table.Add addSize))
  pure (opcode, selected)

-- | The three section contributions of a combined opcode: the single
-- instruction byte (both halves carry a fixed size, so no out-of-line
-- size varint follows), the ADD half's literal in the data section, and
-- the COPY half's operand in the address section. A combined opcode
-- contributes exactly one of each regardless of the halves' order, so one
-- shape serves ADD+COPY and COPY+ADD alike.
combinedSections :: Word8 -> ByteString -> SelectedCopyAddress -> SectionBuilders
combinedSections opcode literal selected = SectionBuilders
  { dataStream        = byteString literal
  , instructionStream = word8 opcode
  , addressStream     = renderOperand (selectedAddressOperand selected) }

-- | Emit one instruction on its own — a RUN, an ADD or COPY with no
-- combinable neighbour, or a half of an adjacency the table had no
-- combined entry for. ADD and RUN advance @here@ and leave the cache
-- untouched; a COPY selects its mode and adopts the recorded cache. Each
-- takes the densest single opcode: the fixed-size entry where the table
-- names the size (no size varint trails), the coded-size entry otherwise.
-- RUN has only the coded form. Exhaustive over the three kinds — no
-- wildcard, so a fourth could not slip through.
emitSingle :: DenseOpcodes -> EmitState -> VCDIFFInstruction -> (EmitState, SectionBuilders)
emitSingle resolver state = \case
  Add literal ->
    let (opcode, sizeVarint) =
          singleSize resolver "ADD" (byteLength literal)
            (\size -> Table.CodeTableEntry (Table.Add size) Table.Noop)
    in ( state { emitHere = advance (emitHere state) (byteLength literal) }
       , SectionBuilders
           { dataStream        = byteString literal
           , instructionStream = word8 opcode <> sizeVarint
           , addressStream     = mempty } )
  Run runLength fillByte ->
    ( state { emitHere = advance (emitHere state) runLength }
    , SectionBuilders
        { dataStream        = word8 fillByte
        , instructionStream = word8 codedRunOpcode <> varintOfLength runLength
        , addressStream     = mempty } )
  Copy copyLength address ->
    let selected = selectCopyAddressMode (emitCache state) (emitHere state) address
        mode     = selectedAddressMode selected
        (opcode, sizeVarint) =
          singleSize resolver ("COPY mode " <> show mode) copyLength
            (\size -> Table.CodeTableEntry (Table.Copy size (Table.CopyAddressMode mode)) Table.Noop)
    in ( EmitState { emitCache = selectedAddressCacheAfter selected
                   , emitHere  = advance (emitHere state) copyLength }
       , SectionBuilders
           { dataStream        = mempty
           , instructionStream = word8 opcode <> sizeVarint
           , addressStream     = renderOperand (selectedAddressOperand selected) } )
  where
    codedRunOpcode = requireOpcode resolver
      (Table.CodeTableEntry (Table.Run Table.SizeCodedSeparately) Table.Noop) "coded RUN"

-- | The address-section bytes a chosen mode's operand contributes: a
-- varint for SELF \/ HERE \/ NEAR, a single byte for SAME.
renderOperand :: CopyAddressOperand -> Builder
renderOperand (AddressVarint value) = putVcdiffVarint value
renderOperand (AddressSameByte byte) = word8 byte

-- | The densest opcode the active table offers for an exact entry shape,
-- or 'Nothing' when the table holds no such entry. Built once per table
-- by scanning 'Table.codeTableEntries' — so a custom table feeds its own
-- opcode set through this resolver unchanged — and keyed by the whole
-- entry, so one lookup answers every query: a single instruction (a
-- 'Table.Noop' second half) or a combined pair (two real halves). The
-- lowest index wins a shape that repeats; the default table holds each
-- shape once.
newtype DenseOpcodes = DenseOpcodes (Map Table.CodeTableEntry Word8)

denseOpcodes :: Table.CodeTable -> DenseOpcodes
denseOpcodes table = DenseOpcodes
  (Map.fromListWith (\_later earlier -> earlier)
    [ (entry, fromIntegral index)
    | (index, entry) <- zip [0 :: Int ..] (Vector.toList (Table.codeTableEntries table)) ])

-- | The opcode an entry shape carries in the active table, if any.
opcodeFor :: DenseOpcodes -> Table.CodeTableEntry -> Maybe Word8
opcodeFor (DenseOpcodes opcodes) entry = Map.lookup entry opcodes

-- | The opcode for an entry the active table must carry — the coded-size
-- singles every usable table holds. Loud, not silent, if absent: the
-- default table carries them all and a custom table the encoder emits
-- would too, so a miss means a broken table, surfaced the proof-by-
-- provenance way the table lookups elsewhere here are.
requireOpcode :: DenseOpcodes -> Table.CodeTableEntry -> String -> Word8
requireOpcode resolver entry name = case opcodeFor resolver entry of
  Just opcode -> opcode
  Nothing     -> error ("Slap.VCDIFF.Create: active code table lacks the " <> name <> " entry")

-- | A fixed inline size for a length the one-byte size field can name
-- (1–255); 'Nothing' for zero, or for a length too large to sit inline,
-- which then falls back to a coded-size opcode. The guard is
-- load-bearing: a raw 'fromIntegral' would wrap a 260-byte run to a fixed
-- size of 4 and emit the wrong opcode for it.
fixedSizeFor :: Length -> Maybe Table.InstructionSize
fixedSizeFor (Length n)
  | n >= 1 && n <= 255 = Just (Table.SizeIs (Table.FixedInstructionSize (fromIntegral n)))
  | otherwise          = Nothing

-- | The opcode and any trailing size bytes for one single instruction of
-- the given output size: the table's fixed-size entry where it has one
-- (the size rides in the opcode, nothing trails), else its coded-size
-- entry (a size varint trails). @entryFor@ builds the lookup key from a
-- size; @name@ labels the coded entry in the provenance error a table
-- missing even that would raise.
singleSize
  :: DenseOpcodes -> String -> Length
  -> (Table.InstructionSize -> Table.CodeTableEntry)
  -> (Word8, Builder)
singleSize resolver name size entryFor =
  case fixedSizeFor size >>= opcodeFor resolver . entryFor of
    Just opcode -> (opcode, mempty)
    Nothing     ->
      ( requireOpcode resolver (entryFor Table.SizeCodedSeparately) (name <> " (coded)")
      , varintOfLength size )

-- | Render a window's three section streams to bytes. 'emitInstructions'
-- does the walk — threading the cache and write head, choosing each
-- opcode, and combining adjacent pairs — and yields the three streams as
-- one 'SectionBuilders'; this realizes them.
layoutSections :: DenseOpcodes -> EmitState -> [VCDIFFInstruction] -> Sections
layoutSections resolver initialState instructions = Sections
  { sectionData         = builderBytes (dataStream combined)
  , sectionInstructions = builderBytes (instructionStream combined)
  , sectionAddresses    = builderBytes (addressStream combined)
  }
  where
    combined = emitInstructions resolver initialState instructions

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
    sections     = layoutSections (denseOpcodes Table.defaultCodeTable)
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
