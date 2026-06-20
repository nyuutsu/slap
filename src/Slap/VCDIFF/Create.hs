{-# LANGUAGE LambdaCase #-}

-- | VCDIFF patch creation: a cover of the target serialized to wire
-- bytes, on the default code table or — when it pays — a custom one.
--
-- Creation has two halves. A /matcher/ ('Slap.VCDIFF.FFI.vcdiffCover',
-- Rust-backed) segments the target into copies and literals — a 'Cover'.
-- This module is the other half: it turns a cover into a VCDIFF patch.
-- 'createRFCVCDIFF' runs the matcher and serializes its cover; when the
-- matcher finds nothing the cover is all-literal and the bytes are the
-- bedrock floor's exactly. Tests feed the cover-driven entries hand-built
-- covers directly — 'createFromCover' for the default-table core,
-- 'createConsideringCustomTable' for the custom-table weigh-up — exercising
-- the full COPY/ADD/RUN path independently of what the matcher happens to
-- find.
--
-- A patch on the default table reaches for no flavor-distinguishing
-- feature, so it parses back as 'Slap.VCDIFF.Types.PatchCoreOnly'; a patch
-- that ships a custom code table uses an RFC-arc feature (RFC 3284 §7's
-- VCD_CODETABLE) and parses back as @PatchRFC@. The @rfc-vcdiff@ token
-- names the arc the user asked for; whether the bytes turn out core-shaped
-- or RFC-shaped is settled by whether a custom table earned its place.
--
-- Instruction selection stays uniform: a literal becomes a 'Run' only
-- when it is a single byte repeated (length ≥ 2), an 'Add' otherwise; a
-- copy passes straight through. Each COPY's address is resolved once, by
-- 'resolveInstructionAddresses', to the cheapest mode the address cache
-- admits — SAME (one byte), NEAR (a short delta off a recent address),
-- HERE (a short distance back from the write head), or SELF (the absolute
-- @U@ offset) — through the shared
-- 'Slap.VCDIFF.AddressCache.selectCopyAddressMode', running the same
-- 'Slap.VCDIFF.AddressCache.recordAddress' the decoder runs so the two
-- caches stay one state. That selection is table-independent (the cache
-- geometry, not the code table, fixes the mode), so one resolved stream
-- feeds every table the patch is weighed under. Each resolved instruction
-- is then packed as the densest entry the active table offers: a fixed-size
-- single where the size has its own opcode (dropping the out-of-line size
-- varint), or a combined opcode where an adjacent ADD+COPY or COPY+ADD pair
-- shares one — the coded-size single is the fallback, not the default.
-- Both choices only ever shrink a section, so the rule is mechanical, with
-- no cost comparison to get wrong. There is still one window.
--
-- The custom code table is the patch carrying its own opcode assignments,
-- tuned so the ADD+COPY and COPY+ADD pairs this patch repeats — ones the
-- default table spends two opcodes on — get a combined opcode each. The
-- table travels as a VCDIFF delta /inside/ the patch: the default table's
-- 1536-byte image transformed by an inner delta this same module emits on
-- the default-only core, so a table close to the default costs almost
-- nothing to ship. 'createRFCVCDIFF' sizes two candidates — the cover under
-- the default table, and under a designed custom one — and ships the
-- smaller, so a custom table appears only when it beats the default
-- outright. The design ('designCandidateTable') is deliberately simple
-- here; sharpening it is later work.
module Slap.VCDIFF.Create
  ( createRFCVCDIFF
    -- * Cover-driven emission (exported for testing)
  , createFromCover
  , createConsideringCustomTable
  , coverToInstructions
    -- * Address resolution and candidate-table design (exported for testing)
  , ResolvedInstruction(..)
  , resolveInstructionAddresses
  , designCandidateTable
  ) where

import Slap.VCDIFF.Types (vcdiffMagicBytes, VCDIFFInstruction(..))
import Slap.VCDIFF.Cover (Cover(..), CoverSegment(..))
import Slap.VCDIFF.FFI (vcdiffCover)
import Slap.VCDIFF.AddressCache
  ( AddressCacheConfig(..), freshAddressCache, defaultAddressCacheConfig
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
import Data.List (sortOn)
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Ord (Down(..))
import qualified Data.Vector as Vector
import Data.Word (Word8)

-- | Create a VCDIFF patch reconstructing @target@. The cover comes from
-- the matcher ('Slap.VCDIFF.FFI.vcdiffCover'), so the patch copies the
-- runs the target shares with the source or with itself; the bytes are
-- then weighed under the default table and a designed custom one, the
-- smaller shipping ('createConsideringCustomTable'). When the matcher finds
-- nothing — an unrelated source, a target shorter than the minimum match —
-- it returns an all-literal cover and the bytes are the bedrock floor's
-- exactly. The 'Either' is shape-symmetry with the other @create*@ entries,
-- whose richer encoders can fail. No metadata, no advisories.
createRFCVCDIFF :: InputFileContents -> OutputFileContents
                -> Either SlapError CreateResult
createRFCVCDIFF inputContents outputContents =
  Right (createConsideringCustomTable inputContents outputContents
           (vcdiffCover inputContents outputContents))

-- | Serialize a cover of @target@ against @source@ into a VCDIFF patch on
-- the default code table, with no custom-table consideration — the core.
-- Tests drive it with hand-built covers to pin the emitter, and the
-- custom-table path reuses it for the inner delta. Total: a well-formed
-- cover always serializes, so the 'CreateResult' carries no advisories.
createFromCover :: InputFileContents -> OutputFileContents -> Cover -> CreateResult
createFromCover (InputFileContents source) (OutputFileContents target) cover =
  CreateResult (PatchFileContents (emitDefaultPatch source target cover)) []

-- | Serialize a cover into a VCDIFF patch, weighing a custom code table
-- against the default and shipping the smaller — the cover-driven form of
-- 'createRFCVCDIFF''s consideration, exposed so tests can exercise the
-- custom-table path on a hand-built cover. Total, like 'createFromCover'.
createConsideringCustomTable :: InputFileContents -> OutputFileContents -> Cover -> CreateResult
createConsideringCustomTable (InputFileContents source) (OutputFileContents target) cover =
  CreateResult (PatchFileContents (emitConsideringCustomTable source target cover)) []

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
-- Instructions -> resolved instructions (address selection)
----------------------------------------------------------------------------

-- | An instruction whose COPY address has been resolved to a concrete
-- address mode and the operand that mode reads back; ADD and RUN, which
-- name no address, carry through unchanged. The address cache is threaded
-- once, here, to produce these. The result is table-independent — the
-- cache geometry, not the code table, fixes each mode — so one resolved
-- stream serves the default-table emission, a candidate-table emission,
-- and the candidate-table /design/, which reads the modes off it.
data ResolvedInstruction
  = ResolvedAdd  !ByteString
  | ResolvedRun  !Length !Word8
  | ResolvedCopy !Length !Table.CopyAddressMode !CopyAddressOperand
    -- ^ the COPY's length, its chosen address mode, and the operand the
    -- address section carries for that mode. The fill byte of 'ResolvedRun'
    -- stays a bare 'Word8' — a verbatim literal value, not a protocol
    -- quantity — but a COPY's mode is the 'Table.CopyAddressMode' the code
    -- table speaks, lifted out of 'selectCopyAddressMode''s wire byte once,
    -- here, rather than re-wrapped at each use.
  deriving (Eq, Show)

-- | Thread the address cache over a window's instructions, resolving each
-- COPY to its cheapest mode and operand through
-- 'Slap.VCDIFF.AddressCache.selectCopyAddressMode' — the same selection,
-- running the same 'Slap.VCDIFF.AddressCache.recordAddress', that the
-- decoder inverts. @here@ — the write head in the superstring @U = S + T@,
-- the position HERE mode measures back from — starts at @len(S)@ and
-- advances by each instruction's output length; only a COPY consults and
-- updates the cache. The result feeds both 'layoutSections' (which packs it
-- under a table) and 'designCandidateTable' (which tallies its
-- adjacencies).
resolveInstructionAddresses
  :: AddressCacheConfig -> Offset -> [VCDIFFInstruction] -> [ResolvedInstruction]
resolveInstructionAddresses config initialHere instructions =
  resolveFrom (freshAddressCache config) initialHere instructions
  where
    resolveFrom _ _ [] = []
    resolveFrom cache here (instruction : rest) = case instruction of
      Add literal ->
        ResolvedAdd literal
          : resolveFrom cache (advance here (byteLength literal)) rest
      Run runLength fillByte ->
        ResolvedRun runLength fillByte
          : resolveFrom cache (advance here runLength) rest
      Copy copyLength address ->
        let selected = selectCopyAddressMode cache here address
        in ResolvedCopy copyLength
                        (Table.CopyAddressMode (selectedAddressMode selected))
                        (selectedAddressOperand selected)
             : resolveFrom (selectedAddressCacheAfter selected) (advance here copyLength) rest

----------------------------------------------------------------------------
-- Resolved instructions -> wire sections (opcode packing)
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

-- | Pack a window's resolved instructions into the three section streams
-- under a table, choosing the densest opcode each step the table offers. A
-- one-step lookahead packs an adjacent ADD+COPY or COPY+ADD into one
-- combined opcode when the table holds an entry for the pair's sizes and
-- the COPY's already-chosen mode; otherwise each instruction packs on its
-- own. RUN never combines. Greedy left-to-right takes a maximal set of
-- non-overlapping pairs, each pairing saving one opcode, so the instruction
-- section is byte-minimal under the table. No cache here: the modes and
-- operands were fixed by 'resolveInstructionAddresses', so packing is pure
-- opcode lookup over the resolved stream.
packInstructions :: DenseOpcodes -> [ResolvedInstruction] -> SectionBuilders
packInstructions resolver = packFrom
  where
    packFrom [] = mempty
    packFrom (ResolvedAdd literal : ResolvedCopy copyLength mode operand : rest)
      | Just opcode <- combinedAddCopyOpcode resolver (byteLength literal) copyLength mode =
          combinedSections opcode literal operand <> packFrom rest
    packFrom (ResolvedCopy copyLength mode operand : ResolvedAdd literal : rest)
      | Just opcode <- combinedCopyAddOpcode resolver copyLength mode (byteLength literal) =
          combinedSections opcode literal operand <> packFrom rest
    packFrom (instruction : rest) = packSingle resolver instruction <> packFrom rest

-- | The combined code-table entry an ADD(addLength) immediately followed by
-- a COPY(copyLength, mode) packs into, when both lengths name fixed-size
-- entries — 'Nothing' otherwise. Shared by the packer's opcode lookup
-- ('combinedAddCopyOpcode') and the candidate-table design
-- ('combinablePairs'), so the two agree on what a combinable adjacency /is/
-- by constructing it the one way.
addCopyEntry :: Length -> Length -> Table.CopyAddressMode -> Maybe Table.CodeTableEntry
addCopyEntry addLength copyLength mode = do
  addSize  <- fixedSizeFor addLength
  copySize <- fixedSizeFor copyLength
  pure (Table.CodeTableEntry (Table.Add addSize) (Table.Copy copySize mode))

-- | The combined entry a COPY(copyLength, mode) immediately followed by an
-- ADD(addLength) packs into — the mirror of 'addCopyEntry'.
copyAddEntry :: Length -> Table.CopyAddressMode -> Length -> Maybe Table.CodeTableEntry
copyAddEntry copyLength mode addLength = do
  copySize <- fixedSizeFor copyLength
  addSize  <- fixedSizeFor addLength
  pure (Table.CodeTableEntry (Table.Copy copySize mode) (Table.Add addSize))

-- | The opcode an ADD-then-COPY adjacency packs into under a table: the
-- shared 'addCopyEntry', looked up in the active table. The mode is the one
-- 'resolveInstructionAddresses' already selected, so a combine never shifts
-- the COPY off the cheapest address mode.
combinedAddCopyOpcode :: DenseOpcodes -> Length -> Length -> Table.CopyAddressMode -> Maybe Word8
combinedAddCopyOpcode resolver addLength copyLength mode =
  addCopyEntry addLength copyLength mode >>= opcodeFor resolver

-- | The opcode a COPY-then-ADD adjacency packs into under a table — the
-- mirror of 'combinedAddCopyOpcode'.
combinedCopyAddOpcode :: DenseOpcodes -> Length -> Table.CopyAddressMode -> Length -> Maybe Word8
combinedCopyAddOpcode resolver copyLength mode addLength =
  copyAddEntry copyLength mode addLength >>= opcodeFor resolver

-- | The three section contributions of a combined opcode: the single
-- instruction byte (both halves carry a fixed size, so no out-of-line
-- size varint follows), the ADD half's literal in the data section, and
-- the COPY half's operand in the address section. A combined opcode
-- contributes exactly one of each regardless of the halves' order, so one
-- shape serves ADD+COPY and COPY+ADD alike.
combinedSections :: Word8 -> ByteString -> CopyAddressOperand -> SectionBuilders
combinedSections opcode literal operand = SectionBuilders
  { dataStream        = byteString literal
  , instructionStream = word8 opcode
  , addressStream     = renderOperand operand }

-- | Pack one instruction on its own — a RUN, an ADD or COPY with no
-- combinable neighbour, or a half of an adjacency the table had no combined
-- entry for. ADD and RUN touch only the data section; a COPY emits its
-- already-chosen operand into the address section. Each takes the densest
-- single opcode: the fixed-size entry where the table names the size (no
-- size varint trails), the coded-size entry otherwise. RUN has only the
-- coded form. Exhaustive over the three kinds — no wildcard, so a fourth
-- could not slip through.
packSingle :: DenseOpcodes -> ResolvedInstruction -> SectionBuilders
packSingle resolver = \case
  ResolvedAdd literal ->
    let (opcode, sizeVarint) =
          singleSize resolver "ADD" (byteLength literal)
            (\size -> Table.CodeTableEntry (Table.Add size) Table.Noop)
    in SectionBuilders
         { dataStream        = byteString literal
         , instructionStream = word8 opcode <> sizeVarint
         , addressStream     = mempty }
  ResolvedRun runLength fillByte ->
    SectionBuilders
      { dataStream        = word8 fillByte
      , instructionStream = word8 codedRunOpcode <> varintOfLength runLength
      , addressStream     = mempty }
  ResolvedCopy copyLength mode operand ->
    let (opcode, sizeVarint) =
          singleSize resolver ("COPY mode " <> show (Table.unCopyAddressMode mode)) copyLength
            (\size -> Table.CodeTableEntry (Table.Copy size mode) Table.Noop)
    in SectionBuilders
         { dataStream        = mempty
         , instructionStream = word8 opcode <> sizeVarint
         , addressStream     = renderOperand operand }
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

-- | Render a window's three section streams to bytes under a table.
-- 'packInstructions' does the walk over the resolved stream — choosing
-- opcodes and combining adjacent pairs — and yields the three streams as
-- one 'SectionBuilders'; this realizes them.
layoutSections :: DenseOpcodes -> [ResolvedInstruction] -> Sections
layoutSections resolver resolved = Sections
  { sectionData         = builderBytes (dataStream combined)
  , sectionInstructions = builderBytes (instructionStream combined)
  , sectionAddresses    = builderBytes (addressStream combined)
  }
  where
    combined = packInstructions resolver resolved

----------------------------------------------------------------------------
-- Cover -> patch (default table, and the custom-table consideration)
----------------------------------------------------------------------------

-- | How a window sources its copies. A window with any COPY declares the
-- whole source as its segment ('DrawsFromSource' — the VCD_SOURCE indicator
-- and the two segment varints); an all-literal window is self-contained
-- ('SelfContained'), with neither. These are exactly the two wire branches
-- 'encodeWindow' takes, and naming them keeps that branch exhaustive: a
-- later sourcing — a VCD_TARGET window, once windows can reference earlier
-- output — lands here as a third constructor and a compile error at every
-- consumer, not a silent fall-through.
data WindowSourcing = SelfContained | DrawsFromSource
  deriving (Eq, Show)

-- | The table-independent groundwork for a cover's single window: the
-- resolved instruction stream (its COPY modes selected once, valid under
-- any table of the same cache geometry) and how the window sources its
-- copies. Both the default and the candidate emission build on the one
-- plan, and the design reads the resolved stream off it.
data WindowPlan = WindowPlan
  { planResolved :: ![ResolvedInstruction]
  , planSourcing :: !WindowSourcing
  }

-- | Plan a cover's single window against a source: select the instruction
-- stream's COPY addresses under the default cache geometry, and decide how
-- the window sources its copies. The write head starts at @len(S)@ for a
-- source-drawing window — the segment it declares — and at zero for a
-- self-contained one, which has no COPY to measure against it anyway.
planWindow :: ByteString -> ByteString -> Cover -> WindowPlan
planWindow source target cover = WindowPlan
  { planResolved = resolveInstructionAddresses defaultAddressCacheConfig initialHere instructions
  , planSourcing = sourcing
  }
  where
    instructions = coverToInstructions target cover
    sourcing     = windowSourcing instructions
    initialHere  = case sourcing of
      DrawsFromSource -> lengthToOffset (byteLength source)
      SelfContained   -> Offset 0

-- | How a window sources its copies, read off its instructions: any COPY
-- and it draws on the source (declaring the whole source as its segment);
-- none and it is self-contained. Total over the three instruction kinds.
windowSourcing :: [VCDIFFInstruction] -> WindowSourcing
windowSourcing instructions
  | any instructionCopies instructions = DrawsFromSource
  | otherwise                          = SelfContained
  where
    instructionCopies = \case
      Copy _ _ -> True
      Add _    -> False
      Run _ _  -> False

-- | The window bytes for a plan under a table: the Win_Indicator and (when
-- copying) the source-segment varints, then the delta encoding — target
-- size, Delta_Indicator, the three section lengths, and the three sections
-- — behind its length varint. When copying, the window declares the entire
-- source as its segment, so the COPY addresses can reach into @U@;
-- otherwise it is self-contained and the two segment varints are absent,
-- reproducing the bedrock floor exactly.
encodeWindow :: Table.CodeTable -> ByteString -> ByteString -> WindowPlan -> ByteString
encodeWindow table source target plan = builderBytes windowBuilder
  where
    sections = layoutSections (denseOpcodes table) (planResolved plan)

    -- The Win_Indicator and (for a source-drawing window) the
    -- source-segment varints, which precede the delta-encoding-length on
    -- the wire.
    windowIndicatorAndSegment = case planSourcing plan of
      DrawsFromSource ->
             word8 sourceSegmentWindow
          <> varintOfLength (byteLength source)   -- source-segment length
          <> putVcdiffVarint 0                    -- source-segment position
      SelfContained -> word8 selfContainedWindow

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

-- | A patch: the magic, the version, then the header — the indicator byte
-- and, when a custom table ships, its framed data — and the window.
assemblePatch :: Builder -> ByteString -> ByteString
assemblePatch headerAfterVersion windowBytes = builderBytes
  (  byteString vcdiffMagicBytes
  <> word8 version0
  <> headerAfterVersion
  <> byteString windowBytes )

-- | Emit a cover as a patch on the default code table — the core: the
-- pre-custom-table behaviour, and what ships whenever a custom table does
-- not pay. Also the encoder a custom table's inner delta runs through:
-- being default-only, the inner delta never itself declares a table, so it
-- decodes cleanly under the no-nesting policy the outer parse applies to
-- it.
emitDefaultPatch :: ByteString -> ByteString -> Cover -> ByteString
emitDefaultPatch source target cover =
  assemblePatch (word8 noHeaderFeatures)
                (encodeWindow Table.defaultCodeTable source target (planWindow source target cover))

-- | Emit a cover as a patch, weighing a custom code table against the
-- default and shipping whichever is smaller. The candidate is designed from
-- the cover's own resolved instruction stream ('designCandidateTable');
-- when none differs from the default, or the one that does fails to earn
-- its inner delta back, the default patch ships byte-for-byte. The choice
-- is an explicit branch, never a wildcard, so a third disposition would
-- have to be written down.
emitConsideringCustomTable :: ByteString -> ByteString -> Cover -> ByteString
emitConsideringCustomTable source target cover =
  case designCandidateTable (planResolved plan) of
    Nothing        -> defaultPatch
    Just candidate ->
      let candidatePatch = assembleCustomTablePatch source target plan candidate
      in if ByteString.length candidatePatch < ByteString.length defaultPatch
           then candidatePatch
           else defaultPatch
  where
    plan         = planWindow source target cover
    defaultPatch = assemblePatch (word8 noHeaderFeatures)
                                 (encodeWindow Table.defaultCodeTable source target plan)

-- | Assemble the custom-table patch for a designed candidate: the header
-- declares VCD_CODETABLE and carries the code-table data — the two
-- cache-size bytes (@s_near@, @s_same@, the default geometry, unchanged by
-- this stage) then the inner delta — behind its length varint, and the
-- window is the cover packed under the candidate. The inner delta is
-- @default-image → candidate-image@ through the default-only core
-- ('emitDefaultPatch'), so the table the decoder rebuilds from it is
-- exactly the one this window was packed against.
assembleCustomTablePatch :: ByteString -> ByteString -> WindowPlan -> Table.CodeTable -> ByteString
assembleCustomTablePatch source target plan candidate =
  assemblePatch (word8 customCodeTableHeader <> framedCodeTableData)
                (encodeWindow candidate source target plan)
  where
    framedCodeTableData = varintOfLength (byteLength codeTableData) <> byteString codeTableData
    codeTableData       = builderBytes (cacheSizeHeader <> byteString innerDelta)
    cacheSizeHeader     = word8 (fromIntegral (nearSlotCount  defaultAddressCacheConfig))
                       <> word8 (fromIntegral (sameBlockCount defaultAddressCacheConfig))
    innerDelta          = emitDefaultPatch defaultImage candidateImage
                            (vcdiffCover (InputFileContents defaultImage)
                                         (OutputFileContents candidateImage))
    defaultImage        = Table.serializeCodeTable Table.defaultCodeTable
    candidateImage      = Table.serializeCodeTable candidate

----------------------------------------------------------------------------
-- Candidate code-table design
----------------------------------------------------------------------------

-- | Design a candidate code table for a window's resolved instruction
-- stream, or 'Nothing' when no table would differ from the default. The
-- design is deliberately simple — this stage is the wire, not the
-- cleverness: tally the ADD+COPY and COPY+ADD adjacencies the default table
-- leaves to two opcodes (those it has no combined entry for), keep the ones
-- this patch repeats, and mint them — most frequent first — into donor
-- opcodes the patch never uses, leaving every other entry default. The
-- cache geometry stays the default 4/3, so every minted COPY mode is one
-- the declared caches reach and the decoder's mode check passes. A lopsided
-- stream earns several mints; an even one earns none — and a barely-lopsided
-- one earns a table the gate then declines.
-- Whatever the design produces, the window is packed against the very table
-- shipped, so the round-trip is correct regardless of how good the design
-- is; the gate, not the design, is what decides a table pays.
designCandidateTable :: [ResolvedInstruction] -> Maybe Table.CodeTable
designCandidateTable resolved
  | null mints = Nothing
  | otherwise  = Just (Table.codeTableWithEntriesReplaced Table.defaultCodeTable mints)
  where
    defaultDense = denseOpcodes Table.defaultCodeTable
    pairs        = combinablePairs resolved

    -- The combined opcodes the default already uses for this patch's pairs
    -- — excluded from the donor pool so a mint never overwrites an entry
    -- the patch still needs.
    usedCombinedOpcodes :: [Word8]
    usedCombinedOpcodes =
      [ opcode | entry <- pairs, Just opcode <- [opcodeFor defaultDense entry] ]

    -- The pairs the default cannot combine and this patch repeats, most
    -- frequent first — the mint candidates. A pair seen once cannot repay
    -- even the leanest table edit, so singletons are dropped here; the gate
    -- weighs whether the repeats that remain are worth their inner delta.
    mintableByFrequency :: [Table.CodeTableEntry]
    mintableByFrequency =
      [ entry
      | (entry, count) <- sortOn (Down . snd) (Map.toList (frequencies mintablePairs))
      , count >= 2 ]
      where mintablePairs = [ entry | entry <- pairs, opcodeFor defaultDense entry == Nothing ]

    -- Donor opcodes: the default's combined slots (its two-template
    -- entries) the patch does not use, in index order. The supply far
    -- exceeds the handful of mints in practice.
    donorOpcodes :: [Word8]
    donorOpcodes =
      [ fromIntegral index
      | (index, entry) <- zip [0 :: Int ..] (Vector.toList (Table.codeTableEntries Table.defaultCodeTable))
      , Table.secondTemplate entry /= Table.Noop
      , fromIntegral index `notElem` usedCombinedOpcodes
      ]

    -- Each mint candidate to a donor opcode; 'zip' drops nothing while
    -- donors outnumber mints, and a (vanishingly unlikely) donor shortage
    -- simply mints fewer.
    mints :: [(Word8, Table.CodeTableEntry)]
    mints = zip donorOpcodes mintableByFrequency

-- | The fixed-size ADD+COPY and COPY+ADD pairs a greedy left-to-right walk
-- would combine, as the code-table entries they would pack into — built by
-- the same 'addCopyEntry' \/ 'copyAddEntry' the packer's opcode lookups use,
-- so the design counts exactly the adjacencies the packer would combine.
-- Mirrors 'packInstructions''s preference — ADD+COPY before COPY+ADD,
-- non-overlapping — so a pair counted here is one a table holding the entry
-- would actually take. RUN never pairs; an instruction with no fixed-size
-- combinable neighbour is passed over.
combinablePairs :: [ResolvedInstruction] -> [Table.CodeTableEntry]
combinablePairs (ResolvedAdd literal : ResolvedCopy copyLength mode _ : rest)
  | Just entry <- addCopyEntry (byteLength literal) copyLength mode = entry : combinablePairs rest
combinablePairs (ResolvedCopy copyLength mode _ : ResolvedAdd literal : rest)
  | Just entry <- copyAddEntry copyLength mode (byteLength literal) = entry : combinablePairs rest
combinablePairs (_ : rest) = combinablePairs rest
combinablePairs []         = []

-- | Count occurrences of each element.
frequencies :: Ord a => [a] -> Map a Int
frequencies items = Map.fromListWith (+) [ (item, 1) | item <- items ]

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

-- | Hdr_Indicator with VCD_CODETABLE (bit 1) set: a custom code table's
-- length varint and data follow in the header. Distinct from the window's
-- VCD_SOURCE bit — this is the patch-level header indicator (RFC 3284
-- §4.1).
customCodeTableHeader :: Word8
customCodeTableHeader = 0x02

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
