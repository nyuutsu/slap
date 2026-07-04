{-# LANGUAGE LambdaCase #-}

-- | VCDIFF patch creation: a cover of the target serialized to wire bytes, in the arc the user named.
--
-- Creation has two halves. A /matcher/ ('Slap.VCDIFF.FFI.vcdiffCover', Rust-backed) segments the target into copies and literals, a 'Cover';
-- this module is the other half, turning a cover into a patch.
-- 'createRFCVCDIFF' and 'createXDelta3' run the matcher and serialize its cover;
-- when the matcher finds nothing the cover is all-literal and the bytes are the bedrock floor's exactly.
-- The cover-driven entries ('createFromCover', 'createConsideringCustomTable') let tests exercise the full COPY\/ADD\/RUN path on hand-built covers.
--
-- The path is cover to instructions to resolved instructions to wire bytes, source-free, under the active code table, in one window:
-- each segment becomes an instruction ('coverToInstructions'),
-- each COPY's address is resolved once against the cache ('resolveInstructionAddresses'),
-- and the resolved stream packs into the densest opcodes the table offers ('packInstructions').
--
-- The create token names the arc the user asked for; the bytes earn their flavor by the features they use.
-- A patch on the default table with no checksum and no compressed section reaches for no flavor-distinguishing feature,
-- so it parses back as 'Slap.VCDIFF.Types.PatchCoreOnly';
-- a custom code table is an RFC-arc feature (RFC 3284 §7's VCD_CODETABLE), parsing back as @PatchRFC@;
-- a per-window Adler32 and a declared secondary compressor are xdelta3 extensions, parsing back as @PatchXDelta3@.
--
-- A custom code table carries its own opcode assignments and cache geometry, tuned to this patch:
-- combined opcodes for the ADD+COPY and COPY+ADD pairs it repeats,
-- single-instruction opcodes for the lone ADD and COPY sizes it repeats outside the default's fixed-size rows,
-- and an address cache grown from the default four-near\/three-same to where a larger cache stops shrinking the address section.
-- The table travels as a VCDIFF delta /inside/ the patch
-- (the default 1536-byte image transformed by an inner delta this module emits on the default-only core),
-- so a table close to the default costs almost nothing to ship.
-- 'createRFCVCDIFF' grows the cache a slot at a time, redesigns the table under each geometry,
-- and ships the smallest candidate, but only when it beats the no-custom-table default patch outright.
-- The design ('designCandidateTable') stays deliberately simple; sharpening it is later work.
-- 'createXDelta3' never considers one: xdelta3 rejects custom tables, so on that arc the default table is the only table there is.
module Slap.VCDIFF.Create
  ( createRFCVCDIFF
  , createXDelta3
  , rejectUnaddressablePair
    -- * Cover-driven emission (exported for testing)
  , createFromCover
  , createConsideringCustomTable
  , coverToInstructions
    -- * Address resolution and candidate-table design (exported for testing)
  , ResolvedInstruction(..)
  , resolveInstructionAddresses
  , designCandidateTable
  ) where

import Slap.VCDIFF.Types (vcdiffMagicBytes, VCDIFFInstruction(..),
                          vcdDecompressBit, vcdSourceBit, vcdAdler32Bit,
                          vcdDataCompBit, vcdInstCompBit, vcdAddrCompBit)
import Slap.VCDIFF.SecondaryCompression
  ( XDelta3SecondaryCompressor(..), secondaryCompressorId
  , SectionCarriage(..), carriageBytes, lzmaSectionCarriage )
import Slap.VCDIFF.Cover (Cover(..), CoverSegment(..))
import Slap.VCDIFF.FFI (vcdiffCover)
import Slap.VCDIFF.AddressCache
  ( AddressCacheConfig(..), NearSlotCount(..), SameBlockCount(..)
  , freshAddressCache, defaultAddressCacheConfig
  , selectCopyAddressMode, SelectedCopyAddress(..), CopyAddressOperand(..)
  , SameSlotByte(..) )
import qualified Slap.VCDIFF.CodeTable as Table
import Slap.Binary (putVcdiffVarint, viewBytesInRange)
import Slap.Checksum (Adler32(..))
import Slap.FFI (adler32)
import Slap.MetadataInclusion (VerificationInclusion(..), CompressionInclusion(..))
import Slap.Status (SlapError(..), CreateResult(..))
import Slap.Measure (Offset(..), Length(..), FileSize(..), byteLength, byteFileSize,
                     Cursor(..), lengthToOffset,
                     SourceFileSize(..), TargetFileSize(..), MaxAddressableSize(..))
import Slap.FileContents (InputFileContents(..), OutputFileContents(..), PatchFileContents(..))

import Data.Bits (bit, (.|.))
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.ByteString.Builder (Builder, byteString, word8, word32BE, toLazyByteString)
import qualified Data.ByteString.Lazy as LazyByteString
import Data.List (sortOn)
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Maybe (fromMaybe)
import Data.Ord (Down(..))
import Data.Word (Word8)

-- | Create a VCDIFF patch reconstructing @target@.
-- The cover comes from the matcher ('Slap.VCDIFF.FFI.vcdiffCover'), so the patch copies the runs the target shares with the source or with itself;
-- the bytes are then weighed under the default table and a designed custom one, the smaller shipping ('createConsideringCustomTable').
-- When the matcher finds nothing (an unrelated source, a target shorter than the minimum match)
-- the cover is all-literal and the bytes are the bedrock floor's exactly.
-- The 'Either' carries one refusal of its own, a pair the matcher could not address ('rejectUnaddressablePair');
-- no metadata, no advisories.
createRFCVCDIFF :: InputFileContents -> OutputFileContents
                -> Either SlapError CreateResult
createRFCVCDIFF inputContents@(InputFileContents source) outputContents@(OutputFileContents target) = do
  rejectUnaddressablePair (SourceFileSize (byteFileSize source)) (TargetFileSize (byteFileSize target))
  Right (createConsideringCustomTable inputContents outputContents
           (vcdiffCover inputContents outputContents))

-- | Create an xdelta3 patch reconstructing @target@:
-- the same matcher-driven cover as 'createRFCVCDIFF', emitted with the extensions the canonical tool's own output carries.
-- Today those are the per-window Adler32
-- (on by default, declined by @--omit-verification@; the only integrity data the format has,
-- so opting out leaves nothing attesting the output — the same gap 'Slap.Status.VerificationOptedOutByCreator' names at apply)
-- and LZMA secondary compression
-- (on by default, declined by @--no-compress@; kept per section only where it shrinks,
-- and shipped only when the compressed patch beats the plain one outright — see 'emitXDelta3Patch').
-- Never a custom code table: xdelta3 rejects them.
-- A patch emitted with both extensions declined — or with verification declined and compression never paying —
-- uses no flavor-distinguishing feature at all,
-- parsing back as 'Slap.VCDIFF.Types.PatchCoreOnly' — readable as xdelta3, which is what was asked for.
createXDelta3 :: VerificationInclusion -> CompressionInclusion -> InputFileContents -> OutputFileContents
              -> Either SlapError CreateResult
createXDelta3 verificationChoice compressionChoice inputContents@(InputFileContents source) outputContents@(OutputFileContents target) = do
  rejectUnaddressablePair (SourceFileSize (byteFileSize source)) (TargetFileSize (byteFileSize target))
  Right (CreateResult (PatchFileContents patchBytes) [])
  where
    patchBytes = emitXDelta3Patch checksumEmission compressionEmission source target
                   (vcdiffCover inputContents outputContents)
    checksumEmission = case verificationChoice of
      IncludeVerification -> CarryWindowAdler32
      OmitVerification    -> OmitWindowAdler32
    compressionEmission = case compressionChoice of
      IncludeCompression -> CompressSectionsWithLZMA
      OmitCompression    -> EmitSectionsPlain

-- | Refuse a pair whose superstring slap could not address: a COPY names an absolute offset into
-- @U = source ++ target@, so the pair's combined size (plus the matcher's two sentinels) must fit
-- the 'Int' every offset rides — past 'maxBound' the cover would come back with positions the carrier cannot hold.
-- Judged in 'Integer', where the very overflow being refused cannot corrupt the judgment,
-- and on sizes alone, so tests can hold the boundary without allocating the files that would sit there.
-- The pair-wise sibling of BPS's per-file 'Slap.BPS.Create.guardAddressable':
-- BPS's wire offsets are relative to one file, so its per-file guard covers its carrier; VCDIFF's span both.
rejectUnaddressablePair :: SourceFileSize -> TargetFileSize -> Either SlapError ()
rejectUnaddressablePair sourceSize@(SourceFileSize source) targetSize@(TargetFileSize target)
  | augmentedLength > toInteger (maxBound :: Int) =
      Left (VCDIFFPairExceedsAddressableRange sourceSize targetSize
              (MaxAddressableSize (FileSize maxBound)))
  | otherwise = Right ()
  where
    augmentedLength = toInteger (unFileSize source) + toInteger (unFileSize target) + 2

-- | Serialize a cover of @target@ against @source@ into a VCDIFF patch on the default code table, with no custom-table consideration: the core.
-- Tests drive it with hand-built covers to pin the emitter, and the custom-table path reuses it for the inner delta.
-- The 'CreateResult' carries no advisories.
createFromCover :: InputFileContents -> OutputFileContents -> Cover -> CreateResult
createFromCover (InputFileContents source) (OutputFileContents target) cover =
  CreateResult (PatchFileContents (emitDefaultPatch source target cover)) []

-- | Serialize a cover into a VCDIFF patch, weighing a custom code table against the default and shipping the smaller:
-- the cover-driven form of 'createRFCVCDIFF''s consideration, exposed so tests can exercise the custom-table path on a hand-built cover.
-- Total, like 'createFromCover'.
createConsideringCustomTable :: InputFileContents -> OutputFileContents -> Cover -> CreateResult
createConsideringCustomTable (InputFileContents source) (OutputFileContents target) cover =
  CreateResult (PatchFileContents (emitConsideringCustomTable source target cover)) []

----------------------------------------------------------------------------
-- Cover -> instructions
----------------------------------------------------------------------------

-- | Choose an instruction for each cover segment: a copy passes through to 'Copy', a literal becomes a 'Run' or 'Add' (see 'literalToInstruction').
coverToInstructions :: ByteString -> Cover -> [VCDIFFInstruction]
coverToInstructions target (Cover segments) = map segmentToInstruction segments
  where
    segmentToInstruction = \case
      CoverCopy copyLength superstringOffset -> Copy copyLength superstringOffset
      CoverLiteral literalStart literalLength ->
        literalToInstruction (viewBytesInRange literalStart literalLength target)

-- | A literal run becomes a 'Run' of its single repeated byte, or an 'Add' of its bytes verbatim.
literalToInstruction :: ByteString -> VCDIFFInstruction
literalToInstruction literalBytes
  | isSingleRepeatedByte literalBytes =
      Run (byteLength literalBytes) (ByteString.head literalBytes)
  | otherwise = Add literalBytes

-- | Whether a literal is three or more copies of one byte.
-- From length 3 a coded 'Run' is never larger than the equivalent 'Add';
-- at length 2 they tie, and only an 'Add' can fold into a combined ADD+COPY, so a two-byte repeat stays an 'Add'.
isSingleRepeatedByte :: ByteString -> Bool
isSingleRepeatedByte bytes =
  byteLength bytes >= Length 3 && ByteString.all (== ByteString.head bytes) bytes

----------------------------------------------------------------------------
-- Instructions -> resolved instructions (address selection)
----------------------------------------------------------------------------

-- | An instruction whose COPY address has been resolved to a concrete address mode and the operand that mode reads back;
-- ADD and RUN, naming no address, carry through unchanged. The address cache is threaded once, here, to produce these.
-- The result is table-independent (the cache geometry, not the code table, fixes each mode),
-- so one resolved stream serves the default-table emission, a candidate-table emission,
-- and the candidate-table /design/, which reads the modes off it.
data ResolvedInstruction
  = ResolvedAdd  !ByteString
  | ResolvedRun  !Length !Word8
  | ResolvedCopy !Length !Table.CopyAddressMode !CopyAddressOperand
    -- ^ the COPY's length, its chosen address mode, and the operand the address section carries for that mode.
    -- The fill byte of 'ResolvedRun' stays a bare 'Word8', a verbatim literal value rather than a protocol quantity,
    -- but a COPY's mode is the 'Table.CopyAddressMode' the code table speaks,
    -- lifted out of 'selectCopyAddressMode''s wire byte once here, not re-wrapped at each use.
  deriving (Eq, Show)

-- | Thread the address cache over a window's instructions, resolving each COPY to its cheapest mode and operand
-- through 'selectCopyAddressMode' — the same selection (running the same 'Slap.VCDIFF.AddressCache.recordAddress') that the decoder inverts.
-- @here@, the write head in @U@ that HERE mode measures back from, starts at @len(S)@ and advances by each instruction's output length;
-- only a COPY consults and updates the cache.
-- The result feeds both 'layoutSections' (which packs it under a table) and 'designCandidateTable' (which tallies its adjacencies).
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

-- | The three section byte-streams under construction.
-- One value is both a single instruction's contribution and, the type being a 'Monoid' that combines the streams componentwise,
-- a whole window's accumulation, so a window's sections are exactly the fold of its instructions' pieces in order.
-- A field is 'mempty' where an instruction contributes nothing there (a COPY adds no data; an ADD or RUN adds no address).
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

-- | Pack a window's resolved instructions into the three section streams under a table, choosing the densest opcode the table offers each step.
-- A one-step lookahead packs an adjacent ADD+COPY or COPY+ADD into one combined opcode
-- when the table holds an entry for the pair's sizes and the COPY's already-chosen mode;
-- otherwise each instruction packs on its own, and RUN never combines.
-- Greedy left-to-right takes a maximal set of non-overlapping pairs, each saving one opcode.
-- No cache here: the modes and operands were fixed by 'resolveInstructionAddresses', so packing is pure opcode lookup over the resolved stream.
packInstructions :: DenseOpcodes -> [ResolvedInstruction] -> SectionBuilders
packInstructions opcodeResolver = packFrom
  where
    packFrom [] = mempty
    packFrom (ResolvedAdd literal : ResolvedCopy copyLength mode operand : rest)
      | Just opcode <- combinedAddCopyOpcode opcodeResolver (byteLength literal) copyLength mode =
          combinedSections opcode literal operand <> packFrom rest
    packFrom (ResolvedCopy copyLength mode operand : ResolvedAdd literal : rest)
      | Just opcode <- combinedCopyAddOpcode opcodeResolver copyLength mode (byteLength literal) =
          combinedSections opcode literal operand <> packFrom rest
    packFrom (instruction : rest) = packSingle opcodeResolver instruction <> packFrom rest

-- | The combined code-table entry an ADD(addLength) immediately followed by a COPY(copyLength, mode) packs into,
-- when both lengths name fixed-size entries, 'Nothing' otherwise.
-- Shared by the packer's opcode lookup ('combinedAddCopyOpcode') and the candidate-table design ('combinablePairs'),
-- so the two agree on what a combinable adjacency /is/ by constructing it the one way.
addCopyEntry :: Length -> Length -> Table.CopyAddressMode -> Maybe Table.CodeTableEntry
addCopyEntry addLength copyLength mode = do
  addSize  <- fixedSizeFor addLength
  copySize <- fixedSizeFor copyLength
  pure (Table.CodeTableEntry (Table.Add addSize) (Table.Copy copySize mode))

-- | The combined entry a COPY(copyLength, mode) immediately followed by an ADD(addLength) packs into: the mirror of 'addCopyEntry'.
copyAddEntry :: Length -> Table.CopyAddressMode -> Length -> Maybe Table.CodeTableEntry
copyAddEntry copyLength mode addLength = do
  copySize <- fixedSizeFor copyLength
  addSize  <- fixedSizeFor addLength
  pure (Table.CodeTableEntry (Table.Copy copySize mode) (Table.Add addSize))

-- | The opcode an ADD-then-COPY adjacency packs into under a table: the shared 'addCopyEntry', looked up in the active table.
-- The mode is the one 'resolveInstructionAddresses' already selected, so a combine never shifts the COPY off the cheapest address mode.
combinedAddCopyOpcode :: DenseOpcodes -> Length -> Length -> Table.CopyAddressMode -> Maybe Table.Opcode
combinedAddCopyOpcode opcodeResolver addLength copyLength mode =
  addCopyEntry addLength copyLength mode >>= opcodeFor opcodeResolver

-- | The opcode a COPY-then-ADD adjacency packs into under a table: the mirror of 'combinedAddCopyOpcode'.
combinedCopyAddOpcode :: DenseOpcodes -> Length -> Table.CopyAddressMode -> Length -> Maybe Table.Opcode
combinedCopyAddOpcode opcodeResolver copyLength mode addLength =
  copyAddEntry copyLength mode addLength >>= opcodeFor opcodeResolver

-- | The three section contributions of a combined opcode:
-- the single instruction byte (both halves carry a fixed size, so no out-of-line size varint follows),
-- the ADD half's literal in the data section, and the COPY half's operand in the address section.
-- A combined opcode contributes exactly one of each regardless of the halves' order, so one shape serves ADD+COPY and COPY+ADD alike.
combinedSections :: Table.Opcode -> ByteString -> CopyAddressOperand -> SectionBuilders
combinedSections opcode literal operand = SectionBuilders
  { dataStream        = byteString literal
  , instructionStream = word8 (Table.unOpcode opcode)
  , addressStream     = renderOperand operand }

-- | Pack one instruction on its own:
-- a RUN, an ADD or COPY with no combinable neighbour, or a half of an adjacency the table had no combined entry for.
-- ADD and RUN touch only the data section; a COPY emits its already-chosen operand into the address section.
-- Each takes the densest single opcode, the fixed-size entry where the table names the size (no size varint trails)
-- and the coded-size entry otherwise; RUN has only the coded form.
packSingle :: DenseOpcodes -> ResolvedInstruction -> SectionBuilders
packSingle opcodeResolver = \case
  ResolvedAdd literal ->
    let (opcode, sizeVarint) =
          singleSize opcodeResolver (byteLength literal)
            (\size -> Table.CodeTableEntry (Table.Add size) Table.Noop)
    in SectionBuilders
         { dataStream        = byteString literal
         , instructionStream = word8 (Table.unOpcode opcode) <> sizeVarint
         , addressStream     = mempty }
  ResolvedRun runLength fillByte ->
    SectionBuilders
      { dataStream        = word8 fillByte
      , instructionStream = word8 (Table.unOpcode codedRunOpcode) <> varintOfLength runLength
      , addressStream     = mempty }
  ResolvedCopy copyLength mode operand ->
    let (opcode, sizeVarint) =
          singleSize opcodeResolver copyLength
            (\size -> Table.CodeTableEntry (Table.Copy size mode) Table.Noop)
    in SectionBuilders
         { dataStream        = mempty
         , instructionStream = word8 (Table.unOpcode opcode) <> sizeVarint
         , addressStream     = renderOperand operand }
  where
    codedRunOpcode = requireOpcode opcodeResolver
      (Table.CodeTableEntry (Table.Run Table.SizeCodedSeparately) Table.Noop)

-- | The address-section bytes a chosen mode's operand contributes: a
-- varint for SELF \/ HERE \/ NEAR, a single byte for SAME.
renderOperand :: CopyAddressOperand -> Builder
renderOperand (AddressVarint value) = putVcdiffVarint value
renderOperand (AddressSameByte (SameSlotByte byte)) = word8 byte

-- | The densest opcode the active table offers for an exact entry shape, or 'Nothing' when the table holds no such entry.
-- Built once per table by scanning 'Table.codeTableAssocs' (so a custom table feeds its own opcode set through unchanged),
-- keyed by the whole entry so one lookup answers every query, a single instruction (a 'Table.Noop' second half) or a combined pair (two real halves).
-- The lowest index wins a shape that repeats; the default table holds each shape once.
newtype DenseOpcodes = DenseOpcodes (Map Table.CodeTableEntry Table.Opcode)

denseOpcodes :: Table.CodeTable -> DenseOpcodes
denseOpcodes table = DenseOpcodes
  (Map.fromListWith (\_later earlier -> earlier)
    [ (entry, opcode) | (opcode, entry) <- Table.codeTableAssocs table ])

-- | The opcode an entry shape carries in the active table, if any.
opcodeFor :: DenseOpcodes -> Table.CodeTableEntry -> Maybe Table.Opcode
opcodeFor (DenseOpcodes opcodes) entry = Map.lookup entry opcodes

-- | The opcode for an entry the active table must carry: the coded-size singles every usable table holds.
-- Loud, not silent, if absent: the default table carries them all and a custom table the encoder emits would too,
-- so a miss means a broken table, surfaced as a loud 'error' the way the other must-hold lookups here are.
requireOpcode :: DenseOpcodes -> Table.CodeTableEntry -> Table.Opcode
requireOpcode opcodeResolver entry = case opcodeFor opcodeResolver entry of
  Just opcode -> opcode
  Nothing     -> error ("Slap.VCDIFF.Create: active code table lacks the entry " <> show entry)

-- | A fixed inline size for a length the one-byte size field can name (1–255);
-- 'Nothing' for zero or for a length too large to sit inline, which falls back to a coded-size opcode.
-- The guard is load-bearing: a raw 'fromIntegral' would wrap a 260-byte run to a fixed size of 4 and emit the wrong opcode for it.
fixedSizeFor :: Length -> Maybe Table.InstructionSize
fixedSizeFor (Length n)
  | n >= 1 && n <= 255 = Just (Table.SizeIs (Table.FixedInstructionSize (fromIntegral n)))
  | otherwise          = Nothing

-- | The opcode and any trailing size bytes for one single instruction of the given output size:
-- the table's fixed-size entry where it has one (the size rides in the opcode, nothing trails), else its coded-size entry (a size varint trails).
-- @entryFor@ builds the lookup key from a size.
singleSize
  :: DenseOpcodes -> Length
  -> (Table.InstructionSize -> Table.CodeTableEntry)
  -> (Table.Opcode, Builder)
singleSize opcodeResolver size entryFor =
  case fixedSizeFor size >>= opcodeFor opcodeResolver . entryFor of
    Just opcode -> (opcode, mempty)
    Nothing     ->
      ( requireOpcode opcodeResolver (entryFor Table.SizeCodedSeparately)
      , varintOfLength size )

-- | Render a window's three section streams to bytes under a table.
-- 'packInstructions' walks the resolved stream, choosing opcodes and combining adjacent pairs,
-- and yields the three streams as one 'SectionBuilders'; this realizes them.
layoutSections :: DenseOpcodes -> [ResolvedInstruction] -> Sections
layoutSections opcodeResolver resolved = Sections
  { sectionData         = builderBytes (dataStream combined)
  , sectionInstructions = builderBytes (instructionStream combined)
  , sectionAddresses    = builderBytes (addressStream combined)
  }
  where
    combined = packInstructions opcodeResolver resolved

----------------------------------------------------------------------------
-- Cover -> patch (default table, and the custom-table consideration)
----------------------------------------------------------------------------

-- | How a window sources its copies.
-- A window with any COPY declares the whole source as its segment ('DrawsFromSource', the VCD_SOURCE indicator and the two segment varints);
-- an all-literal window is self-contained ('SelfContained'), with neither.
-- These are exactly the two wire branches 'encodeWindow' takes, and naming them keeps that branch exhaustive:
-- a later sourcing (a VCD_TARGET window, once windows can reference earlier output)
-- lands here as a third constructor and a compile error at every consumer, not a silent fall-through.
data WindowSourcing = SelfContained | DrawsFromSource
  deriving (Eq, Show)

-- | Whether an emitted window carries the per-window Adler32 of its output (VCD_ADLER32, an xdelta3 extension).
-- The RFC and core emissions always pass 'OmitWindowAdler32' — their windows have no slot for a checksum,
-- the write-side mirror of 'Slap.VCDIFF.Types.XDelta3Window' being the only window type that carries one.
data WindowChecksumEmission = CarryWindowAdler32 | OmitWindowAdler32
  deriving (Eq, Show)

-- | Whether an emitted window's sections ride through the LZMA secondary compressor where that
-- shrinks them, or all ride plain. The compression sibling of 'WindowChecksumEmission'.
-- The RFC and core emissions always pass 'EmitSectionsPlain': the RFC defines secondary compression's framing but no compressor,
-- so the RFC arc's catalog is empty and there is nothing such a patch could declare (docs/vcdiff/questions.md, "secondary compressor declared").
data WindowCompressionEmission = CompressSectionsWithLZMA | EmitSectionsPlain
  deriving (Eq, Show)

-- | A window rendered to wire bytes, paired with how its sections went out.
-- The patch header must declare the secondary compressor exactly when some window's
-- section leans on it, so the fact rides up beside the bytes.
data EncodedWindow = EncodedWindow
  { encodedWindowBytes              :: !ByteString
  , encodedWindowSectionCompression :: !WindowSectionCompression
  }

-- | Whether any of an emitted window's three sections rides secondary-compressed.
data WindowSectionCompression = SomeSectionsCompressed | AllSectionsPlain
  deriving (Eq, Show)

-- | The table-independent groundwork for a cover's single window: how the window sources its copies,
-- and the resolved instruction stream (its COPY modes selected once, valid under any table of the same cache geometry).
-- Both the default and the candidate emission build on the one plan, and the design reads the resolved stream off it.
data WindowPlan = WindowPlan
  { planResolved :: ![ResolvedInstruction]
  , planSourcing :: !WindowSourcing
  }

-- | Plan a cover's single window against a source under a cache geometry:
-- select the instruction stream's COPY addresses against the given 'AddressCacheConfig', and decide how the window sources its copies.
-- The write head starts at @len(S)@ for a source-drawing window (the segment it declares)
-- and at zero for a self-contained one, which has no COPY to measure against it anyway.
--
-- The config is the one the window will declare:
-- its addresses are resolved against the very cache the decoder rebuilds from the table data's cache sizes,
-- so resolve and declaration cannot drift (see 'assembleCustomTablePatch').
-- 'emitDefaultPatch' plans under 'defaultAddressCacheConfig'; 'grownCacheCandidate' plans under each config it probes.
planWindow :: AddressCacheConfig -> ByteString -> ByteString -> Cover -> WindowPlan
planWindow config source target cover = WindowPlan
  { planResolved = resolveInstructionAddresses config initialHere instructions
  , planSourcing = sourcing
  }
  where
    instructions = coverToInstructions target cover
    sourcing     = windowSourcing instructions
    initialHere  = case sourcing of
      DrawsFromSource -> lengthToOffset (byteLength source)
      SelfContained   -> Offset 0

-- | How a window sources its copies, read off its instructions:
-- any COPY and it draws on the source (declaring the whole source as its segment), none and it is self-contained.
-- Total over the three instruction kinds.
windowSourcing :: [VCDIFFInstruction] -> WindowSourcing
windowSourcing instructions
  | any instructionCopies instructions = DrawsFromSource
  | otherwise                          = SelfContained
  where
    instructionCopies = \case
      Copy _ _ -> True
      Add _    -> False
      Run _ _  -> False

-- | The window for a plan under a table:
-- the Win_Indicator and (when copying) the source-segment varints, then the delta encoding behind its length varint —
-- target size, Delta_Indicator, the three section lengths, the checksum when carried, the three sections.
-- When copying, the window declares the entire source as its segment so the COPY addresses can reach into @U@;
-- otherwise it is self-contained, the two segment varints absent, reproducing the bedrock floor exactly.
-- Under 'CompressSectionsWithLZMA' each section rides the carriage 'lzmaSectionCarriage' chooses for it,
-- the Delta_Indicator bits composed from the choices; one window means each kind's stream is exactly its one section.
encodeWindow :: Table.CodeTable -> ByteString -> ByteString
             -> WindowChecksumEmission -> WindowCompressionEmission -> WindowPlan -> EncodedWindow
encodeWindow table source target checksumEmission compressionEmission plan =
  EncodedWindow (builderBytes windowBuilder) sectionCompression
  where
    sections = layoutSections (denseOpcodes table) (planResolved plan)

    chooseCarriage = case compressionEmission of
      CompressSectionsWithLZMA -> lzmaSectionCarriage
      EmitSectionsPlain        -> CarriedPlain
    dataCarriage        = chooseCarriage (sectionData sections)
    instructionCarriage = chooseCarriage (sectionInstructions sections)
    addressCarriage     = chooseCarriage (sectionAddresses sections)

    sectionCompression = case (dataCarriage, instructionCarriage, addressCarriage) of
      (CarriedPlain _, CarriedPlain _, CarriedPlain _) -> AllSectionsPlain
      _                                                -> SomeSectionsCompressed

    deltaIndicator :: Word8
    deltaIndicator =
      carriageCompressionBit vcdDataCompBit dataCarriage
        .|. carriageCompressionBit vcdInstCompBit instructionCarriage
        .|. carriageCompressionBit vcdAddrCompBit addressCarriage

    -- The Win_Indicator and (for a source-drawing window) the source-segment varints, which precede the delta-encoding-length on the wire.
    windowIndicatorAndSegment =
      word8 (windowIndicator (planSourcing plan) checksumEmission)
        <> case planSourcing plan of
             DrawsFromSource ->
                  varintOfLength (byteLength source)   -- source-segment length
               <> putVcdiffVarint 0                    -- source-segment position
             SelfContained -> mempty

    -- The carried checksum is the Adler32 of this window's decoded output — the whole target, the window being the only one —
    -- computed here so the value cannot drift from the window it attests.
    -- Four bytes big-endian between the section lengths and the data section (docs/vcdiff/xdelta3/spec.md "Per-window Adler32").
    checksumBytes = case checksumEmission of
      CarryWindowAdler32 -> word32BE (unAdler32 (adler32 target))
      OmitWindowAdler32  -> mempty

    -- Everything the delta-encoding-length field measures:
    -- the target window size, the indicator, the three section lengths, the checksum when carried, then the three sections in order.
    deltaEncoding = builderBytes
      (  varintOfLength (byteLength target)
      <> word8 deltaIndicator
      <> varintOfLength (byteLength (carriageBytes dataCarriage))
      <> varintOfLength (byteLength (carriageBytes instructionCarriage))
      <> varintOfLength (byteLength (carriageBytes addressCarriage))
      <> checksumBytes
      <> byteString (carriageBytes dataCarriage)
      <> byteString (carriageBytes instructionCarriage)
      <> byteString (carriageBytes addressCarriage) )

    windowBuilder =
         windowIndicatorAndSegment
      <> varintOfLength (byteLength deltaEncoding)
      <> byteString deltaEncoding

-- | A kind's Delta_Indicator contribution: its compression bit when its section rides compressed, no bit when plain.
carriageCompressionBit :: Int -> SectionCarriage -> Word8
carriageCompressionBit _           (CarriedPlain _)      = 0x00
carriageCompressionBit bitPosition (CarriedCompressed _) = bit bitPosition

-- | A patch: the magic, the version, then the header (the indicator byte and, when a custom table ships, its framed data), and the window.
assemblePatch :: Builder -> ByteString -> ByteString
assemblePatch headerAfterVersion windowBytes = builderBytes
  (  byteString vcdiffMagicBytes
  <> word8 version0
  <> headerAfterVersion
  <> byteString windowBytes )

-- | Emit a cover as a patch on the default code table: the core, what ships whenever a custom table does not pay.
-- Also the encoder a custom table's inner delta runs through: being default-only, the inner delta never declares a table itself,
-- so it decodes cleanly under the no-nesting policy the outer parse applies to it.
emitDefaultPatch :: ByteString -> ByteString -> Cover -> ByteString
emitDefaultPatch source target cover =
  assemblePatch (word8 noHeaderFeatures)
                (encodedWindowBytes
                   (encodeWindow Table.defaultCodeTable source target OmitWindowAdler32 EmitSectionsPlain
                      (planWindow defaultAddressCacheConfig source target cover)))

-- | Emit a cover as an xdelta3 patch: the default table always (xdelta3 rejects custom ones),
-- the window carrying its Adler32 when verification is included,
-- its sections riding the LZMA secondary compressor where that shrinks them when compression is included.
-- The header declares the compressor exactly when some section leans on it
-- ('xdelta3HeaderFor'), so a window whose sections all stayed plain declares nothing
-- and its patch comes out byte-identical to the plain emission.
-- The compressed emission ships only when it beats the plain one outright —
-- the same explicit gate 'emitConsideringCustomTable' holds its candidate to,
-- catching the edge where a section shrinks by no more than the one extra header byte
-- (the compressor id) its declaration costs.
emitXDelta3Patch :: WindowChecksumEmission -> WindowCompressionEmission -> ByteString -> ByteString -> Cover -> ByteString
emitXDelta3Patch checksumEmission compressionEmission source target cover =
  case compressionEmission of
    EmitSectionsPlain -> plainPatch
    CompressSectionsWithLZMA
      | ByteString.length compressedPatch < ByteString.length plainPatch -> compressedPatch
      | otherwise                                                        -> plainPatch
  where
    plan            = planWindow defaultAddressCacheConfig source target cover
    plainPatch      = assembledUnder EmitSectionsPlain
    compressedPatch = assembledUnder CompressSectionsWithLZMA
    assembledUnder emission =
      let encodedWindow = encodeWindow Table.defaultCodeTable source target checksumEmission emission plan
      in assemblePatch (xdelta3HeaderFor (encodedWindowSectionCompression encodedWindow))
                       (encodedWindowBytes encodedWindow)

-- | The xdelta3 patch header for what the window actually did: VCD_DECOMPRESS and LZMA's
-- catalog id when some section rides compressed, the bare header when none does —
-- the declaration exists exactly where it is used.
xdelta3HeaderFor :: WindowSectionCompression -> Builder
xdelta3HeaderFor SomeSectionsCompressed =
  word8 (bit vcdDecompressBit) <> word8 (secondaryCompressorId SecondaryLZMA)
xdelta3HeaderFor AllSectionsPlain = word8 noHeaderFeatures

-- | Emit a cover as a patch, weighing custom code tables against the default and shipping whichever is smallest.
-- The candidate is grown from the default cache geometry up to where a larger cache stops shrinking the patch
-- ('grownCacheCandidate'), its table designed afresh under each config probed, then gated against the no-custom-table default patch.
-- The default patch ships unless a candidate beats it outright:
-- when no table differs from the default and no larger cache pays, the grow's smallest is the default-geometry candidate,
-- which carries the custom-table overhead for nothing and loses the gate.
-- The gate is an explicit branch, never a wildcard, so a third disposition would have to be written down.
emitConsideringCustomTable :: ByteString -> ByteString -> Cover -> ByteString
emitConsideringCustomTable source target cover
  | ByteString.length grownCandidate < ByteString.length defaultPatch = grownCandidate
  | otherwise                                                         = defaultPatch
  where
    grownCandidate = grownCacheCandidate source target cover
    defaultPatch   = emitDefaultPatch source target cover

-- | The custom-table patch for one cache geometry, or 'Nothing' when no sound table fits the config's modes into the donor pool.
-- Resolve the cover's window under @config@, take the donor reassignments its stream needs and repeats ('donorMints'),
-- and assemble the custom-table patch declaring @config@.
-- The window's addresses are resolved under the very config the patch declares, so every COPY mode the stream selected
-- (and so every mode a minted entry names) is one the declared cache defines, and the decoder's mode check accepts it.
-- The default geometry is always feasible: it admits no mode past the default nine, all named by the default table.
candidatePatchForConfig :: ByteString -> ByteString -> Cover -> AddressCacheConfig -> Maybe ByteString
candidatePatchForConfig source target cover config =
  fmap assembleUnderDesignedTable (donorMints (planResolved plan))
  where
    plan = planWindow config source target cover
    assembleUnderDesignedTable assignments =
      assembleCustomTablePatch config source target plan
        (Table.codeTableWithEntriesReplaced Table.defaultCodeTable assignments)

-- | A cache geometry probed during the grow, paired with the custom-table patch bytes it produces.
-- The grow threads this so a geometry and the patch it yields are carried as one and never drift apart.
data CacheProbe = CacheProbe
  { probeGeometry   :: !AddressCacheConfig
  , probePatchBytes :: !ByteString
  }

-- | The byte size of a probe's patch: the quantity the grow steers by.
probePatchSize :: CacheProbe -> Int
probePatchSize = ByteString.length . probePatchBytes

-- | Grow the cache geometry from the default to where a larger cache stops paying, returning the smallest custom-table candidate found.
-- A larger cache only ever shrinks the address section (the near cache holds a strict superset of recent addresses, the same cache collides less),
-- so each dimension grows cleanly: bump it a slot while the assembled patch strictly shrinks,
-- stop when a slot buys nothing (or the bumped config is infeasible).
-- Near is grown first, then same from there; the two interact, so the order can nudge where it lands,
-- which is fine, more slots never hurt the address section either way.
-- The patch's own diminishing returns are the stopping rule: no threshold, no cap beyond the one-byte wire ceiling on each cache size.
grownCacheCandidate :: ByteString -> ByteString -> Cover -> ByteString
grownCacheCandidate source target cover =
    probePatchBytes (growWhilePaying growSameBlock (growWhilePaying growNearSlot defaultProbe))
  where
    candidateAt = candidatePatchForConfig source target cover

    -- The default geometry admits no mode past the default nine, so its candidate is always feasible:
    -- the 'fromMaybe' marks an unreachable branch, since 'candidateAt' never returns 'Nothing' for this config.
    defaultProbe = CacheProbe defaultAddressCacheConfig
      (fromMaybe
        (error "Slap.VCDIFF.Create.grownCacheCandidate: the default cache geometry is infeasible")
        (candidateAt defaultAddressCacheConfig))

    growWhilePaying :: (AddressCacheConfig -> Maybe AddressCacheConfig) -> CacheProbe -> CacheProbe
    growWhilePaying growOneStep probe = case growOneStep (probeGeometry probe) of
      Nothing -> probe
      Just largerGeometry -> case candidateAt largerGeometry of
        Just largerBytes
          | ByteString.length largerBytes < probePatchSize probe ->
              growWhilePaying growOneStep (CacheProbe largerGeometry largerBytes)
        _ -> probe

-- | Enlarge the near cache by one slot, or 'Nothing' at the one-byte @s_near@ wire ceiling.
growNearSlot :: AddressCacheConfig -> Maybe AddressCacheConfig
growNearSlot geometry
  | slots < maxCacheDimension = Just geometry { nearSlotCount = NearSlotCount (slots + 1) }
  | otherwise                 = Nothing
  where slots = unNearSlotCount (nearSlotCount geometry)

-- | Enlarge the same cache by one block: the mirror of 'growNearSlot', bounded by the same one-byte @s_same@ ceiling.
growSameBlock :: AddressCacheConfig -> Maybe AddressCacheConfig
growSameBlock geometry
  | blocks < maxCacheDimension = Just geometry { sameBlockCount = SameBlockCount (blocks + 1) }
  | otherwise                  = Nothing
  where blocks = unSameBlockCount (sameBlockCount geometry)

-- | The largest value the one-byte @s_near@ \/ @s_same@ cache-size fields can carry (RFC 3284 §7).
maxCacheDimension :: Int
maxCacheDimension = 255

-- | Assemble the custom-table patch for a designed candidate under a cache geometry:
-- the header declares VCD_CODETABLE and carries the code-table data behind its length varint
-- (the two cache-size bytes @s_near@, @s_same@ from @config@, then the inner delta), and the window is the cover packed under the candidate.
-- The inner delta is @default-image -> candidate-image@ through the default-only core ('emitDefaultPatch'),
-- so the table the decoder rebuilds is exactly the one this window was packed against;
-- and @config@ is the geometry the window's addresses were resolved under ('planWindow'),
-- so the cache the decoder rebuilds matches the cache the encoder selected modes against.
-- The inner delta itself stays on the default geometry, RFC 3284 §7c requiring it, which the default-only 'emitDefaultPatch' provides.
assembleCustomTablePatch
  :: AddressCacheConfig -> ByteString -> ByteString -> WindowPlan -> Table.CodeTable -> ByteString
assembleCustomTablePatch config source target plan candidate =
  assemblePatch (word8 customCodeTableHeader <> framedCodeTableData)
                (encodedWindowBytes
                   (encodeWindow candidate source target OmitWindowAdler32 EmitSectionsPlain plan))
  where
    framedCodeTableData = varintOfLength (byteLength codeTableData) <> byteString codeTableData
    codeTableData       = builderBytes (cacheSizeHeader <> byteString innerDelta)
    cacheSizeHeader     = word8 (fromIntegral (unNearSlotCount  (nearSlotCount  config)))
                       <> word8 (fromIntegral (unSameBlockCount (sameBlockCount config)))
    innerDelta          = emitDefaultPatch defaultImage candidateImage
                            (vcdiffCover (InputFileContents defaultImage)
                                         (OutputFileContents candidateImage))
    defaultImage        = Table.serializeCodeTable Table.defaultCodeTable
    candidateImage      = Table.serializeCodeTable candidate

----------------------------------------------------------------------------
-- Candidate code-table design
----------------------------------------------------------------------------

-- | Design a candidate code table for a window's resolved instruction stream, or 'Nothing' when no sound table would differ from the default.
-- A thin reading of 'donorMints': the table is the default with the donor reassignments applied,
-- present only when there are any and they are sound (every soundness-required mint placed).
-- The design stays deliberately simple, this stage being the wire, not the cleverness.
-- Whatever it produces, the window is packed against the very table shipped,
-- so the round-trip is correct regardless of how good the design is; the gate, not the design, decides a table pays.
designCandidateTable :: [ResolvedInstruction] -> Maybe Table.CodeTable
designCandidateTable resolved = case donorMints resolved of
  Just assignments
    | not (null assignments) ->
        Just (Table.codeTableWithEntriesReplaced Table.defaultCodeTable assignments)
  _ -> Nothing

-- | The donor-opcode reassignments a resolved stream wants, and whether the soundness-required ones all fit.
-- Two kinds of shape draw a donor:
--
--   * /required/: a coded-size COPY opcode for each cache mode the stream uses that the default table cannot name.
--     A grown cache admits modes past the default nine, and 'selectCopyAddressMode' may pick one; without an opcode the packer could not emit it.
--     Frequency-independent (one use still needs it), placed first so they win donors over the savings mints.
--     A stream whose required mints outrun the donor pool has no sound table: 'donorMints' is 'Nothing', and the grow declines it.
--   * /savings/: the ADD+COPY and COPY+ADD adjacencies ('combinablePairs') and the lone fixed-size ADD and COPY shapes ('singleInstructionShapes')
--     the default cannot name and this stream repeats (@count >= 2@; a shape seen once cannot repay even the leanest table edit), most frequent first.
--     Pairs and singles pool into one tally, their entry shapes disjoint, a pair carrying two real templates, a single a trailing 'Table.Noop'.
--
-- Every minted COPY mode is one the resolved stream selected,
-- so it lies within the geometry that stream was resolved under and the decoder's mode check accepts it.
-- 'Nothing' is the infeasible verdict (the required mints outran the donor pool);
-- 'Just []' is feasible with no mints (the default table suffices); 'Just' a non-empty list is the custom table's reassignments.
donorMints :: [ResolvedInstruction] -> Maybe [(Table.Opcode, Table.CodeTableEntry)]
donorMints resolved
  | length requiredCopyModeEntries <= length donorOpcodes = Just (zip donorOpcodes mintEntries)
  | otherwise                                             = Nothing
  where
    defaultDense = denseOpcodes Table.defaultCodeTable
    pairs        = combinablePairs resolved
    singles      = singleInstructionShapes resolved

    requiredCopyModeEntries :: [Table.CodeTableEntry]
    requiredCopyModeEntries =
      [ entry
      | mode <- distinctCopyModes
      , let entry = Table.CodeTableEntry (Table.Copy Table.SizeCodedSeparately mode) Table.Noop
      , opcodeFor defaultDense entry == Nothing ]

    distinctCopyModes :: [Table.CopyAddressMode]
    distinctCopyModes =
      Map.keys (Map.fromList [ (mode, ()) | ResolvedCopy _ mode _ <- resolved ])

    savingsMints :: [Table.CodeTableEntry]
    savingsMints =
      [ entry
      | (entry, count) <- sortOn (Down . snd) (Map.toList (frequencies mintableShapes))
      , count >= 2 ]
      where
        mintableShapes =
          [ shape | shape <- pairs ++ singles, opcodeFor defaultDense shape == Nothing ]

    -- Required first (soundness), then savings (size).
    -- 'zip' against the donor pool drops the tail, so a donor shortage drops savings before it ever drops a required mint;
    -- the feasibility guard above ('Nothing' when the required mints outnumber the donors) catches a shortage of even those.
    mintEntries :: [Table.CodeTableEntry]
    mintEntries = requiredCopyModeEntries ++ savingsMints

    -- The combined opcodes the default already uses for this patch's pairs,
    -- excluded from the donor pool so a mint never overwrites an entry the patch still needs.
    -- Single mints cannot collide: a fixed-size single the default holds lives in the single-instruction region, never a two-template donor slot.
    usedCombinedOpcodes :: [Table.Opcode]
    usedCombinedOpcodes =
      [ opcode | entry <- pairs, Just opcode <- [opcodeFor defaultDense entry] ]

    -- Donor opcodes: the default's combined slots (its two-template entries) the patch does not use,
    -- in index order. The supply far exceeds the handful of mints in practice.
    donorOpcodes :: [Table.Opcode]
    donorOpcodes =
      [ opcode
      | (opcode, entry) <- Table.codeTableAssocs Table.defaultCodeTable
      , Table.secondTemplate entry /= Table.Noop
      , opcode `notElem` usedCombinedOpcodes
      ]

-- | The fixed-size ADD+COPY and COPY+ADD pairs a greedy left-to-right walk would combine, as the code-table entries they would pack into.
-- Built by the same 'addCopyEntry' \/ 'copyAddEntry' the packer's opcode lookups use,
-- so the design counts exactly the adjacencies the packer would combine,
-- mirroring 'packInstructions''s preference (ADD+COPY before COPY+ADD, non-overlapping).
-- RUN never pairs; an instruction with no fixed-size combinable neighbour is passed over.
combinablePairs :: [ResolvedInstruction] -> [Table.CodeTableEntry]
combinablePairs (ResolvedAdd literal : ResolvedCopy copyLength mode _ : rest)
  | Just entry <- addCopyEntry (byteLength literal) copyLength mode = entry : combinablePairs rest
combinablePairs (ResolvedCopy copyLength mode _ : ResolvedAdd literal : rest)
  | Just entry <- copyAddEntry copyLength mode (byteLength literal) = entry : combinablePairs rest
combinablePairs (_ : rest) = combinablePairs rest
combinablePairs []         = []

-- | The lone fixed-size ADD and COPY shapes a resolved stream contains, as the single-instruction code-table entries they would pack into,
-- the size carried in the opcode, no out-of-line size varint.
-- Built so the design can mint an opcode for a size the default table leaves to the coded form (an ADD outside 1–17, a COPY outside 4–18).
-- A length the one-byte size field cannot name ('fixedSizeFor' = 'Nothing') has no fixed-size entry to mint and is passed over;
-- RUN has no fixed-size form and never contributes.
-- One entry per occurrence, so 'donorMints' can keep the repeated ones: the mirror, for singles, of what 'combinablePairs' is for adjacencies.
singleInstructionShapes :: [ResolvedInstruction] -> [Table.CodeTableEntry]
singleInstructionShapes resolved =
  [ entry | instruction <- resolved, Just entry <- [shapeOf instruction] ]
  where
    shapeOf = \case
      ResolvedAdd literal ->
        fmap (\size -> Table.CodeTableEntry (Table.Add size) Table.Noop)
             (fixedSizeFor (byteLength literal))
      ResolvedCopy copyLength mode _ ->
        fmap (\size -> Table.CodeTableEntry (Table.Copy size mode) Table.Noop)
             (fixedSizeFor copyLength)
      ResolvedRun _ _ -> Nothing

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

-- | Hdr_Indicator with no bits set: no secondary compressor, no custom code table, no application header.
noHeaderFeatures :: Word8
noHeaderFeatures = 0x00

-- | Hdr_Indicator with VCD_CODETABLE (bit 1) set: a custom code table's length varint and data follow in the header.
-- Distinct from the window's VCD_SOURCE bit: this is the patch-level header indicator (RFC 3284 §4.1).
customCodeTableHeader :: Word8
customCodeTableHeader = 0x02

-- | A window's Win_Indicator, composed from what the window carries:
-- VCD_SOURCE when its COPYs address the source segment the two following varints name
-- (a self-contained window sets neither copy-source bit and omits both varints), VCD_ADLER32 when its checksum follows the section lengths.
windowIndicator :: WindowSourcing -> WindowChecksumEmission -> Word8
windowIndicator sourcing checksumEmission = sourcingBits .|. checksumBits
  where
    sourcingBits = case sourcing of
      DrawsFromSource -> bit vcdSourceBit
      SelfContained   -> 0x00
    checksumBits = case checksumEmission of
      CarryWindowAdler32 -> bit vcdAdler32Bit
      OmitWindowAdler32  -> 0x00

builderBytes :: Builder -> ByteString
builderBytes = LazyByteString.toStrict . toLazyByteString
