{-# LANGUAGE LambdaCase #-}

-- | VCDIFF patch creation: covers of the target serialized to wire bytes, in the arc the user named.
--
-- Creation has two halves. A /matcher/ ('Slap.VCDIFF.FFI', Rust-backed) segments the target into copies and literals, per window, as 'Cover's;
-- this module is the other half, turning covers into a patch.
-- 'createRFCVCDIFF' and 'createXDelta3' run the matcher and serialize its covers;
-- when the matcher finds nothing the cover is all-literal and the bytes are the bedrock floor's exactly.
-- The cover-driven entries ('createFromCover', 'createConsideringCustomTable') let tests exercise the full COPY\/ADD\/RUN path on hand-built covers.
--
-- The path is cover to instructions to resolved instructions to wire bytes, source-free, under the active code table, window by window:
-- each segment becomes an instruction ('coverToInstructions'),
-- the declared segment tightens to the span the copies actually read ('tightenToUsedSpan'),
-- each COPY's address is resolved once against the cache ('resolveInstructionAddresses'),
-- and the resolved stream packs into the densest opcodes the table offers ('packInstructions').
-- The xdelta3 arc slices the target by the requested 'EmissionWindowSize'
-- (8 MiB by default — the reference tool's own emission shape, and what keeps every xdelta3 build able to decode the result).
-- The RFC arc emits one window spanning the whole target unless @--window-size@ says otherwise ('RFCWindowing', which has the why).
-- The windowed RFC opt-in is where VCD_TARGET lives — each window is covered both against the source and against
-- earlier windows' output, and ships whichever arm encodes smaller ('emitWindowedRFCPatch').
--
-- The create token names the arc the user asked for; the bytes earn their flavor by the features they use.
-- A patch on the default table with no checksum, no compressed section, no application header, and no VCD_TARGET window
-- reaches for no flavor-distinguishing feature, so it parses back as 'Slap.VCDIFF.Types.PatchCoreOnly';
-- a custom code table (RFC 3284 §7's VCD_CODETABLE) and a VCD_TARGET window are RFC-arc features, parsing back as @PatchRFC@;
-- a per-window Adler32, a declared secondary compressor, and an application header are xdelta3 extensions, parsing back as @PatchXDelta3@.
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
-- A windowed create weighs the same consideration over every window's stream at once ('windowedCandidatePatchForConfig').
-- The design ('designCandidateTable') stays deliberately simple; sharpening it is later work.
-- 'createXDelta3' never considers one: xdelta3 rejects custom tables, so on that arc the default table is the only table there is.
module Slap.VCDIFF.Create
  ( createRFCVCDIFF
  , createXDelta3
  , WindowCompressionEmission(..)
  , rejectUnaddressablePair
    -- * Cover-driven emission (exported for testing)
  , createFromCover
  , createConsideringCustomTable
  , coverToInstructions
    -- * Address resolution and candidate-table design (exported for testing)
  , ResolvedInstruction(..)
  , resolveInstructionAddresses
  , designCandidateTable
    -- * The windowed arm compete (exported for testing)
  , WindowArmCompete(..)
  , ChosenWindowArm(..)
  , recompeteArmsUnderCandidateTable
  ) where

import Slap.VCDIFF.Types (vcdiffMagicBytes, VCDIFFInstruction(..), SegmentOrigin(..),
                          EmissionWindowSize, RFCWindowing(..),
                          vcdDecompressBit, vcdAppHeaderBit, vcdSourceBit, vcdTargetBit, vcdAdler32Bit,
                          vcdDataCompBit, vcdInstCompBit, vcdAddrCompBit)
import Slap.VCDIFF.SecondaryCompression
  ( secondaryCompressorId
  , SectionCarriage(..), carriageBytes
  , SectionCompressor, sectionCompressorAlgorithm, sectionCompressorKindCarriages )
import Slap.VCDIFF.Cover (Cover(..), CoverSegment(..))
import Slap.VCDIFF.FFI (vcdiffCover, vcdiffWindowedCovers, vcdiffProducedTargetCovers)
import Slap.VCDIFF.AddressCache
  ( AddressCacheConfig(..), NearSlotCount(..), SameBlockCount(..)
  , freshAddressCache, defaultAddressCacheConfig, everyModeFitsItsByte
  , selectCopyAddressMode, SelectedCopyAddress(..), CopyAddressOperand(..)
  , SameSlotByte(..) )
import qualified Slap.VCDIFF.CodeTable as Table
import Slap.Binary (putVcdiffVarint, viewBytesInRange)
import Slap.Checksum (Adler32(..))
import Slap.FFI (adler32)
import Slap.MetadataInclusion (VerificationInclusion(..))
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
import Data.List.NonEmpty (NonEmpty)
import qualified Data.List.NonEmpty as NonEmpty
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Maybe (fromMaybe)
import Data.Ord (Down(..))
import Data.Word (Word8)

-- | Create a VCDIFF patch reconstructing @target@, windowed as asked.
-- Under 'OneWholeTargetWindow' (the default) the cover comes from the matcher ('Slap.VCDIFF.FFI.vcdiffCover'),
-- so the patch copies the runs the target shares with the source or with itself;
-- the bytes are then weighed under the default table and a designed custom one, the smaller shipping ('createConsideringCustomTable').
-- When the matcher finds nothing (an unrelated source, a target shorter than the minimum match)
-- the cover is all-literal and the bytes are the bedrock floor's exactly.
-- Under 'SlicedIntoWindows' (the @--window-size@ opt-in) the target is sliced and each window competes
-- its source arm against its produced-target arm ('emitWindowedRFCPatch') — the arc VCD_TARGET is emitted on.
-- The 'Either' carries one refusal of its own, a pair the matcher could not address ('rejectUnaddressablePair');
-- no metadata, no advisories.
createRFCVCDIFF :: RFCWindowing -> InputFileContents -> OutputFileContents
                -> Either SlapError CreateResult
createRFCVCDIFF windowing inputContents@(InputFileContents source) outputContents@(OutputFileContents target) = do
  rejectUnaddressablePair (SourceFileSize (byteFileSize source)) (TargetFileSize (byteFileSize target))
  Right $ case windowing of
    OneWholeTargetWindow ->
      createConsideringCustomTable inputContents outputContents
        (vcdiffCover inputContents outputContents)
    SlicedIntoWindows windowSize ->
      CreateResult (PatchFileContents (emitWindowedRFCPatch windowSize source target)) []

-- | Create an xdelta3 patch reconstructing @target@:
-- matcher-driven covers, one per 'EmissionWindowSize' slice of the target, emitted with the extensions the canonical tool's own output carries.
-- Today those are the per-window Adler32
-- (on by default, declined by @--omit-verification@; the only integrity data the format has,
-- so opting out leaves nothing attesting the output — the same gap 'Slap.Status.VerificationOptedOutByCreator' names at apply),
-- secondary compression
-- (on by default with LZMA, redirected by @--compress-with@, declined by @--no-compress@ —
-- 'Slap.Convert.xdelta3CompressionEmission' folds those flags into the 'WindowCompressionEmission' arriving here;
-- kept per section only where it shrinks, and shipped only when the compressed patch beats the plain one outright — see 'emitXDelta3Patch'),
-- and the application header, when one arrives (@--metadata FILE@, or a source patch's header inheriting on convert).
-- Never a custom code table: xdelta3 rejects them.
-- A patch carrying none of these — or with verification declined and compression never paying —
-- uses no flavor-distinguishing feature at all,
-- parsing back as 'Slap.VCDIFF.Types.PatchCoreOnly' — readable as xdelta3, which is what was asked for.
createXDelta3
  :: VerificationInclusion -> WindowCompressionEmission -> EmissionWindowSize
  -> Maybe ByteString -> InputFileContents -> OutputFileContents
  -> Either SlapError CreateResult
createXDelta3 verificationChoice compressionEmission windowSize maybeAppHeader (InputFileContents source) (OutputFileContents target) = do
  rejectUnaddressablePair (SourceFileSize (byteFileSize source)) (TargetFileSize (byteFileSize target))
  Right (CreateResult (PatchFileContents patchBytes) [])
  where
    patchBytes = emitXDelta3Patch checksumEmission compressionEmission maybeAppHeader windowSize source target
    checksumEmission = case verificationChoice of
      IncludeVerification -> CarryWindowAdler32
      OmitVerification    -> OmitWindowAdler32

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
-- A window with external copies declares a segment ('DrawsOn': the matching copy-source indicator bit and the two segment varints),
-- cut from the side its 'SegmentOrigin' names — the source file (VCD_SOURCE) or earlier windows' output (VCD_TARGET).
-- A window with none is self-contained ('SelfContained'), declaring neither bit and no varints —
-- even when it copies its own output, whose addresses then begin at zero.
-- The origin is the decode side's own 'SegmentOrigin', so the two directions cannot drift on what a segment means.
data WindowSourcing = SelfContained | DrawsOn !SegmentOrigin !SourceSegmentSpan
  deriving (Eq, Show)

-- | The span a window declares as its segment: where it starts in its origin's space, and how far it runs.
-- Always the span the window's copies actually read ('tightenToUsedSpan'), never the whole space they could have.
data SourceSegmentSpan = SourceSegmentSpan
  { segmentSpanPosition :: !Offset
  , segmentSpanLength   :: !Length
  }
  deriving (Eq, Show)

-- | The declared segment's length as the position a window's own output begins at in @U@: zero for a self-contained window.
-- Both the resolver's initial write head and the rebasing arithmetic read it, so the two cannot disagree about where the window region starts.
sourcingSegmentLength :: WindowSourcing -> Length
sourcingSegmentLength SelfContained                 = Length 0
sourcingSegmentLength (DrawsOn _origin segmentSpan) = segmentSpanLength segmentSpan

-- | Whether an emitted window carries the per-window Adler32 of its output (VCD_ADLER32, an xdelta3 extension).
-- The RFC and core emissions always plan with 'OmitWindowAdler32' — their windows have no slot for a checksum,
-- the write-side mirror of 'Slap.VCDIFF.Types.XDelta3Window' being the only window type that carries one.
data WindowChecksumEmission = CarryWindowAdler32 | OmitWindowAdler32
  deriving (Eq, Show)

-- | The checksum a planned window carries to the wire: the Adler32 of its slice — its decoded output — or nothing.
-- Settled by 'layoutPlannedWindow' from the window's own slice, so the value travels with the slice it attests,
-- and every emission of one plan reads the one computed value:
-- 'emitXDelta3Patch' weighs a plain and a compressed emission against each other,
-- and both share it rather than each hashing the whole target on its own.
data PlannedWindowChecksum
  = PlannedAdler32 !Adler32
  | NoPlannedChecksum
  deriving (Eq, Show)

-- | Whether an emitted window's sections ride through a secondary compressor where that
-- shrinks them, or all ride plain. The compression sibling of 'WindowChecksumEmission'.
-- The compressor arrives as a 'SectionCompressor' — see there for why an FGK emission is unrepresentable rather than refused.
-- The RFC and core emissions always pass 'EmitSectionsPlain': the RFC defines secondary compression's framing but no compressor,
-- so the RFC arc's catalog is empty and there is nothing such a patch could declare (docs/vcdiff/questions.md, "secondary compressor declared").
data WindowCompressionEmission
  = CompressSectionsWith !SectionCompressor
  | EmitSectionsPlain

-- | Whether any of an emitted patch's sections rides secondary-compressed, and under which compressor when one does,
-- so the header's declaration can only ever name the compressor the sections actually used.
data WindowSectionCompression
  = SomeSectionsCompressed !SectionCompressor
  | AllSectionsPlain

-- | The table-independent groundwork for one window: how it sources its copies,
-- and the resolved instruction stream (its COPY modes selected once, valid under any table of the same cache geometry).
-- Both the default and the candidate emission build on the one plan, and the design reads the resolved stream off it.
data WindowPlan = WindowPlan
  { planResolved :: ![ResolvedInstruction]
  , planSourcing :: !WindowSourcing
  }

-- | Plan one emitted window: instructions from its cover, the declared segment tightened to the span those instructions read,
-- addresses rebased to match, then COPY modes resolved against the cache the declared segment implies —
-- the write head starting at the declared span's length, exactly where the decoder's will.
-- The 'SegmentOrigin' names the side a surviving segment is cut from, and with it the external space the cover addressed:
-- the whole source for a source-arm window, the produced target below the window's base for a target-arm one.
planTightenedWindow :: AddressCacheConfig -> SegmentOrigin -> Length -> ByteString -> Cover -> WindowPlan
planTightenedWindow config origin externalLength windowSlice cover = WindowPlan
  { planResolved = resolveInstructionAddresses config initialHere rebasedInstructions
  , planSourcing = sourcing
  }
  where
    (usedSpan, rebasedInstructions) =
      tightenToUsedSpan externalLength (coverToInstructions windowSlice cover)
    sourcing    = maybe SelfContained (DrawsOn origin) usedSpan
    initialHere = lengthToOffset (sourcingSegmentLength sourcing)

-- | Tighten a window's declared segment to the span its external copies actually read, rebasing every copy address to match.
-- Addresses arrive against @external space ++ window@ (the matcher's world) and leave against @declared segment ++ window@ (the wire's):
-- an external address shifts down by the span's start, a window-region address by the external space's length less the span's.
-- A window with no external copies gets no span at all; the caller wraps a surviving span in its arm's 'SegmentOrigin'.
-- Runs before 'resolveInstructionAddresses' on purpose: the cache state the resolver threads depends on the numeric addresses,
-- so the decoder — which sees only wire addresses — rebuilds exactly the cache the encoder selected modes against.
tightenToUsedSpan :: Length -> [VCDIFFInstruction] -> (Maybe SourceSegmentSpan, [VCDIFFInstruction])
tightenToUsedSpan (Length externalLength) instructions = case externalReadBounds of
    []     -> (Nothing, map (rebaseCopyAddress 0 0) instructions)
    bounds ->
      let spanStart  = minimum (map fst bounds)
          spanLength = maximum (map snd bounds) - spanStart
      in ( Just (SourceSegmentSpan (Offset spanStart) (Length spanLength))
         , map (rebaseCopyAddress spanStart spanLength) instructions )
  where
    -- Each external copy's read interval; a copy never crosses the
    -- external space's end (core invariant 2, which the matcher's reach
    -- cap upholds), so the interval ends are positions in that space and
    -- the span they union to lies entirely inside it.
    externalReadBounds =
      [ (address, address + unLength copyLength)
      | Copy copyLength (Offset address) <- instructions
      , address < externalLength ]

    rebaseCopyAddress spanStart spanLength = \case
      Copy copyLength (Offset address)
        | address < externalLength -> Copy copyLength (Offset (address - spanStart))
        | otherwise                -> Copy copyLength (Offset (address - externalLength + spanLength))
      instruction -> instruction

-- | The groundwork of one emitted window: its slice of the target, how it sources its copies,
-- the checksum it will carry, and its three sections, laid out but not yet carried.
-- Both emissions build on the same planned window —
-- the plain patch and the secondary-compressed one differ only in the carriages dressed on at 'encodeWindowBytes'.
data PlannedWindow = PlannedWindow
  { plannedSlice    :: !ByteString
  , plannedSourcing :: !WindowSourcing
  , plannedChecksum :: !PlannedWindowChecksum
  , plannedSections :: !Sections
  }

-- | Lay a window's plan out into its 'PlannedWindow' under a table's opcodes, computing the checksum it will carry, when it carries one.
layoutPlannedWindow :: WindowChecksumEmission -> DenseOpcodes -> ByteString -> WindowPlan -> PlannedWindow
layoutPlannedWindow checksumEmission opcodeResolver windowSlice plan = PlannedWindow
  { plannedSlice    = windowSlice
  , plannedSourcing = planSourcing plan
  , plannedChecksum = case checksumEmission of
      CarryWindowAdler32 -> PlannedAdler32 (adler32 windowSlice)
      OmitWindowAdler32  -> NoPlannedChecksum
  , plannedSections = layoutSections opcodeResolver (planResolved plan)
  }

-- | The carriages one window's three sections ride out on, kind by kind.
-- A record, not a triple, so the data, instruction, and address sections cannot transpose between layout and wire.
data WindowCarriages = WindowCarriages
  { dataCarriage        :: !SectionCarriage
  , instructionCarriage :: !SectionCarriage
  , addressCarriage     :: !SectionCarriage
  }

-- | Every section as laid out: the plain emission's carriages, and what a compressor's carriage run degrades to where nothing pays.
plainCarriages :: Sections -> WindowCarriages
plainCarriages sections = WindowCarriages
  { dataCarriage        = CarriedPlain (sectionData sections)
  , instructionCarriage = CarriedPlain (sectionInstructions sections)
  , addressCarriage     = CarriedPlain (sectionAddresses sections)
  }

-- | Whether any of a window's sections rides compressed:
-- the fact the Delta_Indicator spells per window and the patch header's declaration folds over.
anyCarriageCompressed :: WindowCarriages -> Bool
anyCarriageCompressed carriages =
  any carriageIsCompressed [dataCarriage carriages, instructionCarriage carriages, addressCarriage carriages]

carriageIsCompressed :: SectionCarriage -> Bool
carriageIsCompressed CarriedCompressed{} = True
carriageIsCompressed CarriedPlain{}      = False

-- | One window's wire bytes: the Win_Indicator and (when a segment is declared) its two varints,
-- then the delta encoding behind its length varint — the target window size, the Delta_Indicator composed from the carriages,
-- the three section lengths, the checksum when carried, and the three sections as carried.
-- The carried checksum is the window's 'plannedChecksum', the Adler32 of its decoded output ('PlannedWindowChecksum' has the story);
-- four bytes big-endian between the section lengths and the data section (docs/vcdiff/xdelta3/spec.md "Per-window Adler32").
encodeWindowBytes :: PlannedWindow -> WindowCarriages -> ByteString
encodeWindowBytes plannedWindow carriages = builderBytes windowBuilder
  where
    windowSlice = plannedSlice plannedWindow

    deltaIndicator :: Word8
    deltaIndicator =
      carriageCompressionBit vcdDataCompBit (dataCarriage carriages)
        .|. carriageCompressionBit vcdInstCompBit (instructionCarriage carriages)
        .|. carriageCompressionBit vcdAddrCompBit (addressCarriage carriages)

    -- The Win_Indicator and (for a segment-declaring window) the segment varints, which precede the delta-encoding-length on the wire.
    -- The varints are origin-blind — which side the segment is cut from lives in the indicator bit alone.
    windowIndicatorAndSegment =
      word8 (windowIndicator (plannedSourcing plannedWindow) (plannedChecksum plannedWindow))
        <> case plannedSourcing plannedWindow of
             DrawsOn _origin segmentSpan ->
                  varintOfLength (segmentSpanLength segmentSpan)
               <> putVcdiffVarint (fromIntegral (unOffset (segmentSpanPosition segmentSpan)))
             SelfContained -> mempty

    checksumBytes = case plannedChecksum plannedWindow of
      PlannedAdler32 windowAdler -> word32BE (unAdler32 windowAdler)
      NoPlannedChecksum          -> mempty

    -- Everything the delta-encoding-length field measures:
    -- the target window size, the indicator, the three section lengths, the checksum when carried, then the three sections in order.
    deltaEncoding = builderBytes
      (  varintOfLength (byteLength windowSlice)
      <> word8 deltaIndicator
      <> varintOfLength (byteLength (carriageBytes (dataCarriage carriages)))
      <> varintOfLength (byteLength (carriageBytes (instructionCarriage carriages)))
      <> varintOfLength (byteLength (carriageBytes (addressCarriage carriages)))
      <> checksumBytes
      <> byteString (carriageBytes (dataCarriage carriages))
      <> byteString (carriageBytes (instructionCarriage carriages))
      <> byteString (carriageBytes (addressCarriage carriages)) )

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
                (encodeWindowBytes plannedWindow
                   (plainCarriages (plannedSections plannedWindow)))
  where
    plannedWindow =
      layoutPlannedWindow OmitWindowAdler32 (denseOpcodes Table.defaultCodeTable) target
        (planTightenedWindow defaultAddressCacheConfig FromSourceFile (byteLength source) target cover)

-- | Emit an xdelta3 patch: the target sliced into 'EmissionWindowSize' windows and each covered against the source
-- ('Slap.VCDIFF.FFI.vcdiffWindowedCovers' — a window's copies reach the source and its own slice, never an earlier window's output),
-- on the default table always (xdelta3 rejects custom ones),
-- every window carrying the Adler32 of its own slice when verification is included,
-- each window's source segment tightened to the span its copies read,
-- and the sections riding the chosen secondary compressor where that shrinks them when compression is included —
-- each kind's sections crossing the compressor together, in window order, the write-side mirror of the decode side's gathering.
-- The header declares the compressor exactly when some section leans on it ('xdelta3HeaderFor'),
-- so a patch whose sections all stayed plain declares nothing and comes out byte-identical to the plain emission.
-- The compressed emission ships only when it beats the plain one outright —
-- the same explicit gate 'emitConsideringCustomTable' holds its candidate to,
-- catching the edge where the sections shrink by no more than the one extra header byte (the compressor id) the declaration costs.
emitXDelta3Patch
  :: WindowChecksumEmission -> WindowCompressionEmission -> Maybe ByteString -> EmissionWindowSize
  -> ByteString -> ByteString -> ByteString
emitXDelta3Patch checksumEmission compressionEmission maybeAppHeader windowSize source target =
  case compressionEmission of
    EmitSectionsPlain -> plainPatch
    CompressSectionsWith compressor ->
      let compressedPatchBytes = compressedPatch compressor
      in if ByteString.length compressedPatchBytes < ByteString.length plainPatch
           then compressedPatchBytes
           else plainPatch
  where
    plannedWindows =
      [ layoutPlannedWindow checksumEmission (denseOpcodes Table.defaultCodeTable) windowSlice
          (planTightenedWindow defaultAddressCacheConfig FromSourceFile (byteLength source) windowSlice cover)
      | (windowSlice, cover) <-
          windowSlicesForCovers target
            (vcdiffWindowedCovers windowSize (InputFileContents source) (OutputFileContents target)) ]

    plainPatch =
      assemblePatch (xdelta3HeaderFor maybeAppHeader AllSectionsPlain)
        (windowRunBytes [ (plannedWindow, plainCarriages (plannedSections plannedWindow))
                        | plannedWindow <- plannedWindows ])

    compressedPatch compressor =
      let carriagedWindows = carriagedUnder compressor plannedWindows
          declaration
            | any (anyCarriageCompressed . snd) carriagedWindows = SomeSectionsCompressed compressor
            | otherwise                                          = AllSectionsPlain
      in assemblePatch (xdelta3HeaderFor maybeAppHeader declaration) (windowRunBytes carriagedWindows)

    windowRunBytes carriagedWindows =
      ByteString.concat
        [ encodeWindowBytes plannedWindow carriages
        | (plannedWindow, carriages) <- carriagedWindows ]

-- | Dress every window's sections in a compressor's carriages: each kind's sections cross the compressor together, in window order,
-- so a gathered compressor's stream (and its keep-where-it-pays settling) spans the patch the way the decode side expects.
carriagedUnder :: SectionCompressor -> [PlannedWindow] -> [(PlannedWindow, WindowCarriages)]
carriagedUnder compressor plannedWindows =
  zip plannedWindows
    (zipWith3 WindowCarriages
      (kindCarriageRun sectionData)
      (kindCarriageRun sectionInstructions)
      (kindCarriageRun sectionAddresses))
  where
    kindCarriageRun sectionOf =
      sectionCompressorKindCarriages compressor
        (map (sectionOf . plannedSections) plannedWindows)

-- | Pair each window's cover with the slice of the target it reconstructs.
-- The covers are the partition's one source of truth: the matcher already cut the target into windows,
-- and each cover spans its whole window with no gaps, so its segments sum to that window's byte count.
-- Splitting by those lengths keeps this side from re-deriving a window size that could drift from the matcher's.
windowSlicesForCovers :: ByteString -> NonEmpty Cover -> [(ByteString, Cover)]
windowSlicesForCovers target covers = pairFrom target (NonEmpty.toList covers)
  where
    pairFrom _ [] = []
    pairFrom remaining (cover : laterCovers) =
      let (windowSlice, restOfTarget) = ByteString.splitAt (unLength (coverOutputLength cover)) remaining
      in (windowSlice, cover) : pairFrom restOfTarget laterCovers

-- | The byte length a cover reconstructs. A cover spans its whole window with no gaps or overlaps,
-- so summing its segments' output lengths gives exactly that window's byte count.
coverOutputLength :: Cover -> Length
coverOutputLength (Cover segments) = foldMap segmentOutputLength segments
  where
    segmentOutputLength (CoverCopy    copyLength _)      = copyLength
    segmentOutputLength (CoverLiteral _ literalLength)   = literalLength

-- | The xdelta3 patch header for what the patch actually carries:
-- VCD_DECOMPRESS and the compressor's catalog id when some section rides compressed,
-- VCD_APPHEADER and its length-prefixed bytes when there is an application header —
-- each declaration exists exactly where it is used, and the fields follow their bits in wire order.
xdelta3HeaderFor :: Maybe ByteString -> WindowSectionCompression -> Builder
xdelta3HeaderFor maybeAppHeader sectionCompression =
  word8 (compressorBit .|. appHeaderBit) <> compressorField <> appHeaderField
  where
    (compressorBit, compressorField) = case sectionCompression of
      SomeSectionsCompressed compressor ->
        (bit vcdDecompressBit, word8 (secondaryCompressorId (sectionCompressorAlgorithm compressor)))
      AllSectionsPlain -> (0x00, mempty)
    (appHeaderBit, appHeaderField) = case maybeAppHeader of
      Just headerBytes ->
        (bit vcdAppHeaderBit, varintOfLength (byteLength headerBytes) <> byteString headerBytes)
      Nothing -> (0x00, mempty)

-- | Emit a windowed RFC patch: the target sliced into 'EmissionWindowSize' windows, each covered twice and shipped once,
-- under the same custom-table consideration the single-window emission weighs.
-- The per-window compete ('chooseWindowArms') settles each window's arm first, under the default table;
-- the candidate is then designed over every settled window's resolved stream ('windowedCandidatePatchForConfig'),
-- geometry grown as ever.
-- A designed table can flip which arm encodes smaller, so once the geometry settles the arms are re-competed
-- under a judging table built for both ('recompeteArmsUnderCandidateTable'),
-- and a flip earns one re-design over the flipped winners, kept only where it beats the settled candidate.
-- The default-table patch ships unless a candidate beats it outright —
-- the gate 'emitConsideringCustomTable' holds its single window to, held here to the whole window run.
-- On the default table, with no checksum and no compression, a run of windows that all settle on the source arm
-- parses back as 'Slap.VCDIFF.Types.PatchCoreOnly'; the first window that wins on VCD_TARGET — or a custom table paying —
-- makes the patch 'Slap.VCDIFF.Types.PatchRFC'.
emitWindowedRFCPatch :: EmissionWindowSize -> ByteString -> ByteString -> ByteString
emitWindowedRFCPatch windowSize source target
  | ByteString.length grownCandidate < ByteString.length defaultTablePatch = grownCandidate
  | otherwise                                                              = defaultTablePatch
  where
    competes   = chooseWindowArms windowSize source target
    chosenArms = map competeWinner competes
    defaultTablePatch =
      assemblePatch (word8 noHeaderFeatures)
        (ByteString.concat (map chosenDefaultTableBytes chosenArms))
    grownProbe = grownCacheCandidate (windowedCandidatePatchForConfig chosenArms)
    grownCandidate = case flippedCandidate of
      Just flippedBytes
        | ByteString.length flippedBytes < probePatchSize grownProbe -> flippedBytes
      _ -> probePatchBytes grownProbe
    flippedCandidate = do
      flippedArms <- recompeteArmsUnderCandidateTable (probeGeometry grownProbe) competes
      windowedCandidatePatchForConfig flippedArms (probeGeometry grownProbe)

-- | One window's settled choice from the per-window compete: the arm that won,
-- everything needed to re-plan it under another cache geometry, and its wire bytes under the default table
-- (the compete's own encoding, reused verbatim by the default-table patch).
-- A window with no external copies still records the arm it settled on;
-- its plan re-derives 'SelfContained' from the cover under any geometry.
data ChosenWindowArm = ChosenWindowArm
  { chosenOrigin            :: !SegmentOrigin
  , chosenExternalLength    :: !Length
  , chosenSlice             :: !ByteString
  , chosenCover             :: !Cover
  , chosenDefaultTableBytes :: !ByteString
  }

-- | One window's per-window compete, both arms kept: the default-table winner the emission builds on,
-- and the runner-up, retained for the re-compete under a designed table ('recompeteArmsUnderCandidateTable'),
-- where the judging changes and the runner-up may earn the window after all.
data WindowArmCompete = WindowArmCompete
  { competeWinner   :: !ChosenWindowArm
  , competeRunnerUp :: !ChosenWindowArm
  }

-- | Run the per-window compete: cover each window twice, encode both arms under the default table, and rank them.
-- The source arm covers a window against the source file ('vcdiffWindowedCovers', VCD_SOURCE on the wire);
-- the target arm covers it against the output of the windows before it ('vcdiffProducedTargetCovers', VCD_TARGET) —
-- the two copy sources a window may declare, one at a time, never both (RFC 3284 §4.2).
-- The source arm takes ties, the way SELF takes address ties in 'selectCopyAddressMode':
-- the plain reading is the default, and the fancy one must win outright.
-- Window 0 has no produced output below its base, so its target arm is self-contained at best
-- and VCD_TARGET can never mark the first window.
chooseWindowArms :: EmissionWindowSize -> ByteString -> ByteString -> [WindowArmCompete]
chooseWindowArms windowSize source target
  -- Both matchers chunk the target by the same window size, so the two cover runs pair one-to-one;
  -- a disagreement is a matcher bug, surfaced as a loud 'error' the way the other must-hold seams here are.
  | length sourceArmWindows == length targetArmCovers =
      zipWith3 competeArms producedBeforeWindow sourceArmWindows targetArmCovers
  | otherwise =
      error ("Slap.VCDIFF.Create: the two matchers disagree on the window partition: "
              <> show (length sourceArmWindows) <> " source-arm windows, "
              <> show (length targetArmCovers) <> " target-arm covers")
  where
    opcodeResolver = denseOpcodes Table.defaultCodeTable

    sourceArmWindows =
      windowSlicesForCovers target
        (vcdiffWindowedCovers windowSize (InputFileContents source) (OutputFileContents target))
    targetArmCovers =
      NonEmpty.toList (vcdiffProducedTargetCovers windowSize (OutputFileContents target))

    -- The produced-target length below each window's base: what the target arm's copies may draw on,
    -- and the external length its addresses arrive against.
    producedBeforeWindow =
      scanl (<>) mempty [byteLength windowSlice | (windowSlice, _cover) <- sourceArmWindows]

    competeArms producedBefore (windowSlice, sourceCover) targetCover
      | ByteString.length (chosenDefaultTableBytes targetArm)
          < ByteString.length (chosenDefaultTableBytes sourceArm) =
          WindowArmCompete { competeWinner = targetArm, competeRunnerUp = sourceArm }
      | otherwise =
          WindowArmCompete { competeWinner = sourceArm, competeRunnerUp = targetArm }
      where
        sourceArm = armOf FromSourceFile     (byteLength source) windowSlice sourceCover
        targetArm = armOf FromProducedTarget producedBefore      windowSlice targetCover

    armOf origin externalLength windowSlice cover = ChosenWindowArm
      { chosenOrigin            = origin
      , chosenExternalLength    = externalLength
      , chosenSlice             = windowSlice
      , chosenCover             = cover
      , chosenDefaultTableBytes =
          encodeWindowBytes plannedWindow (plainCarriages (plannedSections plannedWindow))
      }
      where
        plannedWindow =
          layoutPlannedWindow OmitWindowAdler32 opcodeResolver windowSlice
            (planTightenedWindow defaultAddressCacheConfig origin externalLength windowSlice cover)

-- | Re-run the per-window compete once under the grown geometry, judged by a designed table rather than the default:
-- the flip 'emitWindowedRFCPatch' grants the runner-up arms after the geometry settles.
-- The judge is built the way a shipped table is ('donorMints'), but over both arms' streams,
-- so every COPY mode either arm selects has an opcode and no arm is judged under a table that cannot express it.
-- It only measures and is never emitted: the flipped winners earn their own design afterwards,
-- and the byte gate above decides whether the flip actually paid.
-- 'Nothing' when no sound judge fits the donor pool, and when the rematch flips nothing —
-- either way the settled arms stand, and no re-design runs that could only reproduce the settled candidate.
-- The incumbent keeps ties, the way the source arm takes them in 'chooseWindowArms':
-- the settled reading is the default, and the flip must win outright.
recompeteArmsUnderCandidateTable :: AddressCacheConfig -> [WindowArmCompete] -> Maybe [ChosenWindowArm]
recompeteArmsUnderCandidateTable config competes =
    judgeCompetes
      =<< donorMints [ planResolved plan | (_arm, plan) <- concatMap bothPlanned plannedCompetes ]
  where
    plannedCompetes =
      [ (plannedArm (competeWinner compete), plannedArm (competeRunnerUp compete))
      | compete <- competes ]
    bothPlanned (winner, runnerUp) = [winner, runnerUp]
    plannedArm arm =
      ( arm
      , planTightenedWindow config (chosenOrigin arm) (chosenExternalLength arm)
          (chosenSlice arm) (chosenCover arm) )

    judgeCompetes assignments =
      let judgeOpcodes =
            denseOpcodes (Table.codeTableWithEntriesReplaced Table.defaultCodeTable assignments)
          judgedLength (arm, plan) =
            let plannedWindow = layoutPlannedWindow OmitWindowAdler32 judgeOpcodes (chosenSlice arm) plan
            in ByteString.length
                 (encodeWindowBytes plannedWindow (plainCarriages (plannedSections plannedWindow)))
          rematchedArms =
            [ if judgedLength runnerUp < judgedLength winner then fst runnerUp else fst winner
            | (winner, runnerUp) <- plannedCompetes ]
          -- A compete's two arms are one per 'SegmentOrigin' ('chooseWindowArms' builds one of each),
          -- so a rematch winner flipped exactly when its origin differs from the settled winner's.
          anyWindowFlipped =
            or (zipWith (\compete rematchedArm ->
                           chosenOrigin rematchedArm /= chosenOrigin (competeWinner compete))
                        competes rematchedArms)
      in if anyWindowFlipped then Just rematchedArms else Nothing

-- | The windowed custom-table patch for one cache geometry, or 'Nothing' when no sound table fits the config's modes into the donor pool.
-- Every window's settled arm is re-planned under @config@ — address resolution steers by the cache geometry, so re-planning is not optional —
-- and the design pools the windows' resolved streams ('donorMints' reads them per window).
-- The windowed reading of 'candidatePatchForConfig', with the same soundness:
-- the windows' addresses are resolved under the very geometry the shipped table declares, so the decoder's mode check accepts every mint.
windowedCandidatePatchForConfig :: [ChosenWindowArm] -> AddressCacheConfig -> Maybe ByteString
windowedCandidatePatchForConfig chosenArms config =
    fmap assembleUnderDesignedTable (donorMints (map planResolved plans))
  where
    plans =
      [ planTightenedWindow config (chosenOrigin arm) (chosenExternalLength arm)
          (chosenSlice arm) (chosenCover arm)
      | arm <- chosenArms ]
    assembleUnderDesignedTable assignments =
      let candidate      = Table.codeTableWithEntriesReplaced Table.defaultCodeTable assignments
          opcodeResolver = denseOpcodes candidate
      in assemblePatch (word8 customCodeTableHeader <> framedCustomTableData config candidate)
           (ByteString.concat
             [ encodeWindowBytes plannedWindow (plainCarriages (plannedSections plannedWindow))
             | (arm, plan) <- zip chosenArms plans
             , let plannedWindow = layoutPlannedWindow OmitWindowAdler32 opcodeResolver (chosenSlice arm) plan ])

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
    grownCandidate = probePatchBytes (grownCacheCandidate (candidatePatchForConfig source target cover))
    defaultPatch   = emitDefaultPatch source target cover

-- | The custom-table patch for one cache geometry, or 'Nothing' when no sound table fits the config's modes into the donor pool.
-- Resolve the cover's window under @config@, take the donor reassignments its stream needs and repeats ('donorMints'),
-- and assemble the custom-table patch declaring @config@.
-- The window's addresses are resolved under the very config the patch declares, so every COPY mode the stream selected
-- (and so every mode a minted entry names) is one the declared cache defines, and the decoder's mode check accepts it.
-- The default geometry is always feasible: it admits no mode past the default nine, all named by the default table.
candidatePatchForConfig :: ByteString -> ByteString -> Cover -> AddressCacheConfig -> Maybe ByteString
candidatePatchForConfig source target cover config =
  fmap assembleUnderDesignedTable (donorMints [planResolved plan])
  where
    plan = planTightenedWindow config FromSourceFile (byteLength source) target cover
    assembleUnderDesignedTable assignments =
      assembleCustomTablePatch config target plan
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

-- | Grow the cache geometry from the default to where a larger cache stops paying,
-- returning the winning probe: the geometry the grow stopped at, and the smallest custom-table candidate found there.
-- @candidateAt@ assembles the custom-table patch bytes for one geometry ('Nothing' where no sound table fits);
-- the single-window and windowed emissions each hand in their own ('candidatePatchForConfig', 'windowedCandidatePatchForConfig'),
-- and the grow itself is theirs to share.
-- A larger cache only ever shrinks the address section (the near cache holds a strict superset of recent addresses, the same cache collides less),
-- so each dimension grows cleanly: bump it a slot while the assembled patch strictly shrinks,
-- stop when a slot buys nothing (or the bumped config is infeasible).
-- Near is grown first, then same from there; the two interact, so the order can nudge where it lands,
-- which is fine, more slots never hurt the address section either way.
-- The patch's own diminishing returns are the stopping rule: no threshold, no cap beyond the combined mode-byte ceiling ('everyModeFitsItsByte').
grownCacheCandidate :: (AddressCacheConfig -> Maybe ByteString) -> CacheProbe
grownCacheCandidate candidateAt =
    growWhilePaying growSameBlock (growWhilePaying growNearSlot defaultProbe)
  where
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

-- | Enlarge the near cache by one slot,
-- declining once the grown geometry would name more modes than a mode byte can carry ('everyModeFitsItsByte').
growNearSlot :: AddressCacheConfig -> Maybe AddressCacheConfig
growNearSlot geometry =
  grownGeometryIfModesStillFit
    geometry { nearSlotCount = NearSlotCount (unNearSlotCount (nearSlotCount geometry) + 1) }

-- | Enlarge the same cache by one block: the mirror of 'growNearSlot', held to the same combined mode-byte ceiling.
growSameBlock :: AddressCacheConfig -> Maybe AddressCacheConfig
growSameBlock geometry =
  grownGeometryIfModesStillFit
    geometry { sameBlockCount = SameBlockCount (unSameBlockCount (sameBlockCount geometry) + 1) }

-- | A grown geometry, kept only while every mode it defines still fits its one-byte name ('everyModeFitsItsByte', RFC 3284 §7a).
-- This subsumes the per-dimension one-byte field ceiling: @2 + s_near + s_same <= 256@ forces each dimension below 255,
-- so the @s_near@/@s_same@ header bytes ('framedCustomTableData') stay in range too.
grownGeometryIfModesStillFit :: AddressCacheConfig -> Maybe AddressCacheConfig
grownGeometryIfModesStillFit geometry
  | everyModeFitsItsByte geometry = Just geometry
  | otherwise                     = Nothing

-- | Assemble the custom-table patch for a designed candidate under a cache geometry:
-- the header declares VCD_CODETABLE and carries the framed table data ('framedCustomTableData'),
-- and the window is the cover packed under the candidate,
-- so the table the decoder rebuilds is exactly the one this window was packed against.
-- @config@ is the geometry the window's addresses were resolved under ('planTightenedWindow'),
-- so the cache the decoder rebuilds matches the cache the encoder selected modes against.
assembleCustomTablePatch
  :: AddressCacheConfig -> ByteString -> WindowPlan -> Table.CodeTable -> ByteString
assembleCustomTablePatch config target plan candidate =
  assemblePatch (word8 customCodeTableHeader <> framedCustomTableData config candidate)
                (encodeWindowBytes plannedWindow
                   (plainCarriages (plannedSections plannedWindow)))
  where
    plannedWindow = layoutPlannedWindow OmitWindowAdler32 (denseOpcodes candidate) target plan

-- | The code-table data a custom-table patch's header carries behind VCD_CODETABLE, framed behind its length varint:
-- the two cache-size bytes (@s_near@, @s_same@ from @config@), then the inner delta.
-- The inner delta is @default-image -> candidate-image@ through the default-only core ('emitDefaultPatch'),
-- and itself stays on the default table and geometry, RFC 3284 §7c requiring it, which the default-only core provides.
framedCustomTableData :: AddressCacheConfig -> Table.CodeTable -> Builder
framedCustomTableData config candidate =
  varintOfLength (byteLength codeTableData) <> byteString codeTableData
  where
    codeTableData   = builderBytes (cacheSizeHeader <> byteString innerDelta)
    cacheSizeHeader = word8 (fromIntegral (unNearSlotCount  (nearSlotCount  config)))
                   <> word8 (fromIntegral (unSameBlockCount (sameBlockCount config)))
    innerDelta      = emitDefaultPatch defaultImage candidateImage
                        (vcdiffCover (InputFileContents defaultImage)
                                     (OutputFileContents candidateImage))
    defaultImage    = Table.serializeCodeTable Table.defaultCodeTable
    candidateImage  = Table.serializeCodeTable candidate

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
designCandidateTable resolved = case donorMints [resolved] of
  Just assignments
    | not (null assignments) ->
        Just (Table.codeTableWithEntriesReplaced Table.defaultCodeTable assignments)
  _ -> Nothing

-- | The donor-opcode reassignments a patch's resolved streams want, and whether the soundness-required ones all fit.
-- One stream per window: adjacencies and shapes are read within each stream and the tallies pooled,
-- so a window boundary never counts as a combinable pair, while a shape repeating across windows
-- earns its mint from the whole patch — the table ships once, its opcodes amortized over every window.
-- Two kinds of shape draw a donor:
--
--   * /required/: a coded-size COPY opcode for each cache mode any stream uses that the default table cannot name.
--     A grown cache admits modes past the default nine, and 'selectCopyAddressMode' may pick one; without an opcode the packer could not emit it.
--     Frequency-independent (one use still needs it), placed first so they win donors over the savings mints.
--     Streams whose required mints outrun the donor pool have no sound table: 'donorMints' is 'Nothing', and the grow declines them.
--   * /savings/: the ADD+COPY and COPY+ADD adjacencies ('combinablePairs') and the lone fixed-size ADD and COPY shapes ('singleInstructionShapes')
--     the default cannot name and these streams repeat, most frequent first
--     (@count >= 2@; a shape seen once cannot repay even the leanest table edit).
--     Pairs and singles pool into one tally, their entry shapes disjoint, a pair carrying two real templates, a single a trailing 'Table.Noop'.
--
-- Every minted COPY mode is one a resolved stream selected,
-- so it lies within the geometry the streams were resolved under and the decoder's mode check accepts it.
-- 'Nothing' is the infeasible verdict (the required mints outran the donor pool);
-- 'Just []' is feasible with no mints (the default table suffices); 'Just' a non-empty list is the custom table's reassignments.
donorMints :: [[ResolvedInstruction]] -> Maybe [(Table.Opcode, Table.CodeTableEntry)]
donorMints resolvedPerWindow
  | length requiredCopyModeEntries <= length donorOpcodes = Just (zip donorOpcodes mintEntries)
  | otherwise                                             = Nothing
  where
    defaultDense = denseOpcodes Table.defaultCodeTable
    pairs        = concatMap combinablePairs resolvedPerWindow
    singles      = concatMap singleInstructionShapes resolvedPerWindow

    requiredCopyModeEntries :: [Table.CodeTableEntry]
    requiredCopyModeEntries =
      [ entry
      | mode <- distinctCopyModes
      , let entry = Table.CodeTableEntry (Table.Copy Table.SizeCodedSeparately mode) Table.Noop
      , opcodeFor defaultDense entry == Nothing ]

    distinctCopyModes :: [Table.CopyAddressMode]
    distinctCopyModes =
      Map.keys (Map.fromList [ (mode, ()) | ResolvedCopy _ mode _ <- concat resolvedPerWindow ])

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
-- the copy-source bit its segment's origin names — VCD_SOURCE for the source file, VCD_TARGET for earlier windows' output —
-- when its COPYs address the segment the two following varints describe
-- (a self-contained window sets neither copy-source bit and omits both varints), and VCD_ADLER32 when its checksum follows the section lengths.
windowIndicator :: WindowSourcing -> PlannedWindowChecksum -> Word8
windowIndicator sourcing plannedWindowChecksum = sourcingBits .|. checksumBits
  where
    sourcingBits = case sourcing of
      DrawsOn FromSourceFile     _segmentSpan -> bit vcdSourceBit
      DrawsOn FromProducedTarget _segmentSpan -> bit vcdTargetBit
      SelfContained                           -> 0x00
    checksumBits = case plannedWindowChecksum of
      PlannedAdler32 _  -> bit vcdAdler32Bit
      NoPlannedChecksum -> 0x00

builderBytes :: Builder -> ByteString
builderBytes = LazyByteString.toStrict . toLazyByteString
