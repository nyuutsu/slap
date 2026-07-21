{-# LANGUAGE OverloadedStrings #-}

module Slap.XDelta1.Types
  ( XDelta1Patch(..)
  , XDelta1SourceRoster(..)
  , XDelta1FileSource(..)
  , rosterFileSource
  , rosterSourceCount
  , instructionTargetWireIndex
  , XDelta1Instruction(..)
  , XDelta1InstructionTarget(..)
  , XDelta1OffsetMode(..)
  , XDelta1VerificationPosture(..)
  , XDelta1PatchCompression(..)
  , XDelta1FileAtDeltaTime(..)
    -- * Header-name newtypes
  , XDelta1FromName(..)
  , XDelta1ToName(..)
    -- * Resolved file-name pair (smart constructor; see 'ResolvedXDelta1FileNames')
  , ResolvedXDelta1FileNames
      ( resolvedXDelta1FromName
      , resolvedXDelta1ToName
      )
  , resolveXDelta1FileNames
  , requireXDelta1FileNames
    -- * Named constants
  , xdelta1MagicLength
  , xdelta1HeaderBlockLength
  , xdelta1TrailerSize
  , xdelta1EmptyInputMD5Sentinel
  , xdelta1DataRecordName
  , xdelta1FlagNoVerify
  , xdelta1FlagFromCompressed
  , xdelta1FlagToCompressed
  , xdelta1FlagPatchCompressed
  , xdelta1ControlTypeTag
  , xdelta1ControlAllocationBound
  ) where

import Data.Aeson (FromJSON)
import Data.Bits (shiftL)
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.Text as Text
import Data.Word (Word32, Word64)
import Slap.Checksum (MD5Hash(..))
import Slap.Status (SlapError(..))
import Slap.FieldName (FieldName(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.Measure (Offset(..), FileSize(..),
                     Length(..), EncodedLength(..), MaxLength(..),
                     byteLength)
import Slap.Text (EncodedText(..), EncodingName(..),
                  encodedTextContent, encodeTextLenient)
import System.FilePath (takeFileName)

-- | Per-source wire convention for how instruction offsets are encoded.
-- Under 'AbsoluteOffsets', each instruction's source offset is written verbatim.
-- Under 'SequentialOffsets', the wire offset is 0 for every instruction,
-- and the real offset is reconstructed on parse as the running sum of preceding instructions' lengths against that source.
data XDelta1OffsetMode = AbsoluteOffsets | SequentialOffsets
  deriving (Show, Eq)

-- | An xdelta 1.1.x patch's in-memory model. The data segment's literal bytes live in 'xdelta1DataSegment' whatever the roster shape:
-- the segment belongs to the patch envelope, not the source list, so even a sourceless patch carries an empty one on the wire.
data XDelta1Patch = XDelta1Patch
  { xdelta1FromName         :: XDelta1FromName
  , xdelta1ToName           :: XDelta1ToName
  , xdelta1Verification     :: XDelta1VerificationPosture
  , xdelta1PatchCompression :: XDelta1PatchCompression
  , xdelta1FromAtDeltaTime  :: XDelta1FileAtDeltaTime
  , xdelta1ToAtDeltaTime    :: XDelta1FileAtDeltaTime
  , xdelta1TargetLength     :: FileSize
  , xdelta1SourceRoster     :: XDelta1SourceRoster
  , xdelta1Instructions     :: [XDelta1Instruction]
  , xdelta1DataSegment      :: ByteString  -- decompressed literal data
  } deriving (Show, Eq)

-- | Which sources a patch's EDSIO source list carries.
-- Canonical xdelta drops a source its instructions never cite (@control_add_info@'s @if (! src->used)@ early return,
-- @xdelta.c:1155@ in @docs/xdelta1/upstream/xdelta-1.1.3.tar.gz@),
-- so four shapes reach the wire: the full pair (an ordinary delta), the data segment alone (unrelated or too-short inputs),
-- the file source alone (identical files, or truncation), and nothing at all (an empty target).
-- An instruction's wire index counts positions in this list, so under 'FileSourceOnly' the file source is index 0, not 1.
--
-- Only the file source keeps a payload ('XDelta1FileSource');
-- the data record's name, MD5, length, and offset mode are all fixed or derivable from 'xdelta1DataSegment',
-- re-derived at create rather than stored.
data XDelta1SourceRoster
  = DataAndFileSources XDelta1FileSource
  | DataSourceOnly
  | FileSourceOnly XDelta1FileSource
  | NoSources
  deriving (Show, Eq)

data XDelta1FileSource = XDelta1FileSource
  { xdelta1FileSourceName       :: XDelta1FromName
    -- ^ Distinct from the header 'xdelta1FromName',
    -- though create fills both wire fields from the same resolved value.
  , xdelta1FileSourceMD5        :: Maybe MD5Hash
  , xdelta1FileSourceLength     :: FileSize
  , xdelta1FileSourceOffsetMode :: XDelta1OffsetMode
  } deriving (Show, Eq)

rosterFileSource :: XDelta1SourceRoster -> Maybe XDelta1FileSource
rosterFileSource (DataAndFileSources fileSource) = Just fileSource
rosterFileSource DataSourceOnly                  = Nothing
rosterFileSource (FileSourceOnly fileSource)     = Just fileSource
rosterFileSource NoSources                       = Nothing

rosterSourceCount :: XDelta1SourceRoster -> Int
rosterSourceCount (DataAndFileSources _) = 2
rosterSourceCount DataSourceOnly         = 1
rosterSourceCount (FileSourceOnly _)     = 1
rosterSourceCount NoSources              = 0

-- | An instruction's wire source-index: its position in the emitted list, the inverse of 'Slap.XDelta1.Parse.translateInstruction'.
-- A target the roster does not carry has no index at all — the roster is built from the very instructions that index it,
-- so an 'error' here would mean a broken invariant, not a wire value any reader could resolve.
instructionTargetWireIndex :: XDelta1SourceRoster -> XDelta1InstructionTarget -> Word64
instructionTargetWireIndex roster target = case (roster, target) of
  (DataAndFileSources _, FromDataSource) -> 0
  (DataAndFileSources _, FromFileSource) -> 1
  (DataSourceOnly,       FromDataSource) -> 0
  (FileSourceOnly _,     FromFileSource) -> 0
  (DataSourceOnly,       FromFileSource) -> absentSource "file"
  (FileSourceOnly _,     FromDataSource) -> absentSource "data"
  (NoSources,            _)              -> absentSource (case target of
                                              FromDataSource -> "data"
                                              FromFileSource -> "file")
  where
    absentSource sourceKindName =
      error ("instructionTargetWireIndex: an instruction targets the " ++ sourceKindName
              ++ " source, but the patch's roster does not carry one")

-- | The from-name an xdelta 1.1.x patch carries in its header — the display label for the source file at create time.
-- The wrapped 'EncodedText' carries the decoded codepoints alongside the tag they were decoded under:
-- locale today (matching canonical xdelta's @memcpy@-from-@argv@ convention),
-- but the tag rides along, so a future re-encode under a different encoding picks the right encoder.
--
-- The u16 byte-length cap is checked at construction of 'ResolvedXDelta1FileNames', not here:
-- parsed bytes are already cap-bounded by the wire's u16 length-prefix.
newtype XDelta1FromName = XDelta1FromName
  { unXDelta1FromName :: EncodedText
  } deriving (Eq, Show)
    deriving newtype (FromJSON)

-- | The to-name an xdelta 1.1.x patch carries in its header — the
-- display label for the target file at create time. See
-- 'XDelta1FromName' for the rationale on the newtype boundary and
-- the locale-encoding convention.
newtype XDelta1ToName = XDelta1ToName
  { unXDelta1ToName :: EncodedText
  } deriving (Eq, Show)
    deriving newtype (FromJSON)

-- | The two file-name fields an xdelta 1.1.x patch carries (the
-- source file's display label and the target file's display label),
-- resolved and cap-checked. xdelta1 takes these names from one of
-- three places: a CLI @--from-name@\/@--to-name@ flag (explicit), the
-- basename of the source\/target file path (create-time fallback), or
-- the inherited fields of a parsed xdelta1 source patch
-- (xdelta1@→@xdelta1 convert).
--
-- The bare constructor is not exported; the only paths to a value are 'resolveXDelta1FileNames' (create) and 'requireXDelta1FileNames' (convert).
-- The wire encoder in "Slap.XDelta1.Create" writes the contents to the header without re-checking:
-- a value in hand came from one of those two resolvers, so both names are locale-encoded
-- and within the u16 cap the wire's packed name-lengths header word imposes.
data ResolvedXDelta1FileNames = ResolvedXDelta1FileNames
  { resolvedXDelta1FromName :: !XDelta1FromName
  , resolvedXDelta1ToName   :: !XDelta1ToName
  } deriving (Eq, Show)

-- | Create-time resolver. For each of the two name slots, the CLI
-- override (if any) wins; otherwise the slot is filled with the
-- basename of the corresponding file path, tagged 'EncodingUtf8'.
-- The resulting encoded bytes are then cap-checked.
--
-- The CLI inputs are 'Maybe' 'EncodedText' (already wrapped at the
-- CLI boundary), not 'Maybe' 'XDelta1FromName'\/'ToName' — the
-- newtype wrap is part of what this resolver does, so callers pass
-- typed text and the smart-constructor pattern is the only way to
-- obtain the wrapped, validated values.
resolveXDelta1FileNames
  :: Maybe EncodedText  -- ^ CLI @--from-name@ override; 'Nothing' falls back to @takeFileName@ of the source path.
  -> Maybe EncodedText  -- ^ CLI @--to-name@   override; 'Nothing' falls back to @takeFileName@ of the target path.
  -> FilePath           -- ^ source file path (basename feeds the from-name default)
  -> FilePath           -- ^ target file path (basename feeds the to-name   default)
  -> Either SlapError ResolvedXDelta1FileNames
resolveXDelta1FileNames cliFromName cliToName sourcePath targetPath =
  buildResolvedXDelta1FileNames fromText toText
  where
    fromText = maybe (basenameAsUtf8Text sourcePath) id cliFromName
    toText   = maybe (basenameAsUtf8Text targetPath) id cliToName

-- | Wrap the basename of a 'FilePath' as a UTF-8-tagged 'EncodedText'.
-- Used for the create-side filepath defaulting when neither CLI flag
-- nor inherited source patch supplies a name. GHC delivers 'FilePath'
-- as 'String' (codepoints), so wrapping is one 'Text.pack' away.
basenameAsUtf8Text :: FilePath -> EncodedText
basenameAsUtf8Text = EncodedText EncodingUtf8 . Text.pack . takeFileName

-- | Convert-time resolver. Takes the already-merged CLI-or-inherited
-- pair (the porcelain runs 'Slap.Convert.mergeRequestedMetadata'
-- upstream so a CLI override has already won over a parsed xdelta1
-- source patch's field). If either slot is still 'Nothing', refuses
-- with 'XDelta1ConvertRequiresNames' naming the source format so
-- the user sees "BPS doesn't carry these fields" rather than a
-- bare "names required". Otherwise cap-checks both encoded byte
-- counts and bundles them.
requireXDelta1FileNames
  :: Maybe EncodedText  -- ^ merged from-name (CLI > inherited > 'Nothing')
  -> Maybe EncodedText  -- ^ merged to-name
  -> FormatLabel        -- ^ source format the convert originated from
  -> Either SlapError ResolvedXDelta1FileNames
requireXDelta1FileNames mergedFromName mergedToName sourceLabel =
  case (mergedFromName, mergedToName) of
    (Just fromText, Just toText) ->
      buildResolvedXDelta1FileNames fromText toText
    _ -> Left (XDelta1ConvertRequiresNames sourceLabel)

-- | The one place the u16 byte-length cap is enforced; both exported resolvers funnel through here.
-- The cap-check counts the encoded bytes by re-encoding (lenient) under the value's own encoding tag.
-- Substitution events are silent here (the resolver has no advisory channel),
-- surfacing later through 'Slap.XDelta1.Create.encodeXDelta1''s 'CreateResult'.
buildResolvedXDelta1FileNames
  :: EncodedText -> EncodedText
  -> Either SlapError ResolvedXDelta1FileNames
buildResolvedXDelta1FileNames fromText toText = do
  () <- checkNameLength FieldXDelta1FromName fromText
  () <- checkNameLength FieldXDelta1ToName   toText
  Right (ResolvedXDelta1FileNames (XDelta1FromName fromText) (XDelta1ToName toText))

-- | Refuse a name whose encoded byte length exceeds the u16 cap that
-- the xdelta1 header's packed name-lengths word imposes (top 16 bits
-- = from-name length, bottom 16 = to-name length; see
-- 'Slap.XDelta1.Create.encodeXDelta1'\'s @nameLengthsWord@). The
-- count is computed against the lenient encode under the value's
-- tag; both names are checked independently so the offender's
-- identity reaches the user verbatim.
checkNameLength :: FieldName -> EncodedText -> Either SlapError ()
checkNameLength field text
  | ByteString.length bytes <= xdelta1NameByteCap = Right ()
  | otherwise = Left $ FieldTooLong LabelXDelta1 field
      (EncodedLength (byteLength bytes))
      (MaxLength     (Length (fromIntegral xdelta1NameByteCap)))
  where
    (bytes, _notices) =
      encodeTextLenient (encodedTextEncoding text) (encodedTextContent text)

-- | Maximum byte count a name-length slot of the header's packed name-lengths word can name.
-- The slot is 16 bits, but the reference unpacks each half into a @gint16@ and then allocates against it,
-- so a slot above @0x7FFF@ reads there as a negative byte count.
xdelta1NameByteCap :: Int
xdelta1NameByteCap = 0x7FFF

-- | The slap-internal representation of an xdelta 1.1.x patch's verification posture:
-- whether the MD5 fields carry real verification data, or the canonical sentinel ('xdelta1EmptyInputMD5Sentinel') the reference's @--noverify@ emits.
-- On the wire that is the flag bit set with sentinels in the MD5 slots, or the bit clear with computed MD5s.
-- The file-source MD5 ('xdelta1FileSourceMD5') tracks the same posture —
-- @Just@ under 'VerifyAgainstStoredMD5s', @Nothing@ under 'CreatorOptedOutOfVerification' —
-- but by parser convention, not at the type level.
data XDelta1VerificationPosture
  = VerifyAgainstStoredMD5s MD5Hash
  | CreatorOptedOutOfVerification
  deriving (Show, Eq)

-- | Whether an xdelta1 patch's data and control segments are gzip-
-- compressed in the wire bytes. Bit 3 ('xdelta1FlagPatchCompressed')
-- of the header's flags word; the parser inflates each segment
-- independently when the bit is set. Uncompressed @%XDZ004%@
-- patches are spec-conformant; canonical xdelta-1.x emits
-- compressed by default. Slap follows that default on create and
-- gates the choice on @slap create --no-compress@.
data XDelta1PatchCompression
  = CompressedPatch
  | UncompressedPatch
  deriving (Show, Eq)

-- | Whether one of the two files involved in delta computation was
-- a gzip stream at the time the patch was created. Canonical xdelta
-- detects gzip-magic input and transparently decompresses it before
-- computing the delta; the matching flag bit
-- ('xdelta1FlagFromCompressed' bit 1, 'xdelta1FlagToCompressed'
-- bit 2) tells the apply tool to do the inverse transparency on
-- its side. Slap doesn't implement that transparency today; apply
-- refuses with 'Slap.Status.XDelta1InputPreCompressionUnsupported'
-- when either side is 'FileWasGzipStream', rather than silently
-- producing wrong output against the user's literal source bytes.
data XDelta1FileAtDeltaTime
  = FileWasRawBytes
  | FileWasGzipStream
  deriving (Show, Eq)

-- | Which of the patch's two sources an instruction copies from.
-- The wire format encodes this as an integer index (0 for the data
-- source, 1 for the file source); the parser translates the wire
-- byte to this sum at parse time and refuses any other index with
-- 'Slap.Status.XDelta1UnknownInstructionTarget'. Apply-side
-- dispatch ('Slap.XDelta1.Apply.applyXDelta1') pattern-matches on
-- this rather than threading the raw integer through.
data XDelta1InstructionTarget
  = FromDataSource
  | FromFileSource
  deriving (Show, Eq)

data XDelta1Instruction = XDelta1Instruction
  { xdelta1InstructionTarget :: XDelta1InstructionTarget
  , xdelta1InstructionOffset :: Offset
  , xdelta1InstructionLength :: FileSize
  } deriving (Show, Eq)

-- | Length of the magic prefix that opens, and closes, every xdelta1 patch.
xdelta1MagicLength :: Int
xdelta1MagicLength = 8

-- | Length of the fixed header block: six uint32 BE words after the magic.
xdelta1HeaderBlockLength :: Int
xdelta1HeaderBlockLength = 24

-- | Trailer size: 4-byte control offset + 8-byte trailing magic.
xdelta1TrailerSize :: Int
xdelta1TrailerSize = 12

-- | The MD5 of zero input bytes (@d41d8cd98f00b204e9800998ecf8427e@),
-- used by xdelta 1.1.x's canonical tool as the placeholder in every MD5 slot of a patch created with @--noverify@.
-- Under @--noverify@ the context is initialized (@xdmain.c:997@) and
-- finalized (@xdmain.c:1306@) with every @edsio_md5_update@ skipped by its
-- @if (!no_verify)@ guard (@xdmain.c:1055,1075,1301@ in
-- @docs/xdelta1/upstream/xdelta-1.1.3.tar.gz@), so it finalizes over zero
-- bytes and is forced to this fixed value.
-- Non-canonical producers may write other bytes.
xdelta1EmptyInputMD5Sentinel :: MD5Hash
xdelta1EmptyInputMD5Sentinel = MD5Hash
  "\xd4\x1d\x8c\xd9\x8f\x00\xb2\x04\xe9\x80\x09\x98\xec\xf8\x42\x7e"

-- | The fixed literal canonical xdelta writes into the data-record's @name@ slot —
-- see @xdelta.c:246@ in @docs/xdelta1/upstream/xdelta-1.1.3.tar.gz@, where the data source is added with name @"(patch data)"@.
-- The data record is the patch's inline literal-bytes source ('xdelta1DataSegment'), not an externally-named source,
-- so a name field is meaningful only as a label in @xdelta info@-style displays rather than part of apply semantics.
-- Slap encodes the canonical bytes on create and surfaces an informational notice (no warning, no apply refusal)
-- if the parsed patch carries anything else.
xdelta1DataRecordName :: ByteString
xdelta1DataRecordName = "(patch data)"

-- | Bit 0 of the xdelta1 header's flags word. Set when the patch's
-- verification posture is 'CreatorOptedOutOfVerification' (matching
-- what canonical xdelta's @--noverify@ writes).
xdelta1FlagNoVerify :: Word32
xdelta1FlagNoVerify = 1

-- | Bit 1 of the xdelta1 header's flags word. Set when the from-
-- file was detected as a gzip stream at delta time by the canonical
-- tool, which decompressed it transparently before computing the
-- delta (and expects the apply tool to do the same on its side).
xdelta1FlagFromCompressed :: Word32
xdelta1FlagFromCompressed = 2

-- | Bit 2 of the xdelta1 header's flags word. Set when the to-
-- file was detected as a gzip stream at delta time by the canonical
-- tool, which decompressed it transparently before computing the
-- delta (and expects the apply tool to re-compress the output).
xdelta1FlagToCompressed :: Word32
xdelta1FlagToCompressed = 4

-- | Bit 3 of the xdelta1 header's flags word. Set when the patch's
-- data and control segments are gzip-deflated in the wire bytes
-- (each segment is its own gzip stream).
xdelta1FlagPatchCompressed :: Word32
xdelta1FlagPatchCompressed = 8

-- | EDSIO type tag for canonical xdelta's @ST_XdeltaControl@ record
-- type. Derived from @xd_edsio.h:108@ in @docs/xdelta1/upstream/xdelta-1.1.3.tar.gz@:
--
-- @
-- ST_XdeltaControl = (1 << (7 + EDSIO_LIBRARY_OFFSET_BITS)) + 3
-- @
--
-- with @EDSIO_LIBRARY_OFFSET_BITS = 8@ from @libedsio/edsio.h:40@ in
-- @docs/xdelta1/upstream/xdelta-1.1.3.tar.gz@. The low byte
-- (3) is the library number canonical validates at
-- @libedsio\/generic.c:66@ — a literal-zero library bails with
-- "Unregistered library: 0", which is the symptom slap-made patches
-- produced before this constant was wired in; the high bits identify
-- the type within that library. Big-endian on the wire, occupying
-- bytes 0..3 of the EDSIO-serialized control segment.
xdelta1ControlTypeTag :: Word32
xdelta1ControlTypeTag = (1 `shiftL` 15) + 3  -- = 0x00008003

-- | Allocation upper bound written into the control prelude's second
-- 32-bit slot (bytes 4..7 of the EDSIO-serialized control segment,
-- big-endian). Canonical's parser reads this into
-- @source->alloc_total@ at @libedsio/default.c:149@ in
-- @docs/xdelta1/upstream/xdelta-1.1.3.tar.gz@ and bounds-checks every
-- sub-record allocation against it (@default.c:301@): a sub-allocation
-- request whose running total would exceed the declared bound fires
-- @EC_EdsioIncorrectAllocation@ and bails. Not a hint — a hard cap.
--
-- The precise value isn't derivable from wire bytes, so slap declares
-- a generous fixed bound. 16 MiB clears any patch slap can produce and
-- fits a 32-bit word; over-declaring only costs wasted-then-freed
-- memory in canonical's parser, not wire bytes (the field is always
-- 4 bytes). Revisit if a future patch shape grows past it.
xdelta1ControlAllocationBound :: Word32
xdelta1ControlAllocationBound = 16 * 1024 * 1024
