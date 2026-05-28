{-# LANGUAGE OverloadedStrings #-}

module Slap.XDelta1.Types
  ( XDelta1Patch(..)
  , XDelta1Instruction(..)
  , XDelta1InstructionTarget(..)
  , XDelta1OffsetMode(..)
  , XDelta1VerificationPosture(..)
  , XDelta1PatchCompression(..)
  , XDelta1FileAtDeltaTime(..)
    -- * Header-name newtypes
  , XDelta1FromName(..)
  , XDelta1ToName(..)
    -- * Resolved file-name pair (smart constructor)
    --
    -- The bare data constructor is intentionally not exported; the
    -- only paths to a 'ResolvedXDelta1FileNames' value are the two
    -- resolvers below, so every value at every call site has been
    -- run through the u16 byte-length cap check.
  , ResolvedXDelta1FileNames
      ( resolvedXDelta1FromName
      , resolvedXDelta1ToName
      )
  , resolveXDelta1FileNames
  , requireXDelta1FileNames
    -- * Named constants
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

import Data.Bits (shiftL)
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.Text as Text
import Data.Word (Word32)
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

-- | Per-source wire convention for how instruction offsets are
-- encoded. Under 'AbsoluteOffsets', each instruction's source offset
-- is written verbatim. Under 'SequentialOffsets', the wire offset is
-- 0 for every instruction, and each instruction's actual source
-- offset is reconstructed on parse as the running cumulative sum of
-- preceding instructions' lengths against that source.
-- Encoded by 'Slap.XDelta1.Create.encodeInstruction'; reconstructed
-- by 'Slap.XDelta1.Parse.fixSequentialOffsets'.
data XDelta1OffsetMode = AbsoluteOffsets | SequentialOffsets
  deriving (Show, Eq)

-- | An xdelta 1.1.x patch's in-memory model. Field layout mirrors
-- 'Slap.BPS.Types.BPSPatch' / 'Slap.UPS.Types.UPSPatch' (flat source
-- fields on the patch record) rather than the parallel-source shape
-- canonical xdelta's libedsio serializer paints on the wire. The wire
-- carries two source records (data segment and source file) treated
-- uniformly by libedsio; slap's type model only carries the file
-- source's metadata because the data segment's "name" is the fixed
-- literal 'xdelta1DataRecordName', its MD5 is computed against bytes
-- in 'xdelta1DataSegment', its length equals 'ByteString.length' of
-- that segment, and its offset-mode is always sequential at encode
-- time (slap's differ never emits non-sequential data emits). On
-- parse, the data-record's wire fields are validated against those
-- invariants (length must match the segment bytes; MD5 must match
-- under 'VerifyAgainstStoredMD5s'; offset-mode dispatches sequential-
-- offset reconstruction for data-targeting instructions; name is
-- consulted for an informational notice but never gates apply).
data XDelta1Patch = XDelta1Patch
  { xdelta1FromName         :: XDelta1FromName
  , xdelta1ToName           :: XDelta1ToName
  , xdelta1Verification     :: XDelta1VerificationPosture
  , xdelta1PatchCompression :: XDelta1PatchCompression
  , xdelta1FromAtDeltaTime  :: XDelta1FileAtDeltaTime
  , xdelta1ToAtDeltaTime    :: XDelta1FileAtDeltaTime
  , xdelta1TargetLength     :: FileSize
  , xdelta1SourceName       :: XDelta1FromName
    -- ^ The per-source-record \"name\" field for the file-source record
    -- in the EDSIO source list. Distinct concept from the header
    -- 'xdelta1FromName' (which lives at fixed offsets in the header
    -- words), but slap's create path mirrors the two: the same
    -- 'resolvedXDelta1FromName' from a 'ResolvedXDelta1FileNames'
    -- flows into both wire fields so the source-record name reflects
    -- the real source file, not a placeholder. The type is
    -- 'XDelta1FromName' rather than 'ByteString' so the same value
    -- pipes into both fields without an intermediate raw-byte hop.
  , xdelta1SourceMD5        :: Maybe MD5Hash
  , xdelta1SourceLength     :: FileSize
  , xdelta1SourceOffsetMode :: XDelta1OffsetMode
  , xdelta1Instructions     :: [XDelta1Instruction]
  , xdelta1DataSegment      :: ByteString  -- decompressed literal data
  } deriving (Show, Eq)

-- | The from-name an xdelta 1.1.x patch carries in its header — the
-- display label for the source file at create time. Distinct from
-- 'XDelta1ToName' so transposition at any call site (encoder,
-- parser, resolver, test fixture) is a type error rather than a
-- silent wire-byte swap. The wrapped 'EncodedText' carries the
-- decoded codepoints alongside the encoding tag they were decoded
-- under; locale today (matching canonical xdelta's @memcpy@-from-
-- @argv@ convention), but the tag rides along so a future re-encode
-- under a different encoding picks the right encoder.
--
-- The u16 byte-length cap that the wire's packed name-lengths
-- header word imposes is enforced at construction of
-- 'ResolvedXDelta1FileNames' — not at the newtype itself, since the
-- parser pulls bytes whose length is already cap-bounded by virtue
-- of the u16 length-prefix on the wire. The newtype is a transport
-- for at-rest type discipline; the cap-check is at-edge validation
-- that lives at the resolver.
newtype XDelta1FromName = XDelta1FromName
  { unXDelta1FromName :: EncodedText
  } deriving (Eq, Show)

-- | The to-name an xdelta 1.1.x patch carries in its header — the
-- display label for the target file at create time. See
-- 'XDelta1FromName' for the rationale on the newtype boundary and
-- the locale-encoding convention.
newtype XDelta1ToName = XDelta1ToName
  { unXDelta1ToName :: EncodedText
  } deriving (Eq, Show)

-- | The two file-name fields an xdelta 1.1.x patch carries (the
-- source file's display label and the target file's display label),
-- resolved and cap-checked. xdelta1 takes these names from one of
-- three places: a CLI @--from-name@\/@--to-name@ flag (explicit), the
-- basename of the source\/target file path (create-time fallback), or
-- the inherited fields of a parsed xdelta1 source patch
-- (xdelta1@→@xdelta1 convert).
--
-- The bare constructor is not exported; the only paths to a value
-- are 'resolveXDelta1FileNames' (create) and 'requireXDelta1FileNames'
-- (convert). The wire encoder in "Slap.XDelta1.Create" takes one of
-- these and writes the contents to the header without re-checking —
-- the type IS the proof that resolution ran and that both bytes are
-- locale-encoded and within the u16 byte cap the wire's packed
-- name-lengths header word imposes.
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
-- the user sees \"BPS doesn't carry these fields\" rather than a
-- bare \"names required\". Otherwise cap-checks both encoded byte
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

-- | The one place where the u16 byte-length cap is enforced. Both
-- exported resolvers funnel through here. Construction of
-- 'ResolvedXDelta1FileNames' anywhere else in slap is a type error
-- (the constructor is module-private). The cap-check runs against
-- the encoded byte count under the value's encoding tag: the value
-- re-encodes (lenient) under whatever encoding it carries to count
-- bytes; substitution events at encode time are accepted silently
-- here (the resolver returns 'Either', with no advisory channel —
-- the create-time re-encoder in 'Slap.XDelta1.Create.encodeXDelta1'
-- surfaces them through its 'CreateResult' channel).
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
      (MaxLength     (Length xdelta1NameByteCap))
  where
    (bytes, _notices) =
      encodeTextLenient (encodedTextEncoding text) (encodedTextContent text)

-- | Maximum byte count that fits in a 16-bit name-length slot of the
-- xdelta1 header's packed name-lengths word.
xdelta1NameByteCap :: Int
xdelta1NameByteCap = 0xFFFF

-- | The slap-internal representation of an xdelta 1.1.x patch's
-- verification posture — whether MD5 fields carry real verification
-- data or are the canonical sentinel ('xdelta1EmptyInputMD5Sentinel')
-- emitted by the canonical tool's @--noverify@. The round-trip
-- vehicle for the @--omit-verification@ axis in xdelta1: the parser
-- produces a value of this type from the wire; the encoder in
-- "Slap.XDelta1.Create" consumes one (mapped from
-- 'Slap.Convert.VerificationInclusion' at the porcelain boundary)
-- and writes the corresponding wire bytes (flag bit set with
-- sentinels in MD5 slots, or flag bit clear with computed MD5s).
-- Constructors are unchanged across directions. The source-file
-- MD5 ('xdelta1SourceMD5') shares the patch-level posture: it
-- carries @Just MD5Hash@ under 'VerifyAgainstStoredMD5s' and
-- @Nothing@ under 'CreatorOptedOutOfVerification' (parser-enforced;
-- not type-level). Family siblings:
-- 'Slap.Convert.VerificationInclusion' on create (the user-facing
-- choice the porcelain maps to a posture), 'VerificationPolicy'
-- on apply (the runtime policy that gates mismatch behavior when
-- verification /does/ run),
-- 'Slap.Status.VerificationOptedOutByCreator' (the warning emitted
-- when verification is declared absent at the format level).
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

-- | Trailer size: 4-byte control offset + 8-byte trailing magic.
xdelta1TrailerSize :: Int
xdelta1TrailerSize = 12

-- | The MD5 of zero input bytes
-- (@d41d8cd98f00b204e9800998ecf8427e@), used by xdelta 1.1.x's
-- canonical tool as the placeholder in every MD5 slot of a patch
-- created with @--noverify@. The bytes are written by an
-- @edsio_md5_init@ + 0× @_update@ + @_final@ sequence
-- (@xdmain.c:1055,1075,1301@), forced by the algorithm to produce
-- this fixed value. Non-canonical producers may write other bytes;
-- the constant is named here so future diagnostic code can
-- reference the canonical sentinel by name rather than inline hex.
xdelta1EmptyInputMD5Sentinel :: MD5Hash
xdelta1EmptyInputMD5Sentinel = MD5Hash
  "\xd4\x1d\x8c\xd9\x8f\x00\xb2\x04\xe9\x80\x09\x98\xec\xf8\x42\x7e"

-- | The fixed literal canonical xdelta writes into the data-record's
-- @name@ slot — see @xdelta-1.1.4/xdelta.c:241-251@, where the data
-- source is added with name @"(patch data)"@. The data record is
-- the patch's inline literal-bytes source ('xdelta1DataSegment'),
-- not an externally-named source, so a name field is meaningful
-- only as a label in @xdelta info@-style displays; canonical xdelta
-- itself never consults this field at apply time. Slap encodes the
-- canonical bytes on create and surfaces an informational notice
-- (no warning, no apply refusal) if the parsed patch carries
-- anything else.
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
-- type. Derived from @tools\/xdelta1\/xdelta-1.1.4\/xd_edsio.h:108@:
--
-- @
-- ST_XdeltaControl = (1 << (7 + EDSIO_LIBRARY_OFFSET_BITS)) + 3
-- @
--
-- with @EDSIO_LIBRARY_OFFSET_BITS = 8@ from
-- @tools\/xdelta1\/xdelta-1.1.4\/libedsio\/edsio.h:41@. The low byte
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
-- @source->alloc_total@ at
-- @tools\/xdelta1\/xdelta-1.1.4\/libedsio\/default.c@ and bounds-
-- checks every sub-record allocation against it: a sub-allocation
-- request whose running total would exceed the declared bound fires
-- @EC_EdsioIncorrectAllocation@ and bails. Not a hint — a hard cap.
--
-- The exact "right" value is the in-memory struct allocation
-- canonical would need to reconstruct the parsed objects —
-- platform-dependent (struct layout, pointer size, 8-byte alignment),
-- not derivable from wire bytes alone. Slap doesn't attempt to
-- compute it precisely; this constant is a generous fixed upper
-- bound, large enough to satisfy canonical's check for any patch
-- slap can produce, small enough to fit in a 32-bit word. The cost
-- of over-declaring is wasted-then-freed memory inside canonical's
-- parser, not wire bloat (the field is always 4 bytes regardless of
-- value).
--
-- 16 MiB is comfortably above any realistic per-patch allocation
-- canonical would actually use and well under the 4 GiB ceiling.
-- Revisit if a future patch shape grows past it.
xdelta1ControlAllocationBound :: Word32
xdelta1ControlAllocationBound = 16 * 1024 * 1024
