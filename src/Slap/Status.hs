{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StrictData #-}

module Slap.Status
  ( -- Severity
    Severity(..)
  , severityLabel
  , slapAdvisorySeverity
    -- Emit pipeline
  , emitToStderr
  , emitAdvisory
  , emitAdvisories
  , bail
  , bailError
  , orBail
    -- Status values
  , SlapError(..)
  , SlapAdvisory(..)
  , ApplyError(..)
  , CursorKind(..)
  , UnencodeabilityReason(..)
  , DecompressionFailure(..)
  , BSDiffSection(..)
  , DecompressionCause(..)
  , XDelta1DiffCause(..)
  , XDelta1GzipStreamInputs(..)
  , CompressionAlgorithm(..)
  , decompressionAlgorithm
  , compressionAlgorithmName
  , bsDiffSectionName
  , renderDecompressionFailure
  , DroppedValue(..)
  , CreateResult(..)
  , Parsed(..)
  , Outcome(..)
  , noAdvisories
  , OverlapCount(..)
  , ClippedRecordCount(..)
  , OOBBlockCount(..)
  , MarkerOvershootBytes(..)
  , OOBOvershootBytes(..)
  , ApplyDirection(..)
  , directionVerb
  , VerificationSide(..)
  , HashAlgorithm(..)
  , ExpectedAdler32(..)
  , ActualAdler32(..)
  , ByteCheckLabel(..)
  , verificationSideLabel
  , hashAlgorithmLabel
    -- Restructured payload sums / newtypes
  , EmptyUnit(..)
  , emptyUnitLabel
  , XDelta1KnownUnsupportedVersion(..)
  , XDelta1ShapeViolation(..)
  , VCDIFFShapeViolation(..)
  , VCDIFFCodeTableMalformation(..)
  , VCDIFFCodeTableField(..)
  , VCDIFFUnsupportedFeature(..)
  , VCDIFFXDelta3Feature(..)
  , VCDIFFMalformation(..)
  , VCDIFFIndicatorKind(..)
  , VCDIFFSection(..)
  , BSDiffHeaderMalformation(..)
  , APSN64HeaderMalformation(..)
  , NINJA1Malformation(..)
  , NINJA1SubformatConversion(..)
  , BPSMetadataDivergence(..)
  , LineText(..)
  , OffsetTokenText(..)
  , ByteParserError(..)
  , ByteParserOperation(..)
  , DroppedDescriptionText(..)
    -- Rendering
  , renderSlapError
  , renderApplyError
  , renderByteParserError
  , renderCursorKind
  , renderSlapAdvisory
  ) where

import Slap.FileContents (PatchFileContents)
import Slap.FormatLabel (FormatLabel(..), formatLabelName)
import Slap.Checksum (CRC32, Adler32, MD5Hash(..), SHA1Hash(..),
                      showCRC32, showAdler32,
                      ExpectedCRC32(..), ActualCRC32(..))
import Slap.Display.Common (renderAsText, renderHexAsText, pathText)
import Slap.Archive.Types (ArchiveFormat, archiveFormatName,
                           ToolName(..), ToolDiagnostic(..),
                           EntryName(..), SeenEntryCount(..),
                           UnreadableReason(..), UnwrapError(..))
import Slap.Display.Primitives (hexByteString, padHex, renderPrintableASCIIOrHex)
import Slap.PlatformType (PlatformType, platformName)
import Slap.Measure (Offset(..), Length(..), Position(..), FileSize(..),
                     SignedOffset(..), ActionIndex(unActionIndex),
                     ReadOffset(..), WritePosition(..),
                     RequestedLength(..), RemainingLength(..),
                     ActualSize(..), ExpectedSize(..),
                     MaxAddressableSize(..),
                     DeclaredTargetSize(..), NaturalTargetSize(..),
                     RequiredLength(..), ActualLength(..),
                     EncodedLength(..), MaxLength(..),
                     OriginalLength(..), TruncatedLength(..),
                     SubstitutionCount(..),
                     ActualOffset(..), MaxOffset(..),
                     SentinelOffset(..),
                     ExpectedMagic(..), ActualMagic(..),
                     TrailerMarker(..),
                     ParsedSizeValue(..), FoundVersion(..),
                     RawFlagByte(..), EncodingMethodByte(..))
import Slap.Narrow (NarrowingFailure(..))
import Slap.FieldName (FieldName(..), fieldNameLabel)
import Slap.Constraint (Constraint(..), constraintFlagName, constraintName)
import Slap.Dialect (Dialect, dialectFlagName, dialectName)
import Slap.MetadataField (MetadataField, metadataFieldFlagName, metadataFieldName)
import Slap.PatchField (PatchField, fieldName)

import Data.ByteString (ByteString)
import Data.Foldable (traverse_)
import Data.Int (Int64)
import Data.List.NonEmpty (NonEmpty)
import qualified Data.List.NonEmpty as NonEmpty
import Data.Text (Text)
import qualified Data.Text as Text
import qualified Data.Text.IO as TextIO
import Data.Word (Word8)
import System.Exit (exitFailure)
import System.IO (stderr)

----------------------------------------------------------------------------
-- Severity and emit pipeline
----------------------------------------------------------------------------

-- | The valence of a status item: error halts, warning and note do
-- not. Severity is a property of each 'SlapError' constructor
-- (always 'SeverityError') and each 'SlapAdvisory' constructor
-- (varies, projected by 'slapAdvisorySeverity'). The 'emitToStderr'
-- pipeline uses 'severityLabel' to translate severity into the
-- prefix the user sees.
data Severity = SeverityError | SeverityWarning | SeverityNote
  deriving (Eq, Show)

-- | The user-facing label for each severity. Bare word; the
-- delimiters that surround it on the wire ('emitToStderr' adds
-- @": "@ after) are the formatter's responsibility.
severityLabel :: Severity -> Text
severityLabel SeverityError   = "error"
severityLabel SeverityWarning = "warning"
severityLabel SeverityNote    = "note"

-- | The single low-level stderr writer for slap. Every error,
-- warning, or note the program emits routes through this. The
-- program-name prefix @"slap: "@ and the severity-prefix delimiter
-- @": "@ are the only places those literals appear in the codebase.
emitToStderr :: Severity -> Text -> IO ()
emitToStderr severity body =
  TextIO.hPutStrLn stderr ("slap: " <> severityLabel severity <> ": " <> body)

-- | Emit a single advisory at its declared severity.
emitAdvisory :: SlapAdvisory -> IO ()
emitAdvisory advisory = emitToStderr severity body
  where severity = slapAdvisorySeverity advisory
        body     = renderSlapAdvisory advisory

-- | Emit a list of advisories in order.
emitAdvisories :: [SlapAdvisory] -> IO ()
emitAdvisories = traverse_ emitAdvisory

-- | Emit an ad-hoc error message and exit. Used at the IO boundary
-- for failures that don't yet have a typed 'SlapError' constructor
-- (e.g., file-system preconditions in @Main@).
bail :: Text -> IO a
bail body = emitToStderr SeverityError body >> exitFailure

-- | Emit a typed 'SlapError' and exit.
bailError :: SlapError -> IO a
bailError = bail . renderSlapError

-- | Unwrap an 'Either SlapError' or terminate with a rendered error.
orBail :: Either SlapError a -> IO a
orBail = either bailError pure

----------------------------------------------------------------------------
-- DroppedValue
----------------------------------------------------------------------------

data DroppedValue
  = DroppedCRC CRC32
  | DroppedMD5 MD5Hash
  | DroppedSHA1 SHA1Hash
  | DroppedDescription DroppedDescriptionText
  | DroppedSize FileSize
  | DroppedEmpty
  deriving (Show, Eq)

-- | The text of a description field being dropped during conversion.
-- Wrapped so the opaque user-supplied content stays labeled and
-- non-pattern-matchable at the type level — peer to
-- 'DecompressionCause' and 'XDelta1DiffCause' in spirit.
newtype DroppedDescriptionText = DroppedDescriptionText
  { unDroppedDescriptionText :: Text }
  deriving (Show, Eq)

renderDroppedValue :: DroppedValue -> Text
renderDroppedValue (DroppedCRC crc)                                = "0x" <> showCRC32 crc
renderDroppedValue (DroppedMD5 hash)                               = hexByteString (unMD5Hash hash)
renderDroppedValue (DroppedSHA1 hash)                              = hexByteString (unSHA1Hash hash)
renderDroppedValue (DroppedDescription (DroppedDescriptionText t)) = "\"" <> t <> "\""
renderDroppedValue (DroppedSize size)                              = renderAsText (unFileSize size) <> " bytes"
renderDroppedValue DroppedEmpty                                    = ""

----------------------------------------------------------------------------
-- CursorKind
----------------------------------------------------------------------------

-- | Which of BPS's relative cursors misbehaved. BPS tracks two
-- independent relative cursors — 'SourceCursor' points into the
-- source ByteString for 'SourceCopy' actions, 'TargetCursor' points
-- into the output buffer for 'TargetCopy' actions. Apply errors
-- related to cursor underflow carry this tag to disambiguate.
data CursorKind = SourceCursor | TargetCursor
  deriving (Show, Eq)

----------------------------------------------------------------------------
-- UnencodeabilityReason
----------------------------------------------------------------------------

-- | Why a (source, target) pair cannot be encoded as a patch in some
-- format. Carried by 'UnencodeablePair' alongside the offending
-- format's 'FormatLabel'; the renderer reads both to compose the
-- user-visible refusal message.
--
-- Each variant names a specific structural reason a particular kind
-- of pair has no representation under at least one format slap can
-- emit. The variant set grows as new format-level refusals land;
-- adding one means adding a render arm in
-- 'renderUnencodeabilityReason' and (usually) a call site in the
-- format's create-path enforcer.
data UnencodeabilityReason
  = UPSSourceTailNonZero
    -- ^ UPS: source has non-zero bytes past target size. Refused to
    -- preserve UPS's bi-directional undo guarantee (spec §2): the
    -- block stream only covers @[0, target_size)@, so forward apply
    -- produces the correct target, but reverse apply reconstructs a
    -- source with zeros where the non-zero tail bytes used to be.
  | TargetGrowsBeyondSource  !ActualSize !ExpectedSize
    -- ^ Target file is larger than the source. Raised by formats
    -- whose 'Slap.Measure.SizeChangePolicy' is
    -- 'Slap.Measure.ForbidTargetSizeChange' — PPF1, PPF2, PPF3 —
    -- where the upstream reference encoders refuse on size mismatch
    -- and the wire format has no growth marker. The 'ActualSize' is
    -- the source's size; the 'ExpectedSize' is the would-be target's
    -- size.
  | TargetShrinksBelowSource !ActualSize !ExpectedSize
    -- ^ Target file is smaller than the source. Raised by formats
    -- whose 'Slap.Measure.SizeChangePolicy' is
    -- 'Slap.Measure.ForbidTargetShrinkage' (IPS32, EBP) or
    -- 'Slap.Measure.ForbidTargetSizeChange' (PPF1, PPF2, PPF3) —
    -- where the wire format has no truncation marker. The
    -- 'ActualSize' is the source's size; the 'ExpectedSize' is the
    -- would-be target's size.
  | TruncationTargetUnrepresentable !DeclaredTargetSize !MaxOffset
    -- ^ The pair shrinks, so the encoding needs a truncation marker,
    -- and the marker spells the final size in the same width as the
    -- variant's record offsets — a target size past that width's
    -- maximum has no representation. 'StandardIPS''s 24-bit post-EOF
    -- marker is the only marker-bearing format today. Raised by
    -- 'Slap.IPS.Types.ipsRejectIncompatibleSizeChange'; without the
    -- refusal, the encoder's offset field would mask the size to its
    -- low bits and emit a patch that applies to a wrongly-sized
    -- file, in a format with no checksum to notice.
  deriving (Eq, Show)

----------------------------------------------------------------------------
-- ApplyError
----------------------------------------------------------------------------

-- | Format-agnostic errors encountered during patch application.
-- Paired with a 'FormatLabel' at the outer boundary via the
-- 'ApplyFailed' 'SlapError' constructor. Most variants carry an
-- 'ActionIndex' identifying which action in the patch's action
-- stream triggered the error — this is the first thing to look at
-- when debugging a malformed patch.
--
-- Where a variant would otherwise have two positional arguments of
-- the same base type (two 'Offset's, two 'Length's, two 'FileSize's),
-- the arguments are typed with role newtypes from 'Slap.Measure'
-- ('ReadOffset' vs 'WritePosition', 'RequestedLength' vs
-- 'RemainingLength', 'ActualSize' vs 'ExpectedSize') so the field
-- roles are visible at construction, pattern-match, and rendering
-- sites without needing to consult documentation.
data ApplyError

  -- | A relative cursor (source or target) went negative after
  -- applying the action's delta. Arguments are all distinct types,
  -- so no role newtypes needed.
  = ApplyCursorUnderflow CursorKind ActionIndex SignedOffset

  -- | An action would read past the end of the source ByteString.
  -- The 'Offset' is the would-be read end; the 'FileSize' is the
  -- actual source size. Arguments are distinct types, so no role
  -- newtypes needed.
  | ApplySourceReadOutOfBounds ActionIndex Offset FileSize

  -- | A TargetCopy referenced an output position at or past the
  -- current write position (i.e., unwritten memory).
  | ApplyTargetReadUnwritten ActionIndex ReadOffset WritePosition

  -- | An action's output length would exceed the remaining space in
  -- the target buffer.
  | ApplyWritesPastTarget ActionIndex RequestedLength RemainingLength

  -- | The action stream was exhausted but the target buffer is not
  -- fully written. No 'ActionIndex' because this error fires after
  -- the stream ends and no specific action is responsible — the
  -- whole patch is short. (There is no corresponding
  -- @ApplyTargetOverfilled@ because 'ApplyWritesPastTarget' catches
  -- over-writes per-action before they can happen; writing past
  -- target is impossible if every action's length is validated
  -- against remaining space before the copy runs.)
  | ApplyTargetUnderfilled WritePosition ExpectedSize

  -- | A record's offset is negative. Possible for any format whose
  -- offset encoding admits a negative value: PPF3's signed 64-bit
  -- field, and NINJA2's packed integers, which decode into a signed
  -- 'Int'. The 'Offset' is the negative value as parsed.
  | ApplyNegativeRecordOffset ActionIndex Offset

  -- | A bsdiff control instruction declares a negative region length.
  -- bsdiff stores its control values in sign-magnitude, so a set sign
  -- bit makes a length negative on the wire; a region length is
  -- non-negative by nature, so such a value is malformed. (The seek
  -- delta in the same triple is legitimately signed and is not this.)
  -- The 'RequestedLength' is the negative length as parsed.
  | ApplyNegativeControlLength ActionIndex RequestedLength

  -- | A record's write reaches an offset slap cannot address. The
  -- record's @offset + payload length@ exceeds 'maxBound' :: 'Int', the
  -- ceiling slap can represent (it carries positions in a signed
  -- 'Int'). Only a format whose wire offset is as wide as the carrier —
  -- PPF3's signed 64-bit field — can name such a write; the format
  -- admits the value, and slap declines to materialise an output it
  -- cannot address. The apply-side sibling of
  -- 'FileExceedsAddressableRange'. The 'Offset' and 'Length' are the
  -- record's, carried separately because it is their sum that does not
  -- fit; the renderer adds them in 'Integer'.
  | ApplyOutputExceedsAddressableRange ActionIndex Offset Length

  -- | A PPF4 Replace record would write past the source file's end.
  -- PPF4 Replace records cannot grow the file (only Append records
  -- can); the reference applier rejects this with ERROR_BAD_SIZE.
  -- The 'Offset' is the record's start; the 'RequestedLength' is the
  -- record's payload length; the 'FileSize' is the source size.
  | ApplyReplaceGrowsFile ActionIndex Offset RequestedLength FileSize

  -- | A BSDiff ADD instruction would read past the end of the diff
  -- stream. The 'Offset' is the would-be read end; the 'FileSize' is
  -- the actual diff-stream size. BSDiff-specific because no other
  -- format carries a diff stream alongside the source.
  | ApplyDiffReadOutOfBounds ActionIndex Offset FileSize

  -- | A BSDiff COPY instruction would read past the end of the extra
  -- stream. The 'Offset' is the would-be read end; the 'FileSize' is
  -- the actual extra-stream size. BSDiff-specific (see comment on
  -- 'ApplyDiffReadOutOfBounds').
  | ApplyExtraReadOutOfBounds ActionIndex Offset FileSize

  -- | A record whose wire-defined absolute write position, together
  -- with its payload length, would extend past the target buffer's
  -- declared end. The 'Offset' is the record's write start; the
  -- 'RequestedLength' is the payload length; the 'FileSize' is the
  -- declared target size. Used by formats that name absolute write
  -- positions on the wire — NINJA2's XOR records, NINJA2's
  -- overflow-append step, APSGBA's blocks — where the start position
  -- itself can already sit past the declared target end. Distinct
  -- from 'ApplyWritesPastTarget' (which assumes a forward-walking
  -- cursor that always sits within the buffer by construction) and
  -- from 'ApplyReplaceGrowsFile' (PPF4-specific phrasing about
  -- growing the file).
  | ApplyAbsoluteWritePastTarget ActionIndex Offset RequestedLength FileSize

  deriving (Show, Eq)

----------------------------------------------------------------------------
-- DecompressionFailure
----------------------------------------------------------------------------

-- | A decompression failure, modeled in the 'ApplyError' style — its
-- own narrower vocabulary, lifted into 'SlapError' via a single
-- constructor.  One constructor per real decompression site slap
-- knows about; each carries only the axes that actually vary at that
-- site.  'VCDIFFSectionFailed' is the one site whose algorithm
-- genuinely varies: a secondary stream is decoded by whichever
-- compressor the patch declared, so the 'CompressionAlgorithm' rides
-- in the value — LZMA and DJW today, FGK through the same
-- constructor when its decoder lands.
data DecompressionFailure
  = Yay0WrapperFailed                       DecompressionCause
  | NINJA1Failed                            DecompressionCause
  | XDelta1Failed                           DecompressionCause
  | BSDiffSectionFailed   BSDiffSection     DecompressionCause
  | VCDIFFSectionFailed   VCDIFFSection CompressionAlgorithm DecompressionCause
  deriving (Show, Eq)

-- | BSDiff's three bzip2-compressed sections.
data BSDiffSection = BSDiffControl | BSDiffDiff | BSDiffExtra
  deriving (Show, Eq)

-- | The decompressor's diagnostic message. Carried verbatim from
-- flate2 / bzip2-rs / lzma-rs / slap's own Yay0 implementation; slap
-- relays the underlying library's 'Display' rather than
-- re-classifying. Across the FFI seam the bytes are decoded as UTF-8
-- (see 'Slap.FFI.readText'), so the 'Text' here carries real Unicode
-- codepoints from the moment it lands.
newtype DecompressionCause = DecompressionCause { unDecompressionCause :: Text }
  deriving (Show, Eq)

-- | The cause of an xdelta1 differ failure, carried verbatim from
-- the Rust side. Mirror of 'DecompressionCause' — slap relays the
-- underlying diagnostic rather than re-classifying. Lives at this
-- seam so consumers of 'SlapError' don't have to know about FFI;
-- raised by "Slap.XDelta1.FFI" and lifted into 'SlapError' via
-- 'XDelta1DiffFailed'.
newtype XDelta1DiffCause = XDelta1DiffCause { unXDelta1DiffCause :: Text }
  deriving (Show, Eq)

-- | Which input file(s) the patch expected to be gzip streams at
-- apply time. Carried by 'XDelta1InputPreCompressionUnsupported' so
-- the renderer can name the affected side(s) precisely without
-- recomputing them from raw flag bits. The "neither" case is not
-- representable — that's the success path, not a failure shape.
data XDelta1GzipStreamInputs
  = OnlyFromFileWasGzipStream
  | OnlyToFileWasGzipStream
  | BothFilesWereGzipStreams
  deriving (Show, Eq)

-- | The compression algorithms slap knows about.  Closed and
-- complete: the four with fixed decompression sites, plus the three
-- of xdelta3's secondary-compression catalog (DJW, LZMA, FGK), which
-- ride in 'VCDIFFSectionFailed' and the secondary-stream framing
-- malformations so the rendered failure names the algorithm that was
-- decoding when it fired.
data CompressionAlgorithm
  = Zlib | Gzip | Bzip2 | Yay0
  | DJW  | LZMA | FGK
  deriving (Show, Eq, Ord, Enum, Bounded)

----------------------------------------------------------------------------
-- SlapError
----------------------------------------------------------------------------

data SlapError

  -- IO boundary
  -- | The user pointed slap at a file that doesn't exist on the
  -- filesystem. Pre-parse, pre-detection — we never made it to the
  -- bytes. The 'FilePath' is the path the user typed and renders
  -- verbatim, so the message matches what their tab key (or fingers)
  -- produced.
  = MissingInputFile FilePath
  -- | The file is present but slap couldn't open it: wrong
  -- permissions, the path resolves to a directory, an underlying
  -- filesystem error, and so on. The 'String' carries the OS-supplied
  -- explanation ('System.IO.Error.ioeGetErrorString') so the user
  -- sees the same words their kernel would have said.
  | UnreadableInputFile FilePath String

  -- | slap recognized the input as an archive and tried to unwrap the
  -- single patch inside it, but couldn't. The 'FilePath' is the archive
  -- the user pointed at, the 'ArchiveFormat' is what its magic bytes
  -- identified, and the 'UnwrapError' is which way it failed. Raised by
  -- 'Slap.Archive.unwrapArchive' and rendered at the boundary.
  | ArchiveUnwrapFailed FilePath ArchiveFormat UnwrapError

  -- Detection
  | UnrecognizedFormat
  | AmbiguousDetection [FormatLabel]

  -- Parse: structural
  | InputTooShort FormatLabel RequiredLength ActualLength
  | BadMagic FormatLabel ActualMagic
  | BadVersion FormatLabel FoundVersion
  -- | xdelta1 magic identifies a known older subformat slap does not
  -- read. One constructor per known-unsupported version; future
  -- support graduates a version out of 'XDelta1KnownUnsupportedVersion'
  -- and into its own parser.
  | UnsupportedXDelta1Subformat XDelta1KnownUnsupportedVersion
  -- | NINJA1's @subFormatIdentifier@ two-byte tag names a wire shape
  -- slap does not implement. Canonical NINJA1 only emits @"B "@
  -- (binary), @"BZ"@ (compressed binary), @"T\\n"@ (text), and
  -- @"TZ"@ (compressed text); any other pair is off-spec or from a
  -- newer revision.
  | UnsupportedNINJA1Subformat ByteString
  | TruncatedRecord FormatLabel Int Length Length
  | NegativeSize FormatLabel FieldName ParsedSizeValue
  | DecompressionFailed DecompressionFailure

  -- | The xdelta1 differ ('Slap.XDelta1.FFI.xdelta1Diff')
  -- refused an input. Carries the underlying Rust-side cause
  -- verbatim — at minimum, allocation refusals when building the
  -- source index on memory-constrained hosts; also catches internal-
  -- invariant violations (cumulative emit length \/= target length
  -- at end, etc.) the differ surfaces rather than panicking.
  | XDelta1DiffFailed XDelta1DiffCause

  -- | A parsed record's effective end position lies beyond the
  -- variant's wire-format spec ceiling. The 'ActionIndex' names the
  -- offending record's position in the wire stream; the
  -- 'ActualOffset' is the record's computed end position
  -- (@offset + payloadLength@); the 'MaxOffset' is the variant's
  -- maximum addressable end (typically @maxAddressableOffset +
  -- maxRecordPayload@). Used by IPS-family parsers to reject
  -- records that name a position the format cannot represent on
  -- the wire, before they can flow through to the apply layer.
  | RecordExceedsAddressableRange FormatLabel ActionIndex ActualOffset MaxOffset

  -- | A parsed record carries a structurally malformed field — for
  -- example an RLE record whose run length is zero, or any other
  -- per-record value the spec or slap's strict discipline rejects
  -- as invalid. The 'ActionIndex' names the offending record; the
  -- 'FieldName' identifies which field of that record was
  -- malformed. Distinct from 'TruncatedRecord' (record was too
  -- short) and 'NegativeSize' (a top-level header size was
  -- negative).
  | MalformedRecordField FormatLabel ActionIndex FieldName

  -- | A parser found bytes after a recognized stream-closing trailer
  -- marker that don't match any post-trailer shape the format
  -- accepts. The motivating example is the IPS family: 'StandardIPS'
  -- accepts an empty post-@"EOF"@ trailer, a 3-byte post-EOF truncation
  -- marker, or an EBP JSON metadata blob, while 'IPS32' accepts only
  -- the empty post-@"EEOF"@ trailer; bytes outside those shapes are
  -- a structured parse failure rather than a 'Get'-monad
  -- passthrough. The 'TrailerMarker' carries the marker bytes the
  -- parser was anchored to so the renderer can name them ("after
  -- EOF marker", "after EEOF marker") without knowing about
  -- format-specific variants. The 'ActualLength' is the byte count
  -- of the unrecognized trailer slice.
  | UnrecognizedTrailer FormatLabel TrailerMarker ActualLength

  -- Parse: integrity
  | PatchCRCMismatch FormatLabel ExpectedCRC32 ActualCRC32
  | TrailingMagicMismatch FormatLabel ExpectedMagic ActualMagic

  -- Parse: content
  | UnknownFlag FormatLabel FieldName RawFlagByte
  | UnsupportedEncodingMethod FormatLabel EncodingMethodByte

  -- | A NINJA2 patch's PATCH_ENC byte (offset 6 of the fixed header)
  -- is not 0 (undeclared) or 1 (UTF-8). The NINJA2 spec defines no other
  -- values; slap refuses rather than fabricate a fallback encoding,
  -- because PATCH_ENC governs how every text field in the patch is
  -- decoded and slap has no honest answer for an undefined value.
  | NINJA2UnrecognizedTextMode !Word8

  -- | A structurally malformed text field in a NINJA1 textual patch —
  -- every shape of "the bytes do not parse as the format expects" is
  -- a constructor of 'NINJA1Malformation', enumerated as the failure
  -- space is finite per the format spec.
  | MalformedNINJA1Content NINJA1Malformation

  -- | A byte-parser failure surfaced from a per-format parser. The
  -- payload is a structured 'ByteParserError' that enumerates each
  -- shape the parser layer can fail in (underflow, terminator-not-
  -- found, varint overrun, and so on), so the renderer and any
  -- programmatic consumer can dispatch on the cause without scraping
  -- a free-form string. The 'FormatLabel' names which format's parser
  -- raised the failure; the constructor is per-format because the
  -- same byte-parser primitive surfaces meaning differently depending
  -- on which format-level call site invoked it.
  | ParseError FormatLabel ByteParserError

  -- | The xdelta1 parser rejected a source-list configuration that
  -- was not the canonical @[data segment, file source]@ pair. The
  -- 'XDelta1ShapeViolation' enumerates the off-spec shapes the wire
  -- can produce. The wire encodes the source list as an EDSIO
  -- length-prefixed sequence, so any count parses structurally;
  -- canonical xdelta unconditionally emits exactly two sources in
  -- @[data, file]@ order ('xdelta-1.1.4/xdelta.c:241-251' adds the
  -- data source, 'xdmain.c:1539-1542' adds the from-file source),
  -- and slap refuses anything else as off-spec.
  | UnsupportedXDelta1Shape XDelta1ShapeViolation

  -- | A VCDIFF patch's wire shape disagreed with the per-format
  -- structural rules slap enforces. The 'VCDIFFShapeViolation' names
  -- the specific failure: a nested custom code table (forbidden by
  -- RFC 3284 inside an already-custom-table payload), a window
  -- target-size varint that decoded as negative, or a secondary-
  -- compression flag set on a data section slap doesn't implement.
  -- These are validated after the byte-parser has produced the raw
  -- window list, so the parser stays focused on byte-level reading.
  | UnsupportedVCDIFFShape VCDIFFShapeViolation

  -- | A VCDIFF custom code table failed structural validation. The
  -- 'VCDIFFCodeTableMalformation' names the specific failure: the
  -- decoded table bytes were not exactly 1536 bytes long, contained
  -- a byte that did not decode to a valid instruction type, or were
  -- too short to even contain the 2-byte near\/same-cache-size
  -- header. Surfaced from 'Slap.VCDIFF.CodeTable.deserializeCodeTable',
  -- which runs outside the byte parser.
  | MalformedVCDIFFCodeTable VCDIFFCodeTableMalformation

  -- | A VCDIFF patch uses a feature outside the subset slap decodes —
  -- the custom code table. Such a patch is refused cleanly, the
  -- 'VCDIFFUnsupportedFeature' naming the feature, rather than
  -- mishandled. Raised by 'Slap.VCDIFF.Parse.parseVCDIFF'.
  | VCDIFFFeatureNotYetSupported VCDIFFUnsupportedFeature

  -- | A VCDIFF indicator byte set one or more bits the format
  -- reserves for future definition. slap implements only the bits
  -- defined today, so it does not know what such a patch is asking —
  -- and it must not call the patch malformed, because that is not
  -- slap's to say: a future-dialect patch could be perfectly
  -- well-formed, just unreadable here. A sibling decline to
  -- 'VCDIFFFeatureNotYetSupported', deliberately not a
  -- 'MalformedVCDIFF' arm — 'MalformedVCDIFF' means slap understands
  -- the claim a patch makes and the claim is invalid. Distinct from
  -- 'BadVersion' too: a version byte names a whole generation of the
  -- format, while a reserved bit is an undefined flag within the
  -- generation slap does implement; the two share only the
  -- disposition. The 'VCDIFFIndicatorKind' names which of the three
  -- indicators; the 'Word8' is the indicator byte as read. Raised by
  -- 'Slap.VCDIFF.Parse.parseVCDIFF'.
  | VCDIFFReservedIndicatorBits !VCDIFFIndicatorKind !Word8

  -- | A VCDIFF patch declared a secondary-compressor id outside
  -- xdelta3's catalog (1 = DJW, 2 = LZMA, 16 = FGK — the only
  -- registry that exists, since RFC 3284 registered none). slap does
  -- not know what algorithm such an id names, so it cannot say the
  -- patch is malformed — a future xdelta3 could define id 3 and the
  -- patch would be well-formed, just unreadable here. The same
  -- decline disposition as 'VCDIFFReservedIndicatorBits'; the 'Word8'
  -- is the id byte as read. Raised by
  -- 'Slap.VCDIFF.SecondaryCompression' through
  -- 'Slap.VCDIFF.Parse.parseVCDIFF'.
  | VCDIFFUnknownSecondaryCompressor !Word8

  -- | A VCDIFF patch's wire bytes parsed but disagree with the core
  -- semantics slap enforces: a window naming both copy sources at
  -- once, a core invariant violated (a COPY reading unwritten output
  -- or crossing the source-segment boundary, a window that does not
  -- fill to its declared size), or a section that runs short of what
  -- its instructions demand. The 'VCDIFFMalformation' names the
  -- specific failure. Raised by 'Slap.VCDIFF.Parse.parseVCDIFF' after
  -- the byte-level walk, the way 'UnsupportedVCDIFFShape' validates
  -- window shape; these are loud refusals, never a substituted zero.
  | MalformedVCDIFF VCDIFFMalformation

  -- | A VCDIFF patch mixes a VCD_TARGET window — an RFC 3284 feature
  -- xdelta3 refuses — with an xdelta3 extension RFC 3284 never defined
  -- (a declared secondary compressor, an application header, or a
  -- per-window Adler32). Each half is well-formed on its own, so the
  -- patch is not malformed; it simply belongs to neither dialect slap
  -- reads — a conformant RFC-3284 patch carries no xdelta3 extension,
  -- and an xdelta3 patch carries no VCD_TARGET window. The
  -- 'VCDIFFXDelta3Feature' names which extension it found, so the
  -- refusal's reason is concrete. The Adler32 case in particular is
  -- read and used to reach this verdict, never silently dropped:
  -- 'Slap.VCDIFF.Types.XDelta3Window' makes an RFC-window-with-checksum
  -- unrepresentable, so the checksum could not survive into a 'PatchRFC'
  -- even if slap tried. Raised by 'Slap.VCDIFF.Parse.classifyFlavor'.
  | VCDIFFTargetWindowWithXDelta3Feature VCDIFFXDelta3Feature

  -- | A BSDiff patch's fixed-width header decoded with at least one
  -- of the three size fields as negative. The 'BSDiffHeaderMalformation'
  -- carries all three field values so the renderer can name which
  -- one(s) were off. The check happens outside the byte parser
  -- because the header is read with a fixed-offset signed-magnitude
  -- helper rather than the monadic primitives.
  | MalformedBSDiffHeader BSDiffHeaderMalformation

  -- | An APS-N64 patch's header carried a value that did not decode
  -- to a known variant. The 'APSN64HeaderMalformation' names which
  -- header field rejected which byte. Validated outside the byte
  -- parser at 'Slap.APSN64.Parse.parseAPSN64', using a pre-read of
  -- the patch-type byte at the known fixed offset after the magic
  -- bytes.
  | MalformedAPSN64Header APSN64HeaderMalformation

  -- | A PPF4 Replace record appeared after an Append record. PPF4 is
  -- two-phase — every in-place Replace precedes every Append — and
  -- the reference patchers both emit and consume that order, so a
  -- Replace on the wrong side of the transition is a structural
  -- claim slap understands and rejects. Judged outside the byte
  -- parser by 'Slap.PPF4.Parse.partitionPhases', after the record
  -- walk; the 'ActionIndex' names the offending record.
  | PPF4ReplaceAfterAppend !ActionIndex

  -- | An xdelta1 patch's instruction referenced a source index that
  -- is not 0 (the data source) or 1 (the file source). Canonical
  -- xdelta emits only those two indices and slap rejects anything
  -- else at parse time so 'Slap.XDelta1.Apply.applyXDelta1' can
  -- dispatch on a total two-arm pattern. The 'Int64' is the
  -- offending wire-level index.
  | XDelta1UnknownInstructionTarget !Int64

  -- | An xdelta1 patch expected one or both input files to be gzip
  -- streams at apply time (@FLAG_FROM_COMPRESSED@ bit 1 and\/or
  -- @FLAG_TO_COMPRESSED@ bit 2 set in the wire header). Canonical
  -- xdelta-1.x transparently decompresses gzip-magic inputs before
  -- computing the delta and re-compresses after apply; slap doesn't
  -- implement that transparency, so apply refuses rather than
  -- silently producing wrong output against the user's literal
  -- source bytes. The payload names which side(s) are affected.
  | XDelta1InputPreCompressionUnsupported XDelta1GzipStreamInputs

  -- | An xdelta1 patch's data-record declared a length that
  -- disagrees with the actual byte count of the data segment slap
  -- decompressed out of the patch envelope. Both values live in the
  -- same patch — the data-record's @length@ field inside the EDSIO
  -- control structure, and the byte count of the inline data
  -- segment between the header and control segment — and they
  -- describe the same bytes, so a disagreement is structural
  -- inconsistency the parser cannot reconcile. Slap refuses with
  -- this constructor rather than picking a winner; the 'ExpectedSize'
  -- carries the wire-declared length and 'ActualSize' the segment-
  -- bytes length.
  | XDelta1DataRecordLengthMismatch ExpectedSize ActualSize

  -- | An xdelta1 patch's data-record declared an MD5 that disagrees
  -- with the MD5 of the data-segment bytes slap parsed from the
  -- patch envelope. Both values describe the same bytes, so a
  -- disagreement is structural inconsistency within the patch.
  -- Slap fires only when the patch's verification posture is
  -- 'VerifyAgainstStoredMD5s'; under 'CreatorOptedOutOfVerification'
  -- the wire MD5 is the canonical empty-input sentinel
  -- ('xdelta1EmptyInputMD5Sentinel') by convention and the
  -- comparison is skipped entirely. Parse-time fatal, mirroring
  -- 'PatchCRCMismatch' for UPS\/BPS — the user's apply-time
  -- @--no-verify@ does not downgrade this, because the inconsistency
  -- is between two fields of the patch itself, not between the
  -- patch and any external bytes. The first 'MD5Hash' is the wire-
  -- declared value; the second is the value computed from the
  -- segment bytes.
  | XDelta1DataRecordMD5Mismatch MD5Hash MD5Hash

  -- Apply
  | NegativeTargetSize FormatLabel FileSize
  | ApplyFailed FormatLabel ApplyError

  -- Undo
  | UndoFailed FormatLabel ApplyError

  -- Create / Encode

  -- | A target format's create path refused this (source, target) pair
  -- for the reason carried in the 'UnencodeabilityReason'. The single
  -- carrier for every "this format cannot encode this pair, here's
  -- why" refusal — formerly split between 'UPSUnencodeablePair' (UPS
  -- only) and 'CannotExpressTargetShrinkage' (size-shrinkage only);
  -- both have folded into this one. Raised by 'Slap.UPS.Create' for
  -- the UPS-specific tail invariant, and by each format's per-format
  -- @\<format\>RejectIncompatibleSizeChange@ smart-checker (called via
  -- 'Slap.Convert.rejectIncompatibleSizeChange') for the cross-format
  -- size-change refusals.
  | UnencodeablePair FormatLabel UnencodeabilityReason
  | NarrowingError !NarrowingFailure

  -- | A create-path input (source or target) names more bytes than
  -- slap can address. slap threads every size and offset through a
  -- signed 'Int', so its honest ceiling is 'maxBound' :: 'Int' — about
  -- 9 EB on a 64-bit host. A wire size field wider than the carrier (a
  -- full 64-bit length) can name a file past that ceiling; rather than
  -- wrap or truncate it through 'fromIntegral', slap declines here. The
  -- direction of the apology is "sorry, not 128-bit" — slap conceding a
  -- bit it does not carry, not a worry about a narrow host: the bound
  -- is the carrier's, and on real hardware you would need a ~9 EB file
  -- to reach it. The 'ActualSize' is the offending file; the
  -- 'MaxAddressableSize' is the host's 'maxBound :: Int'.
  | FileExceedsAddressableRange FormatLabel ActualSize MaxAddressableSize

  -- | A record's offset lands on the format's trailer sentinel and
  -- the encoder has no way to shift it back: either the source bytes
  -- needed for the shift-and-prepend fix are absent (source-less
  -- conversion), the source is shorter than the preceding-byte index,
  -- or the sentinel sits at offset @0@ so there is no preceding byte
  -- to consume. IPS and IPS32 are the only affected formats today;
  -- see 'Slap.IPS.Create.resolveSentinelCollisions' for the fix path
  -- that this error is the failure mode of.
  | SentinelCollisionUnfixable FormatLabel SentinelOffset

  -- | The PPF2 wire format mandates a 1024-byte block sampled from
  -- source offset 0x9320, so any source file shorter than 0x9720
  -- (= 0x9320 + 0x400) bytes can't supply one — a boundary the format
  -- never gave a defined behavior. slap names it with this structured
  -- error rather than reading past the source's end. The 'ActualSize'
  -- is the source's size, the 'ExpectedSize' is the @0x9720@-byte
  -- minimum.
  | SourceTooSmallForPPF2Validation FormatLabel ActualSize ExpectedSize

  | FieldTooLong FormatLabel FieldName EncodedLength MaxLength

  -- Convert
  | MissingRequiredField FormatLabel PatchField

  -- | A refusal by the contract layer when the source patch carries
  -- one or more 'PatchField' values that affect the output bytes of
  -- the apply operation (see 'Slap.PatchField.affectsApplyOutput')
  -- and that the target format has no wire representation for.
  -- Silently dropping the fields would change what the resulting
  -- patch produces on apply, so the conversion is refused outright
  -- rather than papered over with a warning. The 'FormatLabel' names
  -- the target format being refused; the inner list pairs each
  -- offending field with the target formats that do preserve it
  -- (possibly empty), so the renderer can point the user at a
  -- target that would work. Only 'FieldTruncation' reaches this error
  -- today; the list shape exists so future apply-output-affecting
  -- fields drop into the same refusal path without new plumbing.
  | ApplyOutputFieldsWouldBeDropped FormatLabel [(PatchField, [FormatLabel])]

  | DiffRequiresSource FormatLabel

  -- | The user asked to convert a patch to PPF4 without supplying the
  -- original ROM. PPF4 splits its records into in-place writes (Replace)
  -- and appended bytes (Append) by where each falls relative to the
  -- source's size; a source-less conversion has the source patch's
  -- records but not the source's size, so it cannot make that split.
  -- The 'FormatLabel' is 'LabelPPF4'. Corrective action: supply the
  -- original ROM with @--with INPUT@, which applies the source patch
  -- and re-diffs against real bytes.
  | PPF4ConvertRequiresSource FormatLabel

  -- | The user set one or more metadata fields via CLI flags that
  -- the target format doesn't consume.  Surfaced before any IO so
  -- the user learns what went wrong before their files are touched.
  -- The 'NonEmpty MetadataField' names every concept the user
  -- expressed; the 'FormatLabel' names the target format that would
  -- silently drop them. Rendering enumerates each offending CLI flag
  -- and the target, so the message points the user at every thing
  -- to fix in one read.
  | MetadataFieldRejected (NonEmpty MetadataField) FormatLabel

  -- | The user opted into one or more 'Constraint's the target
  -- format cannot honor. Same shape and rationale as
  -- 'MetadataFieldRejected'.
  | ConstraintNotSupported (NonEmpty Constraint) FormatLabel

  -- | The user toggled one or more dialect axes via CLI flags that
  -- the target (or, for convert, neither side of the chain) admits.
  -- Surfaced by 'Slap.Convert.rejectIncompatibleDialects' before any
  -- parsing or encoding work begins.
  | DialectNotSupported (NonEmpty Dialect) FormatLabel

  -- | The user asked @slap convert@ to write an xdelta1 patch from a
  -- non-xdelta1 source patch without supplying @--from-name@ /
  -- @--to-name@. xdelta1's header carries two free-form display
  -- labels (the from-file and to-file basenames at create time); no
  -- other format slap reads carries equivalents, so there's nothing
  -- to inherit during a cross-format convert. Slap refuses rather
  -- than fabricate placeholders. The 'FormatLabel' names the source
  -- format the conversion came from.
  | XDelta1ConvertRequiresNames FormatLabel

  -- | The IPS create gate refused a truncation marker whose declared
  -- target size doesn't satisfy SNESTool's
  -- @(size & 0xFFF) == 0x200@ shape filter. Surfaced by
  -- 'Slap.Convert.rejectNonSMCShapedTruncation'; only fires when the
  -- user opted into 'Slap.IPS.Types.RequireSMCShapedTruncation'.
  | TruncationViolatesSMCShape !FileSize

  -- | A verification check would have produced a 'SlapAdvisory' but
  -- the user did not pass @--no-verify@, so the mismatch is fatal.
  -- The embedded 'SlapAdvisory' is one of the four "downgraded fatal"
  -- kinds: 'VerificationCRCMismatch', 'VerificationHashMismatch',
  -- 'VerificationAdler32Mismatch', or 'VerificationFileSizeMismatch'.
  -- The renderer delegates to 'renderSlapAdvisory' for the body and
  -- appends the @--no-verify@ tail. No type-level guarantee enforces
  -- that the embedded advisory is one of the four fatal-promotable
  -- kinds; the four 'check*' helpers in 'Main' are the only callers
  -- and the audit surface is tractable.
  | VerificationFatal SlapAdvisory

  deriving (Show, Eq)

----------------------------------------------------------------------------
-- BPSMetadataDivergence
----------------------------------------------------------------------------

-- | How a BPS patch's metadata blob diverged from the spec-recommended
-- UTF-8 XML, carried by 'BPSMetadataNonConformant'. The BPS spec
-- recommends UTF-8 XML in the metadata field but explicitly permits
-- "literally anything", so neither case is an error — both are
-- spec-valid oddities slap remarks on, because a populated metadata
-- field is rare and a non-conforming one rarer still.
data BPSMetadataDivergence
  = MetadataIsNotUTF8
    -- ^ The bytes do not decode as UTF-8 at all.
  | MetadataIsValidUTF8ButNonText
    -- ^ The bytes are valid UTF-8 but carry control or format
    -- codepoints, so they are not the plain text the field is meant
    -- to hold.
  deriving (Eq, Show)

----------------------------------------------------------------------------
-- SlapAdvisory
----------------------------------------------------------------------------

-- | A non-halting status item slap raises about something it noticed
-- during work — covers both warning-severity ("you may want to know")
-- and note-severity ("informational") items. Severity is a property
-- of each constructor, projected by 'slapAdvisorySeverity'; the
-- 'emitToStderr' pipeline reads it to choose the user-facing prefix.
data SlapAdvisory

  -- Patch quality
  = EmptyPatch FormatLabel EmptyUnit
  | NoEOFMarker FormatLabel

  -- | A PPF1/PPF2/PPF3 patch produced an output longer than the
  -- source at apply time. The format's wire vocabulary has no
  -- command for declaring growth; a patch that produces growth
  -- anyway sits outside what the upstream tooling intends. Slap
  -- applies it but raises this advisory so the user knows the patch
  -- is shaped unusually. The 'FileSize' is the source's actual
  -- length; the 'Length' is how many bytes past that length the
  -- output extends.
  | PPFApplyGrewPastSource FormatLabel FileSize Length

  -- | An IPS-family RLE record whose run-length field was zero was
  -- accepted verbatim as a no-op. The spec does not speak to the
  -- case, and slap's live encoder never emits it; the warning
  -- signals a parsed oddity so the user can decide whether the
  -- source patch is trustworthy. The 'ActionIndex' names the
  -- offending record's position in the wire record stream.
  | ZeroCountRLERecord FormatLabel ActionIndex

  -- | A BPS patch carries the non-canonical @0x81@ encoding of zero
  -- in a 'SourceCopy' or 'TargetCopy' signed-delta varint. Both
  -- @0x80@ and @0x81@ decode to a delta of zero — the sign-magnitude
  -- scheme treats @0x81@ as "negative zero" — but only @0x80@ is the
  -- canonical form, and slap's encoder never emits @0x81@. The
  -- warning fires once per patch (no payload) and signals either a
  -- non-canonical producer or transit corruption; the parse itself
  -- proceeds normally. See @docs/bps/questions.md@ → "two encodings
  -- for zero-delta".
  | NegativeZeroInBPS

  -- | A VCDIFF varint was encoded in a non-canonical (overlong) form:
  -- one or more leading zero-groups padded it longer than the value
  -- needs. Base-128 admits this and xd3 accepts it, so slap does too;
  -- the note is the house-consistent "weird thing happened" flag,
  -- sibling to 'NegativeZeroInBPS'. A slap encoder emits only the
  -- canonical form. The payload is the offending value, so the reader
  -- can see what was padded.
  | NonCanonicalVCDIFFVarint Int64

  -- | At least one pair of records in an IPS-family patch writes
  -- to overlapping regions of the target. Overlap is permitted and
  -- well-defined (later writes clobber earlier ones), but it's
  -- unusual enough that slap flags it. The 'OverlapCount' carries
  -- the total number of intersecting pairs found during the parse;
  -- the warning is only emitted when that count is at least one.
  -- Per-pair detail is intentionally omitted: a pathological
  -- mutually-overlapping cluster of @k@ records would otherwise
  -- produce @k*(k-1)/2@ near-identical warning lines that drown
  -- everything else, and the reader's question is "does this patch
  -- have overlapping writes" not "exactly which pairs".
  | OverlappingRecords FormatLabel OverlapCount

  -- | An IPS-family record carries a smaller offset than the
  -- record that preceded it in the wire stream. slap applies
  -- records strictly in wire order, so unsorted records still
  -- produce correct output, but well-formed patches are sorted by
  -- offset; an unsorted stream is worth flagging. Only the first
  -- out-of-order pair is reported per parse — one warning is enough
  -- to tell the reader the stream is unsorted. The 'ActionIndex'
  -- names the later-in-wire-order record whose offset is lower than
  -- the record before it.
  | UnsortedRecords FormatLabel ActionIndex

  -- | An 'IPS32' patch had trailing bytes past the @"EEOF"@ marker
  -- that did not match any recognized post-trailer shape. slap drops
  -- the trailing slice and proceeds. 'StandardIPS' has three
  -- well-attested post-@"EOF"@ shapes (empty, 3-byte post-EOF
  -- truncation marker, EBP JSON blob) and keeps its strict rejection of
  -- garbage trailers; 'IPS32' has none, and a lenient drop is the
  -- useful choice in the absence of a shape to recognize. The
  -- 'Length' is the byte count dropped.
  | IPS32TrailingBytes FormatLabel Length

  -- | Bytes after a VCDIFF patch's last window matching the one
  -- trailing shape slap recognizes: four @0xFF@ marker bytes, then
  -- nothing but zero padding to end of input — the tail LODModS-made
  -- patches carry. VCDIFF has no window count, total-size field, or
  -- footer, so the format never says what trailing bytes mean, and
  -- xdelta3 is of two minds about this tail (its applier writes the
  -- correct output and then errors on it; its printhdr ignores it).
  -- slap consumes exactly this shape and says what it saw; any other
  -- trailing bytes keep framing as a window and failing as one. The
  -- 'Length' is the remnant's full byte count, marker included.
  | VCDIFFTrailingRemnant !Length

  -- | A VCD_TARGET window declares an empty (zero-length) source
  -- segment, so it draws nothing from the produced target — a window
  -- naming a copy source it cannot read a byte from. Legal (a
  -- zero-length segment fits trivially) and the only shape a
  -- first-window VCD_TARGET can take, there being no earlier output to
  -- point at; pointless everywhere else. slap applies the window and
  -- remarks. The 'ActionIndex' names the window's position in the
  -- patch's window stream.
  | VCDIFFEmptyTargetWindowSegment ActionIndex

  -- | Bytes at the end of an APS-N64 patch too few to begin another
  -- record (a record header is five bytes: a four-byte offset and a
  -- length byte). The reference applier ends its walk the same way —
  -- its next record read returns short and the loop stops — but
  -- silently; slap stops and says so. The 'Length' is the fragment's
  -- byte count (one to four).
  | APSN64TrailingFragment !Length

  -- | An EBP patch's metadata trailer existed (the post-@"EOF"@
  -- byte stream began with @{@, the shape signature of an EBPatcher
  -- JSON blob) but was not valid JSON, or its root was not an
  -- object. The underlying IPS records are unaffected: apply and
  -- convert paths proceed normally, only with empty metadata. The
  -- user can supply @--title@, @--author@, @--description@ on a
  -- convert-to-EBP to populate the target's metadata fields. The
  -- 'FormatLabel' is always 'LabelEBP' at construction; the type
  -- carries it for consistency with the rest of the advisory
  -- family.
  | EBPMetadataMalformed FormatLabel

  -- | A BPS patch carries embedded metadata that isn't the spec-
  -- recommended UTF-8 XML. The BPS spec recommends UTF-8 XML in this
  -- field but explicitly permits "literally anything", so this is a
  -- spec-valid oddity, not an error: slap carries the blob byte-exact
  -- on every payload path and only remarks here, because a populated
  -- metadata field is rare and a non-conforming one rarer still. The
  -- 'BPSMetadataDivergence' names how it diverged; the 'Length' is the
  -- blob's byte count. The 'FormatLabel' is always 'LabelBPS', carried
  -- for consistency with the rest of the advisory family.
  | BPSMetadataNonConformant FormatLabel BPSMetadataDivergence Length

  -- | A 'StandardIPS' patch's post-EOF truncation marker declared a
  -- target size smaller than the natural size, and slap honored it.
  -- Surfaces the truncation as a deliberate diagnostic even when no
  -- records cross the boundary. Pairs with 'IPSRecordsClippedByMarker'
  -- when records were also clipped.
  | IPSTruncationMarkerHonored FormatLabel DeclaredTargetSize NaturalTargetSize

  -- | One or more records' write regions extended past the
  -- truncation boundary that slap honored, and were clipped to fit.
  -- Aggregate count in the style of 'OverlappingRecords'; per-record
  -- detail omitted to keep a pathological patch from drowning
  -- everything else. Only fires when at least one record crossed the
  -- boundary; the 'ActionIndex' names the first such record in wire
  -- order.
  | IPSRecordsClippedByMarker FormatLabel ClippedRecordCount ActionIndex MarkerOvershootBytes

  -- | A 'StandardIPS' patch's truncation marker declared a target
  -- size larger than the natural size, which would grow the output
  -- via zero-fill. Per the docs/ips/questions.md policy, slap ignores
  -- the marker for sizing and emits this warning so the user learns
  -- the patch declared something slap chose not to act on.
  | IPSTruncationMarkerIgnored FormatLabel DeclaredTargetSize NaturalTargetSize

  -- | An xdelta 1.1.x patch had bit 0 (@FLAG_NO_VERIFY@) of the
  -- header's flags word set, but at least one of its stored MD5
  -- slots (target MD5 in the control structure, or any source MD5
  -- in the source-info records) did not equal
  -- 'Slap.XDelta1.Types.xdelta1EmptyInputMD5Sentinel'. Canonical
  -- xdelta writes the empty-input MD5 into every slot under
  -- @--noverify@ (the bytes are forced by the algorithm:
  -- @edsio_md5_init@ + 0x @_update@ + @_final@ produces exactly that
  -- value); divergent bytes mean a non-canonical producer or transit
  -- corruption that left @FLAG_NO_VERIFY@ intact. Slap's behavior is
  -- unaffected — the flag is honored regardless of slot contents,
  -- 'VerificationOptedOutByCreator' fires as usual. The curio is
  -- purely informational, naming the structural oddity so a reader
  -- wondering about the patch's provenance learns it wasn't produced
  -- by canonical xdelta.
  | XDelta1NoVerifyWithDivergentSentinel

  -- | An xdelta 1.1.x patch's data-record carried a @name@ field
  -- that wasn't the canonical literal 'xdelta1DataRecordName'
  -- (@"(patch data)"@). The data-record names the patch's inline
  -- literal-bytes source, not an externally-named file, so the
  -- field is purely a display label — canonical xdelta-1.x consults
  -- it only in @xdelta info@-style displays and never at apply
  -- time. Slap honors the wire bytes (no verification, no apply
  -- refusal) and surfaces this as an informational note (routed
  -- through 'patchSourceAdvisories' at the porcelain boundary, not
  -- through the warning lane) so the reader learns the patch's
  -- data-record carries a non-canonical label. The 'ByteString' is
  -- what was read.
  | XDelta1DataRecordNameDiverges !ByteString

  -- Conversion: dropped fields
  | FieldDropped PatchField DroppedValue
  | UndoDataDropped Int
  | ValidationBlockDropped
  | DisabledEntriesDropped Int
  | BlockDescriptionsDropped
  -- | A BPS metadata blob with no destination channel in the target
  -- format. The 'Length' is the blob's byte count — a measured span
  -- of bytes, not a tally, hence not a bare 'Int' like the
  -- record-counting drop advisories above.
  | MetadataDropped Length

  -- Conversion: defaults assumed
  | DefaultRomType FormatLabel
  | DefaultImageType FormatLabel
  | IncludingUndoByDefault
  | IncludingVerificationByDefault
  | SourceHashesMissing FormatLabel

  -- Encoding
  | FieldTruncated FormatLabel FieldName OriginalLength TruncatedLength

  -- | A text field's wire bytes contained one or more byte sequences
  -- that the declared encoding couldn't decode; slap substituted
  -- 'U+FFFD' for each and continued parsing. Fires from format parse
  -- paths that decode locale-encoded fields (PPF1\/2\/3\/4 description
  -- and the PPF2\/PPF3 FILE_ID.DIZ trailer body). The count is the
  -- number of byte sequences that were substituted; the position
  -- detail in 'Slap.Text.LossNotice' is folded down at the advisory
  -- boundary because the field-level "how many" is what the user
  -- needs at this layer.
  | FieldDecodedSubstituted FormatLabel FieldName SubstitutionCount

  -- | A text field's source 'Text' contained one or more codepoints
  -- that the target encoding couldn't represent; slap substituted
  -- the encoding's replacement character (U+FFFD where representable,
  -- @\'?\'@ otherwise) for each and continued encoding. Fires from
  -- format create paths that encode locale-targeted fields. Sibling
  -- of 'FieldDecodedSubstituted' for the symmetric encode-side
  -- substitution event.
  | FieldEncodedSubstituted FormatLabel FieldName SubstitutionCount

  -- Platform conversion
  --
  -- | The source patch named a platform that the target format
  -- has no wire encoding for; slap falls back to the format's Raw
  -- placeholder and surfaces the change.
  | PlatformNotAvailable FormatLabel PlatformType
  -- | NINJA2's combined SMS/Game Gear slot is ambiguous on convert
  -- to a sibling format: slap defaults to SMS. The user can override
  -- with @--rom-type gg@. Today the only ambiguity slap surfaces;
  -- future ambiguities get their own nullary constructors so each
  -- one's rendered prose is its own thing.
  | NINJA2SMSGameGearAmbiguity

  -- Apply: out-of-bounds block clipping
  | ApplyOOBBlocksSkipped FormatLabel ApplyDirection OOBBlockCount ActionIndex OOBOvershootBytes FileSize

  -- Format-specific
  --
  -- | A NINJA1 textual subformat was converted to its binary peer at
  -- parse time; the wire bytes the user reads will still describe
  -- the same patch but the in-memory shape is the binary one.
  | SubformatConverted NINJA1SubformatConversion

  -- Verification: source/target integrity check mismatches
  --
  -- These fire from app/Main.hs's verification helpers. The four
  -- "downgraded fatal" kinds (CRC, hash, Adler32, file-size) emit
  -- as warnings when the user passed --no-verify; the same mismatch
  -- promotes to 'VerificationFatal' under EnforceVerification. The
  -- four "advisory" kinds always emit as warnings under either
  -- policy; they have no fatal counterpart because the underlying
  -- check is advisory by design (block CRC16, PPF validation block,
  -- file-size advisory, source-bytes byte-range comparison), and
  -- --no-verify does not silence them — the flag's contract is the
  -- fatal-vs-warning axis for fatal-class checks only.
  | VerificationCRCMismatch       VerificationSide ExpectedCRC32 ActualCRC32
  | VerificationHashMismatch      VerificationSide HashAlgorithm
  | VerificationAdler32Mismatch   Offset ExpectedAdler32 ActualAdler32
  | VerificationFileSizeMismatch  VerificationSide ExpectedSize ActualSize
  | VerificationBlockCRC16Mismatch VerificationSide Offset
  | VerificationPPFBlockMismatch  Offset
  | VerificationFileSizeAdvisory  ExpectedSize ActualSize
  | VerificationSourceBytesMismatch ByteCheckLabel Offset

  -- | The patch declares no verification data at the format level
  -- (e.g. xdelta1's @FLAG_NO_VERIFY@ header bit, set by canonical's
  -- @--noverify@; PPF3's absent validation block, set by slap's
  -- create-side @--omit-verification@). Slap honors the declaration by
  -- skipping verification entirely; the warning
  -- reports that slap cannot attest the output matches the creator's
  -- intent. Family sibling of 'VerificationCRCMismatch' and the
  -- other verification warnings: same category from the user's seat
  -- ("a thing about whether the integrity check worked"), different
  -- mechanism (the patch said not to check, vs. the check ran and
  -- failed).
  | VerificationOptedOutByCreator !FormatLabel

  deriving (Show, Eq)

----------------------------------------------------------------------------
-- CreateResult
----------------------------------------------------------------------------

data CreateResult = CreateResult
  { resultBytes      :: !PatchFileContents
  , resultAdvisories :: ![SlapAdvisory]
  } deriving (Show)

----------------------------------------------------------------------------
-- Parsed
----------------------------------------------------------------------------

-- | The parse-side companion to 'CreateResult': a successfully
-- parsed payload paired with any advisories the parser accumulated.
-- Two fields: the parsed value (parametric) and the advisory list.
data Parsed value = Parsed !value ![SlapAdvisory]
  deriving (Show)

----------------------------------------------------------------------------
-- Outcome
----------------------------------------------------------------------------

-- | The value and advisory channels of an apply or undo operation.
-- Mirrors 'CreateResult' on the create side and 'Parsed' on the parse
-- side — every value-producing operation in slap pairs its value with
-- an advisory channel. The polymorphic parameter lets a single envelope
-- serve both apply (carrying 'OutputFileContents') and undo (carrying
-- 'InputFileContents') without duplicating the shape; the 'Functor'
-- instance lets a wrapper function the inner value through 'fmap'
-- without unpacking the envelope.
--
-- Wrap sites that don't emit advisories use 'noAdvisories' to lift
-- their bare value into the envelope; sites that do construct
-- 'Outcome' directly with the advisory list.
data Outcome a = Outcome
  { outcomeValue      :: !a
  , outcomeAdvisories :: ![SlapAdvisory]
  }
  deriving (Eq, Show, Functor)

-- | Wrap an advisory-free value in the 'Outcome' envelope. Every
-- wrap site at the apply/undo boundary uses this so the @[]@ list
-- has exactly one home; specific apply or undo paths that actually
-- emit advisories will construct 'Outcome' directly.
noAdvisories :: a -> Outcome a
noAdvisories value = Outcome value []

----------------------------------------------------------------------------
-- OverlapCount — payload of the OverlappingRecords warning
----------------------------------------------------------------------------

-- | The number of overlapping record pairs detected during an
-- IPS-family parse. Carried by the 'OverlappingRecords' warning so
-- the reader sees both that the patch contains overlapping writes
-- and how many such intersections were found, without enumerating
-- every pair (a pathological mutually-overlapping cluster of @k@
-- records would otherwise produce @k*(k-1)/2@ near-duplicate
-- warning lines). A value of zero is structurally impossible: the
-- warning is only emitted when at least one pair was found.
newtype OverlapCount = OverlapCount { unOverlapCount :: Int }
  deriving (Eq, Ord, Show)

-- | The number of IPS records clipped to fit a honored truncation
-- marker. Value-zero is structurally impossible: the warning is
-- only emitted when at least one record crossed the boundary.
newtype ClippedRecordCount = ClippedRecordCount { unClippedRecordCount :: Int }
  deriving (Eq, Ord, Show)

-- | The number of UPS blocks whose write region extends past the
-- declared target file size. Value-zero is structurally impossible:
-- the warning is only emitted when at least one block was OOB.
-- Peer to 'ClippedRecordCount' — both count records-or-blocks that
-- a format's apply path skipped under a defined policy.
newtype OOBBlockCount = OOBBlockCount { unOOBBlockCount :: Int }
  deriving (Eq, Ord, Show)

-- | The total byte length lost across all records clipped by an
-- honored IPS truncation marker. Sums the per-record overshoots
-- (each record's "bytes beyond effective target"), so a single
-- record clipped by 100 bytes and ten records each clipped by 10
-- both report 100. Carried by 'IPSRecordsClippedByMarker' so the
-- user sees not just "records were clipped" but "this much was
-- thrown away." Peer to 'OOBOvershootBytes' — both sum per-event
-- overshoots under a format-specific apply-time policy.
--
-- 'Semigroup' and 'Monoid' are derived through to 'Length' so walk
-- sites accumulating overshoots can use '<>' and 'mempty' directly.
newtype MarkerOvershootBytes = MarkerOvershootBytes { unMarkerOvershootBytes :: Length }
  deriving (Eq, Ord, Show, Semigroup, Monoid)

-- | The total byte length lost across all UPS blocks whose write
-- region extended past the declared target file size. Sums the
-- per-block overshoots, so a single block clipped by 100 bytes and
-- ten blocks each clipped by 10 both report 100. Carried by
-- 'ApplyOOBBlocksSkipped'. Peer to 'MarkerOvershootBytes'.
--
-- 'Semigroup' and 'Monoid' are derived through to 'Length' so the
-- 'detectOOBBlocks' walk can use '<>' and 'mempty' directly.
newtype OOBOvershootBytes = OOBOvershootBytes { unOOBOvershootBytes :: Length }
  deriving (Eq, Ord, Show, Semigroup, Monoid)

----------------------------------------------------------------------------
-- ApplyDirection — which direction an apply/undo operation ran in
----------------------------------------------------------------------------

-- | Which direction an apply/undo operation ran in. Tagged onto
-- advisories that describe direction-dependent observations about
-- an operation (such as 'ApplyOOBBlocksSkipped', whose count and
-- overshoot are measured against the output the operation actually
-- wrote — target_size for forward, source_size for reverse).
--
-- Not related to the CLI subcommand the user typed. Two distinct
-- subcommands (@slap apply@, @slap undo@) happen to drive the two
-- directions one-to-one, but the direction concept lives at the
-- Format layer (each format's apply/undo functions know which
-- direction they implement), while subcommand selection lives at
-- the Entry-point layer ('app/Main.hs'). Naming an operation by
-- direction rather than by subcommand keeps the Foundation layer's
-- vocabulary independent of the CLI surface.
data ApplyDirection
  = Forward  -- ^ The natural-direction operation: 'applyUPS', 'applyBPS', etc.
  | Reverse  -- ^ The inverse operation: 'undoUPS', 'undoBPS', etc.
  deriving (Eq, Show)

-- | The verb describing operations of each direction, suitable for
-- inclusion in rendered advisory text. Returns @"apply"@ and @"undo"@
-- (rather than @"forward"@ and @"reverse"@) because those are the
-- words slap uses elsewhere in user-facing text, including the CLI
-- subcommands that drive each direction.
directionVerb :: ApplyDirection -> Text
directionVerb Forward = "apply"
directionVerb Reverse = "undo"

----------------------------------------------------------------------------
-- Verification: shared payload types
----------------------------------------------------------------------------

-- | Which side of the apply (input ROM or output ROM) a verification
-- check fired against. Carried by the verification 'SlapAdvisory'
-- constructors so the renderer can name \"input\" vs \"output\" without
-- callers passing strings. The constructor names retain slap's older
-- source\/target vocabulary; the rendered labels track the CLI's
-- input\/output vocabulary.
data VerificationSide = SourceSide | TargetSide
  deriving (Show, Eq)

verificationSideLabel :: VerificationSide -> Text
verificationSideLabel SourceSide = "input"
verificationSideLabel TargetSide = "output"

-- | Which hash algorithm a verification check used. Carried by
-- 'VerificationHashMismatch' so the renderer can name "MD5" vs "SHA1"
-- without callers passing strings.
data HashAlgorithm = MD5 | SHA1
  deriving (Show, Eq)

hashAlgorithmLabel :: HashAlgorithm -> Text
hashAlgorithmLabel MD5  = "MD5"
hashAlgorithmLabel SHA1 = "SHA1"

-- | An Adler32 value that a patch declared or stored. Peer to
-- 'ExpectedCRC32'; carried by 'VerificationAdler32Mismatch'.
newtype ExpectedAdler32 = ExpectedAdler32 { unExpectedAdler32 :: Adler32 }
  deriving (Show, Eq)

-- | An Adler32 value that was computed from the actual data. Peer to
-- 'ActualCRC32'; carried by 'VerificationAdler32Mismatch'.
newtype ActualAdler32 = ActualAdler32 { unActualAdler32 :: Adler32 }
  deriving (Show, Eq)

-- | The label of an advisory byte-range check ("N64 cart ID",
-- "N64 country", "N64 CRC", \[future\] ...). Carried by
-- 'VerificationSourceBytesMismatch' so the renderer names the check
-- without callers passing bare strings.
newtype ByteCheckLabel = ByteCheckLabel { unByteCheckLabel :: Text }
  deriving (Show, Eq)

----------------------------------------------------------------------------
-- renderApplyError
----------------------------------------------------------------------------

renderCursorKind :: CursorKind -> Text
renderCursorKind SourceCursor = "source-relative"
renderCursorKind TargetCursor = "target-relative"

renderApplyError :: ApplyError -> Text

renderApplyError (ApplyCursorUnderflow cursorKind actionIndex cursor) =
  "at step #" <> renderAsText (unActionIndex actionIndex) <> ": "
  <> renderCursorKind cursorKind <> " cursor underflowed (value "
  <> renderAsText (unSignedOffset cursor) <> ")"

renderApplyError (ApplySourceReadOutOfBounds actionIndex readEndOffset sourceSize) =
  "at step #" <> renderAsText (unActionIndex actionIndex)
  <> ": input read would end at offset 0x"
  <> renderHexAsText (unOffset readEndOffset)
  <> " but input is " <> renderAsText (unFileSize sourceSize) <> " bytes"

renderApplyError (ApplyTargetReadUnwritten actionIndex (ReadOffset readOffset) (WritePosition writePosition)) =
  "at step #" <> renderAsText (unActionIndex actionIndex)
  <> ": TargetCopy read at offset 0x"
  <> renderHexAsText (unOffset readOffset)
  <> " references position at or past current write position 0x"
  <> renderHexAsText (unOffset writePosition)

renderApplyError (ApplyWritesPastTarget actionIndex (RequestedLength requestedLength) (RemainingLength remainingLength)) =
  "at step #" <> renderAsText (unActionIndex actionIndex)
  <> ": action of length " <> renderAsText (unLength requestedLength)
  <> " would write past output ("
  <> renderAsText (unLength remainingLength) <> " bytes remaining)"

renderApplyError (ApplyTargetUnderfilled (WritePosition cursor) (ExpectedSize expectedSize)) =
  "output under-filled ("
  <> renderAsText (unOffset cursor) <> " of "
  <> renderAsText (unFileSize expectedSize) <> " bytes written before action stream exhausted)"

renderApplyError (ApplyNegativeRecordOffset actionIndex offset) =
  "record " <> renderAsText (unActionIndex actionIndex)
  <> " has negative offset " <> renderAsText (unOffset offset)

renderApplyError (ApplyNegativeControlLength actionIndex (RequestedLength regionLength)) =
  "control instruction " <> renderAsText (unActionIndex actionIndex)
  <> " declares a negative region length " <> renderAsText (unLength regionLength)

renderApplyError (ApplyOutputExceedsAddressableRange actionIndex offset payloadLength) =
  "record " <> renderAsText (unActionIndex actionIndex)
  <> " writes at offset " <> renderAsText (unOffset offset)
  <> " plus " <> renderAsText (unLength payloadLength)
  <> " bytes, reaching "
  <> renderAsText (toInteger (unOffset offset) + toInteger (unLength payloadLength))
  <> " — past the " <> renderAsText (maxBound :: Int)
  <> "-byte limit slap can address"

renderApplyError (ApplyReplaceGrowsFile actionIndex offset (RequestedLength payloadLength) sourceSize) =
  "record " <> renderAsText (unActionIndex actionIndex)
  <> ": Replace at offset 0x" <> renderHexAsText (unOffset offset)
  <> " writes " <> renderAsText (unLength payloadLength) <> " bytes"
  <> ", which would extend past the source size of "
  <> renderAsText (unFileSize sourceSize) <> " bytes"
  <> " (PPF4 Replaces cannot grow the file; use Append records)"

renderApplyError (ApplyDiffReadOutOfBounds actionIndex readEndOffset diffSize) =
  "at step #" <> renderAsText (unActionIndex actionIndex)
  <> ": diff-stream read would end at offset 0x"
  <> renderHexAsText (unOffset readEndOffset)
  <> " but diff stream is " <> renderAsText (unFileSize diffSize) <> " bytes"

renderApplyError (ApplyExtraReadOutOfBounds actionIndex readEndOffset extraSize) =
  "at step #" <> renderAsText (unActionIndex actionIndex)
  <> ": extra-stream read would end at offset 0x"
  <> renderHexAsText (unOffset readEndOffset)
  <> " but extra stream is " <> renderAsText (unFileSize extraSize) <> " bytes"

renderApplyError (ApplyAbsoluteWritePastTarget actionIndex writeStart (RequestedLength payloadLength) targetSize) =
  "record " <> renderAsText (unActionIndex actionIndex)
  <> ": write at offset 0x" <> renderHexAsText (unOffset writeStart)
  <> " of " <> renderAsText (unLength payloadLength) <> " bytes"
  <> " would extend past the target size of "
  <> renderAsText (unFileSize targetSize) <> " bytes"

----------------------------------------------------------------------------
-- renderByteParserError
----------------------------------------------------------------------------

-- | Human-readable name for the primitive that surfaced an error.
-- Renderer-private; no consumer dispatches on the string form.
byteParserOperationLabel :: ByteParserOperation -> Text
byteParserOperationLabel GetBytesOperation        = "getBytes"
byteParserOperationLabel SkipOperation            = "skip"
byteParserOperationLabel FixedWidthReadOperation  = "fixed-width read"
byteParserOperationLabel VarintReadOperation      = "varint read"

renderByteParserError :: ByteParserError -> Text

renderByteParserError
  (ByteParserUnderflow
      operation
      (RequestedLength (Length requested))
      (RemainingLength (Length available))
      (Position cursor)) =
  byteParserOperationLabel operation
  <> ": need " <> renderAsText requested <> " bytes at offset " <> renderAsText cursor
  <> " but only " <> renderAsText available <> " available"

renderByteParserError
  (ByteParserTruncatedRecord
      recordIndex
      (RequiredLength (Length needed))
      (RemainingLength (Length available))) =
  "record " <> renderAsText (unActionIndex recordIndex)
  <> " truncated (need " <> renderAsText needed
  <> " bytes, have " <> renderAsText available <> ")"

renderByteParserError (ByteParserUnknownCommandByte recordIndex commandByte) =
  "record " <> renderAsText (unActionIndex recordIndex)
  <> ": unknown command byte 0x" <> padHex 2 commandByte

renderByteParserError (ByteParserTerminatorNotFound terminatorByte (Position cursor)) =
  "getUntilByte: terminator 0x" <> padHex 2 terminatorByte
  <> " not found from offset " <> renderAsText cursor

renderByteParserError
  (ByteParserPositionOutOfBounds (Position target) (ActualLength (Length inputLength))) =
  "setPosition: " <> renderAsText target
  <> " out of bounds (input length " <> renderAsText inputLength <> ")"

renderByteParserError
  (ByteParserNegativeLengthRequestedInGetBytes (Length amount)) =
  "getBytes: negative length " <> renderAsText amount

renderByteParserError
  (ByteParserNegativeLengthRequestedInSkip (Length amount)) =
  "skip: negative length " <> renderAsText amount

renderByteParserError (ByteParserVarintOverranBuffer (Position cursor)) =
  "varint read overran buffer at offset " <> renderAsText cursor

renderByteParserError ByteParserVarintExceededWidth =
  "varint overflow (too many continuation bytes)"

renderByteParserError ByteParserVarintExceedsSignedRange =
  "varint decoded a value in [2^63, 2^64): xd3 admits it as an unsigned"
  <> " uint64, but slap carries sizes as a signed Int and declines it"

renderByteParserError (ByteParserEdsioVarintExceeds32Bits value) =
  "EDSIO varint decoded " <> renderAsText value
  <> ", past the 0xFFFFFFFF ceiling of xdelta1's 32-bit fields"

renderByteParserError (ByteParserUnexpectedDoPatternFailure message) =
  "internal: do-pattern match failed in slap's parser: " <> Text.pack message

----------------------------------------------------------------------------
-- renderSlapError
----------------------------------------------------------------------------

-- | Render an archive-unwrap failure: name the archive and its format,
-- and give the corrective action that fits each failure shape.
renderUnwrapError :: FilePath -> ArchiveFormat -> UnwrapError -> Text
renderUnwrapError path format (NoToolForArchive tools) =
  archiveFormatName format <> " archive " <> pathText path
    <> " needs " <> renderToolAlternatives tools <> " on PATH to unwrap; none were found."
    <> " Install one, or pass --raw if this isn't really an archive."
renderUnwrapError path format (ArchiveToolFailed (ToolName tool) (ToolDiagnostic diagnostic)) =
  tool <> " failed while reading the " <> archiveFormatName format
    <> " archive " <> pathText path <> ": " <> diagnostic
renderUnwrapError path format (ArchiveHasNoCandidate (SeenEntryCount entryCount)) =
  "no usable file in the " <> archiveFormatName format <> " archive " <> pathText path
    <> " (" <> renderAsText entryCount <> " entries, all filtered as chaff)."
    <> " If this isn't really an archive, pass --raw."
renderUnwrapError path format (ArchiveHasManyCandidates names) =
  pathText path <> " is a " <> archiveFormatName format <> " archive with "
    <> renderAsText (length names) <> " candidate files:\n"
    <> Text.unlines (map (\(EntryName name) -> "  " <> name) names)
    <> "Extract the one you want and pass it directly."
renderUnwrapError path format (ExtractedEntryMissing (EntryName name)) =
  "extracted " <> name <> " from the " <> archiveFormatName format
    <> " archive " <> pathText path <> " but it was not found afterwards"
renderUnwrapError path format (ArchiveUnreadable (UnreadableReason reason)) =
  "could not read the " <> archiveFormatName format <> " archive "
    <> pathText path <> ": " <> reason

-- | The tools that could open a format, as a grammatical alternative: a
-- lone tool stands alone, two are joined with "or", and any longer list
-- (none arise today) gets an Oxford "a, b, or c".
renderToolAlternatives :: [ToolName] -> Text
renderToolAlternatives tools = case map unToolName tools of
  []                      -> "a supported tool"
  [onlyTool]              -> onlyTool
  [firstTool, secondTool] -> firstTool <> " or " <> secondTool
  manyTools               -> Text.intercalate ", " (init manyTools) <> ", or " <> last manyTools

renderSlapError :: SlapError -> Text

renderSlapError (MissingInputFile path) =
  "cannot read " <> Text.pack path <> ": file not found"

renderSlapError (UnreadableInputFile path reason) =
  "cannot read " <> Text.pack path <> ": " <> Text.pack reason

renderSlapError (ArchiveUnwrapFailed path format unwrapError) =
  renderUnwrapError path format unwrapError

renderSlapError UnrecognizedFormat =
  "unknown patch format"

renderSlapError (AmbiguousDetection labels) =
  "ambiguous format: could be "
  <> commaList (map formatLabelName labels)

renderSlapError (InputTooShort label (RequiredLength needed) (ActualLength actual)) =
  formatLabelName label <> ": input too short (need "
  <> renderAsText (unLength needed) <> " bytes, have "
  <> renderAsText (unLength actual) <> ")"

renderSlapError (BadMagic label (ActualMagic actualBytes)) =
  "not a " <> formatLabelName label <> " file (bad magic: "
  <> renderAsText actualBytes <> ")"

renderSlapError (BadVersion label (FoundVersion versionByte)) =
  formatLabelName label <> ": unsupported version "
  <> renderAsText versionByte

renderSlapError (UnsupportedXDelta1Subformat version) =
  formatLabelName LabelXDelta1 <> ": unsupported subformat: "
  <> case version of
       XDelta1_1_0_4 -> "version 1.0.4"
       XDelta1_1_0   -> "version 1.0"
       XDelta1_0_14  -> "version 0.14"

renderSlapError (UnsupportedNINJA1Subformat subformatBytes) =
  formatLabelName LabelNINJA1 <> ": unsupported subformat: "
  <> renderAsText subformatBytes

renderSlapError (TruncatedRecord label recordIndex needed available) =
  formatLabelName label <> ": record " <> renderAsText recordIndex
  <> " truncated (need " <> renderAsText (unLength needed)
  <> " bytes, have " <> renderAsText (unLength available) <> ")"

renderSlapError (NegativeSize label name (ParsedSizeValue value)) =
  formatLabelName label <> ": negative "
  <> fieldNameLabel name <> ": " <> renderAsText value

renderSlapError (DecompressionFailed failure) =
  renderDecompressionFailure failure

renderSlapError (XDelta1DiffFailed (XDelta1DiffCause causeMessage)) =
  "xdelta1 differ failed: " <> causeMessage

renderSlapError (RecordExceedsAddressableRange label recordIndex (ActualOffset endOffset) (MaxOffset maxEndOffset)) =
  formatLabelName label <> ": record " <> renderAsText (unActionIndex recordIndex)
  <> " ends at offset 0x" <> renderHexAsText (unOffset endOffset)
  <> ", exceeding the variant's maximum addressable end 0x"
  <> renderHexAsText (unOffset maxEndOffset)

renderSlapError (MalformedRecordField label recordIndex name) =
  formatLabelName label <> ": record " <> renderAsText (unActionIndex recordIndex)
  <> " has malformed " <> fieldNameLabel name

renderSlapError (UnrecognizedTrailer label (TrailerMarker markerBytes) (ActualLength actualLength)) =
  formatLabelName label <> ": unrecognized trailing bytes after "
  <> renderTrailerMarkerName markerBytes <> " marker ("
  <> renderAsText (unLength actualLength) <> " bytes)"

renderSlapError (PatchCRCMismatch label (ExpectedCRC32 stored) (ActualCRC32 computed)) =
  formatLabelName label <> ": patch CRC mismatch (stored "
  <> showCRC32 stored <> ", computed " <> showCRC32 computed <> ")"

renderSlapError (TrailingMagicMismatch label (ExpectedMagic expected) (ActualMagic actual)) =
  formatLabelName label <> ": trailing magic mismatch (expected "
  <> renderAsText expected <> ", found " <> renderAsText actual <> ")"

renderSlapError (UnknownFlag label name (RawFlagByte flagByte)) =
  formatLabelName label <> ": unknown "
  <> fieldNameLabel name <> " flag: 0x"
  <> renderHexAsText flagByte

renderSlapError (UnsupportedEncodingMethod label (EncodingMethodByte methodByte)) =
  formatLabelName label <> ": unsupported encoding method: 0x"
  <> renderHexAsText methodByte

renderSlapError (NINJA2UnrecognizedTextMode byte) =
  "NINJA2 PATCH_ENC byte is 0x" <> padHex 2 byte
    <> " (expected 0 for undeclared or 1 for UTF-8); the NINJA2 spec defines no other values, "
    <> "and slap will not guess how to decode text fields under an undefined encoding"

renderSlapError (MalformedNINJA1Content malformation) =
  formatLabelName LabelNINJA1 <> ": malformed text: " <> case malformation of
    NINJA1EmptyTextualPatch                          -> "empty textual patch"
    NINJA1InvalidOffsetInTextRecord (OffsetTokenText t) -> "invalid offset in text record: " <> t
    NINJA1MalformedTextRecord       (LineText line)  -> "malformed text record: " <> line
    NINJA1UnknownTextualRomType     name             -> "unknown ROM type name in text header: " <> name

renderSlapError (ParseError label parserError) =
  formatLabelName label <> ": " <> renderByteParserError parserError

renderSlapError (UnsupportedXDelta1Shape violation) =
  formatLabelName LabelXDelta1
  <> ": source list is not canonical [data segment, file source]: "
  <> describeViolation violation
  <> " (xdelta1 patches carry exactly two sources in that order;"
  <> " any other count or ordering is off-spec)"
  where
    describeViolation XDelta1TwoDataSources        = "[data, data]"
    describeViolation XDelta1ReversedDataFileOrder = "[file, data]"
    describeViolation XDelta1TwoFileSources        = "[file, file]"
    describeViolation XDelta1ZeroSources           = "0 sources"
    describeViolation XDelta1OneDataSource         = "1 source: data"
    describeViolation XDelta1OneFileSource         = "1 source: file"
    describeViolation (XDelta1TooManySources n)    = renderAsText n <> " sources"

renderSlapError (UnsupportedVCDIFFShape violation) =
  formatLabelName LabelVCDIFF <> ": " <> case violation of
    VCDIFFNestedCustomCodeTable ->
      "nested custom code tables are not allowed (RFC 3284 §4.1)"
    VCDIFFNegativeWindowTargetSize rawValue ->
      "negative window target size (decoded as " <> renderAsText rawValue <> ")"
    VCDIFFSecondaryCompressionUnsupportedInDataSections ->
      "secondary compression in data sections is not supported"

renderSlapError (VCDIFFFeatureNotYetSupported feature) =
  formatLabelName LabelVCDIFF <> ": " <> case feature of
    VCDIFFCustomCodeTable ->
      "custom code tables are not supported yet"

renderSlapError (VCDIFFTargetWindowWithXDelta3Feature feature) =
  formatLabelName LabelVCDIFF
  <> ": a VCD_TARGET window (an RFC 3284 feature) together with "
  <> xdelta3FeaturePhrase feature
  <> " (an xdelta3 extension) — neither a conformant RFC-3284 patch nor"
  <> " an xdelta3 patch, and slap applies only conformant patches of either dialect"
  where
    xdelta3FeaturePhrase XDelta3FeatureSecondaryCompressor = "a declared secondary compressor"
    xdelta3FeaturePhrase XDelta3FeatureApplicationHeader   = "an application header"
    xdelta3FeaturePhrase XDelta3FeatureWindowChecksum      = "a per-window Adler32 checksum"

renderSlapError (VCDIFFReservedIndicatorBits indicatorKind rawByte) =
  formatLabelName LabelVCDIFF <> ": reserved bits set in the "
  <> indicatorKindName indicatorKind <> " (0x" <> padHex 2 rawByte
  <> "); the format leaves those bits undefined, so slap cannot"
  <> " interpret what the patch is asking"

renderSlapError (VCDIFFUnknownSecondaryCompressor idByte) =
  formatLabelName LabelVCDIFF <> ": secondary compressor id "
  <> renderAsText idByte
  <> " is not in xdelta3's catalog (1 = DJW, 2 = LZMA, 16 = FGK);"
  <> " slap does not know what algorithm it names"

renderSlapError (MalformedVCDIFF malformation) =
  formatLabelName LabelVCDIFF <> ": " <> case malformation of
    VCDIFFBothSourceAndTargetWindowBits ->
      "window sets both VCD_SOURCE and VCD_TARGET (RFC 3284 §4.2 forbids both)"
    VCDIFFCopyAddressOutOfRange actionIndex (ActualOffset address) (MaxOffset here) ->
      "decoded instruction " <> renderAsText (unActionIndex actionIndex)
      <> ": copy address " <> renderAsText (unOffset address)
      <> " out of range [0, " <> renderAsText (unOffset here) <> ")"
    VCDIFFCopyCrossesSourceSegmentEnd actionIndex ->
      "decoded instruction " <> renderAsText (unActionIndex actionIndex)
      <> ": copy crosses the source-segment boundary"
    VCDIFFWindowSizeMismatch (ExpectedSize expected) (ActualSize actual) ->
      "window produced " <> renderAsText (unFileSize actual)
      <> " bytes, declared " <> renderAsText (unFileSize expected)
    VCDIFFSectionExhausted section actionIndex ->
      "decoded instruction " <> renderAsText (unActionIndex actionIndex)
      <> ": " <> vcdiffSectionName section <> " section exhausted"
    VCDIFFInvalidCopyAddressMode modeByte ->
      "invalid copy address mode " <> renderAsText modeByte
    VCDIFFDeltaEncodingLengthMismatch (ExpectedSize declared) (ActualSize measured) ->
      "window declares a delta-encoding length of "
      <> renderAsText (unFileSize declared) <> " bytes but its fields span "
      <> renderAsText (unFileSize measured)
    VCDIFFCompressedSectionWithoutDeclaredSize section ->
      "a compressed " <> vcdiffSectionName section
      <> " section has no readable decompressed-size varint"
    VCDIFFCompressedSectionDeclaresEmptyOutput section ->
      "a compressed " <> vcdiffSectionName section
      <> " section declares a decompressed size of 0"
      <> " (compressing nothing yields framing bytes, never zero)"
    VCDIFFCompressedSectionWithoutCompressor section ->
      "a window marks its " <> vcdiffSectionName section
      <> " section secondary-compressed, but the header declares no compressor"
    VCDIFFSecondaryStreamUnconsumedInput section algorithm (Length leftover) ->
      "the " <> secondaryStreamPossessive section algorithm
      <> " finished with "
      <> renderAsText leftover <> plural leftover " byte" " bytes"
      <> " of input unused"
    VCDIFFSecondaryStreamOutputSizeMismatch section algorithm
        (ExpectedSize declared) (ActualSize produced) ->
      "the " <> secondaryStreamPossessive section algorithm
      <> " decoded to "
      <> renderAsText (unFileSize produced) <> " bytes; "
      <> (case secondaryStreamGranularity algorithm of
            GatheredAcrossSections -> "the sections declare "
            EachSectionItsOwn      -> "the section declares ")
      <> renderAsText (unFileSize declared)

renderSlapError (MalformedVCDIFFCodeTable malformation) =
  formatLabelName LabelVCDIFF <> ": " <> case malformation of
    VCDIFFCodeTableWrongLength (ActualLength (Length actualLength)) ->
      "code table must be 1536 bytes, got " <> renderAsText actualLength
    VCDIFFCodeTableInvalidInstructionType typeCode ->
      "invalid instruction type in code table: " <> renderAsText typeCode
    VCDIFFCodeTableHeaderTooShort ->
      "custom code table data too short"
    VCDIFFCodeTableUnusedFieldSet field byte ->
      "code table sets the " <> codeTableFieldName field
      <> " byte (0x" <> padHex 2 byte
      <> ") of a template that carries no " <> codeTableFieldName field

renderSlapError (MalformedBSDiffHeader (BSDiffNegativeHeaderSizes controlSize diffSize targetSize)) =
  formatLabelName LabelBSDiff
  <> ": invalid header (negative size: control="
  <> renderAsText controlSize <> ", diff=" <> renderAsText diffSize
  <> ", target=" <> renderAsText targetSize <> ")"

renderSlapError (MalformedAPSN64Header malformation) =
  formatLabelName LabelAPSN64 <> ": " <> case malformation of
    APSN64UnknownPatchType byte -> "unknown patch type: " <> renderAsText byte

renderSlapError (PPF4ReplaceAfterAppend recordIndex) =
  formatLabelName LabelPPF4 <> ": record "
  <> renderAsText (unActionIndex recordIndex)
  <> " is a Replace after an Append; PPF4 is two-phase — once an Append"
  <> " record appears, every subsequent record must also be Append"

renderSlapError (XDelta1UnknownInstructionTarget wireIndex) =
  formatLabelName LabelXDelta1
  <> ": instruction references source index " <> renderAsText wireIndex
  <> "; xdelta1 patches carry exactly two sources, so valid indices are"
  <> " 0 (data segment) or 1 (file source)"

renderSlapError (XDelta1DataRecordLengthMismatch (ExpectedSize declared) (ActualSize actual)) =
  formatLabelName LabelXDelta1
  <> ": data-record declares length " <> renderAsText (unFileSize declared)
  <> " bytes but the patch's data segment is " <> renderAsText (unFileSize actual)
  <> " bytes (structural inconsistency; the two fields describe the same bytes and slap cannot pick a winner)"

renderSlapError (XDelta1DataRecordMD5Mismatch declared computed) =
  formatLabelName LabelXDelta1
  <> ": data-record declares MD5 " <> hexByteString (unMD5Hash declared)
  <> " but the patch's data segment hashes to " <> hexByteString (unMD5Hash computed)
  <> " (structural inconsistency; the two values describe the same bytes and slap cannot pick a winner)"

renderSlapError (XDelta1InputPreCompressionUnsupported sides) =
  formatLabelName LabelXDelta1
  <> ": apply refused — patch expects " <> describeSides sides
  <> " to be a gzip stream at apply time, which slap doesn't currently"
  <> " implement (canonical xdelta-1.x decompresses gzip-magic inputs"
  <> " transparently before delta and recompresses after apply; this"
  <> " patch's FROM_COMPRESSED / TO_COMPRESSED header bits record"
  <> " that the original delta did so)"
  where
    describeSides OnlyFromFileWasGzipStream = "the source (from) file"
    describeSides OnlyToFileWasGzipStream   = "the target (to) file"
    describeSides BothFilesWereGzipStreams  = "both the source (from) and target (to) files"

renderSlapError (NegativeTargetSize label size) =
  formatLabelName label <> ": negative output size: "
  <> renderAsText (unFileSize size)

renderSlapError (ApplyFailed label applyErr) =
  formatLabelName label <> " apply: " <> renderApplyError applyErr

renderSlapError (UndoFailed label applyErr) =
  formatLabelName label <> " undo: " <> renderApplyError applyErr

renderSlapError (UnencodeablePair label reason) =
  formatLabelName label <> ": won't produce a patch for this input→output: "
  <> renderUnencodeabilityReason label reason

renderSlapError (NarrowingError nf) = renderNarrowingFailure nf

renderSlapError (FileExceedsAddressableRange label (ActualSize actualSize) (MaxAddressableSize maxSize)) =
  formatLabelName label <> ": input file is "
  <> renderAsText (unFileSize actualSize) <> " bytes, exceeding the host platform's "
  <> renderAsText (unFileSize maxSize) <> "-byte addressable range"

renderSlapError (SentinelCollisionUnfixable label (SentinelOffset sentinel)) =
  formatLabelName label <> ": hunk offset 0x"
  <> renderHexAsText (unOffset sentinel)
  <> " collides with trailer sentinel and cannot be shifted"
  <> " (no preceding source byte available to prepend)"

renderSlapError (SourceTooSmallForPPF2Validation label
                                                 (ActualSize sourceSize)
                                                 (ExpectedSize minimumSize)) =
  formatLabelName label <> ": source file is "
  <> renderAsText (unFileSize sourceSize) <> " bytes; PPF2 requires at least "
  <> renderAsText (unFileSize minimumSize) <> " bytes ("
  <> "the validation block samples 1024 bytes from offset 0x9320,"
  <> " so anything below 0x9720 has no block to embed)"

renderSlapError (FieldTooLong label name (EncodedLength encodedLength) (MaxLength maxLength)) =
  formatLabelName label <> ": " <> fieldNameLabel name
  <> " too long (" <> renderAsText (unLength encodedLength)
  <> " bytes, maximum " <> renderAsText (unLength maxLength) <> ")"

renderSlapError (MissingRequiredField label field) =
  formatLabelName label <> " requires " <> fieldName field
  <> " but source patch doesn't provide it"

renderSlapError (ApplyOutputFieldsWouldBeDropped label drops) =
  "cannot convert to " <> formatLabelName label <> ": "
  <> renderApplyOutputDrops label drops

renderSlapError (DiffRequiresSource label) =
  formatLabelName label
  <> " requires source+target diff data\nuse --with INPUT"

renderSlapError (PPF4ConvertRequiresSource label) =
  "converting to " <> formatLabelName label
  <> " needs the original ROM (--with INPUT)\n"
  <> formatLabelName label
  <> " splits its records into in-place writes and appended bytes by"
  <> " where they fall relative to the source's size, which a"
  <> " source-less conversion can't determine"

renderSlapError (MetadataFieldRejected fields target) =
  let renderOne field =
        "--" <> metadataFieldFlagName field
        <> " (" <> metadataFieldName field <> ")"
  in case NonEmpty.toList fields of
       [single] ->
         "--" <> metadataFieldFlagName single <> " is not accepted by "
         <> formatLabelName target
         <> " (the " <> metadataFieldName single <> " field is not part of this format)"
       many ->
         formatLabelName target
         <> " does not accept these flags:"
         <> Text.concat (map (\field -> "\n  - " <> renderOne field) many)

renderSlapError (ConstraintNotSupported constraints target) =
  let renderOne c =
        "--" <> constraintFlagName c <> " (" <> constraintName c <> ")"
  in case NonEmpty.toList constraints of
       [single] ->
         "the " <> formatLabelName target
         <> " format does not support --" <> constraintFlagName single
         <> " (" <> constraintName single <> ")"
       many ->
         "the " <> formatLabelName target
         <> " format does not support these constraints:"
         <> Text.concat (map (\c -> "\n  - " <> renderOne c) many)

renderSlapError (DialectNotSupported axes target) =
  let renderOne d =
        "--" <> dialectFlagName d <> " (" <> dialectName d <> ")"
  in case NonEmpty.toList axes of
       [single] ->
         "the " <> formatLabelName target
         <> " format does not have a " <> dialectName single
         <> " axis (--" <> dialectFlagName single <> ")"
       many ->
         "the " <> formatLabelName target
         <> " format does not have these dialect axes:"
         <> Text.concat (map (\d -> "\n  - " <> renderOne d) many)

renderSlapError (XDelta1ConvertRequiresNames sourceLabel) =
  "cannot convert from " <> formatLabelName sourceLabel
  <> " to " <> formatLabelName LabelXDelta1
  <> ": xdelta1 patches carry a from-name and a to-name in the header,"
  <> " and " <> formatLabelName sourceLabel <> " has no equivalent fields to inherit from."
  <> "\n  pass --from-name TEXT and --to-name TEXT to supply them explicitly"

renderSlapError (TruncationViolatesSMCShape size) =
  "--" <> constraintFlagName SMCShapeConstraint
  <> ": output size " <> renderAsText (unFileSize size)
  <> " bytes does not satisfy (size & 0xFFF) == 0x200; "
  <> "the resulting IPS patch's truncation marker would be rejected by SNESTool"

renderSlapError (VerificationFatal advisory) =
  renderSlapAdvisory advisory <> "\n  use --no-verify to proceed anyway"

----------------------------------------------------------------------------
-- renderDecompressionFailure
----------------------------------------------------------------------------

-- | The compression algorithm in flight at a given failure site.
-- Implicit per constructor for the four sites with fixed algorithms;
-- read off the value for 'VCDIFFSectionFailed', the one site whose
-- algorithm varies.  The exhaustive match is the seam that fires
-- '-Wincomplete-patterns' when a new 'DecompressionFailure'
-- constructor lands.
decompressionAlgorithm :: DecompressionFailure -> CompressionAlgorithm
decompressionAlgorithm Yay0WrapperFailed{}                 = Yay0
decompressionAlgorithm NINJA1Failed{}                      = Zlib
decompressionAlgorithm XDelta1Failed{}                     = Gzip
decompressionAlgorithm BSDiffSectionFailed{}               = Bzip2
decompressionAlgorithm (VCDIFFSectionFailed _ algorithm _) = algorithm

-- | Display name for a 'CompressionAlgorithm'.  Read by the
-- 'VCDIFFSectionFailed' renderer arm and the secondary-stream
-- malformation renders, where the algorithm genuinely varies; the
-- four fixed-algorithm arms render their algorithm name as a literal
-- in their site description instead.  Exhaustive over
-- 'CompressionAlgorithm' so that adding a new compression algorithm
-- fires '-Wincomplete-patterns' here.
compressionAlgorithmName :: CompressionAlgorithm -> Text
compressionAlgorithmName Zlib  = "zlib"
compressionAlgorithmName Gzip  = "gzip"
compressionAlgorithmName Bzip2 = "bzip2"
compressionAlgorithmName Yay0  = "Yay0"
compressionAlgorithmName DJW   = "DJW"
compressionAlgorithmName LZMA  = "LZMA"
compressionAlgorithmName FGK   = "FGK"

bsDiffSectionName :: BSDiffSection -> Text
bsDiffSectionName BSDiffControl = "control"
bsDiffSectionName BSDiffDiff    = "diff"
bsDiffSectionName BSDiffExtra   = "extra"

-- | How a compressor's stream relates to the payloads that carry it:
-- one continuous stream whose carried pieces are slices of it, or a
-- self-contained stream per piece. A total projection over
-- 'CompressionAlgorithm', so a new algorithm must declare its shape
-- before anything can speak about its streams — there is no wildcard
-- to inherit one silently. Of the VCDIFF catalog, LZMA and FGK gather
-- across a kind's sections, for different reasons — LZMA's bytes are
-- one continuous stream (the xz header rides in a kind's first
-- compressed section, the rest are continuation slices), FGK's are
-- byte-flushed per section but share one adaptive tree — while DJW is
-- fresh per section, its tables read anew each time. The four
-- fixed-site algorithms
-- compress self-contained payloads at their sites, so the per-piece
-- shape is already the true one for them.
data SecondaryStreamGranularity
  = GatheredAcrossSections
  | EachSectionItsOwn

secondaryStreamGranularity :: CompressionAlgorithm -> SecondaryStreamGranularity
secondaryStreamGranularity Zlib  = EachSectionItsOwn
secondaryStreamGranularity Gzip  = EachSectionItsOwn
secondaryStreamGranularity Bzip2 = EachSectionItsOwn
secondaryStreamGranularity Yay0  = EachSectionItsOwn
secondaryStreamGranularity DJW   = EachSectionItsOwn
secondaryStreamGranularity LZMA  = GatheredAcrossSections
secondaryStreamGranularity FGK   = GatheredAcrossSections

-- | The possessive subject of a secondary-stream message: which
-- sections own the stream being spoken of. The grammatical number
-- follows 'secondaryStreamGranularity', because it is a fact about
-- the stream's shape — a gathered stream belongs to all the kind's
-- sections, a per-section stream to just one.
secondaryStreamPossessive :: VCDIFFSection -> CompressionAlgorithm -> Text
secondaryStreamPossessive section algorithm =
  vcdiffSectionName section <> ownerSuffix <> " "
  <> compressionAlgorithmName algorithm <> " stream"
  where
    ownerSuffix = case secondaryStreamGranularity algorithm of
      GatheredAcrossSections -> " sections'"
      EachSectionItsOwn      -> " section's"

-- | Render a decompression failure as a user-facing line.  The four
-- fixed-algorithm arms supply their site description as a literal —
-- NINJA1's description contains the word "zlib" because NINJA1 uses
-- zlib, and that fact is restated at the renderer rather than
-- threaded through the 'compressionAlgorithmName' indirection.  The
-- VCDIFF arm reads the name off the value, because there the
-- algorithm genuinely varies.
renderDecompressionFailure :: DecompressionFailure -> Text
renderDecompressionFailure failure = case failure of
  Yay0WrapperFailed       cause -> render "Yay0 wrapper"        cause
  NINJA1Failed            cause -> render "NINJA1 zlib payload" cause
  XDelta1Failed           cause -> render "XDelta1 gzip body"   cause
  BSDiffSectionFailed sec cause -> render
    ("BSDiff " <> bsDiffSectionName sec <> " bzip2 section") cause
  VCDIFFSectionFailed sec algorithm cause -> render
    ("VCDIFF " <> secondaryStreamPossessive sec algorithm) cause
  where
    render siteName (DecompressionCause msg) =
      siteName <> ": decompression failed: " <> msg

----------------------------------------------------------------------------
-- renderNarrowingFailure
----------------------------------------------------------------------------

renderNarrowingFailure :: NarrowingFailure -> Text
renderNarrowingFailure (OffsetExceedsBound label (ActualOffset actual) (MaxOffset maxOffset)) =
  formatLabelName label <> ": hunk offset 0x"
  <> renderHexAsText (unOffset actual)
  <> " exceeds maximum offset 0x"
  <> renderHexAsText (unOffset maxOffset)
renderNarrowingFailure (NegativeOffset label (ActualOffset actual)) =
  formatLabelName label <> ": record offset " <> renderAsText (unOffset actual)
  <> " is negative; the wire format addresses only non-negative positions"
renderNarrowingFailure (FieldValueExceedsBound label field actual maxValue) =
  formatLabelName label
  <> " " <> fieldNameLabel field
  <> " field value " <> renderAsText actual
  <> " exceeds the wire-format maximum of " <> renderAsText maxValue

----------------------------------------------------------------------------
-- renderSlapAdvisory
----------------------------------------------------------------------------

renderSlapAdvisory :: SlapAdvisory -> Text

renderSlapAdvisory (EmptyPatch _label unit) =
  "empty patch (0 " <> emptyUnitLabel unit <> ")"

renderSlapAdvisory (NoEOFMarker _label) =
  "no EOF marker (patch may be truncated)"

renderSlapAdvisory (PPFApplyGrewPastSource label (FileSize sourceSize) (Length overflow)) =
  formatLabelName label
  <> ": this patch makes the output longer than the input (input 0x"
  <> renderHexAsText sourceSize <> " bytes, output extends 0x"
  <> renderHexAsText overflow <> " bytes further)"
  <> case label of
       -- PPF2 permits growth (its size check is advisory), so this is
       -- purely informational. PPF1/PPF3 are intended for same-size
       -- patches, so growth there is worth flagging as unusual.
       LabelPPF2 -> ""
       _         -> "; growth is unusual for this format, which is"
                    <> " intended for same-size patching"

renderSlapAdvisory (ZeroCountRLERecord label actionIndex) =
  formatLabelName label
  <> ": zero-count RLE record at position " <> renderAsText (unActionIndex actionIndex)
  <> " (accepted as no-op)"

renderSlapAdvisory NegativeZeroInBPS =
  formatLabelName LabelBPS
  <> ": signed-delta varint encoded zero as 0x81 (non-canonical;"
  <> " 0x80 is the canonical form)"

renderSlapAdvisory (NonCanonicalVCDIFFVarint value) =
  formatLabelName LabelVCDIFF
  <> ": varint for " <> renderAsText value
  <> " was encoded overlong (leading zero-groups; canonical form is shorter)"

renderSlapAdvisory (OverlappingRecords label (OverlapCount pairCount)) =
  formatLabelName label
  <> ": " <> renderAsText pairCount
  <> (if pairCount == 1 then " overlapping record pair"
                        else " overlapping record pairs")
  <> " (later writes clobber earlier; unusual)"

renderSlapAdvisory (UnsortedRecords label actionIndex) =
  formatLabelName label
  <> ": record at position " <> renderAsText (unActionIndex actionIndex)
  <> " has a lower offset than the record before it"
  <> " (unsorted records; applied in wire order)"

renderSlapAdvisory (IPS32TrailingBytes label (Length n)) =
  formatLabelName label
  <> ": dropped " <> renderAsText n <> " trailing bytes after EEOF marker"

renderSlapAdvisory (VCDIFFTrailingRemnant (Length remnantLength)) =
  formatLabelName LabelVCDIFF
  <> ": " <> renderAsText remnantLength
  <> " trailing bytes after the last window (0xFF 0xFF 0xFF 0xFF, then"
  <> " zero padding — the LODModS-style tail); not window data, ignored"

renderSlapAdvisory (VCDIFFEmptyTargetWindowSegment windowIndex) =
  formatLabelName LabelVCDIFF
  <> ": VCD_TARGET window " <> renderAsText (unActionIndex windowIndex)
  <> " declares an empty source segment; it draws nothing from the"
  <> " produced target"

renderSlapAdvisory (APSN64TrailingFragment (Length fragmentLength)) =
  formatLabelName LabelAPSN64
  <> ": " <> renderAsText fragmentLength
  <> plural fragmentLength " trailing byte" " trailing bytes"
  <> " after the last record (too few to begin another); not record data, ignored"

renderSlapAdvisory (EBPMetadataMalformed label) =
  formatLabelName label
  <> ": metadata trailer is not valid JSON (or its root is not an object);"
  <> " the patch's records are unaffected and apply/convert proceed,"
  <> " but no title, author, description, or patcher could be extracted"
  <> " (supply --title / --author / --description on convert-to-EBP to populate the target's metadata)"

renderSlapAdvisory (BPSMetadataNonConformant label divergence (Length byteCount)) =
  formatLabelName label
  <> ": metadata is " <> renderAsText byteCount
  <> plural byteCount " byte" " bytes" <> " that " <> divergencePhrase
  <> "; the spec recommends UTF-8 XML here but permits arbitrary bytes,"
  <> " so this is unusual but valid"
  where
    divergencePhrase = case divergence of
      MetadataIsNotUTF8             -> "aren't valid UTF-8"
      MetadataIsValidUTF8ButNonText -> "are valid UTF-8 but carry non-text control codepoints"

renderSlapAdvisory (IPSTruncationMarkerHonored label
    (DeclaredTargetSize declared) (NaturalTargetSize natural)) =
  formatLabelName label
  <> " apply: honored truncation marker (declared "
  <> renderAsText (unFileSize declared) <> " bytes, natural "
  <> renderAsText (unFileSize natural) <> " bytes)"

renderSlapAdvisory (IPSRecordsClippedByMarker label
    (ClippedRecordCount count) firstIndex (MarkerOvershootBytes overshoot)) =
  formatLabelName label <> " apply: "
  <> renderAsText count <> plural count " record" " records"
  <> " clipped by truncation marker (first at step #"
  <> renderAsText (unActionIndex firstIndex) <> ", "
  <> renderAsText (unLength overshoot)
  <> plural (unLength overshoot) " byte" " bytes"
  <> " total clipped)"

renderSlapAdvisory (IPSTruncationMarkerIgnored label
    (DeclaredTargetSize declared) (NaturalTargetSize natural)) =
  formatLabelName label
  <> " apply: ignored truncation marker (declared "
  <> renderAsText (unFileSize declared) <> " bytes, natural "
  <> renderAsText (unFileSize natural) <> " bytes; declared > natural means the marker would grow the output, which slap does not honor)"

renderSlapAdvisory XDelta1NoVerifyWithDivergentSentinel =
  "xdelta1: FLAG_NO_VERIFY is set but stored MD5s are not the canonical empty-input sentinel (non-canonical producer or transit corruption)"

renderSlapAdvisory (XDelta1DataRecordNameDiverges observedName) =
  formatLabelName LabelXDelta1
  <> ": data-record name is " <> renderAsText observedName
  <> " (canonical xdelta writes \"(patch data)\"; the field is a display label only, so slap proceeds normally)"

renderSlapAdvisory (FieldDropped field droppedValue) =
  let rendered = renderDroppedValue droppedValue
  in if Text.null rendered
     then "dropping " <> fieldName field
     else "dropping " <> fieldName field <> ": " <> rendered

renderSlapAdvisory (UndoDataDropped recordCount) =
  "dropping undo data (" <> renderAsText recordCount
  <> plural recordCount " record" " records" <> ")"

renderSlapAdvisory ValidationBlockDropped =
  "dropping validation block (1024 bytes)"

renderSlapAdvisory (DisabledEntriesDropped entryCount) =
  "dropping " <> renderAsText entryCount
  <> plural entryCount " disabled entry" " disabled entries"

renderSlapAdvisory BlockDescriptionsDropped =
  "dropping block descriptions"

renderSlapAdvisory (MetadataDropped (Length byteCount)) =
  "dropping metadata (" <> renderAsText byteCount
  <> plural byteCount " byte" " bytes" <> ")"

renderSlapAdvisory (DefaultRomType _label) =
  "assuming ROM type RAW (override with --rom-type)"

renderSlapAdvisory (DefaultImageType _label) =
  "assuming image type BIN (override with --image-type gi for GI disc images)"

renderSlapAdvisory IncludingUndoByDefault =
  "including undo data (omit with --no-undo)"

renderSlapAdvisory IncludingVerificationByDefault =
  "including verification data (omit with --omit-verification)"

renderSlapAdvisory (SourceHashesMissing _label) =
  "input verification hashes not available (populate with --with INPUT)"

renderSlapAdvisory (FieldTruncated label name (OriginalLength original) (TruncatedLength truncated)) =
  formatLabelName label <> " "
  <> fieldNameLabel name <> " truncated to fit "
  <> renderAsText (unLength truncated) <> "-byte field (was "
  <> renderAsText (unLength original) <> " bytes)"

renderSlapAdvisory (FieldDecodedSubstituted label name (SubstitutionCount count)) =
  formatLabelName label <> " "
  <> fieldNameLabel name <> ": "
  <> renderAsText count <> plural count " byte sequence" " byte sequences"
  <> " did not decode under the declared encoding; substituted U+FFFD"

renderSlapAdvisory (FieldEncodedSubstituted label name (SubstitutionCount count)) =
  formatLabelName label <> " "
  <> fieldNameLabel name <> ": "
  <> renderAsText count <> plural count " codepoint was" " codepoints were"
  <> " not representable in the target encoding; substituted"

renderSlapAdvisory (PlatformNotAvailable label platform) =
  "platform " <> platformName platform
  <> " not available in " <> formatLabelName label <> "; using Raw"

renderSlapAdvisory NINJA2SMSGameGearAmbiguity =
  formatLabelName LabelNINJA2 <> " ROM type SMS/Game Gear"
  <> " is ambiguous; defaults to SMS"
  <> " on conversion (override with --rom-type gg)"

renderSlapAdvisory (ApplyOOBBlocksSkipped label direction (OOBBlockCount count) firstIndex (OOBOvershootBytes overshoot) declaredSize) =
  formatLabelName label <> " " <> directionVerb direction <> ": "
  <> renderAsText count <> plural count " block writes" " blocks write"
  <> " past declared output size ("
  <> renderAsText (unFileSize declaredSize) <> " bytes); first at step #"
  <> renderAsText (unActionIndex firstIndex) <> ", "
  <> renderAsText (unLength overshoot) <> plural (unLength overshoot) " byte" " bytes"
  <> " total overshoot — clipped to output bounds"

renderSlapAdvisory (SubformatConverted conversion) = case conversion of
  NINJA1TextToBinary                       ->
    formatLabelName LabelNINJA1 <> " text (T) converted to binary (B)"
  NINJA1CompressedTextToCompressedBinary   ->
    formatLabelName LabelNINJA1 <> " text (TZ) converted to compressed binary (BZ)"

----------------------------------------------------------------------------
-- Verification: source/target integrity check mismatches
----------------------------------------------------------------------------

renderSlapAdvisory (VerificationCRCMismatch side (ExpectedCRC32 expected) (ActualCRC32 actual)) =
  verificationSideLabel side <> " CRC mismatch (expected 0x"
  <> showCRC32 expected <> ", got 0x" <> showCRC32 actual <> ")"

renderSlapAdvisory (VerificationHashMismatch side algorithm) =
  verificationSideLabel side <> " " <> hashAlgorithmLabel algorithm <> " mismatch"

renderSlapAdvisory (VerificationAdler32Mismatch windowOffset (ExpectedAdler32 expected) (ActualAdler32 actual)) =
  "Adler32 mismatch at window 0x" <> padHex 8 (unOffset windowOffset)
  <> " (expected 0x" <> showAdler32 expected
  <> ", got 0x" <> showAdler32 actual <> ")"

renderSlapAdvisory (VerificationFileSizeMismatch side (ExpectedSize expectedSize) (ActualSize actualSize)) =
  verificationSideLabel side <> " file size mismatch (expected "
  <> renderAsText (unFileSize expectedSize) <> " bytes, got "
  <> renderAsText (unFileSize actualSize) <> " bytes)"

renderSlapAdvisory (VerificationBlockCRC16Mismatch side blockOffset) =
  verificationSideLabel side <> " CRC16 mismatch at 0x" <> padHex 8 (unOffset blockOffset)

renderSlapAdvisory (VerificationPPFBlockMismatch blockOffset) =
  "validation block mismatch at 0x" <> padHex 8 (unOffset blockOffset)

renderSlapAdvisory (VerificationFileSizeAdvisory (ExpectedSize expectedSize) (ActualSize actualSize)) =
  "file size mismatch (expected " <> renderAsText (unFileSize expectedSize)
  <> ", got " <> renderAsText (unFileSize actualSize) <> ")"

renderSlapAdvisory (VerificationSourceBytesMismatch (ByteCheckLabel label) checkOffset) =
  label <> " mismatch at 0x" <> padHex 8 (unOffset checkOffset)

renderSlapAdvisory (VerificationOptedOutByCreator label) =
  formatLabelName label
    <> ": creator opted out of verification (--omit-verification); slap cannot attest the output matches the creator's intent"

----------------------------------------------------------------------------
-- Helpers
----------------------------------------------------------------------------

-- | Choose the singular or plural label for a count, by simple
-- @== 1@ comparison. Each call site supplies the leading space (or
-- absence thereof) inside the singular and plural strings, so the
-- helper composes uniformly into the surrounding sentence whether
-- the number is followed by @" record"@ \/ @" records"@ or @" byte"@
-- \/ @" bytes"@. Used by every 'renderSlapAdvisory' equation whose
-- prose carries a count.
plural :: Int -> Text -> Text -> Text
plural n singular pluralForm = if n == 1 then singular else pluralForm

-- | Render the reason a (source, target) pair was refused. Takes the
-- 'FormatLabel' so an arm can vary its wording per format where the
-- honest explanation differs; arms that don't need to differentiate
-- ignore the label. Wording is deliberately plain here and refined
-- per case as the need arises.
renderUnencodeabilityReason :: FormatLabel -> UnencodeabilityReason -> Text
renderUnencodeabilityReason _label UPSSourceTailNonZero =
  "the input has non-zero bytes past the end of the output;"
  <> " a UPS patch is bi-directional and cannot represent them"
renderUnencodeabilityReason _label
  (TargetGrowsBeyondSource (ActualSize sourceSize) (ExpectedSize targetSize)) =
  "the output is larger than the input"
  <> " (input 0x" <> renderHexAsText (unFileSize sourceSize)
  <> " bytes, output 0x" <> renderHexAsText (unFileSize targetSize)
  <> " bytes); this format is intended for same-size patching"
renderUnencodeabilityReason _label
  (TargetShrinksBelowSource (ActualSize sourceSize) (ExpectedSize targetSize)) =
  "the output is smaller than the input"
  <> " (input 0x" <> renderHexAsText (unFileSize sourceSize)
  <> " bytes, output 0x" <> renderHexAsText (unFileSize targetSize)
  <> " bytes); this format does not represent shrinking"
renderUnencodeabilityReason _label
  (TruncationTargetUnrepresentable (DeclaredTargetSize targetSize) (MaxOffset markerMaximum)) =
  "the output is smaller than the input, so the patch needs a"
  <> " truncation marker, and the marker cannot name a size of 0x"
  <> renderHexAsText (unFileSize targetSize)
  <> " bytes — its field caps at 0x"
  <> renderHexAsText (unOffset markerMaximum)

-- | Render a trailer marker's raw bytes for inclusion in an error
-- message. The 'StandardIPS' and 'IPS32' markers are ASCII-printable
-- (@"EOF"@, @"EEOF"@), so the common case is the literal string. For
-- a hypothetical future trailer marker that contained any non-
-- printable byte, the renderer falls back to a hex dump rather than
-- emitting raw control characters into the error stream.
renderTrailerMarkerName :: ByteString -> Text
renderTrailerMarkerName = renderPrintableASCIIOrHex

-- | Render the apply-output-field-drop refusal body. The single-drop
-- case (today's only case, 'FieldTruncation') produces one clean sentence;
-- the multi-drop case (trivially available if 'affectsApplyOutput'
-- grows) bullets each field on its own line so nothing gets lost.
renderApplyOutputDrops :: FormatLabel -> [(PatchField, [FormatLabel])] -> Text
renderApplyOutputDrops target [singleDrop] = renderOneDrop target singleDrop
renderApplyOutputDrops target manyDrops =
  Text.concat (map (\drop_ -> "\n  - " <> renderOneDrop target drop_) manyDrops)

renderOneDrop :: FormatLabel -> (PatchField, [FormatLabel]) -> Text
renderOneDrop target (field, preservers) =
  "the source patch declares a " <> fieldName field
  <> ", and " <> formatLabelName target
  <> " has no representation for it. " <> renderPreservers field preservers

renderPreservers :: PatchField -> [FormatLabel] -> Text
renderPreservers field [] =
  "No target format preserves " <> fieldName field <> "."
renderPreservers field preservers =
  "Targets that preserve " <> fieldName field <> ": "
  <> commaSeparated (map formatLabelName preservers) <> "."

commaSeparated :: [Text] -> Text
commaSeparated []      = ""
commaSeparated [x]     = x
commaSeparated (x:xs)  = x <> ", " <> commaSeparated xs

commaList :: [Text] -> Text
commaList []     = ""
commaList [x]    = x
commaList [x, y] = x <> " or " <> y
commaList items  = Text.concat (map (<> ", ") (init items)) <> "or " <> last items

----------------------------------------------------------------------------
-- Restructured payload types
----------------------------------------------------------------------------

-- | The semantic unit a patch enumerates. Used by the 'EmptyPatch'
-- advisory so the renderer can name the right noun for the format
-- ("records", "blocks", "windows", ...) without callers passing
-- strings. Each constructor's 'emptyUnitLabel' gives the noun used
-- in the rendered text.
data EmptyUnit
  = EmptyRecords
  | EmptyActions
  | EmptyBlocks
  | EmptyWindows
  | EmptyCommands
  | EmptyInstructions
  | EmptyEntries
  deriving (Eq, Show)

emptyUnitLabel :: EmptyUnit -> Text
emptyUnitLabel EmptyRecords      = "records"
emptyUnitLabel EmptyActions      = "actions"
emptyUnitLabel EmptyBlocks       = "blocks"
emptyUnitLabel EmptyWindows      = "windows"
emptyUnitLabel EmptyCommands     = "commands"
emptyUnitLabel EmptyInstructions = "instructions"
emptyUnitLabel EmptyEntries      = "entries"

-- | The xdelta1 versions whose magic slap recognizes but whose body
-- shape it does not parse. The constructor's stable property is
-- "slap does not implement this version" rather than "older"; if
-- support for any of them lands later, that constructor graduates
-- to its own parser and leaves this sum.
data XDelta1KnownUnsupportedVersion
  = XDelta1_1_0_4
  | XDelta1_1_0
  | XDelta1_0_14
  deriving (Eq, Show)

-- | The off-spec shapes the xdelta1 source-list parser refuses. The
-- nullary constructors cover the enumerable cases; 'XDelta1TooManySources'
-- carries the count (N >= 3) because the value is open-ended.
data XDelta1ShapeViolation
  = XDelta1TwoDataSources
  | XDelta1ReversedDataFileOrder
  | XDelta1TwoFileSources
  | XDelta1ZeroSources
  | XDelta1OneDataSource
  | XDelta1OneFileSource
  | XDelta1TooManySources Int
  deriving (Eq, Show)

-- | The off-spec wire shapes a VCDIFF (RFC 3284) parser refuses. The
-- byte-parser produces raw windows without enforcing these rules;
-- 'Slap.VCDIFF.Parse.parseVCDIFFWith' validates each one against
-- this sum after the wire-level walk and lifts the failure into
-- 'UnsupportedVCDIFFShape'.
data VCDIFFShapeViolation
  -- | The patch had its @VCD_CODETABLE@ header flag set inside a
  -- payload that was itself a custom code table delta. RFC 3284
  -- §4.1 forbids nesting; the inner-delta parse is invoked with
  -- @allowCustom = False@ and rejects anything that tries.
  = VCDIFFNestedCustomCodeTable
  -- | A window's target-size varint decoded as a negative
  -- 'Int64'. VCDIFF varints are signed but every spec-allowed
  -- value is non-negative; the field carries the offending raw
  -- value verbatim.
  | VCDIFFNegativeWindowTargetSize !Int64
  -- | A window's delta indicator set at least one of the three
  -- secondary-compression bits ('VCD_DATACOMP', 'VCD_INSTCOMP',
  -- 'VCD_ADDRCOMP'). Slap does not implement the secondary
  -- compressor; the renderer names the rule without naming
  -- which bit fired (any subset is equally refused).
  | VCDIFFSecondaryCompressionUnsupportedInDataSections
  deriving (Eq, Show)

-- | The structural failures slap raises when decoding a VCDIFF
-- custom code table. Validated outside the byte parser by
-- 'Slap.VCDIFF.CodeTable.deserializeCodeTable', which receives a
-- bytestring slice and returns 'Either SlapError ...' directly.
data VCDIFFCodeTableMalformation
  -- | The serialized code-table bytes did not have the spec-
  -- mandated 1536-byte width (six 256-entry slices: types1,
  -- types2, sizes1, sizes2, modes1, modes2). The 'ActualLength'
  -- carries the observed length.
  = VCDIFFCodeTableWrongLength !ActualLength
  -- | A byte in the types1 or types2 slice did not decode to a
  -- valid instruction type tag (Noop=0, Add=1, Run=2, Copy=3).
  -- The 'Word8' is the offending byte value.
  | VCDIFFCodeTableInvalidInstructionType !Word8
  -- | The custom-code-table data section was shorter than the
  -- 2-byte header (near-cache size byte, same-cache size byte)
  -- it must begin with.
  | VCDIFFCodeTableHeaderTooShort
  -- | A size or mode byte was nonzero for a template type that
  -- carries no such field — a size on a NOOP, a mode on a NOOP, ADD,
  -- or RUN. The grammar gives those bytes exactly one well-formed
  -- value (zero, matching the default-table image a custom image is
  -- delta-encoded against), so a nonzero value is not an alternative
  -- spelling of anything: it is evidence the table bytes are damaged,
  -- and with no checksum in this arc the table check is the tripwire
  -- (docs/vcdiff/rfc-vcdiff/questions.md, "invalid decoded-table
  -- entries"). The 'Word8' is the offending byte.
  | VCDIFFCodeTableUnusedFieldSet !VCDIFFCodeTableField !Word8
  deriving (Eq, Show)

-- | Which per-template byte of the serialized code-table image a
-- malformation names: the size byte or the mode byte.
data VCDIFFCodeTableField = CodeTableSizeField | CodeTableModeField
  deriving (Eq, Show)

codeTableFieldName :: VCDIFFCodeTableField -> Text
codeTableFieldName CodeTableSizeField = "size"
codeTableFieldName CodeTableModeField = "mode"

-- | A VCDIFF feature outside the subset slap decodes, carried by
-- 'VCDIFFFeatureNotYetSupported': a wire feature the engine refuses
-- rather than mishandles, with the parenthetical naming its arc. The
-- custom code table is the one such feature, the last RFC-arc feature
-- slap does not yet read.
data VCDIFFUnsupportedFeature
  = VCDIFFCustomCodeTable             -- ^ Hdr_Indicator VCD_CODETABLE: a custom code table (RFC-arc).
  deriving (Eq, Show)

-- | Which xdelta3 extension a VCD_TARGET-bearing patch also carried,
-- making it neither dialect. Carried by
-- 'VCDIFFTargetWindowWithXDelta3Feature'; the renderer names the
-- specific extension so the refusal's reason is concrete. Priority of
-- detection (compressor, then header, then checksum) is the classifier's
-- — any one of them is enough to eject the patch from the RFC arc.
data VCDIFFXDelta3Feature
  = XDelta3FeatureSecondaryCompressor  -- ^ a declared secondary compressor (VCD_DECOMPRESS).
  | XDelta3FeatureApplicationHeader    -- ^ an application header (VCD_APPHEADER).
  | XDelta3FeatureWindowChecksum       -- ^ a per-window Adler32 (VCD_ADLER32).
  deriving (Eq, Show)

-- | A semantics failure in a VCDIFF patch that parsed at the byte
-- level, carried by 'MalformedVCDIFF'. These are the loud refusals
-- the core invariants demand (docs/vcdiff/core/spec.md "Core
-- invariants") — a window naming both copy sources at once, a COPY
-- that reads unwritten output or crosses the source-segment boundary,
-- a window that does not fill to its declared size, an oversize
-- section reference, an address mode the table cannot name — plus the
-- secondary-compression framing contradictions
-- (docs/vcdiff/xdelta3/questions.md "Secondary compression — the
-- framing"): a compressed section whose own declarations cannot be
-- honored, or a kind's gathered stream whose decode disagrees with
-- what its sections declared. Every arm is a claim slap understands
-- and finds invalid; a reserved indicator bit or an uncataloged
-- compressor id — claims slap cannot interpret — are the separate
-- declines 'VCDIFFReservedIndicatorBits' and
-- 'VCDIFFUnknownSecondaryCompressor'. The 'ActionIndex' an arm
-- carries counts decoded instructions, not instruction-section
-- bytes: one code byte can carry two instructions, and an inline
-- size varint widens others, so the index names what the stream
-- means rather than where it sits.
data VCDIFFMalformation
  -- | A window's indicator set both VCD_SOURCE and VCD_TARGET, which
  -- RFC 3284 §4.2 forbids.
  = VCDIFFBothSourceAndTargetWindowBits
  -- | Core invariant 1: a COPY address must point strictly inside the
  -- already-produced superstring. The 'ActualOffset' is the decoded
  -- address; the 'MaxOffset' is @here@ (the current write position in
  -- the superstring), so the valid range is @[0, here)@.
  | VCDIFFCopyAddressOutOfRange !ActionIndex !ActualOffset !MaxOffset
  -- | Core invariant 2: a COPY that begins inside the source segment
  -- must not run past its end.
  | VCDIFFCopyCrossesSourceSegmentEnd !ActionIndex
  -- | Core invariant 3: a window's instructions must produce exactly
  -- its declared target size. The 'ExpectedSize' is the declared size;
  -- the 'ActualSize' is what the instructions produced.
  | VCDIFFWindowSizeMismatch !ExpectedSize !ActualSize
  -- | An instruction demanded more bytes than its 'VCDIFFSection'
  -- holds — the data, instruction, or address section ran short.
  | VCDIFFSectionExhausted !VCDIFFSection !ActionIndex
  -- | A COPY's code-table entry named an address mode outside the
  -- range the cache configuration defines. The 'Word8' is the mode.
  | VCDIFFInvalidCopyAddressMode !Word8
  -- | A window's declared delta-encoding length disagrees with the
  -- measured span of its own fields — self-consistency the core
  -- ruling demands (docs/vcdiff/core/questions.md,
  -- "delta-encoding-length"): the length is the boundary a reader
  -- navigates windows by, so once slap steers by it, verifying it is
  -- obligatory. The 'ExpectedSize' is the wire declaration; the
  -- 'ActualSize' is the span the framer measured.
  | VCDIFFDeltaEncodingLengthMismatch !ExpectedSize !ActualSize
  -- | A section flagged secondary-compressed whose bytes cannot
  -- supply the decompressed-size varint every compressed section
  -- begins with — the zero-length section is the canonical case
  -- (nothing to read a varint from). Rejected per
  -- docs/vcdiff/xdelta3/questions.md, "compressed-but-empty section".
  | VCDIFFCompressedSectionWithoutDeclaredSize !VCDIFFSection
  -- | A section flagged secondary-compressed whose decompressed-size
  -- varint is zero. A category error rather than a no-op: compressing
  -- nothing yields framing bytes, never zero bytes, so a section
  -- cannot honestly decompress to empty. xd3 rejects it as "invalid
  -- output size"; slap does too.
  | VCDIFFCompressedSectionDeclaresEmptyOutput !VCDIFFSection
  -- | A window's Delta_Indicator flags a section as compressed, but
  -- the patch's header declares no secondary compressor. The two
  -- declarations live in the same patch and contradict each other;
  -- there is no algorithm the section could honestly be decoded by.
  | VCDIFFCompressedSectionWithoutCompressor !VCDIFFSection
  -- | A secondary stream finished decoding with input left over —
  -- the named 'Length' of it. Mirrors xd3's "finished with unused
  -- input" verdict (@xd3_decode_secondary@), kept distinct from the
  -- short-output sibling below because over-supplied input and
  -- under-produced output are different faults. The
  -- 'CompressionAlgorithm' names the decoder that was running, and
  -- fixes the stream's granularity: a kind's windows-spanning
  -- gathered stream for LZMA, one section's own self-contained
  -- stream for DJW.
  | VCDIFFSecondaryStreamUnconsumedInput !VCDIFFSection !CompressionAlgorithm !Length
  -- | A secondary stream decoded to a byte count other than its
  -- framing declared. Mirrors xd3's "short output" verdict; the
  -- 'ExpectedSize' is the declared size (the sections' sum for
  -- LZMA's gathered kind, the one section's own for DJW), the
  -- 'ActualSize' what the decoder produced.
  | VCDIFFSecondaryStreamOutputSizeMismatch !VCDIFFSection !CompressionAlgorithm !ExpectedSize !ActualSize
  deriving (Eq, Show)

-- | Which of a VCDIFF patch's three indicator bytes carried a
-- reserved bit (see 'VCDIFFReservedIndicatorBits').
data VCDIFFIndicatorKind = HeaderIndicator | WindowIndicator | DeltaIndicator
  deriving (Eq, Show)

-- | One of a VCDIFF window's three data sections (see
-- 'VCDIFFSectionExhausted') — and, since the sections of one kind
-- form a continuous secondary stream across windows, also the name
-- of that kind in the secondary-compression arms above.
data VCDIFFSection = VCDIFFDataSection | VCDIFFInstructionSection | VCDIFFAddressSection
  deriving (Eq, Show)

indicatorKindName :: VCDIFFIndicatorKind -> Text
indicatorKindName HeaderIndicator = "header indicator"
indicatorKindName WindowIndicator = "window indicator"
indicatorKindName DeltaIndicator  = "delta indicator"

vcdiffSectionName :: VCDIFFSection -> Text
vcdiffSectionName VCDIFFDataSection        = "data"
vcdiffSectionName VCDIFFInstructionSection = "instruction"
vcdiffSectionName VCDIFFAddressSection     = "address"

-- | The structural failures slap raises when validating a BSDiff
-- fixed-width header. The three 'Int64' fields are the
-- @control@, @diff@, and @target@ sizes in declaration order; at
-- least one of them decoded as negative, and all three are
-- preserved verbatim so the renderer can name which.
data BSDiffHeaderMalformation
  = BSDiffNegativeHeaderSizes !Int64 !Int64 !Int64
  deriving (Eq, Show)

-- | The structural failures slap raises when validating an
-- APS-N64 header byte before invoking the main wire-level walk.
-- Today only the patch-type byte is pre-validated; future
-- additions (unrecognized image format, unrecognized record
-- encoding) will add sibling constructors here as those fields
-- migrate from "carried verbatim with an advisory" to "rejected
-- with an error".
data APSN64HeaderMalformation
  = APSN64UnknownPatchType !Word8
  deriving (Eq, Show)

-- | The NINJA1-format-specific malformations a textual-patch parser
-- can refuse. Each constructor names a structural failure mode of
-- the textual patch grammar; the labeled newtypes (e.g. 'LineText')
-- carry the offending wire bytes verbatim for the renderer.
data NINJA1Malformation
  = NINJA1EmptyTextualPatch
  | NINJA1InvalidOffsetInTextRecord OffsetTokenText
  | NINJA1MalformedTextRecord       LineText
  -- | A textual NINJA1 patch's header line declared a ROM type
  -- name slap doesn't recognize. The NINJA1 spec
  -- (@docs\/ninja1\/upstream\/ninja1-filespec10.txt@, §"SYSTEM
  -- SPECIFIC") says implementations encountering an unsupported
  -- mode "print an error message and exit"; the carried 'Text'
  -- is the offending name from the wire so the renderer can name
  -- it.
  | NINJA1UnknownTextualRomType Text
  deriving (Eq, Show)

-- | The shape of a NINJA1 subformat conversion noticed at parse time.
-- NINJA1's textual variants are decoded into their binary peers
-- before slap's per-format machinery sees them; this advisory
-- surfaces that change. The FormatLabel is implicit (always NINJA1).
data NINJA1SubformatConversion
  = NINJA1TextToBinary
  | NINJA1CompressedTextToCompressedBinary
  deriving (Eq, Show)

-- | A line of textual-patch input, carried verbatim for inclusion in
-- a malformation diagnostic. Labeled so the wire content stays
-- non-pattern-matchable at the type level.
newtype LineText = LineText { unLineText :: Text }
  deriving (Eq, Show)

-- | A hex-offset token slice from a textual-patch line, carried
-- verbatim for inclusion in a malformation diagnostic.
newtype OffsetTokenText = OffsetTokenText { unOffsetTokenText :: Text }
  deriving (Eq, Show)

----------------------------------------------------------------------------
-- ByteParserError
----------------------------------------------------------------------------

-- | Which primitive of 'Slap.ByteParser' surfaced an underflow.
-- Carried by 'ByteParserUnderflow' so the renderer can name which
-- call site the failure came from. All four primitives can
-- genuinely underflow; the parallel "negative length requested"
-- failure is split into per-primitive constructors instead
-- ('ByteParserNegativeLengthRequestedInGetBytes',
-- 'ByteParserNegativeLengthRequestedInSkip') because only those
-- two primitives accept a caller-supplied length.
data ByteParserOperation
  = GetBytesOperation
  | SkipOperation
  | FixedWidthReadOperation
  | VarintReadOperation
  deriving (Eq, Show)

-- | The structured failure type for 'Slap.ByteParser.ByteParser'.
-- Lifted into 'SlapError' via the per-format 'ParseError' constructor;
-- each format's 'Parse.hs' wraps it with its own 'FormatLabel' at the
-- @runByteParser@ seam.
--
-- Constructors are 'ByteParser'-prefixed to match slap's per-domain
-- convention ('ApplyError' constructors are @Apply*@, 'NINJA1Malformation'
-- are @NINJA1*@, and so on). Shared underflow shape is parameterized
-- over 'ByteParserOperation' rather than split into a constructor per
-- primitive — the axes the consumer wants to dispatch on are the
-- failure kind and the surfacing primitive, in that order.
--
-- 'ByteParserUnexpectedDoPatternFailure' is the 'MonadFail' fallback
-- and exists for one reason only: when a @do@-notation pattern bind
-- inside slap's parser code fails (e.g. a refutable pattern that
-- doesn't match), the desugaring needs somewhere to land that isn't
-- 'error'. Reaching that arm means slap has a bug, not that the
-- input was malformed; the renderer prefixes it as an internal
-- failure for that reason. Real failure shapes have typed
-- constructors above.
data ByteParserError

  -- | A read could not be satisfied: 'RequestedLength' bytes were
  -- asked for at 'Position', but only 'RemainingLength' bytes were
  -- left in the input. The 'ByteParserOperation' names which
  -- primitive surfaced the underflow.
  = ByteParserUnderflow ByteParserOperation RequestedLength RemainingLength Position

  -- | A record declares more bytes than the stream holds. Raised by
  -- format walkers through 'Slap.ByteParser.throwByteParserError'
  -- ahead of the doomed read, so the failure names the record (and
  -- its full declared size) rather than the byte offset a raw
  -- underflow would have named. The 'RequiredLength' is the whole
  -- record's byte count, header included; the 'RemainingLength' is
  -- what the stream had where the record began.
  | ByteParserTruncatedRecord !ActionIndex !RequiredLength !RemainingLength

  -- | A command-coded stream's next code byte is outside the
  -- format's command table. Raised by format walkers through
  -- 'Slap.ByteParser.throwByteParserError'; the 'ActionIndex' names
  -- the offending record in wire order and the 'Word8' carries the
  -- byte as read.
  | ByteParserUnknownCommandByte !ActionIndex !Word8

  -- | 'Slap.ByteParser.getUntilByte' scanned for the given terminator
  -- byte from 'Position' to end-of-input and did not find it.
  | ByteParserTerminatorNotFound Word8 Position

  -- | A 'Slap.ByteParser.setPosition' target was outside the half-
  -- open interval @[0, inputLength]@. The 'Position' is the
  -- offending target; the 'ActualLength' is the input's total length.
  | ByteParserPositionOutOfBounds Position ActualLength

  -- | 'Slap.ByteParser.getBytes' was asked for a negative number
  -- of bytes. The 'Length' is the offending value as received.
  -- Split from the parallel 'Skip' variant below so the only
  -- representable shapes are the ones the byte-parser can
  -- actually surface — fixed-width and varint reads don't take a
  -- caller-supplied length, so they can't produce this failure.
  | ByteParserNegativeLengthRequestedInGetBytes Length

  -- | 'Slap.ByteParser.skip' was asked to advance by a negative
  -- number of bytes. The 'Length' is the offending value.
  | ByteParserNegativeLengthRequestedInSkip Length

  -- | A varint started inside the buffer but its continuation bytes
  -- ran past the end. The 'Position' is where the varint started.
  -- Distinct from 'ByteParserUnderflow'\@'VarintReadOperation', which
  -- fires when the read started at or past EOF.
  | ByteParserVarintOverranBuffer Position

  -- | A varint decoded a value too large to represent at all. Raised
  -- by all three slap varint readers (byuu, VCDIFF, EDSIO): byuu and
  -- EDSIO use it as their single over-width verdict, VCDIFF only for
  -- the @>= 2^64@ band beyond even xd3's @uint64@ (the @[2^63, 2^64)@
  -- band is the apologetic 'ByteParserVarintExceedsSignedRange'). byuu
  -- and VCDIFF detect the condition by value; EDSIO still bails on its
  -- bit-offset. The constructor takes no payload because the only
  -- thing the variant says is "the value can't be represented".
  | ByteParserVarintExceededWidth

  -- | A VCDIFF varint decoded a value in @[2^63, 2^64)@ — one that
  -- xd3's unsigned @uint64@ reader accepts but slap's signed 'Int'
  -- declines. The apologetic arm: distinct from
  -- 'ByteParserVarintExceededWidth' (which is the @>= 2^64@ band,
  -- beyond xd3 too) precisely so the renderer can concede the one bit
  -- slap gives up rather than blame the input. Only the VCDIFF reader
  -- raises it; the byuu reader caps at the same value as a plain
  -- over-width and never reaches this arm.
  | ByteParserVarintExceedsSignedRange

  -- | An EDSIO varint decoded a value past @0xFFFFFFFF@. Every integer
  -- in the xdelta1 wire format is a @guint32@ — offsets, lengths,
  -- counts alike (upstream @xd_edsio.h@; the reader reconstructs into
  -- a @guint32@ in @libedsio/default.c@) — so a value wider than 32
  -- bits is not a representable xdelta1 quantity, and slap declines it
  -- rather than carry a number the format has no field for.
  -- (Canonical xdelta truncates such a value into its @guint32@
  -- silently; slap refuses, the same posture it takes wherever a wire
  -- field overflows its defined width.) The 'Int64' is the offending
  -- decoded value. Only the EDSIO reader raises it.
  | ByteParserEdsioVarintExceeds32Bits !Int64

  -- | 'MonadFail'\@'fail' fallback for @do@-notation pattern-match
  -- failures inside slap's parser code. Reaching this arm means a
  -- refutable pattern bind in a parser body didn't match — i.e.
  -- slap has a bug, not that the wire input was malformed. The
  -- string is the desugared @fail@ message; the renderer prefixes
  -- it as an internal failure.
  | ByteParserUnexpectedDoPatternFailure String

  deriving (Eq, Show)

----------------------------------------------------------------------------
-- Severity assignment
----------------------------------------------------------------------------

-- | Map each 'SlapAdvisory' constructor to its severity. Severity is
-- a property of the value, not a call-site decision; this is the
-- single source of truth for which prefix the user sees when an
-- advisory is emitted. The 'emitToStderr' pipeline reads this
-- value and looks the prefix up via 'severityLabel'.
slapAdvisorySeverity :: SlapAdvisory -> Severity
slapAdvisorySeverity advisory = case advisory of

  -- Warnings: something happened the user should look at. Patch
  -- shape that suggests truncation, decisions slap made at apply
  -- time that altered output bytes vs the wire, or integrity checks
  -- that didn't agree with the patch's stored hashes.
  NoEOFMarker{}                        -> SeverityWarning
  -- PPF2 permits growth, so its apply-grow advisory is a note; PPF1/PPF3
  -- are intended same-size, so growth there warns.
  PPFApplyGrewPastSource LabelPPF2 _ _ -> SeverityNote
  PPFApplyGrewPastSource{}             -> SeverityWarning
  IPSTruncationMarkerHonored{}         -> SeverityWarning
  IPSRecordsClippedByMarker{}          -> SeverityWarning
  IPSTruncationMarkerIgnored{}         -> SeverityWarning
  XDelta1NoVerifyWithDivergentSentinel -> SeverityWarning
  ApplyOOBBlocksSkipped{}              -> SeverityWarning
  VerificationCRCMismatch{}            -> SeverityWarning
  VerificationHashMismatch{}           -> SeverityWarning
  VerificationAdler32Mismatch{}        -> SeverityWarning
  VerificationFileSizeMismatch{}       -> SeverityWarning
  VerificationBlockCRC16Mismatch{}     -> SeverityWarning
  VerificationPPFBlockMismatch{}       -> SeverityWarning
  VerificationFileSizeAdvisory{}       -> SeverityWarning
  VerificationSourceBytesMismatch{}    -> SeverityWarning
  VerificationOptedOutByCreator{}      -> SeverityWarning

  -- Notes: informational. Spec-level oddities accepted as no-ops,
  -- conversions that dropped a field with no equivalent in the
  -- target format, defaults slap chose when the user didn't specify,
  -- truncations and encoding gaps that did happen but are reported
  -- so the reader knows rather than because anything needs fixing.
  EmptyPatch{}                         -> SeverityNote
  ZeroCountRLERecord{}                 -> SeverityNote
  NegativeZeroInBPS                    -> SeverityNote
  NonCanonicalVCDIFFVarint{}           -> SeverityNote
  OverlappingRecords{}                 -> SeverityNote
  UnsortedRecords{}                    -> SeverityNote
  IPS32TrailingBytes{}                 -> SeverityNote
  VCDIFFTrailingRemnant{}              -> SeverityNote
  VCDIFFEmptyTargetWindowSegment{}     -> SeverityNote
  APSN64TrailingFragment{}             -> SeverityNote
  EBPMetadataMalformed{}               -> SeverityNote
  BPSMetadataNonConformant{}           -> SeverityNote
  XDelta1DataRecordNameDiverges{}      -> SeverityNote
  FieldDropped{}                       -> SeverityNote
  UndoDataDropped{}                    -> SeverityNote
  ValidationBlockDropped               -> SeverityNote
  DisabledEntriesDropped{}             -> SeverityNote
  BlockDescriptionsDropped             -> SeverityNote
  MetadataDropped{}                    -> SeverityNote
  DefaultRomType{}                     -> SeverityNote
  DefaultImageType{}                   -> SeverityNote
  IncludingUndoByDefault               -> SeverityNote
  IncludingVerificationByDefault       -> SeverityNote
  SourceHashesMissing{}                -> SeverityNote
  FieldTruncated{}                     -> SeverityNote
  FieldDecodedSubstituted{}            -> SeverityNote
  FieldEncodedSubstituted{}            -> SeverityNote
  PlatformNotAvailable{}               -> SeverityNote
  NINJA2SMSGameGearAmbiguity           -> SeverityNote
  SubformatConverted{}                 -> SeverityNote
