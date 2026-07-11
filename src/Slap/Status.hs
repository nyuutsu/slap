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
  , ExtractionSubject(..)
  , SlapAdvisory(..)
  , ApplyError(..)
  , CursorKind(..)
  , UnencodeabilityReason(..)
  , DecompressionFailure(..)
  , BSDiffSection(..)
  , DecompressionCause(..)
  , XDelta1DiffCause(..)
  , BSDiffDifferCause(..)
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
  , UndoRecordCount(..)
  , ControlSectionSize(..)
  , DiffSectionSize(..)
  , TargetSectionSize(..)
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
  , XDelta1SourceListShape(..)
  , XDelta1SourcelessShape(..)
  , XDelta1SourceFlag(..)
  , VCDIFFShapeViolation(..)
  , VCDIFFCodeTableMalformation(..)
  , VCDIFFCodeTableField(..)
  , VCDIFFRFCFeature(..)
  , VCDIFFXDelta3Feature(..)
  , VCDIFFMalformation(..)
  , VCDIFFIndicatorKind(..)
  , VCDIFFSection(..)
  , BSDiffHeaderMalformation(..)
  , APSN64HeaderMalformation(..)
  , NINJA1Malformation(..)
  , NINJA1SubformatConversion(..)
  , NormalizationStep(..)
  , SNESInterleaveLayout(..)
  , NormalizedImageRole(..)
  , NormalizationSkipReason(..)
  , RestoredContent(..)
  , BPSMetadataDivergence(..)
  , LineText(..)
  , OffsetTokenText(..)
  , ChecksumTokenText(..)
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
import Slap.Archive.Types (ArchiveFormat, archiveFormatName, toolsFor,
                           ToolName(..), ToolDiagnostic(..),
                           EntryName(..), SeenEntryCount(..),
                           UnreadableReason(..), UnwrapError(..))
import Slap.Display.Primitives (hexByteString, padHex, renderPrintableASCIIOrHex)
import Slap.PlatformType (PlatformType(..), platformName,
                          CarriedRomType(..), RequestedRomType(..))
import Slap.Measure (Offset(..), Length(..), Position(..), FileSize(..),
                     SignedOffset(..), ActionIndex(unActionIndex),
                     ReadOffset(..), WritePosition(..),
                     RequestedLength(..), RemainingLength(..),
                     ActualSize(..), ExpectedSize(..),
                     MaxAddressableSize(..),
                     SourceFileSize(..), TargetFileSize(..),
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
import Slap.Header (ConsoleHeader, consoleHeaderName, consoleHeaderLength)
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
import Data.Word (Word8, Word32)
import Numeric (showHex)
import System.Exit (exitFailure)
import System.IO (stderr)

----------------------------------------------------------------------------
-- Severity and emit pipeline
----------------------------------------------------------------------------

-- | The valence of a status item: error halts, warning and note do not.
-- Every 'SlapError' is 'SeverityError'; a 'SlapAdvisory' varies by constructor, projected by 'slapAdvisorySeverity'.
data Severity = SeverityError | SeverityWarning | SeverityNote
  deriving (Eq, Show)

severityLabel :: Severity -> Text
severityLabel SeverityError   = "error"
severityLabel SeverityWarning = "warning"
severityLabel SeverityNote    = "note"

-- | The single stderr writer: every error, warning, or note slap emits routes through here.
emitToStderr :: Severity -> Text -> IO ()
emitToStderr severity body =
  TextIO.hPutStrLn stderr ("slap: " <> severityLabel severity <> ": " <> body)

emitAdvisory :: SlapAdvisory -> IO ()
emitAdvisory advisory = emitToStderr severity body
  where severity = slapAdvisorySeverity advisory
        body     = renderSlapAdvisory advisory

emitAdvisories :: [SlapAdvisory] -> IO ()
emitAdvisories = traverse_ emitAdvisory

-- | Emit an ad-hoc error and exit — for failures that have no typed 'SlapError' constructor yet.
bail :: Text -> IO a
bail body = emitToStderr SeverityError body >> exitFailure

bailError :: SlapError -> IO a
bailError = bail . renderSlapError

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

-- | Which of BPS's two independent relative cursors underflowed:
-- the source cursor ('SourceCopy' reads) or the target cursor ('TargetCopy' reads).
data CursorKind = SourceCursor | TargetCursor
  deriving (Show, Eq)

----------------------------------------------------------------------------
-- UnencodeabilityReason
----------------------------------------------------------------------------

-- | Why a (source, target) pair cannot be encoded in some format. Carried by 'UnencodeablePair'.
data UnencodeabilityReason
  = UPSSourceTailNonZero
    -- ^ UPS: the source has non-zero bytes past the target size. Refused to preserve UPS's bi-directional undo (spec §2):
    -- the block stream covers only @[0, target_size)@, so forward apply produces the correct target,
    -- but reverse apply would rebuild those tail bytes as zeros.
  | TargetGrowsBeyondSource  !ActualSize !ExpectedSize
    -- ^ The target is larger than the source and the format's 'Slap.Measure.SizeChangePolicy' is 'Slap.Measure.ForbidTargetSizeChange'.
    -- The 'ActualSize' is the source's size; the 'ExpectedSize' is the would-be target's.
  | TargetShrinksBelowSource !ActualSize !ExpectedSize
    -- ^ The target is smaller than the source and the format's policy is 'Slap.Measure.ForbidTargetShrinkage' or 'Slap.Measure.ForbidTargetSizeChange'.
    -- Fields as in 'TargetGrowsBeyondSource'.
  | TruncationTargetUnrepresentable !DeclaredTargetSize !MaxOffset
    -- ^ 'StandardIPS' only: the pair shrinks, so the encoding needs the post-EOF truncation marker,
    -- and the marker spells the final size in the same 24-bit width as record offsets — a size past that maximum has no representation.
    -- Without the refusal, the encoder would mask the size to its low bits and emit a patch that applies to a wrongly-sized file,
    -- in a format with no checksum to notice.
  deriving (Eq, Show)

----------------------------------------------------------------------------
-- ApplyError
----------------------------------------------------------------------------

-- | Format-agnostic errors from patch application, paired with a 'FormatLabel' via 'ApplyFailed'.
-- Most variants carry the 'ActionIndex' of the action that triggered them.
data ApplyError

  -- | A relative cursor (source or target) went negative after applying the action's delta.
  = ApplyCursorUnderflow CursorKind ActionIndex SignedOffset

  -- | An action would read past the end of the source ByteString.
  -- The 'Offset' is the would-be read end; the 'FileSize' is the actual source size.
  | ApplySourceReadOutOfBounds ActionIndex Offset FileSize

  -- | A TargetCopy referenced an output position at or past the write head — bytes not yet written.
  | ApplyTargetReadUnwritten ActionIndex ReadOffset WritePosition

  -- | An action's output length would exceed the remaining space in the target buffer.
  | ApplyWritesPastTarget ActionIndex RequestedLength RemainingLength

  -- | The action stream was exhausted but the target buffer is not fully written.
  -- No 'ActionIndex': this fires after the stream ends, with no specific action responsible — the whole patch is short.
  -- (No corresponding @ApplyTargetOverfilled@: 'ApplyWritesPastTarget' catches over-writes per-action before they can happen.)
  | ApplyTargetUnderfilled WritePosition ExpectedSize

  -- | A record's offset is negative. Possible only where the offset encoding admits one:
  -- PPF3's signed 64-bit field, and NINJA2's packed integers, which decode into a signed 'Int'.
  | ApplyNegativeRecordOffset ActionIndex Offset

  -- | A bsdiff control instruction declares a negative region length — bsdiff's sign-magnitude wire encoding admits one,
  -- but a region length is non-negative by nature. (The seek delta in the same triple is legitimately signed and is not this.)
  | ApplyNegativeControlLength ActionIndex RequestedLength

  -- | A record's write end — offset plus payload length — exceeds 'maxBound' :: 'Int', the ceiling of slap's position carrier.
  -- Only a wire offset as wide as the carrier (PPF3's signed 64-bit field) can name such a write;
  -- the format admits it, and slap declines to materialise an output it cannot address.
  -- The apply-side sibling of 'FileExceedsAddressableRange'.
  -- The 'Offset' and 'Length' are carried separately because it is their sum that does not fit; the renderer adds them in 'Integer'.
  | ApplyOutputExceedsAddressableRange ActionIndex Offset Length

  -- | A PPF4 Replace record would write past the source's end. Replace cannot grow the file — only Append can;
  -- the reference applier rejects this with @ERROR_BAD_SIZE@.
  | ApplyReplaceGrowsFile ActionIndex Offset RequestedLength FileSize

  -- | A BSDiff ADD instruction would read past the end of the diff stream.
  -- The 'Offset' is the would-be read end; the 'FileSize' is the diff stream's size.
  | ApplyDiffReadOutOfBounds ActionIndex Offset FileSize

  -- | The extra-stream mirror of 'ApplyDiffReadOutOfBounds', for BSDiff COPY.
  | ApplyExtraReadOutOfBounds ActionIndex Offset FileSize

  -- | A record's wire-declared absolute write position plus payload extends past the declared target end ('FileSize').
  -- For formats that name absolute positions on the wire — NINJA2's XOR records and overflow-append step, APSGBA's blocks —
  -- where the start alone can already sit past the end,
  -- unlike 'ApplyWritesPastTarget', whose forward-walking cursor always sits within the buffer.
  | ApplyAbsoluteWritePastTarget ActionIndex Offset RequestedLength FileSize

  deriving (Show, Eq)

----------------------------------------------------------------------------
-- DecompressionFailure
----------------------------------------------------------------------------

-- | One constructor per decompression site, each carrying only the axes that vary there.
-- 'VCDIFFSectionFailed' is the one site whose algorithm varies — a secondary stream is decoded
-- by whichever compressor the patch declared — so it alone carries a 'CompressionAlgorithm'.
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

-- | The decompressor's own diagnostic, relayed verbatim (flate2, bzip2-rs, lzma-rs, or slap's Yay0).
-- Decoded as UTF-8 at the FFI seam ('Slap.FFI.readText').
newtype DecompressionCause = DecompressionCause { unDecompressionCause :: Text }
  deriving (Show, Eq)

-- | The xdelta1 differ's failure cause, in the Rust side's own words —
-- an allocation refusal while building the source index, or an internal-invariant violation surfaced rather than panicked.
newtype XDelta1DiffCause = XDelta1DiffCause { unXDelta1DiffCause :: Text }
  deriving (Show, Eq)

-- | The bsdiff differ's counterpart of 'XDelta1DiffCause' — always an invariant violation:
-- bsdiff's 64-bit wire fields outreach any input buffer, so there is no size refusal to relay.
newtype BSDiffDifferCause = BSDiffDifferCause { unBSDiffDifferCause :: Text }
  deriving (Show, Eq)

-- | Which input file(s) an xdelta1 patch expected to be gzip streams, for 'XDelta1InputPreCompressionUnsupported'.
-- "Neither" is unrepresentable — that is the success path, not a failure shape.
data XDelta1GzipStreamInputs
  = OnlyFromFileWasGzipStream
  | OnlyToFileWasGzipStream
  | BothFilesWereGzipStreams
  deriving (Show, Eq)

-- | Every compression algorithm slap knows: four with fixed decompression sites,
-- plus xdelta3's secondary-compression catalog (DJW, LZMA, FGK).
data CompressionAlgorithm
  = Zlib | Gzip | Bzip2 | Yay0
  | DJW  | LZMA | FGK
  deriving (Show, Eq, Ord, Enum, Bounded)

----------------------------------------------------------------------------
-- SlapError
----------------------------------------------------------------------------

-- | Which @info@ extraction found nothing to write, for 'NothingToExtract'.
data ExtractionSubject
  = EmbeddedMetadataSubject
  | FileIdDizSubject
  deriving (Show, Eq)

data SlapError

  -- IO boundary
  = MissingInputFile FilePath
  -- | The file exists but could not be opened.
  -- The 'String' is the OS's own explanation ('System.IO.Error.ioeGetErrorString').
  | UnreadableInputFile FilePath String

  -- | The write-side mirror of 'UnreadableInputFile'.
  | UnwritableOutputFile FilePath String

  -- | @info --extract-metadata@ or @--extract-diz@ found nothing to write.
  | NothingToExtract FilePath ExtractionSubject

  -- | The input was recognized as an archive, but unwrapping the single patch inside it failed;
  -- the 'UnwrapError' says which way.
  | ArchiveUnwrapFailed FilePath ArchiveFormat UnwrapError

  -- Header flags
  -- | @--remove-header@ was asked to drop more bytes than the input has.
  -- The 'ActualSize' is the input's size; the header's width comes from 'consoleHeaderLength'.
  | HeaderRemovalExceedsInput ConsoleHeader ActualSize

  -- | @--add-header@ and @--remove-header@ change the output's shape,
  -- so they refuse @--in-place@ rather than replace the original with a differently-shaped file.
  | HeaderDirectiveRequiresSeparateOutput

  -- Detection
  | UnrecognizedFormat
  | AmbiguousDetection [FormatLabel]

  -- Parse: structural
  | InputTooShort FormatLabel RequiredLength ActualLength
  | BadMagic FormatLabel ActualMagic
  | BadVersion FormatLabel FoundVersion
  -- | xdelta1 magic identifying a known older subformat slap does not read.
  | UnsupportedXDelta1Subformat XDelta1KnownUnsupportedVersion
  -- | NINJA1's two-byte @subFormatIdentifier@ names a wire shape slap does not implement.
  -- Canonical NINJA1 emits only @"B "@, @"BZ"@, @"T\\n"@, and @"TZ"@; any other pair is off-spec or from a newer revision.
  | UnsupportedNINJA1Subformat ByteString
  | NegativeSize FormatLabel FieldName ParsedSizeValue
  | DecompressionFailed DecompressionFailure

  | XDelta1DiffFailed XDelta1DiffCause
  | BSDiffDifferFailed BSDiffDifferCause

  -- | A parsed record's end position — offset plus payload length — lies past the variant's own wire-format ceiling.
  -- The 'ActualOffset' is that computed end; the 'MaxOffset' is the variant's maximum addressable end.
  | RecordExceedsAddressableRange FormatLabel ActionIndex ActualOffset MaxOffset

  -- | A parsed record's write end — offset plus payload length — exceeds 'maxBound' :: 'Int'.
  -- Both fit the carrier alone; only their sum overflows, so they are carried separately and the renderer adds them in 'Integer'.
  -- Distinct from 'RecordExceedsAddressableRange', whose ceiling is the format's own wire maximum, not slap's carrier.
  | RecordEndExceedsAddressableRange FormatLabel ActionIndex Offset Length

  -- | A parsed record carries a structurally malformed field — an RLE record whose run length is zero, say,
  -- or any other per-record value the spec or slap's strict discipline rejects.
  -- The 'ActionIndex' names the offending record; the 'FieldName' identifies which field was malformed.
  -- Distinct from 'NegativeSize' (a top-level header size was negative).
  | MalformedRecordField FormatLabel ActionIndex FieldName

  -- | Bytes after a recognized stream-closing trailer marker that match no post-trailer shape the format accepts.
  -- 'StandardIPS' is the one format that raises this: it accepts an empty post-@"EOF"@ trailer,
  -- a 3-byte truncation marker, or an EBP JSON metadata blob, and rejects anything else.
  -- The 'TrailerMarker' carries the marker bytes, so the renderer can name them without knowing the variant;
  -- the 'ActualLength' is the unrecognized slice's byte count.
  | UnrecognizedTrailer FormatLabel TrailerMarker ActualLength

  -- Parse: integrity
  | PatchCRCMismatch FormatLabel ExpectedCRC32 ActualCRC32
  | TrailingMagicMismatch FormatLabel ExpectedMagic ActualMagic

  -- Parse: content
  | UnknownFlag FormatLabel FieldName RawFlagByte
  | UnsupportedEncodingMethod FormatLabel EncodingMethodByte

  -- | A NINJA2 patch's PATCH_ENC byte (offset 6 of the fixed header) is not 0 (undeclared) or 1 (UTF-8).
  -- The NINJA2 spec defines no other values; slap refuses rather than fabricate a fallback encoding,
  -- because PATCH_ENC governs how every text field in the patch is decoded, and slap has no defined answer for an undefined value.
  | NINJA2UnrecognizedTextMode !Word8

  -- | A structurally malformed text field in a NINJA1 textual patch; 'NINJA1Malformation' enumerates the shapes.
  | MalformedNINJA1Content NINJA1Malformation

  | NINJA1BinaryMissingEOFFooter

  -- | A byte-parser failure surfaced from the named format's parser.
  | ParseError FormatLabel ByteParserError

  -- | The xdelta1 parser rejected a source-list shape canonical xdelta cannot emit: duplicated kinds, the reversed pair, or more than two sources.
  -- The list is an EDSIO length-prefixed sequence, so any count parses structurally;
  -- the 'XDelta1ShapeViolation' names which off-spec shape the patch carried.
  | UnsupportedXDelta1Shape XDelta1ShapeViolation

  -- | A source record's @isdata@ or @sequential@ flag byte held a value other than 0 or 1. Both are booleans,
  -- so 0 and 1 are the only defined bytes; slap refuses rather than guess at an undefined value (canonical xdelta reads any nonzero byte as set).
  -- The 'XDelta1SourceFlag' names which flag; the 'Word8' is the byte as read.
  | XDelta1NonBooleanSourceFlag XDelta1SourceFlag Word8

  -- | A VCDIFF wire shape slap refuses outright; 'VCDIFFShapeViolation' names it and has the story
  -- (one arm today, raised while 'Slap.VCDIFF.Parse' settles the header's code table).
  | UnsupportedVCDIFFShape VCDIFFShapeViolation

  -- | A VCDIFF custom code table failed structural validation;
  -- 'VCDIFFCodeTableMalformation' names which failure it was and where each is checked.
  | MalformedVCDIFFCodeTable VCDIFFCodeTableMalformation

  -- | Decoding a patch's custom code table failed. A custom table is an inner VCDIFF delta against the serialized default table (RFC 3284 §7),
  -- so the decode can fail in any way a whole patch's can; the 'SlapError' is that inner failure.
  | VCDIFFCustomCodeTableDecodeFailed !SlapError

  -- | An indicator byte set bits the format reserves for future definition. Deliberately not a 'MalformedVCDIFF' arm:
  -- malformed means slap understands a patch's claim and the claim is invalid,
  -- while a future-dialect patch could be well-formed, just unreadable here —
  -- the same decline as 'VCDIFFUnknownSecondaryCompressor'.
  -- The 'VCDIFFIndicatorKind' names which of the three indicators; the 'Word8' is the byte as read.
  | VCDIFFReservedIndicatorBits !VCDIFFIndicatorKind !Word8

  -- | A declared secondary-compressor id outside xdelta3's catalog (1 = DJW, 2 = LZMA, 16 = FGK — the only registry there is; RFC 3284 registered none).
  -- A future xdelta3 could define the id, so this is the 'VCDIFFReservedIndicatorBits' decline, not a malformation.
  | VCDIFFUnknownSecondaryCompressor !Word8

  -- | Wire bytes that parsed but violate the core semantics slap enforces; 'VCDIFFMalformation' names the specific failure.
  | MalformedVCDIFF VCDIFFMalformation

  -- | A patch mixes an RFC 3284 feature xdelta3 refuses (a VCD_TARGET window, a custom code table)
  -- with an xdelta3 extension the RFC never defined (a secondary compressor, an application header, a per-window Adler32).
  -- Each half is well-formed on its own; the patch belongs to neither dialect slap reads.
  -- The payload names one feature from each side, so the refusal is concrete on both.
  | VCDIFFRFCFeatureWithXDelta3Feature VCDIFFRFCFeature VCDIFFXDelta3Feature

  -- | A BSDiff patch's fixed-width header failed validation: a size field decoded negative,
  -- or the declared control and diff blocks overrun the patch body.
  -- The 'BSDiffHeaderMalformation' says which, and carries the offending values for the renderer.
  -- The check happens outside the byte parser: the header is read with a fixed-offset signed-magnitude helper, not the monadic primitives.
  | MalformedBSDiffHeader BSDiffHeaderMalformation

  -- | An APS-N64 header value that decodes to no known variant;
  -- 'APSN64HeaderMalformation' names which field rejected which byte.
  | MalformedAPSN64Header APSN64HeaderMalformation

  -- | A PPF4 Replace record appeared after an Append record. PPF4 is two-phase —
  -- every in-place Replace precedes every Append — and the reference patchers both emit and consume that order.
  -- The 'ActionIndex' names the offender.
  | PPF4ReplaceAfterAppend !ActionIndex

  -- | An xdelta1 instruction referenced a source index its own emitted list has no position for.
  -- Indices count positions in the list, so the valid set depends on the shape:
  -- the 'XDelta1SourceListShape' carries it, so the refusal names the indices this patch actually declared. The 'Int64' is the offending index.
  | XDelta1UnknownInstructionTarget !XDelta1SourceListShape !Int64

  -- | The patch expects one or both input files to be gzip streams (@FLAG_FROM_COMPRESSED@ \/ @FLAG_TO_COMPRESSED@).
  -- Canonical xdelta-1.x transparently decompresses gzip-magic inputs before diffing and re-compresses after apply;
  -- slap does not, and refuses rather than run the delta against the user's literal bytes and produce wrong output.
  | XDelta1InputPreCompressionUnsupported XDelta1GzipStreamInputs

  -- | An xdelta1 patch's envelope carries literal data bytes, but its source list has no data record to name them —
  -- no index reaches the segment, so no instruction could ever read it. Canonical emits an empty data area whenever it drops the data record,
  -- so a populated one means the envelope and source list disagree about what the patch carries.
  -- The 'ActualSize' is the decompressed segment's byte count.
  | XDelta1DanglingDataSegment ActualSize

  -- | An xdelta1 control segment decompressed to fewer bytes than a control body's fixed minimum.
  -- The 'RequiredLength' is that floor; the 'ActualLength' is what the segment held.
  | XDelta1ControlSegmentTooShort !RequiredLength !ActualLength

  -- | The data record's declared @length@ disagrees with the byte count of the data segment
  -- slap decompressed from the envelope. Both describe the same bytes, so slap refuses rather than pick a winner.
  -- The 'ExpectedSize' is the wire declaration; the 'ActualSize' is the segment's measure.
  | XDelta1DataRecordLengthMismatch ExpectedSize ActualSize

  -- | The data record's declared MD5 disagrees with the MD5 of the data-segment bytes —
  -- a patch disagreeing with itself, so parse-time fatal like 'PatchCRCMismatch':
  -- apply-time @--no-verify@ speaks to external bytes and does not downgrade this.
  -- Only checked under 'VerifyAgainstStoredMD5s'; a creator opt-out stores the sentinel MD5 and the comparison is skipped.
  -- The first 'MD5Hash' is the wire declaration; the second is computed from the segment bytes.
  | XDelta1DataRecordMD5Mismatch MD5Hash MD5Hash

  -- Apply
  | NegativeTargetSize FormatLabel FileSize
  | ApplyFailed FormatLabel ApplyError

  -- Undo
  | UndoFailed FormatLabel ApplyError

  -- Create / Encode

  -- | A create path refused this (source, target) pair; the 'UnencodeabilityReason' says why.
  | UnencodeablePair FormatLabel UnencodeabilityReason
  | NarrowingError !NarrowingFailure

  -- | A create-path input (source or target) names more bytes than slap can address.
  -- slap threads every size and offset through a signed 'Int', so its true ceiling is 'maxBound' :: 'Int', about 9 EB on a 64-bit host.
  -- A wire size field wider than the carrier (a full 64-bit length) can name a file past that ceiling;
  -- rather than wrap or truncate it through 'fromIntegral', slap declines here.
  | FileExceedsAddressableRange FormatLabel ActualSize MaxAddressableSize

  -- | A VCDIFF create's (source, target) pair spans more bytes than slap can address at once.
  -- Unlike the sparse formats' relative offsets, a VCDIFF COPY addresses the superstring @U = source ++ target@ absolutely,
  -- so the quantity slap's 'Int' must carry is the pair's combined size (plus the matcher's two sentinels) —
  -- and a pair whose sum exceeds 'maxBound' :: 'Int' would name positions the carrier cannot hold.
  -- The pair-wise sibling of 'FileExceedsAddressableRange': each size fits an 'Int' on its own (a ByteString's length is one),
  -- and it is only their sum that does not, so the sizes are carried separately and the renderer adds them in 'Integer',
  -- the way 'ApplyOutputExceedsAddressableRange' does.
  -- Raised by 'Slap.VCDIFF.Create.rejectUnaddressablePair'.
  | VCDIFFPairExceedsAddressableRange SourceFileSize TargetFileSize MaxAddressableSize

  -- | A record's offset lands on the format's trailer sentinel and the encoder cannot shift it back:
  -- the source bytes for the shift-and-prepend fix are absent (source-less conversion),
  -- the source is shorter than the preceding-byte index,
  -- or the sentinel sits at offset @0@ and there is no preceding byte to consume.
  -- The failure mode of 'Slap.IPS.Create.resolveSentinelCollisions'.
  | SentinelCollisionUnfixable FormatLabel SentinelOffset

  -- | PPF2 mandates a 1024-byte validation block sampled from source offset 0x9320,
  -- so a source shorter than 0x9720 bytes cannot supply one — a boundary the format never gave a defined behavior.
  -- The 'ExpectedSize' is that 0x9720-byte minimum.
  | SourceTooSmallForPPF2Validation FormatLabel ActualSize ExpectedSize

  | FieldTooLong FormatLabel FieldName EncodedLength MaxLength

  -- Convert
  | MissingRequiredField FormatLabel PatchField

  -- | The contract layer's refusal when the source patch carries fields that affect apply output ('Slap.PatchField.affectsApplyOutput')
  -- and that the target format has no wire home for — dropping them silently would change what the converted patch produces,
  -- so the conversion is refused, not warned.
  -- Each offending field is paired with the formats that do preserve it, so the renderer can point at a target that would work.
  | ApplyOutputFieldsWouldBeDropped FormatLabel [(PatchField, [FormatLabel])]

  | DiffRequiresSource FormatLabel

  -- | Converting to PPF4 without the original ROM.
  -- PPF4 splits records into in-place Replace and appended-bytes Append by where each falls against the source's size,
  -- and a source-less conversion has no source size to split by. @--with INPUT@ is the way out.
  | PPF4ConvertRequiresSource FormatLabel

  -- | The user set metadata fields via CLI flags that the target format has no wire home for. Surfaced before any IO touches their files.
  | MetadataFieldRejected (NonEmpty MetadataField) FormatLabel

  -- | The user opted into 'Constraint's the target format cannot honor — same shape and rationale as 'MetadataFieldRejected'.
  | ConstraintNotSupported (NonEmpty Constraint) FormatLabel

  -- | The user toggled dialect axes that the target format (for convert, neither side of the chain) admits —
  -- same shape and rationale as 'MetadataFieldRejected'.
  | DialectNotSupported (NonEmpty Dialect) FormatLabel

  -- | The user asked @slap convert@ to retag a patch's ROM type across platforms — the source patch declares one platform,
  -- @--rom-type@ names another. The records were built against the carried platform's normalized form,
  -- so a different tag would tell appliers to normalize the input differently, and the records would land on the wrong bytes.
  -- The one retag convert honors is the same-layout sibling pair — SMS and Game Gear, whose procedures are identical.
  | RomTypeRetagRejected CarriedRomType RequestedRomType

  -- | Converting a non-xdelta1 patch to xdelta1 without @--from-name@ \/ @--to-name@.
  -- xdelta1's header carries two free-form display labels no other format has an equivalent of,
  -- so a cross-format convert has nothing to inherit, and slap refuses to fabricate placeholders.
  -- The 'FormatLabel' is the source format.
  | XDelta1ConvertRequiresNames FormatLabel

  -- | The user selected a secondary compressor slap decodes but cannot yet encode — FGK today.
  -- 'Slap.VCDIFF.SecondaryCompression.encodableSectionCompressor' is the registry this refusal reads.
  -- Distinct from 'MetadataFieldRejected': the flag and the name are both understood; what is missing is slap's own encoder.
  | XDelta3CompressorEncodingUnsupported !CompressionAlgorithm

  -- | The IPS create gate refused a truncation marker whose declared target size fails SNESTool's @(size & 0xFFF) == 0x200@ shape filter.
  -- Only fires when the user opted into 'Slap.IPS.Types.RequireSMCShapedTruncation'.
  | TruncationViolatesSMCShape !FileSize

  -- | A verification mismatch the user did not @--no-verify@ away, so it is fatal rather than advisory.
  -- That the payload is one of 'VerificationCRCMismatch', 'VerificationHashMismatch',
  -- 'VerificationAdler32Mismatch', or 'VerificationFileSizeMismatch' is a documented invariant, not a type-level one.
  | VerificationFatal SlapAdvisory

  deriving (Show, Eq)

----------------------------------------------------------------------------
-- BPSMetadataDivergence
----------------------------------------------------------------------------

-- | How a BPS patch's metadata blob diverged from the spec-recommended UTF-8 XML, carried by 'BPSMetadataNonConformant'.
data BPSMetadataDivergence
  = MetadataIsNotUTF8
    -- ^ The bytes do not decode as UTF-8 at all.
  | MetadataIsValidUTF8ButNonText
    -- ^ Valid UTF-8 carrying control or format codepoints — not the plain text the field is meant to hold.
  deriving (Eq, Show)

----------------------------------------------------------------------------
-- SlapAdvisory
----------------------------------------------------------------------------

-- | A non-halting status item — warning-severity ("you may want to know") or note-severity ("informational"),
-- projected per constructor by 'slapAdvisorySeverity'.
data SlapAdvisory

  -- Patch quality
  = EmptyPatch FormatLabel EmptyUnit
  | NoEOFMarker FormatLabel

  -- Header flags
  -- | Note: @--remove-header@ dropped the console's header from the input before applying.
  | InputHeaderRemoved ConsoleHeader
  -- | Note: @--add-header@ prepended a blank header to the input before applying.
  | InputHeaderAdded ConsoleHeader

  -- | A PPF patch's apply produced an output longer than the source; slap applies it and remarks.
  -- The 'FileSize' is the source's length; the 'Length' is the overshoot.
  | PPFApplyGrewPastSource FormatLabel FileSize Length

  -- | An IPS-family RLE record with a zero run length, accepted verbatim as a no-op.
  -- The spec does not speak to the case, and slap's own encoder never emits it.
  | ZeroCountRLERecord FormatLabel ActionIndex

  -- | A BPS signed-delta varint carried @0x81@, sign-magnitude "negative zero" — the same zero delta as the canonical @0x80@,
  -- but no canonical encoder writes it, so it signals a non-canonical producer or transit corruption. Fires once per patch.
  -- See @docs/bps/questions.md@, "two encodings for zero-delta".
  | NegativeZeroInBPS

  -- | A VCDIFF varint in overlong form: leading zero-groups pad it longer than the value needs.
  -- Base-128 admits it and xd3 accepts it, so slap does too and remarks; slap's own encoder emits only the canonical form.
  -- The payload is the offending value.
  | NonCanonicalVCDIFFVarint Int64

  -- | At least one pair of records in an IPS-family patch writes overlapping target regions.
  -- Legal and well-defined (later writes win), but unusual enough to flag.
  -- Per-pair detail is deliberately absent: a mutually-overlapping cluster of @k@ records would emit @k*(k-1)\/2@ near-identical lines,
  -- and the reader's question is "does this patch overlap writes", not "which pairs".
  | OverlappingRecords FormatLabel OverlapCount

  -- | An IPS-family record carries a smaller offset than its predecessor. slap applies in wire order, so the output is still correct,
  -- but well-formed patches are sorted; one report per parse is enough, so only the first out-of-order pair fires.
  -- The 'ActionIndex' names the later record of that pair.
  | UnsortedRecords FormatLabel ActionIndex

  -- | An IPS32 patch had trailing bytes past the @"EEOF"@ marker; slap drops the slice, warns, and proceeds.
  -- 'StandardIPS' has three attested post-EOF shapes and rejects anything else ('UnrecognizedTrailer');
  -- IPS32 has none, so there is no shape to hold a trailer against, and a lenient drop is the useful choice.
  -- The 'Length' is the byte count dropped.
  | IPS32TrailingBytes FormatLabel Length

  -- | Bytes after the last window matching the one trailing shape slap recognizes: four @0xFF@ marker bytes, then nothing but zero padding —
  -- a harmless trailer some patches carry. VCDIFF has no window count, total-size field, or footer, so it never says what trailing bytes mean;
  -- xdelta3's applier writes the correct output and then errors on this tail, while its printhdr ignores it.
  -- slap consumes exactly this shape and says what it saw; any other trailing bytes keep framing as a window and failing as one.
  -- The 'Length' is the remnant's full byte count, marker included.
  | VCDIFFTrailingRemnant !Length

  -- | A VCD_TARGET window declares a zero-length source segment — a window naming a copy source it cannot read a byte from.
  -- Legal, and the only shape a first-window VCD_TARGET can take, there being no earlier output to point at; pointless everywhere else.
  -- slap applies the window and remarks.
  | VCDIFFEmptyTargetWindowSegment ActionIndex

  -- | An xdelta3 patch declares an application header of zero bytes: the VCD_APPHEADER bit set over a length varint of zero.
  -- Legal, just quiet; slap parses on and remarks.
  | VCDIFFEmptyApplicationHeader

  -- | A multi-window patch's window sizes are not a run of one size and then a remainder — the shape every encoder slap knows of emits.
  -- Window sizing is the encoder's own affair (RFC 3284 asks a decoder for no knowledge of the window selection algorithm),
  -- so the patch is valid; slap applies it and remarks.
  | VCDIFFUnevenWindowSizes

  -- | An xdelta3 create was asked (@--window-size@) for windows larger than the widespread xdelta3 3.0.11 build's compiled ceiling,
  -- which that build refuses to decode past.
  -- The patch is conformant, and slap and later xdelta3 builds read it fine; the note names the one decoder that will decline it.
  -- The 'Length' is the requested window size; the 'MaxLength' is that build's ceiling.
  | XDelta3WindowSizePastReferenceDecoder Length MaxLength

  -- | A custom code table holds entries that are NOOP followed by NOOP — entries that do nothing at all.
  -- Legal (RFC 3284 §5.4 lets NOOP fill either half), and absent from the default table,
  -- so the patch shipped a table deliberately shaped this way. slap builds the table, applies the patch, and remarks.
  -- The 'Int' is how many of the 256 entries are NOOP+NOOP.
  | VCDIFFCustomTableNoopNoopEntries !Int

  -- | Bytes at the end of an APS-N64 patch too few to begin another record (a record header is five bytes).
  -- The reference applier's next record read returns short and its loop stops, silently; slap stops and says so.
  -- The 'Length' is the fragment's byte count (one to four).
  | APSN64TrailingFragment !Length

  -- | Bytes at the end of a BSDiff control stream too few to form another
  -- instruction (one is 24 bytes: three 8-byte sign-magnitude values).
  -- An applier that reads triples on demand stops when the target fills and never sees such a tail;
  -- slap decodes the whole stream up front, drops the fragment, and warns —
  -- the tail sits inside a bzip2-compressed section, so it is the producer's doing, not transit damage.
  -- The 'Length' is the fragment's byte count (1 to 23).
  | BSDiffTrailingControlFragment !Length

  -- | An EBP patch's post-@"EOF"@ trailer began with @{@ — the shape signature of an EBPatcher JSON blob — but was not valid JSON,
  -- or its root was not an object. The IPS records underneath are unaffected; apply and convert proceed with empty metadata.
  | EBPMetadataMalformed FormatLabel

  -- | A BPS patch's embedded metadata is not the spec-recommended UTF-8 XML, which the spec itself permits ("literally anything" is legal),
  -- so this is a spec-valid oddity, not an error: slap carries the blob byte-exact on every payload path and only remarks.
  -- The 'BPSMetadataDivergence' names how it diverged; the 'Length' is the blob's byte count.
  | BPSMetadataNonConformant FormatLabel BPSMetadataDivergence Length

  -- | A 'StandardIPS' post-EOF truncation marker declared a target size below the natural size, and slap honored it.
  -- Surfaces the truncation even when no records cross the boundary; 'IPSRecordsClippedByMarker' fires when they do.
  | IPSTruncationMarkerHonored FormatLabel DeclaredTargetSize NaturalTargetSize

  -- | Records' write regions extended past the honored truncation boundary and were clipped to fit.
  -- An aggregate count in the style of 'OverlappingRecords'; the 'ActionIndex' names the first crossing record in wire order.
  | IPSRecordsClippedByMarker FormatLabel ClippedRecordCount ActionIndex MarkerOvershootBytes

  -- | A 'StandardIPS' truncation marker declared a target size above the natural size, which would grow the output via zero-fill;
  -- per the docs/ips/questions.md ruling, slap ignores the marker for sizing and says so.
  | IPSTruncationMarkerIgnored FormatLabel DeclaredTargetSize NaturalTargetSize

  -- | An xdelta 1.1.x patch has @FLAG_NO_VERIFY@ set, but a stored MD5 slot does not hold 'Slap.XDelta1.Types.xdelta1EmptyInputMD5Sentinel'.
  -- Canonical xdelta writes that sentinel into every slot under @--noverify@,
  -- so divergent bytes mean a non-canonical producer or transit corruption that left the flag intact.
  -- The flag is honored regardless; the note is purely informational.
  | XDelta1NoVerifyWithDivergentSentinel

  -- | A source-less patch (@[data]@ or @[]@) was applied: its output is fully determined by the patch, so the handed input was never read.
  -- Canonical says so at create time ("patch will apply without it"); slap says it at apply, where the unused argument is the surprise.
  -- The 'XDelta1SourcelessShape' names which shape it is.
  | XDelta1InputFileNotConsulted !XDelta1SourcelessShape

  -- | An xdelta 1.1.x data-record's @name@ field is not the canonical @"(patch data)"@ ('xdelta1DataRecordName').
  -- The data-record names the patch's inline literal bytes, not an external file, so the field is purely a display label;
  -- slap honors the wire bytes and notes the non-canonical producer. The 'ByteString' is what was read.
  | XDelta1DataRecordNameDiverges !ByteString

  -- Conversion: dropped fields
  | FieldDropped PatchField DroppedValue
  | UndoDataDropped UndoRecordCount
  | ValidationBlockDropped
  -- | A BPS metadata blob with no destination channel in the target format.
  -- The 'Length' is the blob's byte count.
  | MetadataDropped Length

  -- Conversion: defaults assumed
  | DefaultRomType FormatLabel
  | DefaultImageType FormatLabel
  | IncludingUndoByDefault
  | IncludingVerificationByDefault
  | SourceHashesMissing FormatLabel

  -- Encoding
  | FieldTruncated FormatLabel FieldName OriginalLength TruncatedLength

  -- | A text field's wire bytes held sequences the declared encoding cannot decode;
  -- slap substituted U+FFFD for each and parsed on. The 'SubstitutionCount' is how many.
  | FieldDecodedSubstituted FormatLabel FieldName SubstitutionCount

  -- | The encode-side sibling of 'FieldDecodedSubstituted': source codepoints the target encoding cannot represent,
  -- each replaced with the encoding's replacement character (U+FFFD where representable, @\'?\'@ otherwise).
  | FieldEncodedSubstituted FormatLabel FieldName SubstitutionCount

  -- | A fixed-width text field carried real text past its first NUL terminator. slap keeps the content up to the terminator,
  -- sets the tail aside, and re-pads canonically on any re-encode; the 'Length' is how many characters were set aside.
  -- (A field merely padded with the "wrong" byte — zeros where the format spaces — leaves nothing past a NUL and is not flagged.)
  | FieldContentPastEnd FormatLabel FieldName Length

  -- Platform conversion
  --
  -- | A requested (@--rom-type@) or inherited platform the target format
  -- has no wire encoding for; slap writes the format's Raw placeholder
  -- instead and surfaces the change.
  | PlatformNotAvailable FormatLabel PlatformType
  -- | NINJA2's combined SMS/Game Gear slot is ambiguous on convert to a sibling format: slap defaults to SMS.
  -- The user can override with @--rom-type gg@.
  | NINJA2SMSGameGearAmbiguity

  -- NINJA rom-type handling
  --
  -- | A non-Raw NINJA ROM type the spec defines no normalization for: slap
  -- has nothing to run and applies the patch as-is.
  | RomTypeWithoutNormalization FormatLabel PlatformType
  -- | A NINJA patch's ROM-type byte is not one the format names. slap keeps
  -- the byte, applies the records unchanged, and cannot say what
  -- preprocessing it implies.
  | UnrecognizedRomType FormatLabel Word8
  -- | The textual sibling of 'UnrecognizedRomType': a NINJA1 textual patch
  -- named a ROM type the format does not define, carried as the name.
  | UnrecognizedRomTypeName FormatLabel Text

  -- ROM-image normalization ('Slap.Normalize')
  --
  -- | Note: the ROM type's normalization procedure changed an image on its way into a diff or an apply.
  -- One advisory per step, so a ROM that is both header-stripped and deinterleaved narrates both.
  | RomImageNormalized FormatLabel NormalizedImageRole PlatformType NormalizationStep
  -- | Note: content the normalization set aside was returned to the output after the apply —
  -- a header re-prepended, or patched data reinserted into its UNIF container.
  | RomImageContentRestored FormatLabel RestoredContent
  -- | The image matches none of the shapes the ROM type's procedure recognizes.
  -- Where the reference tool would refuse outright, slap takes the image as-is.
  | RomImageShapeUnrecognized FormatLabel NormalizedImageRole PlatformType
  -- | The image matched one of the ROM type's shapes, but its structure makes the transform impossible —
  -- the 'NormalizationSkipReason' names how. The image is taken as-is.
  | RomImageNormalizationSkipped FormatLabel NormalizedImageRole PlatformType NormalizationSkipReason
  -- | The ROM type has a normalization procedure but the patch carries no source checksum,
  -- so nothing can confirm the normalized input is what it was built against. slap normalizes and proceeds;
  -- the absent checksum is the creator's omission, not a reason to be stricter than the format.
  | RomTypeNormalizationUnconfirmable FormatLabel PlatformType
  -- | The patched data's byte count no longer matches what the original UNIF container's PRG and CHR chunks hold,
  -- so the data cannot be reinserted and the output is left in the merged (headerless) form.
  -- The 'ExpectedSize' is the container's chunk total; the 'ActualSize' is the patched data's length.
  | UNIFContainerNotRebuilt FormatLabel ExpectedSize ActualSize
  -- | The source ROM's byte-order does not match the image format an APS-N64 Type-1 patch declares.
  -- Gated by the verification policy, so @--no-verify@ overrides.
  | APSN64ImageFormatMismatch
  -- | Converting a source APS-N64 Type-1 patch:
  -- slap writes only Type-0, so its Type-1 N64 header (image format, cart ID, country, CRC) is not carried into the converted patch.
  | APSN64Type1HeaderDropped

  -- Apply: out-of-bounds block clipping
  | ApplyOOBBlocksSkipped FormatLabel ApplyDirection OOBBlockCount ActionIndex OOBOvershootBytes FileSize

  -- Format-specific
  --
  -- | A NINJA1 textual subformat was converted to its binary peer at parse time;
  -- the wire bytes still describe the same patch, but the in-memory shape is the binary one.
  | SubformatConverted NINJA1SubformatConversion

  -- Verification: source/target integrity check mismatches
  --
  -- The first four kinds are fatal-class: under 'EnforceVerification' they promote to 'VerificationFatal',
  -- and @--no-verify@ demotes them to warnings.
  -- The other four are advisory by design (block CRC16, PPF validation block, file-size advisory, source-bytes comparison)
  -- and always emit as warnings — @--no-verify@ does not silence them;
  -- the flag's contract is the fatal-vs-warning axis for the fatal-class checks only.
  | VerificationCRCMismatch       VerificationSide ExpectedCRC32 ActualCRC32
  | VerificationHashMismatch      VerificationSide HashAlgorithm
  | VerificationAdler32Mismatch   Offset ExpectedAdler32 ActualAdler32
  | VerificationFileSizeMismatch  VerificationSide ExpectedSize ActualSize
  | VerificationBlockCRC16Mismatch VerificationSide Offset
  | VerificationPPFBlockMismatch  Offset
  | VerificationFileSizeAdvisory  ExpectedSize ActualSize
  | VerificationSourceBytesMismatch ByteCheckLabel Offset

  -- | The patch declares no verification data at the format level — xdelta1's @FLAG_NO_VERIFY@ bit, PPF3's absent validation block.
  -- slap honors the declaration and skips verification;
  -- the warning reports that nothing attests the output matches the creator's intent.
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
data Parsed value = Parsed !value ![SlapAdvisory]
  deriving (Show)

----------------------------------------------------------------------------
-- Outcome
----------------------------------------------------------------------------

-- | The value and advisory channels of an apply or undo operation — the apply-side companion of 'CreateResult' and 'Parsed'.
-- The polymorphic parameter lets one envelope serve both apply (carrying 'OutputFileContents') and undo (carrying 'InputFileContents').
data Outcome a = Outcome
  { outcomeValue      :: !a
  , outcomeAdvisories :: ![SlapAdvisory]
  }
  deriving (Eq, Show, Functor)

-- | Wrap an advisory-free value in the 'Outcome' envelope.
noAdvisories :: a -> Outcome a
noAdvisories value = Outcome value []

----------------------------------------------------------------------------
-- OverlapCount — payload of the OverlappingRecords warning
----------------------------------------------------------------------------

-- | The number of overlapping record pairs an IPS-family parse found.
-- Never zero: 'OverlappingRecords' only fires when at least one pair exists.
newtype OverlapCount = OverlapCount { unOverlapCount :: Int }
  deriving (Eq, Ord, Show)

-- | The number of IPS records clipped to fit a honored truncation marker.
-- Never zero: 'IPSRecordsClippedByMarker' only fires when at least one record crossed the boundary.
newtype ClippedRecordCount = ClippedRecordCount { unClippedRecordCount :: Int }
  deriving (Eq, Ord, Show)

-- | The number of UPS blocks whose write region extends past the declared target file size.
-- Never zero: 'ApplyOOBBlocksSkipped' only fires when at least one block was out of bounds.
newtype OOBBlockCount = OOBBlockCount { unOOBBlockCount :: Int }
  deriving (Eq, Ord, Show)

-- | The number of undo records dropped when converting to a target format with no undo representation.
-- Emitted only when the source actually carried undo records.
newtype UndoRecordCount = UndoRecordCount { unUndoRecordCount :: Int }
  deriving (Eq, Ord, Show)

-- | The total byte length lost across all records clipped by an honored IPS truncation marker — per-record overshoots, summed.
-- 'Semigroup' and 'Monoid' pass through to 'Length' so accumulating walks can use '<>' and 'mempty'.
newtype MarkerOvershootBytes = MarkerOvershootBytes { unMarkerOvershootBytes :: Length }
  deriving (Eq, Ord, Show, Semigroup, Monoid)

-- | The UPS counterpart of 'MarkerOvershootBytes': the total byte length lost across blocks that extended past the declared target size.
newtype OOBOvershootBytes = OOBOvershootBytes { unOOBOvershootBytes :: Length }
  deriving (Eq, Ord, Show, Semigroup, Monoid)

----------------------------------------------------------------------------
-- ApplyDirection — which direction an apply/undo operation ran in
----------------------------------------------------------------------------

-- | Which direction an apply/undo operation ran in.
-- Tagged onto advisories that describe direction-dependent observations (such as 'ApplyOOBBlocksSkipped',
-- whose count and overshoot are measured against the output the operation actually wrote: target_size forward, source_size reverse).
--
-- Not the CLI subcommand the user typed: @slap apply@ and @slap undo@ drive the two directions one-to-one,
-- but direction lives at the Format layer (each format's apply/undo functions know which they implement),
-- while subcommand selection lives at the Entry-point layer ('app/Main.hs').
data ApplyDirection
  = Forward  -- ^ The natural-direction operation: 'applyUPS', 'applyBPS', etc.
  | Reverse  -- ^ The inverse operation: 'undoUPS', 'undoBPS', etc.
  deriving (Eq, Show)

-- | The user-facing verb for each direction: @"apply"@ and @"undo"@, the CLI's own words, not "forward" and "reverse".
directionVerb :: ApplyDirection -> Text
directionVerb Forward = "apply"
directionVerb Reverse = "undo"

----------------------------------------------------------------------------
-- Verification: shared payload types
----------------------------------------------------------------------------

-- | Which side of the apply a verification check fired against.
-- The constructors keep slap's source\/target vocabulary; the rendered labels track the CLI's input\/output.
data VerificationSide = SourceSide | TargetSide
  deriving (Show, Eq)

verificationSideLabel :: VerificationSide -> Text
verificationSideLabel SourceSide = "input"
verificationSideLabel TargetSide = "output"

data HashAlgorithm = MD5 | SHA1
  deriving (Show, Eq)

hashAlgorithmLabel :: HashAlgorithm -> Text
hashAlgorithmLabel MD5  = "MD5"
hashAlgorithmLabel SHA1 = "SHA1"

-- | An Adler32 value a patch declared or stored — 'ExpectedCRC32''s peer.
newtype ExpectedAdler32 = ExpectedAdler32 { unExpectedAdler32 :: Adler32 }
  deriving (Show, Eq)

-- | An Adler32 value computed from the actual data — 'ActualCRC32''s peer.
newtype ActualAdler32 = ActualAdler32 { unActualAdler32 :: Adler32 }
  deriving (Show, Eq)

-- | The label of an advisory byte-range check ("N64 cart ID", "N64 country", "N64 CRC"), for 'VerificationSourceBytesMismatch'.
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

renderByteParserError (ByteParserFieldExceedsAddressableRange recordIndex field) =
  "record " <> renderAsText (unActionIndex recordIndex)
  <> ": " <> fieldNameLabel field <> " past the "
  <> renderAsText (maxBound :: Int) <> "-byte limit slap can address"

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

renderByteParserError (ByteParserXDelta1UnexpectedControlTypeTag observedTag) =
  "xdelta1 control segment opens with type tag 0x" <> Text.pack (showHex observedTag "")
  <> ", not ST_XdeltaControl; canonical's EDSIO reader rejects an unregistered library number "
  <> "(the tag's low byte) with \"Unregistered library: N\""

renderByteParserError (ByteParserUnexpectedDoPatternFailure message) =
  "internal: do-pattern match failed in slap's parser: " <> Text.pack message

----------------------------------------------------------------------------
-- renderSlapError
----------------------------------------------------------------------------

renderUnwrapError :: FilePath -> ArchiveFormat -> UnwrapError -> Text
renderUnwrapError path format NoToolForArchive =
  archiveFormatName format <> " archive " <> pathText path
    <> " needs " <> renderToolAlternatives (toolsFor format) <> " on PATH to unwrap; none were found."
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

renderSlapError (UnwritableOutputFile path reason) =
  "cannot write " <> Text.pack path <> ": " <> Text.pack reason

renderSlapError (NothingToExtract path subject) =
  "no " <> subjectText <> " to extract to " <> Text.pack path
  where subjectText = case subject of
          EmbeddedMetadataSubject -> "embedded metadata"
          FileIdDizSubject        -> "FILE_ID.DIZ"

renderSlapError (ArchiveUnwrapFailed path format unwrapError) =
  renderUnwrapError path format unwrapError

renderSlapError (HeaderRemovalExceedsInput console (ActualSize inputSize)) =
  "cannot remove a " <> renderAsText (unLength (consoleHeaderLength console)) <> "-byte "
  <> consoleHeaderName console <> " header from a "
  <> renderAsText (unFileSize inputSize) <> "-byte input"

renderSlapError HeaderDirectiveRequiresSeparateOutput =
  "--add-header and --remove-header don't combine with --in-place: the output would replace the original with a differently-shaped file"

renderSlapError UnrecognizedFormat =
  "unknown patch format"

renderSlapError (AmbiguousDetection labels) =
  "ambiguous format: could be "
  <> commaList (map formatLabelName labels)

renderSlapError (InputTooShort label (RequiredLength needed) (ActualLength actual)) =
  formatLabelName label <> ": input too short (need "
  <> renderAsText (unLength needed) <> " bytes, have "
  <> renderAsText (unLength actual) <> ")"

renderSlapError (XDelta1ControlSegmentTooShort (RequiredLength needed) (ActualLength actual)) =
  formatLabelName LabelXDelta1 <> ": control segment too short (need "
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

renderSlapError NINJA1BinaryMissingEOFFooter =
  formatLabelName LabelNINJA1 <> ": binary patch ends without the EOF footer"

renderSlapError (NegativeSize label name (ParsedSizeValue value)) =
  formatLabelName label <> ": negative "
  <> fieldNameLabel name <> ": " <> renderAsText value

renderSlapError (DecompressionFailed failure) =
  renderDecompressionFailure failure

renderSlapError (XDelta1DiffFailed (XDelta1DiffCause causeMessage)) =
  "xdelta1 differ failed: " <> causeMessage

renderSlapError (BSDiffDifferFailed (BSDiffDifferCause causeMessage)) =
  "bsdiff differ failed: " <> causeMessage

renderSlapError (RecordExceedsAddressableRange label recordIndex (ActualOffset endOffset) (MaxOffset maxEndOffset)) =
  formatLabelName label <> ": record " <> renderAsText (unActionIndex recordIndex)
  <> " ends at offset 0x" <> renderHexAsText (unOffset endOffset)
  <> ", exceeding the variant's maximum addressable end 0x"
  <> renderHexAsText (unOffset maxEndOffset)

renderSlapError (RecordEndExceedsAddressableRange label recordIndex offset payloadLength) =
  formatLabelName label <> ": record " <> renderAsText (unActionIndex recordIndex)
  <> " writes at offset " <> renderAsText (unOffset offset)
  <> " plus " <> renderAsText (unLength payloadLength)
  <> " bytes, reaching "
  <> renderAsText (toInteger (unOffset offset) + toInteger (unLength payloadLength))
  <> " — past the " <> renderAsText (maxBound :: Int)
  <> "-byte limit slap can address"

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
    NINJA1UnaddressableOffsetInTextRecord (OffsetTokenText t) ->
      "offset " <> t <> " in text record is past the "
      <> renderAsText (maxBound :: Int) <> "-byte limit slap can address"
    NINJA1MalformedChecksum field (ChecksumTokenText t) ->
      fieldNameLabel field <> " token \"" <> t <> "\" is neither unk nor a valid hex checksum"
    NINJA1MalformedTextRecord       (LineText line)  -> "malformed text record: " <> line

renderSlapError (ParseError label parserError) =
  formatLabelName label <> ": " <> renderByteParserError parserError

renderSlapError (UnsupportedXDelta1Shape violation) =
  formatLabelName LabelXDelta1
  <> ": source list is " <> describeViolation violation
  <> ", a shape canonical xdelta cannot emit"
  <> " (it writes the data segment and the from-file source, dropping whichever its"
  <> " instructions never cite, so [data, file], [data], [file], and [] are the only"
  <> " source lists a patch can carry)"
  where
    describeViolation XDelta1TwoDataSources        = "[data, data]"
    describeViolation XDelta1ReversedDataFileOrder = "[file, data]"
    describeViolation XDelta1TwoFileSources        = "[file, file]"
    describeViolation (XDelta1TooManySources n)    = renderAsText n <> " sources"

renderSlapError (XDelta1NonBooleanSourceFlag flag byteValue) =
  formatLabelName LabelXDelta1 <> ": " <> case flag of
    XDelta1SourceKindFlag ->
      "isdata is 0x" <> padHex 2 byteValue
      <> " (0 marks a file source, 1 marks patch data; nothing defines 0x" <> padHex 2 byteValue <> ")"
    XDelta1SourceOffsetModeFlag ->
      "sequential is 0x" <> padHex 2 byteValue
      <> " (0 marks absolute offsets, 1 marks sequential offsets; nothing defines 0x" <> padHex 2 byteValue <> ")"

renderSlapError (UnsupportedVCDIFFShape violation) =
  formatLabelName LabelVCDIFF <> ": " <> case violation of
    VCDIFFNestedCustomCodeTable ->
      "nested custom code tables are not allowed (RFC 3284 §7c)"

renderSlapError (VCDIFFCustomCodeTableDecodeFailed innerError) =
  -- No format-label prefix of its own: the inner error already carries one.
  "while decoding the custom code table: " <> renderSlapError innerError

renderSlapError (VCDIFFRFCFeatureWithXDelta3Feature rfcFeature xdelta3Feature) =
  formatLabelName LabelVCDIFF
  <> ": " <> rfcFeaturePhrase rfcFeature <> " (an RFC 3284 feature) together with "
  <> xdelta3FeaturePhrase xdelta3Feature
  <> " (an xdelta3 extension) — neither a conformant RFC-3284 patch nor"
  <> " an xdelta3 patch, and slap applies only conformant patches of either dialect"
  where
    rfcFeaturePhrase RFCFeatureTargetWindow    = "a VCD_TARGET window"
    rfcFeaturePhrase RFCFeatureCustomCodeTable = "a custom code table"
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
    VCDIFFSectionUnconsumedBytes section (Length leftover) ->
      "window's instructions finished with " <> renderAsText leftover
      <> plural leftover " byte" " bytes"
      <> " of its " <> vcdiffSectionName section <> " section unconsumed"
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
    VCDIFFCodeTableCopyModeOutOfRange mode highestValidMode ->
      "code table names COPY address mode " <> renderAsText mode
      <> ", but the declared caches reach only mode " <> renderAsText highestValidMode

renderSlapError (MalformedBSDiffHeader (BSDiffNegativeHeaderSizes control diff target)) =
  formatLabelName LabelBSDiff
  <> ": invalid header (negative size: control="
  <> renderAsText (unControlSectionSize control) <> ", diff=" <> renderAsText (unDiffSectionSize diff)
  <> ", target=" <> renderAsText (unTargetSectionSize target) <> ")"

renderSlapError (MalformedBSDiffHeader (BSDiffControlOverrunsPatch overrunBytes)) =
  formatLabelName LabelBSDiff
  <> ": invalid header (the control block's declared size reaches "
  <> renderAsText overrunBytes <> plural (fromIntegral overrunBytes) " byte" " bytes"
  <> " past the end of the patch)"

renderSlapError (MalformedBSDiffHeader (BSDiffDiffOverrunsPatch overrunBytes)) =
  formatLabelName LabelBSDiff
  <> ": invalid header (the diff block's declared size reaches "
  <> renderAsText overrunBytes <> plural (fromIntegral overrunBytes) " byte" " bytes"
  <> " past the end of the patch)"

renderSlapError (MalformedAPSN64Header malformation) =
  formatLabelName LabelAPSN64 <> ": " <> case malformation of
    APSN64UnknownPatchType byte    -> "unknown patch type: " <> renderAsText byte
    APSN64UnsupportedEncoding byte -> "unsupported encoding method: " <> renderAsText byte

renderSlapError (PPF4ReplaceAfterAppend recordIndex) =
  formatLabelName LabelPPF4 <> ": record "
  <> renderAsText (unActionIndex recordIndex)
  <> " is a Replace after an Append; PPF4 is two-phase — once an Append"
  <> " record appears, every subsequent record must also be Append"

renderSlapError (XDelta1UnknownInstructionTarget listShape wireIndex) =
  formatLabelName LabelXDelta1
  <> ": instruction references source index " <> renderAsText wireIndex
  <> "; " <> case listShape of
       SourceListDataAndFile ->
         "the patch's source list is [data segment, file source], so the valid indices are 0 and 1"
       SourceListDataOnly ->
         "the patch's source list holds only the data segment, at index 0"
       SourceListFileOnly ->
         "the patch's source list holds only the file source, at index 0"
       SourceListEmpty ->
         "the patch's source list is empty, so no instruction may reference a source"

renderSlapError (XDelta1DanglingDataSegment (ActualSize segmentSize)) =
  formatLabelName LabelXDelta1
  <> ": the patch carries " <> renderAsText (unFileSize segmentSize)
  <> " bytes of literal data, but its source list has no data record to name them;"
  <> " no instruction could ever read those bytes"

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

renderSlapError (VCDIFFPairExceedsAddressableRange
                   (SourceFileSize sourceSize) (TargetFileSize targetSize) (MaxAddressableSize maxSize)) =
  formatLabelName LabelVCDIFF <> ": the matcher indexes input and output as one string, spanning "
  <> renderAsText (unFileSize sourceSize) <> " + " <> renderAsText (unFileSize targetSize)
  <> " bytes plus two sentinels, reaching "
  <> renderAsText (toInteger (unFileSize sourceSize) + toInteger (unFileSize targetSize) + 2)
  <> " — past the " <> renderAsText (unFileSize maxSize)
  <> "-byte limit slap can address"

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

renderSlapError (RomTypeRetagRejected (CarriedRomType carried) (RequestedRomType requested)) =
  "--rom-type: this patch declares ROM type " <> platformName carried
  <> ", and convert does not retag across platforms: the records were built against the "
  <> platformName carried <> " normalized form, and a " <> platformName requested
  <> " tag would tell appliers to normalize the input differently."
  <> "\n  --rom-type on convert only disambiguates the combined SMS/Game Gear slot;"
  <> " to target " <> platformName requested <> ", create a new patch from the ROM files"

renderSlapError (XDelta1ConvertRequiresNames sourceLabel) =
  "cannot convert from " <> formatLabelName sourceLabel
  <> " to " <> formatLabelName LabelXDelta1
  <> ": xdelta1 patches carry a from-name and a to-name in the header,"
  <> " and " <> formatLabelName sourceLabel <> " has no equivalent fields to inherit from."
  <> "\n  pass --from-name TEXT and --to-name TEXT to supply them explicitly"

renderSlapError (XDelta3CompressorEncodingUnsupported algorithm) =
  "xdelta3: slap reads " <> compressionAlgorithmName algorithm
  <> "-compressed patches but cannot yet write them"
  <> "\n  available: --compress-with lzma, --compress-with djw, or --no-compress"

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
decompressionAlgorithm :: DecompressionFailure -> CompressionAlgorithm
decompressionAlgorithm Yay0WrapperFailed{}                 = Yay0
decompressionAlgorithm NINJA1Failed{}                      = Zlib
decompressionAlgorithm XDelta1Failed{}                     = Gzip
decompressionAlgorithm BSDiffSectionFailed{}               = Bzip2
decompressionAlgorithm (VCDIFFSectionFailed _ algorithm _) = algorithm

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

-- | How a compressor's stream relates to the sections that carry it: one continuous stream whose sections are slices of it
-- ('GatheredAcrossSections'), or a self-contained stream per section ('EachSectionItsOwn').
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

-- | The possessive subject of a secondary-stream message. The grammatical number follows 'secondaryStreamGranularity':
-- a gathered stream belongs to all sections of its kind, a per-section stream to just one.
secondaryStreamPossessive :: VCDIFFSection -> CompressionAlgorithm -> Text
secondaryStreamPossessive section algorithm =
  vcdiffSectionName section <> ownerSuffix <> " "
  <> compressionAlgorithmName algorithm <> " stream"
  where
    ownerSuffix = case secondaryStreamGranularity algorithm of
      GatheredAcrossSections -> " sections'"
      EachSectionItsOwn      -> " section's"

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

renderSlapAdvisory (InputHeaderRemoved console) =
  "removed the input's " <> renderAsText (unLength (consoleHeaderLength console)) <> "-byte "
  <> consoleHeaderName console <> " header"

renderSlapAdvisory (InputHeaderAdded console) =
  "prepended a blank " <> renderAsText (unLength (consoleHeaderLength console)) <> "-byte "
  <> consoleHeaderName console <> " header to the input"

renderSlapAdvisory (PPFApplyGrewPastSource label (FileSize sourceSize) (Length overflow)) =
  formatLabelName label
  <> ": this patch makes the output longer than the input (input 0x"
  <> renderHexAsText sourceSize <> " bytes, output extends 0x"
  <> renderHexAsText overflow <> " bytes further)"
  <> case label of
       -- PPF2 tolerates growth, so there the line above says everything; the other labels earn the extra remark.
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
  <> " zero padding); not window data, ignored"

renderSlapAdvisory (VCDIFFEmptyTargetWindowSegment windowIndex) =
  formatLabelName LabelVCDIFF
  <> ": VCD_TARGET window " <> renderAsText (unActionIndex windowIndex)
  <> " declares an empty source segment; it draws nothing from the"
  <> " produced target"

renderSlapAdvisory VCDIFFEmptyApplicationHeader =
  formatLabelName LabelVCDIFF
  <> ": the patch declares an application header and then says nothing (zero bytes)"

renderSlapAdvisory VCDIFFUnevenWindowSizes =
  formatLabelName LabelVCDIFF
  <> ": windows are unevenly sized; unusual, applied normally"

renderSlapAdvisory (XDelta3WindowSizePastReferenceDecoder (Length requestedWindowBytes) (MaxLength (Length referenceCeiling))) =
  "xdelta3: window size " <> renderAsText requestedWindowBytes
  <> " bytes is larger than the " <> renderAsText referenceCeiling
  <> "-byte windows the widespread xdelta3 3.0.11 build decodes;"
  <> " the patch is valid, but that build will refuse it"

renderSlapAdvisory (VCDIFFCustomTableNoopNoopEntries entryCount) =
  formatLabelName LabelVCDIFF
  <> ": custom code table has " <> renderAsText entryCount
  <> " do-nothing " <> pluralizeEntry entryCount <> " (NOOP followed by NOOP)"
  where
    pluralizeEntry 1 = "entry"
    pluralizeEntry _ = "entries"

renderSlapAdvisory (APSN64TrailingFragment (Length fragmentLength)) =
  formatLabelName LabelAPSN64
  <> ": " <> renderAsText fragmentLength
  <> plural fragmentLength " trailing byte" " trailing bytes"
  <> " after the last record (too few to begin another); not record data, ignored"

renderSlapAdvisory (BSDiffTrailingControlFragment (Length fragmentLength)) =
  formatLabelName LabelBSDiff
  <> ": " <> renderAsText fragmentLength
  <> plural fragmentLength " trailing byte" " trailing bytes"
  <> " at the end of the control stream (too few to form another instruction); not instruction data, ignored"

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

renderSlapAdvisory (XDelta1InputFileNotConsulted sourcelessShape) =
  formatLabelName LabelXDelta1 <> case sourcelessShape of
    OutputComesFromDataSegment ->
      ": the patch names no source file — the output comes entirely from the patch's own data, and the input was not consulted"
    OutputIsEmpty ->
      ": the patch names no source file and its target is empty; the input was not consulted"

renderSlapAdvisory (XDelta1DataRecordNameDiverges observedName) =
  formatLabelName LabelXDelta1
  <> ": data-record name is " <> renderAsText observedName
  <> " (canonical xdelta writes \"(patch data)\"; the field is a display label only, so slap proceeds normally)"

renderSlapAdvisory (FieldDropped field droppedValue) =
  let rendered = renderDroppedValue droppedValue
  in if Text.null rendered
     then "dropping " <> fieldName field
     else "dropping " <> fieldName field <> ": " <> rendered

renderSlapAdvisory (UndoDataDropped (UndoRecordCount recordCount)) =
  "dropping undo data (" <> renderAsText recordCount
  <> plural recordCount " record" " records" <> ")"

renderSlapAdvisory ValidationBlockDropped =
  "dropping validation block (1024 bytes)"

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

renderSlapAdvisory (FieldContentPastEnd label name (Length dropped)) =
  formatLabelName label <> " "
  <> fieldNameLabel name <> ": "
  <> renderAsText dropped <> plural dropped " character" " characters"
  <> " past a NUL terminator (dropped on re-encode)"

renderSlapAdvisory (PlatformNotAvailable label platform) =
  formatLabelName label <> " has no type for " <> platformName platform
  <> "; written as Raw"

renderSlapAdvisory NINJA2SMSGameGearAmbiguity =
  formatLabelName LabelNINJA2 <> " ROM type SMS/Game Gear"
  <> " is ambiguous; defaults to SMS"
  <> " on conversion (override with --rom-type gg)"

renderSlapAdvisory (RomTypeWithoutNormalization label platform) =
  formatLabelName label <> ": ROM type " <> platformName platform
  <> " carries no normalization; the patch is applied as-is"

renderSlapAdvisory (UnrecognizedRomType label romByte) =
  formatLabelName label <> ": unrecognized ROM type 0x" <> padHex 2 romByte
  <> "; records are applied unchanged, but any preprocessing it implies is unknown"

renderSlapAdvisory (UnrecognizedRomTypeName label romName) =
  formatLabelName label <> ": unrecognized ROM type \"" <> romName
  <> "\"; records are applied unchanged, but any preprocessing it implies is unknown"

renderSlapAdvisory (RomImageNormalized label role platform step) =
  formatLabelName label <> ": normalized the " <> normalizedImageRoleLabel role
  <> " as " <> platformName platform <> ": " <> normalizationStepPhrase step

renderSlapAdvisory (RomImageContentRestored label restored) =
  formatLabelName label <> ": " <> case restored of
    RestoredHeaderPrefix (Length headerLength) ->
      "restored the " <> renderAsText headerLength <> "-byte header to the front of the output"
    RestoredUNIFContainer ->
      "reinserted the patched data into the original UNIF container"

renderSlapAdvisory (RomImageShapeUnrecognized label role platform) =
  formatLabelName label <> ": the patch's ROM type is " <> platformName platform
  <> ", but the " <> normalizedImageRoleLabel role <> " "
  <> unrecognizedShapePhrase platform <> "; taken as-is"

renderSlapAdvisory (RomImageNormalizationSkipped label role platform reason) =
  formatLabelName label <> ": the " <> normalizedImageRoleLabel role
  <> " matches a " <> platformName platform <> " shape whose "
  <> normalizationSkipPhrase reason <> "; taken as-is"

renderSlapAdvisory (RomTypeNormalizationUnconfirmable label platform) =
  formatLabelName label <> ": ROM type " <> platformName platform
  <> " calls for normalization, and the patch carries no source checksum"
  <> " to confirm the normalized input is what it was built against"

renderSlapAdvisory (UNIFContainerNotRebuilt label (ExpectedSize containerTotal) (ActualSize patchedLength)) =
  formatLabelName label <> ": the original UNIF container's PRG and CHR chunks hold "
  <> renderAsText (unFileSize containerTotal) <> " bytes but the patched data is "
  <> renderAsText (unFileSize patchedLength)
  <> "; the output is the merged data, not a UNIF file"

renderSlapAdvisory APSN64ImageFormatMismatch =
  formatLabelName LabelAPSN64 <> ": the source ROM's byte order does not match"
  <> " the image format this patch was built for (V64 vs Z64)"

renderSlapAdvisory APSN64Type1HeaderDropped =
  formatLabelName LabelAPSN64 <> ": Type-1 N64 header (image format, cart ID,"
  <> " country, CRC) is not carried into the converted patch"

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

-- | Choose the singular or plural label for a count. Call sites carry any leading space inside the two label strings.
plural :: Int -> Text -> Text -> Text
plural n singular pluralForm = if n == 1 then singular else pluralForm

-- | Render the reason a (source, target) pair was refused.
-- The 'FormatLabel' lets an arm vary its wording per format; arms with one wording ignore it.
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

-- | The markers in the wild are ASCII-printable (@"EOF"@, @"EEOF"@), so the common case is the literal string;
-- a marker with a non-printable byte falls back to hex rather than putting control characters in the error stream.
renderTrailerMarkerName :: ByteString -> Text
renderTrailerMarkerName = renderPrintableASCIIOrHex

renderApplyOutputDrops :: FormatLabel -> [(PatchField, [FormatLabel])] -> Text
renderApplyOutputDrops target [singleDrop] = renderOneDrop target singleDrop
renderApplyOutputDrops target manyDrops =
  Text.concat (map (\fieldDrop -> "\n  - " <> renderOneDrop target fieldDrop) manyDrops)

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

-- | The semantic unit a patch enumerates, so 'EmptyPatch' can name the right noun ("records", "blocks", "windows", ...).
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

-- | The xdelta1 versions whose magic slap recognizes but whose body shape it does not parse.
data XDelta1KnownUnsupportedVersion
  = XDelta1_1_0_4
  | XDelta1_1_0
  | XDelta1_0_14
  deriving (Eq, Show)

-- | The off-spec source-list shapes the xdelta1 parser refuses. The nullary constructors are the fixed cases;
-- 'XDelta1TooManySources' carries the count (N >= 3), which is open-ended.
data XDelta1ShapeViolation
  = XDelta1TwoDataSources
  | XDelta1ReversedDataFileOrder
  | XDelta1TwoFileSources
  | XDelta1TooManySources Int
  deriving (Eq, Show)

-- | The emitted source-list shape an instruction's wire index indexes into,
-- carried by 'XDelta1UnknownInstructionTarget' so the refusal can name the indices the patch actually declared.
data XDelta1SourceListShape
  = SourceListDataAndFile  -- ^ index 0 is the data segment, index 1 the file source.
  | SourceListDataOnly     -- ^ index 0 is the data segment; there is no index 1.
  | SourceListFileOnly     -- ^ index 0 is the file source; there is no index 1.
  | SourceListEmpty        -- ^ no valid indices at all.
  deriving (Eq, Show)

-- | Why an xdelta1 apply never read the handed input, carried by 'XDelta1InputFileNotConsulted'.
data XDelta1SourcelessShape
  = OutputComesFromDataSegment  -- ^ @[data]@: every instruction reads the patch's own segment.
  | OutputIsEmpty               -- ^ @[]@: the declared target is empty; nothing reads anything.
  deriving (Eq, Show)

-- | Which boolean flag on an xdelta1 source record held a non-boolean byte, for 'XDelta1NonBooleanSourceFlag'.
data XDelta1SourceFlag
  = XDelta1SourceKindFlag        -- ^ the @isdata@ byte
  | XDelta1SourceOffsetModeFlag  -- ^ the @sequential@ byte
  deriving (Show, Eq)

-- | The one off-spec wire shape 'UnsupportedVCDIFFShape' carries: a custom code table's inner delta declaring a custom table of its own.
-- RFC 3284 §7c requires the inner delta to use the default table; 'Slap.VCDIFF.Parse' decodes it with custom tables forbidden,
-- so the refusal points at the header's table declaration, not the inner body.
data VCDIFFShapeViolation
  = VCDIFFNestedCustomCodeTable
  deriving (Eq, Show)

-- | The structural failures of decoding a VCDIFF custom code table, validated outside the byte parser.
-- All but the last are decidable from the 1536-byte image alone and surface from 'Slap.VCDIFF.CodeTable.deserializeCodeTable';
-- 'VCDIFFCodeTableCopyModeOutOfRange' depends on the declared cache sizes, so it is checked at table-build in 'Slap.VCDIFF.Parse'.
data VCDIFFCodeTableMalformation
  -- | The serialized code-table bytes are not the spec-mandated 1536-byte width (six 256-entry slices).
  = VCDIFFCodeTableWrongLength !ActualLength
  -- | A byte in a types slice outside the valid instruction type tags (Noop=0, Add=1, Run=2, Copy=3).
  | VCDIFFCodeTableInvalidInstructionType !Word8
  -- | The custom-code-table data section is shorter than the 2-byte header (near-cache size, same-cache size) it must begin with.
  | VCDIFFCodeTableHeaderTooShort
  -- | A size or mode byte was nonzero for a template type that carries no such field — a size on a NOOP; a mode on a NOOP, ADD, or RUN.
  -- The grammar gives those bytes exactly one well-formed value (zero, matching the default-table image a custom image is delta-encoded against),
  -- so a nonzero value is not an alternative spelling of anything: it is evidence the table bytes are damaged,
  -- and with no checksum in this arc the table check is the tripwire (docs/vcdiff/rfc-vcdiff/questions.md, "invalid decoded-table entries").
  | VCDIFFCodeTableUnusedFieldSet !VCDIFFCodeTableField !Word8
  -- | A COPY template named an address mode the declared caches do not reach: at or above @2 + s_near + s_same@,
  -- the band 'Slap.VCDIFF.Parse.classifyAddressMode' admits. Checked once at table-build, used or not —
  -- damage evidence on the same reasoning as 'VCDIFFCodeTableUnusedFieldSet'.
  | VCDIFFCodeTableCopyModeOutOfRange !Word8 !Word8
  deriving (Eq, Show)

-- | Which per-template byte of the serialized code-table image a malformation names: the size byte or the mode byte.
data VCDIFFCodeTableField = CodeTableSizeField | CodeTableModeField
  deriving (Eq, Show)

codeTableFieldName :: VCDIFFCodeTableField -> Text
codeTableFieldName CodeTableSizeField = "size"
codeTableFieldName CodeTableModeField = "mode"

-- | The two RFC 3284 features xdelta3 refuses — the RFC half of 'VCDIFFRFCFeatureWithXDelta3Feature'.
data VCDIFFRFCFeature
  = RFCFeatureTargetWindow    -- ^ Win_Indicator VCD_TARGET: a window copying earlier target output.
  | RFCFeatureCustomCodeTable -- ^ Hdr_Indicator VCD_CODETABLE: a custom code table.
  deriving (Eq, Show)

-- | The xdelta3-extension half of 'VCDIFFRFCFeatureWithXDelta3Feature'.
-- When a patch carries several, the classifier reports whichever it met first: compressor, then header, then checksum.
data VCDIFFXDelta3Feature
  = XDelta3FeatureSecondaryCompressor  -- ^ a declared secondary compressor (VCD_DECOMPRESS).
  | XDelta3FeatureApplicationHeader    -- ^ an application header (VCD_APPHEADER).
  | XDelta3FeatureWindowChecksum       -- ^ a per-window Adler32 (VCD_ADLER32).
  deriving (Eq, Show)

-- | A semantics failure in a VCDIFF patch that parsed at the byte level, carried by 'MalformedVCDIFF' —
-- the loud refusals the core invariants demand (docs/vcdiff/core/spec.md "Core invariants").
-- Every arm is a claim slap understands and finds invalid; the claims it cannot interpret decline instead,
-- through 'VCDIFFReservedIndicatorBits' and 'VCDIFFUnknownSecondaryCompressor'.
-- The 'ActionIndex' an arm carries counts decoded instructions, not instruction-section bytes:
-- one code byte can carry two instructions, and an inline size varint widens others,
-- so the index names what the stream means rather than where it sits.
data VCDIFFMalformation
  -- | A window's indicator set both VCD_SOURCE and VCD_TARGET, which RFC 3284 §4.2 forbids.
  = VCDIFFBothSourceAndTargetWindowBits
  -- | Core invariant 1: a COPY address must point strictly inside the already-produced superstring.
  -- The 'ActualOffset' is the decoded address; the 'MaxOffset' is @here@, the current write position, so the valid range is @[0, here)@.
  | VCDIFFCopyAddressOutOfRange !ActionIndex !ActualOffset !MaxOffset
  -- | Core invariant 2: a COPY that begins inside the source segment must not run past its end.
  | VCDIFFCopyCrossesSourceSegmentEnd !ActionIndex
  -- | Core invariant 3: a window's instructions must produce exactly its declared target size ('ExpectedSize' declared, 'ActualSize' produced).
  | VCDIFFWindowSizeMismatch !ExpectedSize !ActualSize
  -- | An instruction demanded more bytes than its 'VCDIFFSection' holds — the data, instruction, or address section ran short.
  | VCDIFFSectionExhausted !VCDIFFSection !ActionIndex
  -- | A COPY's code-table entry named an address mode outside the range the cache configuration defines. The 'Word8' is the mode.
  | VCDIFFInvalidCopyAddressMode !Word8
  -- | A window's declared delta-encoding length disagrees with the measured span of its own fields.
  -- A self-consistency check the core ruling demands, not a boundary slap navigates by:
  -- a mismatch catches corruption (docs/vcdiff/core/questions.md, "delta-encoding-length"). The 'ExpectedSize' is the wire declaration;
  -- the 'ActualSize' is the span the framer measured.
  | VCDIFFDeltaEncodingLengthMismatch !ExpectedSize !ActualSize
  -- | A window's instructions finished with bytes still unconsumed in its data or address section: the named 'Length' of them.
  -- The decode is complete and the output correct; what fails is self-consistency —
  -- the window declared section lengths its own instructions contradict —
  -- the sibling of 'VCDIFFDeltaEncodingLengthMismatch' (docs/vcdiff/core/questions.md, "leftover bytes").
  -- The instruction section cannot be named here: it drives the walk, which ends exactly when it is spent.
  | VCDIFFSectionUnconsumedBytes !VCDIFFSection !Length
  -- | A section flagged secondary-compressed whose bytes cannot supply the decompressed-size varint every compressed section begins with —
  -- the zero-length section is the canonical case. Rejected per docs/vcdiff/xdelta3/questions.md, "compressed-but-empty section".
  | VCDIFFCompressedSectionWithoutDeclaredSize !VCDIFFSection
  -- | A section flagged secondary-compressed whose decompressed-size varint is zero.
  -- A category error rather than a no-op: compressing nothing yields framing bytes, never zero bytes, so a section cannot decompress to empty.
  -- xd3 rejects it as "invalid output size"; slap does too.
  | VCDIFFCompressedSectionDeclaresEmptyOutput !VCDIFFSection
  -- | A window's Delta_Indicator flags a section as compressed, but the patch's header declares no secondary compressor.
  -- The two declarations live in the same patch and contradict each other; there is no algorithm the section could be decoded by.
  | VCDIFFCompressedSectionWithoutCompressor !VCDIFFSection
  -- | A secondary stream finished decoding with input left over: the named 'Length' of it.
  -- Mirrors xd3's "finished with unused input" verdict (@xd3_decode_secondary@),
  -- kept distinct from the short-output sibling below because over-supplied input and under-produced output are different faults.
  -- The 'CompressionAlgorithm' names the decoder that was running, and fixes the stream's granularity:
  -- a windows-spanning gathered stream for LZMA, one section's own self-contained stream for DJW.
  | VCDIFFSecondaryStreamUnconsumedInput !VCDIFFSection !CompressionAlgorithm !Length
  -- | A secondary stream decoded to a byte count other than its framing declared. Mirrors xd3's "short output" verdict;
  -- the 'ExpectedSize' is the declared size (the sections' sum for LZMA's gathered kind, the one section's own for DJW),
  -- the 'ActualSize' what the decoder produced.
  | VCDIFFSecondaryStreamOutputSizeMismatch !VCDIFFSection !CompressionAlgorithm !ExpectedSize !ActualSize
  deriving (Eq, Show)

-- | Which of a VCDIFF patch's three indicator bytes carried a reserved bit, for 'VCDIFFReservedIndicatorBits'.
data VCDIFFIndicatorKind = HeaderIndicator | WindowIndicator | DeltaIndicator
  deriving (Eq, Show)

-- | One of a VCDIFF window's three data sections — and, since sections of one kind form a continuous secondary stream across windows,
-- also the name of that kind in the secondary-compression arms above.
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

newtype ControlSectionSize = ControlSectionSize { unControlSectionSize :: Int64 } deriving (Eq, Show)
newtype DiffSectionSize    = DiffSectionSize    { unDiffSectionSize    :: Int64 } deriving (Eq, Show)
newtype TargetSectionSize  = TargetSectionSize  { unTargetSectionSize  :: Int64 } deriving (Eq, Show)

-- | The structural failures slap raises when validating a BSDiff fixed-width header.
-- 'BSDiffNegativeHeaderSizes': at least one of the three section sizes decoded as negative.
-- The two overrun arms name the block whose declared size reaches past the end of the patch, carrying the distance in bytes;
-- 'Slap.BSDiff.Parse.parseBSDiff' judges them sequentially (control against the whole body, then diff against what control left),
-- each step a comparison that cannot wrap the way a summed bound could.
data BSDiffHeaderMalformation
  = BSDiffNegativeHeaderSizes !ControlSectionSize !DiffSectionSize !TargetSectionSize
  | BSDiffControlOverrunsPatch !Int64
  | BSDiffDiffOverrunsPatch !Int64
  deriving (Eq, Show)

-- | A header byte slap validates before the main wire-level walk and cannot accept:
-- a patch type other than simple or N64, or a record encoding other than 0, the only one slap can decode.
data APSN64HeaderMalformation
  = APSN64UnknownPatchType !Word8
  | APSN64UnsupportedEncoding !Word8
  deriving (Eq, Show)

-- | The NINJA1-format-specific malformations a textual-patch parser can refuse.
-- Each names a structural failure of the textual grammar.
-- The exception is 'NINJA1UnaddressableOffsetInTextRecord': a value the grammar admits but slap cannot carry.
-- The labeled newtypes (e.g. 'LineText') carry the offending wire bytes for the renderer.
data NINJA1Malformation
  = NINJA1EmptyTextualPatch
  | NINJA1InvalidOffsetInTextRecord OffsetTokenText
  | NINJA1UnaddressableOffsetInTextRecord OffsetTokenText
    -- ^ The offset token is clean hex but names a position past 'maxBound' :: 'Int'.
    -- Textual offsets have no width limit, so the parser decodes at 'Integer' and refuses rather than wrapping.
  | NINJA1MalformedChecksum FieldName ChecksumTokenText
    -- ^ A header checksum slot holds a token that is neither @"unk"@\/@"unk."@ nor a valid checksum for that slot.
    -- Such a token is refused rather than skipped or truncated into a wrong one; the 'FieldName' names the slot.
  | NINJA1MalformedTextRecord       LineText
  deriving (Eq, Show)

-- | Which textual-to-binary decode 'SubformatConverted' reports.
data NINJA1SubformatConversion
  = NINJA1TextToBinary
  | NINJA1CompressedTextToCompressedBinary
  deriving (Eq, Show)

-- | One canonicalization a ROM type's normalization procedure performed, carried by 'RomImageNormalized'.
-- The header widths are fixed per arm (the iNES header is 16 bytes, the copier-era headers 512), so no arm carries a length.
-- The procedures live in "Slap.Normalize".
data NormalizationStep
  = StrippedINESHeader
  | StrippedFFEHeader
  | MergedUNIFChunks
  | StrippedSNESCopierHeader
  | StrippedNSRTHeader
  | DeinterleavedSNESHiROM SNESInterleaveLayout
  | ByteswappedN64Image
  | StrippedSmartCardHeader
  | DeinterleavedSMDImage
  | StrippedMagicSuperGriffinHeader
  | StrippedLynxHeader
  deriving (Eq, Show)

normalizationStepPhrase :: NormalizationStep -> Text
normalizationStepPhrase StrippedINESHeader = "removed the 16-byte iNES header"
normalizationStepPhrase StrippedFFEHeader  = "removed the 512-byte FFE header"
normalizationStepPhrase MergedUNIFChunks   = "merged the UNIF container's PRG and CHR chunks into one image"
normalizationStepPhrase StrippedSNESCopierHeader = "removed the 512-byte copier header"
normalizationStepPhrase StrippedNSRTHeader = "removed the 512-byte NSRT header"
normalizationStepPhrase (DeinterleavedSNESHiROM layout) =
  "deinterleaved the HiROM image (" <> snesInterleaveLayoutPhrase layout <> ")"
normalizationStepPhrase ByteswappedN64Image = "byteswapped the V64 image to native byte order"
normalizationStepPhrase StrippedSmartCardHeader = "removed the 512-byte SmartCard header"
normalizationStepPhrase DeinterleavedSMDImage = "removed the 512-byte SMD header and deinterleaved the 16 KiB blocks"
normalizationStepPhrase StrippedMagicSuperGriffinHeader = "removed the 512-byte Magic Super Griffin header"
normalizationStepPhrase StrippedLynxHeader = "removed the 64-byte LYNX header"

-- | Which interleave layout a SNES HiROM deinterleave undid: the generic even/odd halves scheme,
-- or one of the three Game Doctor SF charts, keyed to exact image sizes (20, 24, 48 Mbit).
data SNESInterleaveLayout
  = EvenOddHalvesLayout
  | GD3Chart20MbitLayout
  | GD3Chart24MbitLayout
  | GD3Chart48MbitLayout
  deriving (Eq, Show)

snesInterleaveLayoutPhrase :: SNESInterleaveLayout -> Text
snesInterleaveLayoutPhrase EvenOddHalvesLayout  = "even/odd 32 KiB halves"
snesInterleaveLayoutPhrase GD3Chart20MbitLayout = "Game Doctor 20 Mbit chart"
snesInterleaveLayoutPhrase GD3Chart24MbitLayout = "Game Doctor 24 Mbit chart"
snesInterleaveLayoutPhrase GD3Chart48MbitLayout = "Game Doctor 48 Mbit chart"

-- | Which file a normalization advisory speaks about: the apply-side input, or one of the two files handed to create.
data NormalizedImageRole
  = NormalizedApplyInput
  | NormalizedCreateOriginal
  | NormalizedCreateModified
  deriving (Eq, Show)

normalizedImageRoleLabel :: NormalizedImageRole -> Text
normalizedImageRoleLabel NormalizedApplyInput     = "input"
normalizedImageRoleLabel NormalizedCreateOriginal = "original"
normalizedImageRoleLabel NormalizedCreateModified = "modified"

-- | Why an image that matched one of its ROM type's shapes still could not be normalized:
-- the declared structure and the actual bytes disagree in a way the transform cannot bridge.
data NormalizationSkipReason
  = ImageShorterThanItsHeader
  | SMDBlocksNotWhole
  | SNESInterleavedBlocksNotWhole
  | UNIFChunkTableTruncated
  | N64ImageOddLength
  deriving (Eq, Show)

-- | The clause after "matches a <platform> shape whose ..." in the 'RomImageNormalizationSkipped' rendering; each phrase completes that sentence.
normalizationSkipPhrase :: NormalizationSkipReason -> Text
normalizationSkipPhrase ImageShorterThanItsHeader =
  "image is smaller than the header the procedure would remove"
normalizationSkipPhrase SMDBlocksNotWhole =
  "body after the SMD header does not divide into whole 16 KiB blocks"
normalizationSkipPhrase SNESInterleavedBlocksNotWhole =
  "body does not divide into two equal halves of whole 32 KiB blocks"
normalizationSkipPhrase UNIFChunkTableTruncated =
  "chunk table runs past the end of the file"
normalizationSkipPhrase N64ImageOddLength =
  "byteswapped image has an odd byte count"

-- | What the image was expected to show and did not, for the 'RomImageShapeUnrecognized' rendering.
-- Only platforms whose procedures reach that verdict have a specific phrase; the final arm covers the rest.
unrecognizedShapePhrase :: PlatformType -> Text
unrecognizedShapePhrase platform = case platform of
  PlatformNES      -> "has no iNES or UNIF signature and no FFE marker at offset 8"
  PlatformSNES     -> "carries no internal header checksum at 0x7FDC or 0xFFDC"
  PlatformN64      -> "leads with neither N64 magic (native 0x80371240, byteswapped 0x37804012)"
  PlatformSMS      -> "has neither the SEGA signature at 0x7FF4 nor the SMD marker at offset 8"
  PlatformGameGear -> "has neither the SEGA signature at 0x7FF4 nor the SMD marker at offset 8"
  PlatformGenesis  -> "has neither the SEGA signature at 0x100 nor the SMD marker at offset 8"
  _                -> "matches none of the shapes its normalization procedure recognizes"

-- | What 'RomImageContentRestored' put back into the output: a stripped header re-prepended (carrying its width for the rendering),
-- or patched data reinserted into the original UNIF chunk table.
data RestoredContent
  = RestoredHeaderPrefix Length
  | RestoredUNIFContainer
  deriving (Eq, Show)

-- | A line of textual-patch input, carried verbatim for a malformation diagnostic.
newtype LineText = LineText { unLineText :: Text }
  deriving (Eq, Show)

-- | A hex-offset token slice from a textual-patch line, carried verbatim for a malformation diagnostic.
newtype OffsetTokenText = OffsetTokenText { unOffsetTokenText :: Text }
  deriving (Eq, Show)

-- | A header checksum token, carried verbatim for a 'NINJA1MalformedChecksum' diagnostic.
newtype ChecksumTokenText = ChecksumTokenText { unChecksumTokenText :: Text }
  deriving (Eq, Show)

----------------------------------------------------------------------------
-- ByteParserError
----------------------------------------------------------------------------

-- | Which primitive of 'Slap.ByteParser' surfaced an underflow, for 'ByteParserUnderflow'.
data ByteParserOperation
  = GetBytesOperation
  | SkipOperation
  | FixedWidthReadOperation
  | VarintReadOperation
  deriving (Eq, Show)

-- | The structured failure type for 'Slap.ByteParser.ByteParser',
-- lifted into 'SlapError' via 'ParseError' with the wrapping format's 'FormatLabel'.
data ByteParserError

  -- | A read asked for 'RequestedLength' bytes at 'Position' with only 'RemainingLength' left.
  = ByteParserUnderflow ByteParserOperation RequestedLength RemainingLength Position

  -- | A record declares more bytes than the stream holds. Format walkers raise it ahead of the doomed read,
  -- so the failure names the record and its full declared size ('RequiredLength', header included)
  -- rather than the byte offset a raw underflow would have named.
  | ByteParserTruncatedRecord !ActionIndex !RequiredLength !RemainingLength

  -- | A command-coded stream's next code byte is outside the format's command table.
  | ByteParserUnknownCommandByte !ActionIndex !Word8

  -- | A width-prefixed integer field decoded a value past 'maxBound' :: 'Int' — the sibling of 'ByteParserVarintExceededWidth'.
  -- The width prefix has no ceiling, so the wire can name a value no 'Int' holds;
  -- the reader decodes at 'Integer' and declines rather than wrapping. The 'ActionIndex' names the record and the 'FieldName' which field.
  | ByteParserFieldExceedsAddressableRange !ActionIndex !FieldName

  -- | 'Slap.ByteParser.getUntilByte' scanned from 'Position' to end of input without finding the terminator byte.
  | ByteParserTerminatorNotFound Word8 Position

  -- | A 'Slap.ByteParser.setPosition' target outside @[0, inputLength]@.
  | ByteParserPositionOutOfBounds Position ActualLength

  -- | 'Slap.ByteParser.getBytes' was asked for a negative count. Split from the 'Slap.ByteParser.skip' variant below
  -- because only those two primitives accept a caller-supplied length; the fixed-width and varint reads cannot produce this failure.
  | ByteParserNegativeLengthRequestedInGetBytes Length

  -- | 'Slap.ByteParser.skip' was asked to advance by a negative count.
  | ByteParserNegativeLengthRequestedInSkip Length

  -- | A varint started inside the buffer but its continuation bytes ran past the end; the 'Position' is where it started.
  -- Distinct from 'ByteParserUnderflow' at 'VarintReadOperation', which fires when the read started at or past EOF.
  | ByteParserVarintOverranBuffer Position

  -- | A varint decoded a value too large to represent at all. All three varint readers (byuu, VCDIFF, EDSIO) raise it;
  -- for VCDIFF it means a value at or past @2^64@, beyond even xd3's @uint64@ —
  -- the @[2^63, 2^64)@ band is the separate 'ByteParserVarintExceedsSignedRange'.
  | ByteParserVarintExceededWidth

  -- | A VCDIFF varint decoded a value in @[2^63, 2^64)@ — xd3's unsigned reader accepts it, slap's signed 'Int' cannot.
  -- Kept apart from 'ByteParserVarintExceededWidth' so the renderer can concede the one bit slap gives up rather than blame the input.
  | ByteParserVarintExceedsSignedRange

  -- | An EDSIO varint decoded a value past @0xFFFFFFFF@. Every integer in the xdelta1 wire format is a @guint32@ (upstream @xd_edsio.h@),
  -- so a wider value is not a representable xdelta1 quantity; canonical xdelta truncates such a value silently, slap declines it.
  | ByteParserEdsioVarintExceeds32Bits !Int64

  -- | The xdelta1 control segment opened with a type tag that isn't @ST_XdeltaControl@.
  -- Canonical's EDSIO reader rejects an unregistered library number (the tag's low byte) with "Unregistered library: N";
  -- slap declines the same way. The 'Word32' is the tag as read.
  | ByteParserXDelta1UnexpectedControlTypeTag !Word32

  -- | The 'MonadFail' fallback for @do@-pattern failures in parser code.
  -- Reaching this arm means slap has a bug, not that the wire input was malformed.
  | ByteParserUnexpectedDoPatternFailure String

  deriving (Eq, Show)

----------------------------------------------------------------------------
-- Severity assignment
----------------------------------------------------------------------------

slapAdvisorySeverity :: SlapAdvisory -> Severity
slapAdvisorySeverity advisory = case advisory of

  -- Warnings: something happened the user should look at.
  NoEOFMarker{}                        -> SeverityWarning
  BSDiffTrailingControlFragment{}      -> SeverityWarning
  APSN64TrailingFragment{}             -> SeverityWarning
  IPS32TrailingBytes{}                 -> SeverityWarning
  -- PPF2 tolerates growth, so its apply-grow advisory is a note; the other labels warn.
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

  -- Notes: informational — reported so the reader knows, not because anything needs fixing.
  EmptyPatch{}                         -> SeverityNote
  InputHeaderRemoved{}                 -> SeverityNote
  InputHeaderAdded{}                   -> SeverityNote
  ZeroCountRLERecord{}                 -> SeverityNote
  NegativeZeroInBPS                    -> SeverityNote
  NonCanonicalVCDIFFVarint{}           -> SeverityNote
  OverlappingRecords{}                 -> SeverityNote
  UnsortedRecords{}                    -> SeverityNote
  VCDIFFTrailingRemnant{}              -> SeverityNote
  VCDIFFEmptyTargetWindowSegment{}     -> SeverityNote
  VCDIFFEmptyApplicationHeader         -> SeverityNote
  VCDIFFUnevenWindowSizes              -> SeverityNote
  XDelta3WindowSizePastReferenceDecoder{} -> SeverityNote
  VCDIFFCustomTableNoopNoopEntries{}   -> SeverityNote
  EBPMetadataMalformed{}               -> SeverityNote
  BPSMetadataNonConformant{}           -> SeverityNote
  XDelta1DataRecordNameDiverges{}      -> SeverityNote
  XDelta1InputFileNotConsulted{}       -> SeverityNote
  FieldDropped{}                       -> SeverityNote
  UndoDataDropped{}                    -> SeverityNote
  ValidationBlockDropped               -> SeverityNote
  MetadataDropped{}                    -> SeverityNote
  DefaultRomType{}                     -> SeverityNote
  DefaultImageType{}                   -> SeverityNote
  IncludingUndoByDefault               -> SeverityNote
  IncludingVerificationByDefault       -> SeverityNote
  SourceHashesMissing{}                -> SeverityNote
  FieldTruncated{}                     -> SeverityNote
  FieldDecodedSubstituted{}            -> SeverityNote
  FieldEncodedSubstituted{}            -> SeverityNote

  -- Field, rom-type, image, and platform handling, where severity turns on whether slap could act cleanly:
  -- a recognized default or a clean normalization is a note; anything unrecognized, unconfirmable, or dropped warns.
  FieldContentPastEnd{}                -> SeverityWarning
  PlatformNotAvailable{}               -> SeverityWarning
  NINJA2SMSGameGearAmbiguity           -> SeverityNote
  RomTypeWithoutNormalization{}        -> SeverityNote
  UnrecognizedRomType{}                -> SeverityWarning
  UnrecognizedRomTypeName{}            -> SeverityWarning
  RomImageNormalized{}                 -> SeverityNote
  RomImageContentRestored{}            -> SeverityNote
  RomImageShapeUnrecognized{}          -> SeverityWarning
  RomImageNormalizationSkipped{}       -> SeverityWarning
  RomTypeNormalizationUnconfirmable{}  -> SeverityWarning
  UNIFContainerNotRebuilt{}            -> SeverityWarning
  APSN64ImageFormatMismatch            -> SeverityWarning
  APSN64Type1HeaderDropped             -> SeverityWarning
  SubformatConverted{}                 -> SeverityNote
