{-# LANGUAGE StrictData #-}

-- | 'SlapError': everything that halts slap.
module Slap.Status.Error
  ( SlapError(..)
  , UnencodeabilityReason(..)
  ) where

import Slap.Archive.Types (ArchiveFormat, UnwrapError)
import Slap.Checksum (MD5Hash, ExpectedCRC32, ActualCRC32)
import Slap.Constraint (Constraint)
import Slap.Dialect (Dialect)
import Slap.FieldName (FieldName)
import Slap.FormatLabel (FormatLabel)
import Slap.Header (ConsoleHeader)
import Slap.Measure (Offset, Length, FileSize, ActionIndex,
                     ActualSize, ExpectedSize, MaxAddressableSize,
                     SourceFileSize, TargetFileSize,
                     DeclaredTargetSize,
                     RequiredLength, ActualLength,
                     EncodedLength, MaxLength,
                     ActualOffset, MaxOffset, SentinelOffset,
                     ExpectedMagic, ActualMagic, TrailerMarker,
                     ParsedSizeValue, FoundVersion,
                     RawFlagByte, EncodingMethodByte)
import Slap.MetadataField (MetadataField)
import Slap.Narrow (NarrowingFailure)
import Slap.PatchField (PatchField)
import Slap.PlatformType (CarriedRomType, RequestedRomType)
import Slap.Status.Advisory (SlapAdvisory)
import Slap.Status.ApplyError (ApplyError)
import Slap.Status.ByteParserError (ByteParserError)
import Slap.Status.Decompression (DecompressionFailure, XDelta1DiffCause, BSDiffDifferCause)
import Slap.Status.VCDIFF (VCDIFFShapeViolation, VCDIFFCodeTableMalformation,
                           VCDIFFIndicatorKind, ReservedBitsSet, VCDIFFMalformation,
                           VCDIFFRFCFeature, VCDIFFXDelta3Feature)
import Slap.Status.Vocabulary (ExtractionSubject, CompressionAlgorithm,
                               BSDiffHeaderMalformation, APSN64HeaderMalformation, NINJA1Malformation)
import Slap.Status.XDelta1 (XDelta1KnownUnsupportedVersion, XDelta1ShapeViolation,
                            XDelta1SourceListShape, XDelta1SourceFlag, XDelta1GzipStreamInputs)

import Data.ByteString (ByteString)
import Data.Int (Int64)
import Data.List.NonEmpty (NonEmpty)
import Data.Word (Word8)

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
    -- ^ 'Slap.IPS.Types.StandardIPS' only: the pair shrinks, so the encoding needs the post-EOF truncation marker,
    -- and the marker spells the final size in the same 24-bit width as record offsets — a size past that maximum has no representation.
    -- Without the refusal, the encoder would mask the size to its low bits and emit a patch that applies to a wrongly-sized file,
    -- in a format with no checksum to notice.
  deriving (Eq, Show)

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
  -- The 'ActualSize' is the input's size; the header's width comes from 'Slap.Header.consoleHeaderLength'.
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
  -- 'Slap.IPS.Types.StandardIPS' is the one format that raises this: it accepts an empty post-@"EOF"@ trailer,
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
  -- The 'VCDIFFIndicatorKind' names which of the three indicators; the 'Word8' is the byte as read, the 'ReservedBitsSet' its undefined bits.
  | VCDIFFReservedIndicatorBits !VCDIFFIndicatorKind !Word8 !ReservedBitsSet

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
  -- Only checked under 'Slap.XDelta1.Types.VerifyAgainstStoredMD5s'; a creator opt-out stores the sentinel MD5 and the comparison is skipped.
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
  -- the way 'Slap.Status.ApplyOutputExceedsAddressableRange' does.
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
  -- That the payload is one of 'Slap.Status.VerificationCRCMismatch', 'Slap.Status.VerificationHashMismatch',
  -- 'Slap.Status.VerificationAdler32Mismatch', or 'Slap.Status.VerificationFileSizeMismatch'
  -- is a documented invariant, not a type-level one.
  | VerificationFatal SlapAdvisory

  deriving (Show, Eq)
