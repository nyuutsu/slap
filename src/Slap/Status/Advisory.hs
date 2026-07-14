{-# LANGUAGE StrictData #-}

-- | 'SlapAdvisory': everything slap remarks on without halting, and the envelopes that carry advisories beside a value.
module Slap.Status.Advisory
  ( SlapAdvisory(..)
  , VerificationMismatch(..)
  , BPSMetadataDivergence(..)
  , slapAdvisorySeverity
  , CreateResult(..)
  , Parsed(..)
  , Outcome(..)
  , noAdvisories
  ) where

import Slap.Checksum (ExpectedCRC32, ActualCRC32)
import Slap.FieldName (FieldName)
import Slap.FileContents (PatchFileContents)
import Slap.FormatLabel (FormatLabel(..))
import Slap.Header (ConsoleHeader, HeaderAdjustment)
import Slap.Measure (Offset, Length, FileSize, ActionIndex,
                     ExpectedSize, ActualSize,
                     DeclaredTargetSize, NaturalTargetSize,
                     MaxLength, OriginalLength, TruncatedLength,
                     SubstitutionCount)
import Slap.PatchField (PatchField)
import Slap.PlatformType (PlatformType)
import Slap.Status.Severity (Severity(..))
import Slap.Status.Vocabulary (EmptyUnit, DroppedValue, OverlapCount, ClippedRecordCount,
                               OOBBlockCount, UndoRecordCount, MarkerOvershootBytes, OOBOvershootBytes,
                               ApplyDirection, VerificationSide, HashAlgorithm, DeclaredCheckKind,
                               ExpectedAdler32, ActualAdler32, ByteCheckLabel,
                               NINJA1SubformatConversion,
                               NormalizationStep, NormalizedImageRole, NormalizationSkipReason, RestoredContent)
import Slap.Status.XDelta1 (XDelta1SourcelessShape)

import Data.ByteString (ByteString)
import Data.Int (Int64)
import Data.List.NonEmpty (NonEmpty)
import Data.Text (Text)
import Data.Word (Word8)

-- | How a BPS patch's metadata blob diverged from UTF-8, the encoding the spec recommends.
-- Both arms leave the blob shown and carried byte-exact; they name what a lenient UTF-8 decode found.
data BPSMetadataDivergence
  = MetadataBytesSubstituted !SubstitutionCount
    -- ^ That many byte sequences are not valid UTF-8; each decoded to U+FFFD.
  | MetadataDecodedButNonText
    -- ^ Valid UTF-8, but carrying control codepoints — not the plain text the field is meant to hold.
  deriving (Eq, Show)

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

  -- | The header rescue's find: this arrangement makes the input match every check the patch declares.
  | SourceMatchesAfterHeaderAdjustment HeaderAdjustment (NonEmpty ConsoleHeader) (NonEmpty DeclaredCheckKind)
  -- | The header rescue's empty hands, so the fiddling can stop: no arrangement reconciles the input with the patch.
  | NoHeaderAdjustmentMatches
  -- | Warning: the input differed as handed and exactly one arrangement reconciles it,
  -- so the run proceeded with the input reframed that way.
  | InputReframedToMatchPatch HeaderAdjustment (NonEmpty ConsoleHeader) (NonEmpty DeclaredCheckKind)

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
  -- 'Slap.IPS.Types.StandardIPS' has three attested post-EOF shapes and rejects anything else ('Slap.Status.UnrecognizedTrailer');
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

  -- | A 'Slap.IPS.Types.StandardIPS' post-EOF truncation marker declared a target size below the natural size, and slap honored it.
  -- Surfaces the truncation even when no records cross the boundary; 'IPSRecordsClippedByMarker' fires when they do.
  | IPSTruncationMarkerHonored FormatLabel DeclaredTargetSize NaturalTargetSize

  -- | Records' write regions extended past the honored truncation boundary and were clipped to fit.
  -- An aggregate count in the style of 'OverlappingRecords'; the 'ActionIndex' names the first crossing record in wire order.
  | IPSRecordsClippedByMarker FormatLabel ClippedRecordCount ActionIndex MarkerOvershootBytes

  -- | A 'Slap.IPS.Types.StandardIPS' truncation marker declared a target size above the natural size, which would grow the output via zero-fill;
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

  -- | An xdelta 1.1.x data-record's @name@ field is not the canonical @"(patch data)"@ ('Slap.XDelta1.Types.xdelta1DataRecordName').
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

  -- | A FILE_ID.DIZ being written carries bytes outside 7-bit ASCII. The convention is plain ASCII,
  -- but neither PPF2.txt nor PPF3.txt names a charset and the reference tools pass the bytes through untouched,
  -- so this is a note, not a refusal. The 'Length' is how many bytes are non-ASCII.
  | FileIdDizNonASCII FormatLabel Length

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
  -- | A declared verification check did not hold. Fatal-class mismatches ride here only after @--no-verify@ demoted them;
  -- advisory-class ones always do ('Slap.Verify.mismatchClass' assigns the lane).
  | DeclaredCheckMismatched VerificationMismatch

  -- | The patch declares no verification data at the format level — xdelta1's @FLAG_NO_VERIFY@ bit, PPF3's absent validation block.
  -- slap honors the declaration and skips verification;
  -- the warning reports that nothing attests the output matches the creator's intent.
  | VerificationOptedOutByCreator !FormatLabel

  deriving (Show, Eq)

-- | One declared check that did not hold against the file it describes: the payload of a differing 'Slap.Verify.VerificationVerdict',
-- of the 'Slap.Status.VerificationFatal' refusal, and of the 'DeclaredCheckMismatched' warnings.
-- Which constructors refuse an apply and which only warn is 'Slap.Verify.mismatchClass''s to say.
data VerificationMismatch
  = VerificationCRCMismatch         VerificationSide ExpectedCRC32 ActualCRC32
  | VerificationHashMismatch        VerificationSide HashAlgorithm
  | VerificationAdler32Mismatch     Offset ExpectedAdler32 ActualAdler32
  | VerificationFileSizeMismatch    VerificationSide ExpectedSize ActualSize
  | VerificationBlockCRC16Mismatch  VerificationSide Offset
  | VerificationPPFBlockMismatch    Offset
  | VerificationFileSizeAdvisory    ExpectedSize ActualSize
  | VerificationSourceBytesMismatch ByteCheckLabel Offset
    -- | The source ROM's byte order does not match the image format an APS-N64 Type-1 patch declares.
  | APSN64ImageFormatMismatch
  deriving (Show, Eq)

data CreateResult = CreateResult
  { resultBytes      :: !PatchFileContents
  , resultAdvisories :: ![SlapAdvisory]
  } deriving (Show)

-- | The parse-side companion to 'CreateResult': a successfully
-- parsed payload paired with any advisories the parser accumulated.
data Parsed value = Parsed !value ![SlapAdvisory]
  deriving (Show)

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
  DeclaredCheckMismatched{}            -> SeverityWarning
  VerificationOptedOutByCreator{}      -> SeverityWarning
  -- Slap acted unasked, so the narration earns warning prominence even though the run succeeds.
  InputReframedToMatchPatch{}          -> SeverityWarning

  -- Notes: informational — reported so the reader knows, not because anything needs fixing.
  EmptyPatch{}                         -> SeverityNote
  InputHeaderRemoved{}                 -> SeverityNote
  InputHeaderAdded{}                   -> SeverityNote
  SourceMatchesAfterHeaderAdjustment{} -> SeverityNote
  NoHeaderAdjustmentMatches            -> SeverityNote
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
  FileIdDizNonASCII{}                  -> SeverityNote

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
  APSN64Type1HeaderDropped             -> SeverityWarning
  SubformatConverted{}                 -> SeverityNote
