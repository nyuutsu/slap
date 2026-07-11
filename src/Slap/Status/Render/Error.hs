{-# LANGUAGE OverloadedStrings #-}

-- | Where a 'SlapError' becomes the words the user reads.
module Slap.Status.Render.Error
  ( renderSlapError
  ) where

import Slap.Archive.Types (ArchiveFormat, archiveFormatName, toolsFor,
                           ToolName(..), ToolDiagnostic(..),
                           EntryName(..), SeenEntryCount(..),
                           UnreadableReason(..), UnwrapError(..))
import Slap.Checksum (showCRC32, MD5Hash(..), ExpectedCRC32(..), ActualCRC32(..))
import Slap.Constraint (Constraint(..), constraintFlagName, constraintName)
import Slap.Dialect (dialectFlagName, dialectName)
import Slap.Display.Common (renderAsText, renderHexAsText, pathText)
import Slap.Display.Primitives (hexByteString, padHex, renderPrintableASCIIOrHex)
import Slap.FieldName (fieldNameLabel)
import Slap.FormatLabel (FormatLabel(..), formatLabelName)
import Slap.Header (consoleHeaderName, consoleHeaderLength)
import Slap.Measure (Offset(..), Length(..), FileSize(..), ActionIndex(unActionIndex),
                     ActualSize(..), ExpectedSize(..), MaxAddressableSize(..),
                     SourceFileSize(..), TargetFileSize(..),
                     DeclaredTargetSize(..),
                     RequiredLength(..), ActualLength(..),
                     EncodedLength(..), MaxLength(..),
                     ActualOffset(..), MaxOffset(..), SentinelOffset(..),
                     ExpectedMagic(..), ActualMagic(..), TrailerMarker(..),
                     ParsedSizeValue(..), FoundVersion(..),
                     RawFlagByte(..), EncodingMethodByte(..))
import Slap.MetadataField (metadataFieldFlagName, metadataFieldName)
import Slap.Narrow (NarrowingFailure(..))
import Slap.PatchField (PatchField, fieldName)
import Slap.PlatformType (platformName, CarriedRomType(..), RequestedRomType(..))
import Slap.Status.ApplyError (renderApplyError)
import Slap.Status.ByteParserError (renderByteParserError)
import Slap.Status.Decompression (renderDecompressionFailure,
                                  XDelta1DiffCause(..), BSDiffDifferCause(..),
                                  SecondaryStreamGranularity(..),
                                  secondaryStreamGranularity, secondaryStreamPossessive)
import Slap.Status.Error (SlapError(..), UnencodeabilityReason(..))
import Slap.Status.Render.Advisory (renderSlapAdvisory, plural)
import Slap.Status.VCDIFF (VCDIFFShapeViolation(..), VCDIFFCodeTableMalformation(..),
                           codeTableFieldName, indicatorKindName, vcdiffSectionName,
                           VCDIFFMalformation(..), VCDIFFRFCFeature(..), VCDIFFXDelta3Feature(..))
import Slap.Status.Vocabulary (ExtractionSubject(..), compressionAlgorithmName,
                               ControlSectionSize(..), DiffSectionSize(..), TargetSectionSize(..),
                               BSDiffHeaderMalformation(..), APSN64HeaderMalformation(..),
                               NINJA1Malformation(..),
                               LineText(..), OffsetTokenText(..), ChecksumTokenText(..))
import Slap.Status.XDelta1 (XDelta1KnownUnsupportedVersion(..), XDelta1ShapeViolation(..),
                            XDelta1SourceListShape(..), XDelta1SourceFlag(..),
                            XDelta1GzipStreamInputs(..))

import Data.ByteString (ByteString)
import qualified Data.List.NonEmpty as NonEmpty
import Data.Text (Text)
import qualified Data.Text as Text

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
