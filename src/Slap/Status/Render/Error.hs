{-# LANGUAGE OverloadedStrings #-}

-- | Where a 'SlapError' becomes the words the user reads.
module Slap.Status.Render.Error
  ( renderSlapError
  ) where

import Slap.Archive.Types (ArchiveFormat, archiveFormatName, toolsFor,
                           ToolName(..), ToolDiagnostic(..),
                           EntryName(..), SeenEntryCount(..),
                           UnreadableReason(..), UnwrapError(..))
import Slap.Binary (VarintReadFailure(..))
import Slap.Checksum (showCRC32, MD5Hash(..), ExpectedCRC32(..), ActualCRC32(..))
import Slap.Constraint (Constraint(..), constraintFlagName, constraintName)
import Slap.Dialect (dialectFlagName, dialectName)
import Slap.Display.Common (renderAsText, renderHexAsText, pathText)
import Slap.Display.Primitives (hexByteString, padHex, renderPrintableASCIIOrHex)
import Slap.FieldName (fieldNameLabel)
import Slap.FormatLabel (FormatLabel(..), formatLabelName, formatLabelWithIndefiniteArticle)
import Slap.Header (consoleHeaderName, consoleHeaderLength)
import Slap.Measure (Offset(..), Length(..), FileSize(..), ActionIndex(unActionIndex),
                     ActualSize(..), ExpectedSize(..), MaxAddressableSize(..),
                     SourceFileSize(..), TargetFileSize(..),
                     DeclaredTargetSize(..),
                     RequiredLength(..), ActualLength(..),
                     EncodedLength(..), MaxLength(..),
                     ActualOffset(..), MaxOffset(..), MaxWritableSize(..), SentinelOffset(..),
                     ExpectedMagic(..), ActualMagic(..), TrailerMarker(..),
                     ParsedSizeValue(..), FoundVersion(..),
                     RawFlagByte(..), EncodingMethodByte(..))
import Slap.MetadataField (MetadataRequest(..), metadataFieldName, requestField, requestFlagName)
import Slap.Narrow (NarrowingFailure(..))
import Slap.PatchField (PatchField, fieldName)
import Slap.PlatformType (platformName, CarriedRomType(..), RequestedRomType(..))
import Slap.Status.ApplyError (renderApplyError)
import Slap.Status.ByteParserError (renderByteParserError)
import Slap.Status.Decompression (renderDecompressionFailure,
                                  XDelta1DiffCause(..), BSDiffDifferCause(..), GDIFFDiffCause(..),
                                  SecondaryStreamGranularity(..),
                                  secondaryStreamGranularity, secondaryStreamPossessive)
import Slap.Status.Error (SlapError(..), UnencodeabilityReason(..), SourceRequiredCause(..))
import Slap.Status.Render.Advisory (renderVerificationMismatch, plural)
import Slap.Status.VCDIFF (VCDIFFShapeViolation(..), VCDIFFCodeTableMalformation(..),
                           codeTableFieldName, codeTableTemplateKindPhrase, indicatorKindName,
                           vcdiffSectionName, ReservedBitsSet(..), VCDIFFOnDemandSection(..),
                           VCDIFFMalformation(..), VCDIFFRFCFeature(..), VCDIFFXDelta3Feature(..))
import Slap.Status.Vocabulary (ExtractionSubject(..), compressionAlgorithmName,
                               slapAddressableCeiling, CarriedFileCount(..),
                               ControlSectionSize(..), DiffSectionSize(..), TargetSectionSize(..),
                               BSDiffHeaderMalformation(..), APSN64HeaderMalformation(..),
                               NINJA1Malformation(..), NINJA1SubformatIdentifier(..),
                               LineText(..), OffsetTokenText(..), ChecksumTokenText(..))
import Slap.Status.XDelta1 (XDelta1KnownUnsupportedVersion(..), XDelta1ShapeViolation(..),
                            XDelta1SourceListShape(..), XDelta1SourceFlag(..),
                            XDelta1GzipStreamInputs(..))

import Data.Bits (testBit)
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
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
    <> " (" <> renderAsText entryCount <> plural entryCount " entry" " entries"
    <> ", none that looks like a patch)."
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

renderSlapError (OutputFileExists path) =
  pathText path <> " already exists (use --force to overwrite)"

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

renderSlapError UnrecognizedFormat =
  "this file doesn't look like any patch format slap knows"

renderSlapError (AmbiguousDetection labels) =
  "this file looks like more than one patch format: could be "
  <> commaList (map formatLabelName labels)

renderSlapError (InputTooShort label (RequiredLength needed) (ActualLength actual)) =
  formatLabelName label <> ": the patch is too short (at least "
  <> renderAsText (unLength needed) <> " bytes needed; the file is "
  <> renderAsText (unLength actual) <> plural (unLength actual) " byte" " bytes" <> ")"

renderSlapError (XDelta1ControlSegmentTooShort (RequiredLength needed) (ActualLength actual)) =
  formatLabelName LabelXDelta1
  <> ": the patch's instructions are cut short (the control segment, which holds them, needs at least "
  <> renderAsText (unLength needed) <> " bytes; this one holds "
  <> renderAsText (unLength actual) <> ")"

renderSlapError (BadMagic label (ActualMagic actualBytes))
  | ByteString.null actualBytes =
      "this file is empty, so it cannot open with the "
      <> formatLabelName label <> " signature"
  | otherwise =
      "this file doesn't open with the " <> formatLabelName label
      <> " signature (it begins with "
      <> renderPrintableASCIIOrHex actualBytes <> ")"

renderSlapError (BadVersion label (FoundVersion versionByte)) =
  formatLabelName label <> ": the patch declares version "
  <> renderAsText versionByte <> ", which slap does not know"

renderSlapError (UnsupportedXDelta1Subformat version) =
  formatLabelName LabelXDelta1 <> ": this patch is the "
  <> (case version of
        XDelta1_1_0_4 -> "version 1.0.4"
        XDelta1_1_0   -> "version 1.0"
        XDelta1_0_14  -> "version 0.14")
  <> " subformat, which slap does not read"

renderSlapError (UnsupportedNINJA1Subformat (NINJA1SubformatIdentifier subformatBytes)) =
  formatLabelName LabelNINJA1 <> ": this patch declares subformat "
  <> renderAsText subformatBytes <> ", which slap does not read"

renderSlapError NINJA1BinaryMissingEOFFooter =
  formatLabelName LabelNINJA1 <> ": the patch ends without its closing marker (an EOF footer)"

renderSlapError NINJA2MissingEndCommand =
  formatLabelName LabelNINJA2 <> ": the patch ends without its closing marker (the END command, byte 0x00)"

renderSlapError (NegativeSize label name (ParsedSizeValue value)) =
  formatLabelName label <> ": the patch declares a "
  <> fieldNameLabel name <> " of " <> renderAsText value

renderSlapError (DecompressionFailed failure) =
  renderDecompressionFailure failure

renderSlapError NestedYay0Envelope =
  "the Yay0 wrapper holds another Yay0 wrapper, not a patch"

renderSlapError (XDelta1DiffFailed (XDelta1DiffCause causeMessage)) =
  "the xdelta1 differ failed: " <> causeMessage

renderSlapError (BSDiffDifferFailed (BSDiffDifferCause causeMessage)) =
  "the bsdiff differ failed: " <> causeMessage

renderSlapError (GDIFFDiffFailed (GDIFFDiffCause causeMessage)) =
  "the GDIFF differ failed: " <> causeMessage

renderSlapError (RecordExceedsAddressableRange label recordIndex (ActualOffset endOffset) (MaxOffset maxEndOffset)) =
  formatLabelName label <> ": record " <> renderAsText (unActionIndex recordIndex)
  <> " ends at offset 0x" <> renderHexAsText (unOffset endOffset)
  <> "; the format cannot address past 0x"
  <> renderHexAsText (unOffset maxEndOffset)

renderSlapError (RecordEndExceedsAddressableRange label recordIndex offset payloadLength) =
  formatLabelName label <> ": record " <> renderAsText (unActionIndex recordIndex)
  <> " writes at offset " <> renderAsText (unOffset offset)
  <> " plus " <> renderAsText (unLength payloadLength)
  <> " bytes, reaching "
  <> renderAsText (toInteger (unOffset offset) + toInteger (unLength payloadLength))
  <> "; that is past " <> slapAddressableCeiling
  <> ", the largest position slap can address"

renderSlapError (MalformedRecordField label recordIndex name) =
  formatLabelName label <> ": record " <> renderAsText (unActionIndex recordIndex)
  <> " has a malformed " <> fieldNameLabel name

renderSlapError (UnrecognizedTrailer label (TrailerMarker markerBytes) (ActualLength actualLength)) =
  formatLabelName label <> ": the patch carries "
  <> renderAsText (unLength actualLength)
  <> plural (unLength actualLength) " unrecognized byte" " unrecognized bytes"
  <> " after its " <> renderTrailerMarkerName markerBytes <> " end marker"

renderSlapError (PatchCRCMismatch label (ExpectedCRC32 stored) (ActualCRC32 computed)) =
  formatLabelName label <> ": the patch's own checksum doesn't match its contents (stored CRC "
  <> showCRC32 stored <> ", computed " <> showCRC32 computed <> ")"

renderSlapError (TrailingMagicMismatch label (ExpectedMagic expected) (ActualMagic actual)) =
  formatLabelName label <> ": the patch's closing signature is wrong (expected "
  <> renderAsText expected <> ", found " <> renderAsText actual <> ")"

renderSlapError (UnknownFlag label name (RawFlagByte flagByte)) =
  formatLabelName label <> ": the patch's "
  <> fieldNameLabel name <> " byte is 0x"
  <> renderHexAsText flagByte
  <> ", a value the format does not define"

renderSlapError (UnsupportedEncodingMethod label (EncodingMethodByte methodByte)) =
  formatLabelName label <> ": the patch declares encoding method 0x"
  <> renderHexAsText methodByte
  <> ", which slap does not support"

renderSlapError (NINJA2UnrecognizedTextMode byte) =
  formatLabelName LabelNINJA2
    <> ": the patch doesn't say how its text is encoded: its PATCH_ENC byte is 0x" <> padHex 2 byte
    <> ", and the spec defines only 0 (undeclared) and 1 (UTF-8); slap won't guess at an undefined encoding"

renderSlapError (MalformedNINJA1Content malformation) =
  formatLabelName LabelNINJA1 <> ": " <> case malformation of
    NINJA1EmptyTextualPatch -> "the textual patch is empty"
    NINJA1InvalidOffsetInTextRecord (OffsetTokenText t) ->
      "a text record's offset token \"" <> t <> "\" cannot be read as a number"
    NINJA1UnaddressableOffsetInTextRecord (OffsetTokenText t) ->
      "offset " <> t <> " in a text record is past "
      <> slapAddressableCeiling <> ", the largest position slap can address"
    NINJA1MalformedChecksum field (ChecksumTokenText t) ->
      "the " <> fieldNameLabel field <> " token \"" <> t <> "\" is neither \"unk\" nor a valid hex checksum"
    NINJA1MalformedTextRecord (LineText line) ->
      "a text record cannot be read: \"" <> line <> "\""

renderSlapError (ParseError label parserError) =
  formatLabelName label <> ": " <> renderByteParserError parserError

renderSlapError (UnsupportedXDelta1Shape violation) =
  formatLabelName LabelXDelta1 <> ": " <> case violation of
    XDelta1TwoDataSources ->
      "this patch lists its own bundled data twice, but it carries only one block of data,"
      <> " so the two entries can't both describe it"
      <> " (an xdelta1 patch copies from its own data and at most one input file)"
    XDelta1ReversedDataFileOrder ->
      "this patch lists the input file before its own bundled data, but xdelta1 fixes the order"
      <> " the other way: the patch's data first, then the input file."
      <> " A source list in the reverse order isn't one the format allows"
    XDelta1TwoFileSources ->
      "this patch lists two input files, but an xdelta1 patch reads from only one,"
      <> " alongside the patch's own bundled data. The format has no place for a second input"
    XDelta1TooManySources sourceCount ->
      "this patch lists " <> renderAsText sourceCount
      <> " sources, but an xdelta1 patch reads from at most two:"
      <> " its own bundled data and one input file"

renderSlapError (XDelta1NonBooleanSourceFlag flag byteValue) =
  formatLabelName LabelXDelta1
  <> ": one of the patch's sources has a yes/no flag set to neither; " <> case flag of
    XDelta1SourceKindFlag ->
      "the byte for whether the source is the patch's own data or an external file reads 0x" <> padHex 2 byteValue
      <> ", where only 0 (an external file) and 1 (the patch's own data) mean anything"
    XDelta1SourceOffsetModeFlag ->
      "the byte for whether its copy offsets are absolute or run in sequence reads 0x" <> padHex 2 byteValue
      <> ", where only 0 (absolute) and 1 (sequential) mean anything"

renderSlapError (UnsupportedVCDIFFShape violation) =
  formatLabelName LabelVCDIFF <> ": " <> case violation of
    VCDIFFNestedCustomCodeTable ->
      "slap can't find a place to start reading this patch's instruction table:"
      <> " the table arrives as a small patch of its own, and reading that small patch"
      <> " needs a table too, which this patch also says is custom"
      <> " (a custom code table is a delta against the standard table;"
      <> " that delta must itself use the standard table)"

renderSlapError (VCDIFFCustomCodeTableDecodeFailed innerError) =
  -- No format-label prefix of its own: the inner error already carries one.
  "while reading the instruction table this patch brought with it: "
  <> renderSlapError innerError

renderSlapError (VCDIFFRFCFeatureWithXDelta3Feature rfcFeature xdelta3Feature) =
  formatLabelName LabelVCDIFF
  <> ": this patch mixes two different flavors of VCDIFF, and slap doesn't know"
  <> " which one it is meant to be read as (" <> rfcFeaturePhrase rfcFeature
  <> ", which only the RFC flavor has; and " <> xdelta3FeaturePhrase xdelta3Feature
  <> ", which only xdelta3 has)"
  where
    rfcFeaturePhrase RFCFeatureTargetWindow =
      "it uses a VCD_TARGET window, a stretch of output copied from output built earlier"
    rfcFeaturePhrase RFCFeatureCustomCodeTable =
      "it uses a custom code table, its own coding for its instructions"
    xdelta3FeaturePhrase XDelta3FeatureSecondaryCompressor =
      "it declares a secondary compressor, a second layer of packing inside the patch"
    xdelta3FeaturePhrase XDelta3FeatureApplicationHeader =
      "it carries an application header, a note from the tool that made it"
    xdelta3FeaturePhrase XDelta3FeatureWindowChecksum =
      "it carries a per-window Adler32 checksum"

renderSlapError (VCDIFFReservedIndicatorBits indicatorKind rawByte (ReservedBitsSet undefinedBits)) =
  formatLabelName LabelVCDIFF
  <> ": this patch is flagged as carrying something slap doesn't know how to read."
  <> " An indicator byte's bits say what fields come next, so slap can't skip"
  <> " an unknown one and read on. (the " <> indicatorKindName indicatorKind
  <> " is 0x" <> padHex 2 rawByte <> "; " <> reservedBitsClause <> ")"
  where
    reservedBitsClause =
      case [bitNumber | bitNumber <- [0 .. 7 :: Int], testBit undefinedBits bitNumber] of
        [loneBit] -> "its bit " <> renderAsText loneBit
                     <> " is reserved, and nothing has defined it yet"
        manyBits  -> "its bits " <> joinedWithAnd (map renderAsText manyBits)
                     <> " are reserved, and nothing has defined them yet"
    joinedWithAnd :: [Text] -> Text
    joinedWithAnd []                    = ""
    joinedWithAnd [only]                = only
    joinedWithAnd [nextToLast, final]   = nextToLast <> " and " <> final
    joinedWithAnd (leading : remaining) = leading <> ", " <> joinedWithAnd remaining

renderSlapError (VCDIFFUnknownSecondaryCompressor idByte) =
  formatLabelName LabelVCDIFF
  <> ": slap doesn't know how to unpack this patch (it declares secondary compressor "
  <> renderAsText idByte <> ", and slap knows only three: 1 for DJW, 2 for LZMA, 16 for FGK)"

renderSlapError (MalformedVCDIFF malformation) =
  formatLabelName LabelVCDIFF <> ": " <> case malformation of
    VCDIFFBothSourceAndTargetWindowBits ->
      "slap can't tell where part of this patch copies from: it marks off a slice of material"
      <> " for its copies to read, and claims that slice is in the input and in the output"
      <> " at once (a window's indicator sets both VCD_SOURCE, meaning the input,"
      <> " and VCD_TARGET, meaning the output built so far)"
    VCDIFFCopyReadsUnwrittenOutput actionIndex ->
      "record " <> renderAsText (unActionIndex actionIndex)
      <> "'s copy reads from a part of the output the patch hasn't produced yet"
    VCDIFFCopyAddressNegative actionIndex (ActualOffset address) ->
      "record " <> renderAsText (unActionIndex actionIndex)
      <> "'s copy asks to read from position " <> renderAsText (unOffset address)
    VCDIFFCopyCrossesSourceSegmentEnd actionIndex ->
      "record " <> renderAsText (unActionIndex actionIndex)
      <> "'s copy reads past the end of the material it copies from"
      <> " (it starts inside the source segment and its length carries it past the segment's end)"
    VCDIFFWindowSizeMismatch (ExpectedSize expected) (ActualSize actual) ->
      "this patch promises one amount of output and builds another (one of its windows declares "
      <> renderAsText (unFileSize expected) <> " bytes; its instructions produce "
      <> renderAsText (unFileSize actual) <> ")"
    VCDIFFSectionExhausted section actionIndex ->
      "record " <> renderAsText (unActionIndex actionIndex)
      <> " runs out of bytes partway through (the " <> vcdiffSectionName section
      <> " section it draws on ends before the record does)"
    VCDIFFInvalidCopyAddressMode actionIndex modeByte highestValidMode ->
      "record " <> renderAsText (unActionIndex actionIndex)
      <> "'s copy names a way of writing its address that this patch never set up"
      <> " (it uses address mode " <> renderAsText modeByte
      <> ", and the patch's address caches define only modes 0 through "
      <> renderAsText highestValidMode <> ")"
    VCDIFFDeltaEncodingLengthMismatch (ExpectedSize declared) (ActualSize measured) ->
      "one chunk of this patch says it is " <> renderAsText (unFileSize declared)
      <> " bytes long and measures " <> renderAsText (unFileSize measured)
      <> " (a window's declared delta-encoding length doesn't match the span of its own fields)"
    VCDIFFSectionUnconsumedBytes onDemandSection (ExpectedSize declared) (Length leftover) ->
      let (sectionName, sectionReaders) = case onDemandSection of
            OnDemandDataSection    -> ("data", "its ADD and RUN instructions")
            OnDemandAddressSection -> ("address", "its COPY instructions")
      in "this patch sets aside " <> renderAsText leftover
         <> plural leftover " byte" " bytes"
         <> " that nothing reads. Each part of a VCDIFF patch is exactly as long as"
         <> " what it holds, so something has gone wrong here. (one window's "
         <> sectionName <> " section declares " <> renderAsText (unFileSize declared)
         <> " bytes; " <> sectionReaders <> " read "
         <> renderAsText (unFileSize declared - leftover) <> ")"
    VCDIFFCompressedSectionWithoutDeclaredSize section varintFailure ->
      "part of this patch is compressed, and it doesn't say how big it unpacks to."
      <> " VCDIFF works by having every part announce its own size in advance;"
      <> " without that number there is no way to read what follows. (the "
      <> vcdiffSectionName section <> " section is flagged compressed, and the size varint"
      <> " that should open it "
      <> (case varintFailure of
            VarintRanPastEndOfInput ->
              "runs off the end of the section"
            VarintTooManyContinuationBytes ->
              "names a number of 2^64 or more, too big to be a size"
            VarintExceedsSignedButFitsUnsigned ->
              "names a number that needs the 64th bit, which slap cannot carry")
      <> ")"
    VCDIFFCompressedSectionDeclaresEmptyOutput section ->
      "this patch says one of its compressed pieces unpacks to nothing, which no compressor"
      <> " produces: squeezing even an empty run of bytes leaves a little framing behind"
      <> " (the " <> vcdiffSectionName section
      <> " section is flagged compressed and declares an unpacked size of 0)"
    VCDIFFCompressedSectionWithoutCompressor section ->
      "part of this patch is marked compressed, and the patch never says what compressed it"
      <> " (a window flags its " <> vcdiffSectionName section
      <> " section compressed; the header names no secondary compressor)"
    VCDIFFSecondaryStreamUnconsumedInput section algorithm (Length leftover) ->
      "this patch holds " <> renderAsText leftover
      <> plural leftover " byte" " bytes"
      <> " of compressed data that nothing unpacks. A compressed stream is exactly as long"
      <> " as what it encodes, so something has gone wrong here. (the "
      <> secondaryStreamPossessive section algorithm
      <> " finished with " <> renderAsText leftover
      <> plural leftover " byte" " bytes" <> " of its input unused)"
    VCDIFFSecondaryStreamOutputSizeMismatch section algorithm
        (ExpectedSize declared) (ActualSize produced) ->
      "this patch says how big its compressed data unpacks to, and it's wrong (the "
      <> secondaryStreamPossessive section algorithm
      <> " decoded to " <> renderAsText (unFileSize produced) <> " bytes; "
      <> (case secondaryStreamGranularity algorithm of
            GatheredAcrossSections -> "the sections declare "
            EachSectionItsOwn      -> "the section declares ")
      <> renderAsText (unFileSize declared) <> ")"

renderSlapError (MalformedVCDIFFCodeTable malformation) =
  formatLabelName LabelVCDIFF <> ": " <> case malformation of
    VCDIFFCodeTableWrongLength (ActualLength (Length actualLength)) ->
      "the instruction table this patch brought with it is the wrong size"
      <> " (a code table is always 1536 bytes, six 256-byte slices; this one comes out "
      <> renderAsText actualLength <> ")"
    VCDIFFCodeTableInvalidInstructionType typeCode ->
      "the instruction table this patch brought with it names an instruction"
      <> " that doesn't exist (an entry's type byte reads " <> renderAsText typeCode
      <> "; VCDIFF has only four instructions: 0 no-op, 1 add, 2 run, 3 copy)"
    VCDIFFCodeTableHeaderTooShort ->
      "the instruction table this patch brought with it is cut off at the very start"
      <> " (a table opens with two bytes naming its address-cache sizes, and they aren't both there)"
    VCDIFFCodeTableUnusedFieldSet templateKind field byte ->
      "an entry in the instruction table this patch brought with it puts a value in a slot"
      <> " that entry doesn't use (its " <> codeTableFieldName field
      <> " byte reads 0x" <> padHex 2 byte <> " on " <> codeTableTemplateKindPhrase templateKind
      <> ", an instruction that takes no " <> codeTableFieldName field
      <> ", where the only meaningful value is zero)"
    VCDIFFCodeTableCopyModeOutOfRange mode highestValidMode ->
      "the instruction table this patch brought with it doesn't agree with itself about"
      <> " how copy addresses are written (one of its entries gives copies address mode "
      <> renderAsText mode <> ", while the table's own cache sizes only create modes 0 through "
      <> renderAsText highestValidMode <> ")"

renderSlapError (MalformedBSDiffHeader (BSDiffNegativeHeaderSizes control diff target)) =
  formatLabelName LabelBSDiff
  <> ": the header declares a negative size (control "
  <> renderAsText (unControlSectionSize control) <> ", diff " <> renderAsText (unDiffSectionSize diff)
  <> ", target " <> renderAsText (unTargetSectionSize target) <> ")"

renderSlapError (MalformedBSDiffHeader (BSDiffControlOverrunsPatch overrunBytes)) =
  formatLabelName LabelBSDiff
  <> ": the header describes more data than the patch holds (the control block's declared size reaches "
  <> renderAsText overrunBytes <> plural overrunBytes " byte" " bytes"
  <> " past the end of the patch)"

renderSlapError (MalformedBSDiffHeader (BSDiffDiffOverrunsPatch overrunBytes)) =
  formatLabelName LabelBSDiff
  <> ": the header describes more data than the patch holds (the diff block's declared size reaches "
  <> renderAsText overrunBytes <> plural overrunBytes " byte" " bytes"
  <> " past the end of the patch)"

renderSlapError (MalformedAPSN64Header malformation) =
  formatLabelName LabelAPSN64 <> ": " <> case malformation of
    APSN64UnknownPatchType byte ->
      "the patch declares patch type " <> renderAsText byte <> ", which the format does not define"
    APSN64UnsupportedEncoding byte ->
      "the patch declares encoding method " <> renderAsText byte <> ", which slap does not support"

renderSlapError (PPF4ReplaceAfterAppend recordIndex) =
  formatLabelName LabelPPF4 <> ": record "
  <> renderAsText (unActionIndex recordIndex)
  <> " is a Replace after an Append; PPF4 is two-phase — once an Append"
  <> " record appears, every subsequent record must also be Append"

renderSlapError (XDelta1UnknownInstructionTarget listShape wireIndex) =
  formatLabelName LabelXDelta1
  <> ": an instruction copies from a source the patch doesn't have; it asks for source "
  <> renderAsText wireIndex <> ", but " <> case listShape of
       SourceListDataAndFile ->
         "the patch lists only two: 0 (its own data) and 1 (the input file)"
       SourceListDataOnly ->
         "the patch lists only one: 0 (its own data)"
       SourceListFileOnly ->
         "the patch lists only one: 0 (the input file)"
       SourceListEmpty ->
         "the patch lists none (its declared target is empty, so no instruction should reference a source at all)"

renderSlapError (XDelta1DanglingDataSegment (ActualSize segmentSize)) =
  formatLabelName LabelXDelta1
  <> ": this patch carries " <> renderAsText (unFileSize segmentSize)
  <> " bytes of its own data, but nothing in its source list points to them,"
  <> " so no instruction can read those bytes."
  <> " data left unreferenced means the patch's control and data segments no longer describe"
  <> " the same thing, a sign it was truncated or corrupted"

renderSlapError (XDelta1DataRecordLengthMismatch (ExpectedSize declared) (ActualSize actual)) =
  formatLabelName LabelXDelta1
  <> ": the patch disagrees with itself about how much data it carries;"
  <> " the header for its own data says " <> renderAsText (unFileSize declared)
  <> " bytes, but the data that follows measures " <> renderAsText (unFileSize actual)
  <> " (both describe the same bytes, so slap can't tell which to trust)"

renderSlapError (XDelta1DataRecordMD5Mismatch declared computed) =
  formatLabelName LabelXDelta1
  <> ": the patch's header records a checksum for its own bundled data that the data doesn't match"
  <> " (header MD5 " <> hexByteString (unMD5Hash declared)
  <> "; the data hashes to " <> hexByteString (unMD5Hash computed)
  <> "). both describe the same bytes, so slap can't tell which to trust"

renderSlapError (XDelta1InputPreCompressionUnsupported sides) =
  formatLabelName LabelXDelta1
  <> ": slap can't apply this patch; it was built expecting " <> describeSides sides
  <> " to arrive gzip-compressed and be unpacked on the fly, which slap doesn't do yet"
  <> " (xdelta 1.x quietly unzips gzip-compressed inputs before diffing and re-zips after applying;"
  <> " this patch's FROM_COMPRESSED / TO_COMPRESSED header bits record that it did)"
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

renderSlapError (PatchCarriesNoUndoData label) = case label of
  LabelNINJA2 ->
    "this NINJA2 patch carries no undo data\n"
    <> "the patch shrinks its file, but its overflow section is marked append rather than truncate,"
    <> " so the bytes the shrink discarded were never stored"
  _ ->
    "this " <> formatLabelName label <> " patch carries no undo data\n"
    <> formatLabelName label <> " patches can carry the bytes each record replaced,"
    <> " but including them was up to the patch's author, and this one was made without them"

renderSlapError (NoUndoForFormat label) =
  "no undo for " <> formatLabelName label <> " patches"

renderSlapError (PatchCarriesMultipleFiles label (CarriedFileCount fileCount)) =
  "this " <> formatLabelName label <> " patch carries " <> renderAsText fileCount <> " files\n"
  <> "a " <> formatLabelName label <> " patch can bundle several files;"
  <> " slap reads the whole bundle and shows it, and applies, undoes, and converts single-file patches only"

renderSlapError (UnencodeablePair label reason) =
  formatLabelName label <> ": can't encode this input and output as a patch: "
  <> renderUnencodeabilityReason label reason

renderSlapError (NarrowingError nf) = renderNarrowingFailure nf

renderSlapError (FileExceedsAddressableRange label (ActualSize actualSize) (MaxAddressableSize maxSize)) =
  formatLabelName label <> ": input file is "
  <> renderAsText (unFileSize actualSize) <> " bytes, exceeding the host platform's "
  <> renderAsText (unFileSize maxSize) <> "-byte addressable range"

renderSlapError (VCDIFFPairExceedsAddressableRange
                   (SourceFileSize sourceSize) (TargetFileSize targetSize) (MaxAddressableSize _maxSize)) =
  formatLabelName LabelVCDIFF
  <> ": to build this diff, slap lays the input and output end to end and indexes the whole span; here it comes to "
  <> renderAsText (unFileSize sourceSize) <> " + " <> renderAsText (unFileSize targetSize)
  <> " bytes plus two separator bytes, reaching "
  <> renderAsText (toInteger (unFileSize sourceSize) + toInteger (unFileSize targetSize) + 2)
  <> ", past " <> slapAddressableCeiling <> ", the largest span slap can address"

renderSlapError (SentinelCollisionUnfixable label (SentinelOffset sentinel)) =
  formatLabelName label <> ": a record writes at offset 0x"
  <> renderHexAsText (unOffset sentinel)
  <> ", which on the wire is the exact byte pattern of the marker that ends "
  <> formatLabelWithIndefiniteArticle label
  <> " patch; a reader would stop there and drop everything after it."
  <> " slap normally nudges such a record one byte earlier to sidestep the clash,"
  <> " but here there's no earlier source byte to borrow, so it can't."

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

renderSlapError (MissingRequiredFields label fields) =
  case NonEmpty.toList fields of
    [single] ->
      formatLabelName label <> " requires " <> fieldName single
      <> " but source patch doesn't provide it"
    many ->
      formatLabelName label <> " requires fields the source patch doesn't provide:"
      <> Text.concat (map (\field -> "\n  - " <> fieldName field) many)

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

renderSlapError (ConvertRequiresSource label cause) =
  "converting from " <> formatLabelName label
  <> " requires the original ROM (--with INPUT)\n"
  <> formatLabelName label <> " " <> causeClause <> "."
  <> " To convert it, we'd apply the patch to the input first and convert the result"
  <> " — which is why we need the input."
  where
    causeClause = case cause of
      SourcePatchIsDifferential -> "tells us what to change in the input ROM, not what the result should be"
      SourcePatchNotReencodable -> "can't be converted directly into another patch format"

renderSlapError (MetadataFieldRejected requests target) =
  let renderOne request =
        "--" <> requestFlagName request
        <> " (" <> metadataFieldName (requestField request) <> ")"
      -- Only a request that arrived on a drop flag earns the extra clause: such a request is not just unaccepted, it is about nothing.
      dropTail (DropField _)        = ", so there is nothing to drop"
      dropTail (SetField _)         = ""
      dropTail (SetFieldFromText _) = ""
  in case NonEmpty.toList requests of
       [single] ->
         "--" <> requestFlagName single <> " is not accepted by "
         <> formatLabelName target
         <> " (the " <> metadataFieldName (requestField single) <> " field is not part of this format" <> dropTail single <> ")"
       many ->
         formatLabelName target
         <> " does not accept these flags:"
         <> Text.concat (map (\request -> "\n  - " <> renderOne request) many)

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

renderSlapError SecondaryCompressorRequestedWithCompressionOff =
  "--compress-with is not accepted alongside --no-compress"
  <> " (with compression switched off, there is nothing for the chosen compressor to do)"

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
  <> ": this flag asks for a patch SNESTool can apply, but SNESTool won't accept a "
  <> renderAsText (unFileSize size) <> "-byte truncation;"
  <> " it only takes sizes shaped like a copier-headered SNES ROM,"
  <> " a multiple of 4096 plus 512 (size & 0xFFF == 0x200)."

renderSlapError (VerificationFatal mismatch) =
  renderVerificationMismatch mismatch <> "\n  use --no-verify to proceed anyway"

-- Deliberate twins in web-reactor/envelope-worker.mjs say nearly the same thing for the failures no envelope can cross
-- (a refused seat allocation, a mid-act trap); an edit here should visit them.
renderSlapError ReactorMemoryExhausted =
  "these files don't fit in the browser's memory; the slap command line has no such ceiling"

renderNarrowingFailure :: NarrowingFailure -> Text
renderNarrowingFailure (OffsetExceedsBound label (ActualOffset actual) (MaxOffset maxOffset)) =
  formatLabelName label <> ": a record writes at offset 0x"
  <> renderHexAsText (unOffset actual)
  <> ", but " <> formatLabelWithIndefiniteArticle label
  <> " patch can only address up to 0x"
  <> renderHexAsText (unOffset maxOffset)
  <> "; that write is past the format's reach"
renderNarrowingFailure (NegativeOffset label (ActualOffset actual)) =
  formatLabelName label <> ": a record sits at a negative offset ("
  <> renderAsText (unOffset actual)
  <> "), but " <> formatLabelWithIndefiniteArticle label
  <> " patch can only address positions from 0 onward; there's nowhere to put this write"
renderNarrowingFailure (FieldValueExceedsBound label field actual maxValue) =
  formatLabelName label <> ": the " <> fieldNameLabel field
  <> " is " <> renderAsText actual
  <> ", but " <> formatLabelWithIndefiniteArticle label <> " patch's "
  <> fieldNameLabel field <> " field holds at most " <> renderAsText maxValue
  <> ", so it doesn't fit"

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
  "the output is smaller than the input, so the patch would need a truncation marker"
  <> " to record the trimmed size, and that marker's field is only 24 bits:"
  <> " it can't name 0x" <> renderHexAsText (unFileSize targetSize)
  <> " bytes, past its 0x" <> renderHexAsText (unOffset markerMaximum) <> " ceiling"
renderUnencodeabilityReason _label
  (GrowthReachesPastAddressableRange (DeclaredTargetSize targetSize) (MaxWritableSize writableCeiling)) =
  "the output is larger than the input, so every byte past the input's end must be written,"
  <> " but records reach no further than 0x" <> renderHexAsText (unFileSize writableCeiling)
  <> ": an output of 0x" <> renderHexAsText (unFileSize targetSize) <> " bytes ends out of reach"

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
