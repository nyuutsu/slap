{-# LANGUAGE OverloadedStrings #-}

-- | Where a 'SlapAdvisory' becomes the words the user reads.
module Slap.Status.Render.Advisory
  ( renderSlapAdvisory
  , renderVerificationMismatch
  , plural
  ) where

import Slap.Checksum (showCRC32, showAdler32, ExpectedCRC32(..), ActualCRC32(..))
import Slap.Display.Common (renderAsText, proseList)
import Slap.Display.Primitives (padHex)
import Slap.FieldName (fieldNameLabel)
import Slap.FormatLabel (FormatLabel(..), formatLabelName)
import Slap.Header (ConsoleHeader, HeaderAdjustment(..), consoleHeaderName, consoleHeaderLength, consoleHeaderToken)
import Slap.Measure (Offset(..), Length(..), FileSize(..), ActionIndex(unActionIndex),
                     ExpectedSize(..), ActualSize(..),
                     DeclaredTargetSize(..), NaturalTargetSize(..),
                     MaxLength(..), OriginalLength(..), TruncatedLength(..),
                     SubstitutionCount(..))
import Slap.PatchField (fieldName)
import Slap.PlatformType (PlatformType(..), platformName)
import Slap.Status.Advisory (SlapAdvisory(..), VerificationMismatch(..), BPSMetadataDivergence(..))
import Slap.Status.Vocabulary (emptyUnitLabel, renderDroppedValue, directionVerb,
                               verificationSideLabel, hashAlgorithmLabel, declaredCheckKindNoun,
                               OverlapCount(..), ClippedRecordCount(..), OOBBlockCount(..),
                               UndoRecordCount(..), MarkerOvershootBytes(..), OOBOvershootBytes(..),
                               ExpectedAdler32(..), ActualAdler32(..), ByteCheckLabel(..),
                               NINJA1SubformatConversion(..),
                               NormalizationStep(..), SNESInterleaveLayout(..),
                               normalizedImageRoleLabel, NormalizationSkipReason(..), RestoredContent(..))
import Slap.Status.XDelta1 (XDelta1SourcelessShape(..))

import Data.List.NonEmpty (NonEmpty)
import qualified Data.List.NonEmpty as NonEmpty
import Data.Text (Text)
import qualified Data.Text as Text

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

renderSlapAdvisory (SourceMatchesAfterHeaderAdjustment adjustment consoles heldKinds) =
  "the input matches the patch's " <> proseList (map declaredCheckKindNoun (NonEmpty.toList heldKinds))
  <> " once a " <> renderAsText (unLength (consoleHeaderLength (NonEmpty.head consoles))) <> "-byte "
  <> slashedConsoleNames consoles <> " header " <> adjustmentPhrase
  <> " (retry with --" <> flagName <> " " <> Text.pack (consoleHeaderToken (NonEmpty.head consoles)) <> ")"
  where
    (adjustmentPhrase, flagName) = case adjustment of
      HeaderComesOff -> ("comes off", "remove-header")
      HeaderGoesOn   -> ("goes on",   "add-header")

renderSlapAdvisory NoHeaderAdjustmentMatches =
  "no header arrangement reconciles the input with this patch; it is most likely a different ROM"

renderSlapAdvisory (InputReframedToMatchPatch adjustment consoles heldKinds) =
  "the input matches the patch's " <> proseList (map declaredCheckKindNoun (NonEmpty.toList heldKinds))
  <> arrangementPhrase <> renderAsText (unLength (consoleHeaderLength (NonEmpty.head consoles))) <> "-byte "
  <> slashedConsoleNames consoles <> " header " <> adjustmentPhrase <> ", and was applied that way; " <> outputRemark
  where
    (arrangementPhrase, adjustmentPhrase, outputRemark) = case adjustment of
      HeaderComesOff -> (" with its ",     "set aside", "the output carries no header")
      HeaderGoesOn   -> (" with a blank ", "put on",    "the output begins with that header")

renderSlapAdvisory (PPFApplyGrewPastSource label (FileSize sourceSize) (Length overflow)) =
  formatLabelName label
  <> ": this patch makes the output longer than the input (input "
  <> renderAsText sourceSize <> " bytes, output extends "
  <> renderAsText overflow <> " bytes further)"
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
  <> plural byteCount " byte" " bytes" <> ", " <> divergencePhrase
  <> "; the spec recommends UTF-8 XML here but permits arbitrary bytes,"
  <> " so this is unusual but valid"
  where
    divergencePhrase = case divergence of
      MetadataBytesSubstituted (SubstitutionCount substituted) ->
        renderAsText substituted <> plural substituted " sequence" " sequences"
        <> " of which aren't valid UTF-8 (substituted U+FFFD)"
      MetadataDecodedButNonText ->
        "valid UTF-8 but carrying non-text control codepoints"

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
  <> " clipped by truncation marker (first at record "
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

renderSlapAdvisory (FileIdDizNonASCII label (Length nonAsciiCount)) =
  formatLabelName label
  <> ": FILE_ID.DIZ has " <> renderAsText nonAsciiCount
  <> plural nonAsciiCount " byte" " bytes"
  <> " outside 7-bit ASCII; the convention is plain ASCII, so older viewers may render them as garbage"

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

renderSlapAdvisory APSN64Type1HeaderDropped =
  formatLabelName LabelAPSN64 <> ": Type-1 N64 header (image format, cart ID,"
  <> " country, CRC) is not carried into the converted patch"

renderSlapAdvisory (ApplyOOBBlocksSkipped label direction (OOBBlockCount count) firstIndex (OOBOvershootBytes overshoot) declaredSize) =
  formatLabelName label <> " " <> directionVerb direction <> ": "
  <> renderAsText count <> plural count " block writes" " blocks write"
  <> " past declared output size ("
  <> renderAsText (unFileSize declaredSize) <> " bytes); first at record "
  <> renderAsText (unActionIndex firstIndex) <> ", "
  <> renderAsText (unLength overshoot) <> plural (unLength overshoot) " byte" " bytes"
  <> " total overshoot — clipped to output bounds"

renderSlapAdvisory (SubformatConverted conversion) = case conversion of
  NINJA1TextToBinary                       ->
    formatLabelName LabelNINJA1 <> " text (T) converted to binary (B)"
  NINJA1CompressedTextToCompressedBinary   ->
    formatLabelName LabelNINJA1 <> " text (TZ) converted to compressed binary (BZ)"

renderSlapAdvisory (DeclaredCheckMismatched mismatch) = renderVerificationMismatch mismatch

renderSlapAdvisory (VerificationOptedOutByCreator label) =
  formatLabelName label
    <> ": creator opted out of verification (--omit-verification); slap cannot attest the output matches the creator's intent"

-- | The words a mismatch speaks — shared by the 'DeclaredCheckMismatched' warnings and the 'Slap.Status.VerificationFatal' refusal.
renderVerificationMismatch :: VerificationMismatch -> Text

renderVerificationMismatch (VerificationCRCMismatch side (ExpectedCRC32 expected) (ActualCRC32 actual)) =
  verificationSideLabel side <> " CRC mismatch (expected 0x"
  <> showCRC32 expected <> ", got 0x" <> showCRC32 actual <> ")"

renderVerificationMismatch (VerificationHashMismatch side algorithm) =
  verificationSideLabel side <> " " <> hashAlgorithmLabel algorithm <> " mismatch"

renderVerificationMismatch (VerificationAdler32Mismatch windowOffset (ExpectedAdler32 expected) (ActualAdler32 actual)) =
  "Adler32 mismatch at window 0x" <> padHex 8 (unOffset windowOffset)
  <> " (expected 0x" <> showAdler32 expected
  <> ", got 0x" <> showAdler32 actual <> ")"

renderVerificationMismatch (VerificationFileSizeMismatch side (ExpectedSize expectedSize) (ActualSize actualSize)) =
  verificationSideLabel side <> " file size mismatch (expected "
  <> renderAsText (unFileSize expectedSize) <> " bytes, got "
  <> renderAsText (unFileSize actualSize) <> " bytes)"

renderVerificationMismatch (VerificationBlockCRC16Mismatch side blockOffset) =
  verificationSideLabel side <> " CRC16 mismatch at 0x" <> padHex 8 (unOffset blockOffset)

renderVerificationMismatch (VerificationPPFBlockMismatch blockOffset) =
  "validation block mismatch at 0x" <> padHex 8 (unOffset blockOffset)

renderVerificationMismatch (VerificationFileSizeAdvisory (ExpectedSize expectedSize) (ActualSize actualSize)) =
  "file size mismatch (expected " <> renderAsText (unFileSize expectedSize)
  <> ", got " <> renderAsText (unFileSize actualSize) <> ")"

renderVerificationMismatch (VerificationSourceBytesMismatch (ByteCheckLabel label) checkOffset) =
  label <> " mismatch at 0x" <> padHex 8 (unOffset checkOffset)

renderVerificationMismatch APSN64ImageFormatMismatch =
  formatLabelName LabelAPSN64 <> ": the source ROM's byte order does not match"
  <> " the image format this patch was built for (V64 vs Z64)"

-- | Choose the singular or plural label for a count. Call sites carry any leading space inside the two label strings.
plural :: (Eq count, Num count) => count -> Text -> Text -> Text
plural n singular pluralForm = if n == 1 then singular else pluralForm

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

snesInterleaveLayoutPhrase :: SNESInterleaveLayout -> Text
snesInterleaveLayoutPhrase EvenOddHalvesLayout  = "even/odd 32 KiB halves"
snesInterleaveLayoutPhrase GD3Chart20MbitLayout = "Game Doctor 20 Mbit chart"
snesInterleaveLayoutPhrase GD3Chart24MbitLayout = "Game Doctor 24 Mbit chart"
snesInterleaveLayoutPhrase GD3Chart48MbitLayout = "Game Doctor 48 Mbit chart"

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

-- | Width-sharing consoles, spoken as one: "NES / FDS".
slashedConsoleNames :: NonEmpty ConsoleHeader -> Text
slashedConsoleNames = Text.intercalate " / " . map consoleHeaderName . NonEmpty.toList

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
