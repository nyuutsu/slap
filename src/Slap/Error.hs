{-# LANGUAGE StrictData #-}

module Slap.Error
  ( SlapError(..)
  , SlapWarning(..)
  , ApplyError(..)
  , CursorKind(..)
  , UnencodeabilityReason(..)
  , DroppedValue(..)
  , CreateResult(..)
  , Parsed(..)
  , FieldName(..)
  , fieldNameLabel
  , renderSlapError
  , renderApplyError
  , renderCursorKind
  , renderSlapWarning
  ) where

import Numeric (showHex)
import Slap.FileContents (PatchFileContents)
import Slap.FormatLabel (FormatLabel, formatLabelName)
import Slap.Checksum (CRC32, MD5Hash(..), SHA1Hash(..), showCRC32,
                      ExpectedCRC32(..), ActualCRC32(..))
import Slap.Format (hexByteString, renderPrintableASCIIOrHex)
import Slap.Measure (Offset(..), Length(..), FileSize(..),
                     SignedOffset(..), ActionIndex(..),
                     ReadOffset(..), WritePosition(..),
                     RequestedLength(..), RemainingLength(..),
                     ActualSize(..), ExpectedSize(..),
                     MaxAddressableSize(..),
                     RequiredLength(..), ActualLength(..),
                     EncodedLength(..), MaxLength(..),
                     OriginalLength(..), TruncatedLength(..),
                     ActualOffset(..), MaxOffset(..),
                     SentinelOffset(..),
                     ExpectedMagic(..), ActualMagic(..),
                     TrailerMarker(..),
                     ParsedSizeValue(..), FoundVersion(..),
                     RawFlagByte(..), EncodingMethodByte(..))
import Slap.PatchField (PatchField, fieldName)

import Data.ByteString (ByteString)

----------------------------------------------------------------------------
-- FieldName
----------------------------------------------------------------------------

data FieldName
  -- Metadata fields
  = FieldTitle
  | FieldAuthor
  | FieldDescription
  | FieldVersion
  | FieldPatchName
  | FieldGenre
  | FieldLanguage
  | FieldDate
  | FieldWebsite
  -- Header fields
  | FieldRomType
  | FieldImageType
  | FieldPatchEncoding
  | FieldStability
  | FieldPatchType
  | FieldImageFormat
  | FieldCartId
  | FieldCountry
  | FieldEncodingMethod
  -- Sizes
  | FieldSourceSize
  | FieldTargetSize
  | FieldDestinationSize
  -- Checksums
  | FieldSourceCRC
  | FieldTargetCRC
  | FieldPatchCRC
  -- Record fields
  | FieldRLERunLength
  | FieldRecordMode
  deriving (Show, Eq, Enum, Bounded)

fieldNameLabel :: FieldName -> String
fieldNameLabel FieldTitle           = "title"
fieldNameLabel FieldAuthor          = "author"
fieldNameLabel FieldDescription     = "description"
fieldNameLabel FieldVersion         = "version"
fieldNameLabel FieldPatchName       = "name"
fieldNameLabel FieldGenre           = "genre"
fieldNameLabel FieldLanguage        = "language"
fieldNameLabel FieldDate            = "date"
fieldNameLabel FieldWebsite         = "website"
fieldNameLabel FieldRomType         = "ROM type"
fieldNameLabel FieldImageType       = "image type"
fieldNameLabel FieldPatchEncoding   = "patch encoding"
fieldNameLabel FieldStability       = "stability flag"
fieldNameLabel FieldPatchType       = "patch type"
fieldNameLabel FieldImageFormat     = "image format"
fieldNameLabel FieldCartId          = "cart ID"
fieldNameLabel FieldCountry         = "country"
fieldNameLabel FieldEncodingMethod  = "encoding method"
fieldNameLabel FieldSourceSize      = "source size"
fieldNameLabel FieldTargetSize      = "target size"
fieldNameLabel FieldDestinationSize = "destination size"
fieldNameLabel FieldSourceCRC       = "source CRC"
fieldNameLabel FieldTargetCRC       = "target CRC"
fieldNameLabel FieldPatchCRC        = "patch CRC"
fieldNameLabel FieldRLERunLength    = "RLE run length"
fieldNameLabel FieldRecordMode      = "record mode"

----------------------------------------------------------------------------
-- DroppedValue
----------------------------------------------------------------------------

data DroppedValue
  = DroppedCRC CRC32
  | DroppedMD5 MD5Hash
  | DroppedSHA1 SHA1Hash
  | DroppedDescription String
  | DroppedSize FileSize
  | DroppedEmpty
  deriving (Show, Eq)

renderDroppedValue :: DroppedValue -> String
renderDroppedValue (DroppedCRC crc)             = "0x" ++ showCRC32 crc
renderDroppedValue (DroppedMD5 hash)            = hexByteString (unMD5Hash hash)
renderDroppedValue (DroppedSHA1 hash)           = hexByteString (unSHA1Hash hash)
renderDroppedValue (DroppedDescription text)    = "\"" ++ text ++ "\""
renderDroppedValue (DroppedSize size)           = show (unFileSize size) ++ " bytes"
renderDroppedValue DroppedEmpty                 = ""

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

-- | Why a (source, target) pair cannot be encoded as a UPS patch.
-- Per the UPS spec, each diff run must end with a terminator byte
-- that counts against the target file pointer; this makes certain
-- byte configurations impossible to represent.
data UnencodeabilityReason
  = UPSLastByteDiffers     -- ^ target's final byte differs from source (with
                           --   virtual zero-padding past source end), so any
                           --   diff run at that position would need a terminator
                           --   past target end
  | UPSSourceTailNonZero   -- ^ source has non-zero bytes past target size,
                           --   which appear as diffs against virtual-zero
                           --   target and cannot be represented without
                           --   writing past target end
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
  | ApplyTargetUnderfilled ActualSize ExpectedSize

  -- | A record's offset is negative. Only possible for formats that
  -- store signed offsets (PPF3 uses signed 64-bit). The Offset is
  -- the negative value as parsed.
  | ApplyNegativeRecordOffset ActionIndex Offset

  deriving (Show, Eq)

----------------------------------------------------------------------------
-- SlapError
----------------------------------------------------------------------------

data SlapError

  -- Detection
  = UnrecognizedFormat
  | AmbiguousDetection [FormatLabel]

  -- Parse: structural
  | InputTooShort FormatLabel RequiredLength ActualLength
  | BadMagic FormatLabel ActualMagic
  | BadVersion FormatLabel FoundVersion
  | UnsupportedSubformat FormatLabel String
  | TruncatedRecord FormatLabel Int Length Length
  | NegativeSize FormatLabel FieldName ParsedSizeValue
  | DecompressionFailed FormatLabel String

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
  -- accepts an empty post-@"EOF"@ trailer, a Flips-style truncation
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
  | MalformedTextField FormatLabel String
  | EntryOutsideBlock FormatLabel String

  -- Parse: generic Get monad failures
  | ParseError FormatLabel String

  -- Apply
  | NegativeTargetSize FormatLabel FileSize
  | ApplyFailed FormatLabel ApplyError

  -- Undo
  | UndoFailed FormatLabel ApplyError

  -- Create / Encode
  | CannotExpressTargetShrinkage FormatLabel ActualSize ExpectedSize
  | UPSUnencodeablePair FormatLabel UnencodeabilityReason
  | OffsetExceedsRange FormatLabel ActualOffset MaxOffset

  -- | A create-path input (source or target) is larger than the
  -- host platform's addressable range. slap's varint encoders
  -- shuttle lengths through 'Int', so on a 32-bit platform where
  -- 'Int' is 31-bit-addressable, a file over ~2 GB would truncate
  -- via 'fromIntegral' and produce a malformed patch. The
  -- 'ActualSize' is the offending file's size; the
  -- 'MaxAddressableSize' is the host's 'maxBound :: Int'. On 64-bit
  -- platforms the cap is ~9 EB and this error is effectively dead.
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

  | FieldTooLong FormatLabel FieldName EncodedLength MaxLength
  | EncodingFailure FormatLabel FieldName String

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
  -- target that would work. Only 'FTruncation' reaches this error
  -- today; the list shape exists so future apply-output-affecting
  -- fields drop into the same refusal path without new plumbing.
  | ApplyOutputFieldsWouldBeDropped FormatLabel [(PatchField, [FormatLabel])]

  | DiffRequiresSource FormatLabel

  -- Container
  | Yay0DecompressionFailed String

  deriving (Show, Eq)

----------------------------------------------------------------------------
-- SlapWarning
----------------------------------------------------------------------------

data SlapWarning

  -- Patch quality
  = EmptyPatch FormatLabel String
  | NoEOFMarker FormatLabel

  -- | An IPS-family RLE record whose run-length field was zero was
  -- accepted verbatim as a no-op. The spec does not speak to the
  -- case, and slap's live encoder never emits it; the warning
  -- signals a parsed oddity so the user can decide whether the
  -- source patch is trustworthy. The 'ActionIndex' names the
  -- offending record's position in the wire record stream.
  | ZeroCountRLERecord FormatLabel ActionIndex

  -- | Two IPS-family records write to overlapping regions of the
  -- target. Overlap is permitted and well-defined (later writes
  -- clobber earlier ones), but it's unusual enough that slap flags
  -- each overlapping pair for the reader. The 'ActionIndex' pair
  -- is @(earlierRecord, laterRecord)@ in wire order: the record
  -- written first and then clobbered, followed by the record whose
  -- writes do the clobbering.
  | OverlappingRecords FormatLabel ActionIndex ActionIndex

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
  -- that did not match any recognised post-trailer shape. slap drops
  -- the trailing slice and proceeds. 'StandardIPS' has three
  -- well-attested post-@"EOF"@ shapes (empty, Flips truncation
  -- marker, EBP JSON blob) and keeps its strict rejection of
  -- garbage trailers; 'IPS32' has none, and a lenient drop is the
  -- useful choice in the absence of a shape to recognise. The
  -- 'Length' is the byte count dropped.
  | IPS32TrailingBytes FormatLabel Length

  -- Conversion: dropped fields
  | FieldDropped PatchField DroppedValue
  | UndoDataDropped Int
  | ValidationBlockDropped
  | DisabledEntriesDropped Int
  | BlockDescriptionsDropped
  | MetadataDropped Int

  -- Conversion: defaults assumed
  | DefaultRomType FormatLabel
  | DefaultImageType FormatLabel
  | IncludingUndoByDefault
  | IncludingValidationByDefault
  | SourceHashesMissing FormatLabel

  -- Encoding
  | FieldTruncated FormatLabel FieldName OriginalLength TruncatedLength
  | EncodingGap FormatLabel FormatLabel

  -- Platform conversion
  | PlatformNotAvailable FormatLabel String  -- target format, platform name
  | PlatformAmbiguous FormatLabel String String String  -- source format, combined name, default name, override value

  -- Apply: out-of-bounds block clipping
  | ApplyOOBBlocksSkipped FormatLabel Int ActionIndex Length FileSize

  -- Format-specific
  | SubformatConverted FormatLabel String String
  | OffsetShiftApplied

  deriving (Show, Eq)

----------------------------------------------------------------------------
-- CreateResult
----------------------------------------------------------------------------

data CreateResult = CreateResult
  { resultBytes    :: !PatchFileContents
  , resultWarnings :: ![SlapWarning]
  } deriving (Show)

----------------------------------------------------------------------------
-- Parsed
----------------------------------------------------------------------------

-- | The parse-side companion to 'CreateResult': a successfully parsed
-- payload paired with any warnings the parser accumulated. Today every
-- parser emits an empty warning list; the channel is infrastructure for
-- future parsers that want to flag recoverable shape anomalies without
-- failing outright.
data Parsed value = Parsed
  { parsedValue    :: !value
  , parsedWarnings :: ![SlapWarning]
  } deriving (Show)

----------------------------------------------------------------------------
-- renderApplyError
----------------------------------------------------------------------------

renderCursorKind :: CursorKind -> String
renderCursorKind SourceCursor = "source-relative"
renderCursorKind TargetCursor = "target-relative"

renderApplyError :: ApplyError -> String

renderApplyError (ApplyCursorUnderflow cursorKind actionIndex cursor) =
  "at step #" ++ show (unActionIndex actionIndex) ++ ": "
  ++ renderCursorKind cursorKind ++ " cursor underflowed (value "
  ++ show (unSignedOffset cursor) ++ ")"

renderApplyError (ApplySourceReadOutOfBounds actionIndex readEndOffset sourceSize) =
  "at step #" ++ show (unActionIndex actionIndex)
  ++ ": source read would end at offset 0x"
  ++ showHex (unOffset readEndOffset) ""
  ++ " but source is " ++ show (unFileSize sourceSize) ++ " bytes"

renderApplyError (ApplyTargetReadUnwritten actionIndex (ReadOffset readOffset) (WritePosition writePosition)) =
  "at step #" ++ show (unActionIndex actionIndex)
  ++ ": TargetCopy read at offset 0x"
  ++ showHex (unOffset readOffset) ""
  ++ " references position at or past current write position 0x"
  ++ showHex (unOffset writePosition) ""

renderApplyError (ApplyWritesPastTarget actionIndex (RequestedLength requestedLength) (RemainingLength remainingLength)) =
  "at step #" ++ show (unActionIndex actionIndex)
  ++ ": action of length " ++ show (unLength requestedLength)
  ++ " would write past target ("
  ++ show (unLength remainingLength) ++ " bytes remaining)"

renderApplyError (ApplyTargetUnderfilled (ActualSize actualSize) (ExpectedSize expectedSize)) =
  "target under-filled ("
  ++ show (unFileSize actualSize) ++ " of "
  ++ show (unFileSize expectedSize) ++ " bytes written before action stream exhausted)"

renderApplyError (ApplyNegativeRecordOffset actionIndex offset) =
  "record " ++ show (unActionIndex actionIndex)
  ++ " has negative offset " ++ show (unOffset offset)

----------------------------------------------------------------------------
-- renderSlapError
----------------------------------------------------------------------------

renderSlapError :: SlapError -> String

renderSlapError UnrecognizedFormat =
  "unknown patch format"

renderSlapError (AmbiguousDetection labels) =
  "ambiguous format: could be "
  ++ commaList (map formatLabelName labels)

renderSlapError (InputTooShort label (RequiredLength needed) (ActualLength actual)) =
  formatLabelName label ++ ": input too short (need "
  ++ show (unLength needed) ++ " bytes, have "
  ++ show (unLength actual) ++ ")"

renderSlapError (BadMagic label (ActualMagic actualBytes)) =
  "not a " ++ formatLabelName label ++ " file (bad magic: "
  ++ show actualBytes ++ ")"

renderSlapError (BadVersion label (FoundVersion versionByte)) =
  formatLabelName label ++ ": unsupported version "
  ++ show versionByte

renderSlapError (UnsupportedSubformat label subformat) =
  formatLabelName label ++ ": unsupported subformat: "
  ++ subformat

renderSlapError (TruncatedRecord label recordIndex needed available) =
  formatLabelName label ++ ": record " ++ show recordIndex
  ++ " truncated (need " ++ show (unLength needed)
  ++ " bytes, have " ++ show (unLength available) ++ ")"

renderSlapError (NegativeSize label name (ParsedSizeValue value)) =
  formatLabelName label ++ ": negative "
  ++ fieldNameLabel name ++ ": " ++ show value

renderSlapError (DecompressionFailed label detail) =
  formatLabelName label ++ ": decompression failed: " ++ detail

renderSlapError (RecordExceedsAddressableRange label recordIndex (ActualOffset endOffset) (MaxOffset maxEndOffset)) =
  formatLabelName label ++ ": record " ++ show (unActionIndex recordIndex)
  ++ " ends at offset 0x" ++ showHex (unOffset endOffset) ""
  ++ ", exceeding the variant's maximum addressable end 0x"
  ++ showHex (unOffset maxEndOffset) ""

renderSlapError (MalformedRecordField label recordIndex name) =
  formatLabelName label ++ ": record " ++ show (unActionIndex recordIndex)
  ++ " has malformed " ++ fieldNameLabel name

renderSlapError (UnrecognizedTrailer label (TrailerMarker markerBytes) (ActualLength actualLength)) =
  formatLabelName label ++ ": unrecognized trailing bytes after "
  ++ renderTrailerMarkerName markerBytes ++ " marker ("
  ++ show (unLength actualLength) ++ " bytes)"

renderSlapError (PatchCRCMismatch label (ExpectedCRC32 stored) (ActualCRC32 computed)) =
  formatLabelName label ++ ": patch CRC mismatch (stored "
  ++ showCRC32 stored ++ ", computed " ++ showCRC32 computed ++ ")"

renderSlapError (TrailingMagicMismatch label (ExpectedMagic expected) (ActualMagic actual)) =
  formatLabelName label ++ ": trailing magic mismatch (expected "
  ++ show expected ++ ", found " ++ show actual ++ ")"

renderSlapError (UnknownFlag label name (RawFlagByte flagByte)) =
  formatLabelName label ++ ": unknown "
  ++ fieldNameLabel name ++ " flag: 0x"
  ++ showHex flagByte ""

renderSlapError (UnsupportedEncodingMethod label (EncodingMethodByte methodByte)) =
  formatLabelName label ++ ": unsupported encoding method: 0x"
  ++ showHex methodByte ""

renderSlapError (MalformedTextField label detail) =
  formatLabelName label ++ ": malformed text: " ++ detail

renderSlapError (EntryOutsideBlock label detail) =
  formatLabelName label ++ ": entry outside block: " ++ detail

renderSlapError (ParseError label message) =
  formatLabelName label ++ ": " ++ message

renderSlapError (NegativeTargetSize label size) =
  formatLabelName label ++ ": negative target size: "
  ++ show (unFileSize size)

renderSlapError (ApplyFailed label applyErr) =
  formatLabelName label ++ " apply: " ++ renderApplyError applyErr

renderSlapError (UndoFailed label applyErr) =
  formatLabelName label ++ " undo: " ++ renderApplyError applyErr

renderSlapError (CannotExpressTargetShrinkage label (ActualSize sourceSize) (ExpectedSize targetSize)) =
  formatLabelName label ++ ": cannot express a target file smaller than the source"
  ++ " (source: 0x" ++ showHex (unFileSize sourceSize) ""
  ++ " bytes, target: 0x" ++ showHex (unFileSize targetSize) ""
  ++ " bytes); this format has no truncation marker"

renderSlapError (UPSUnencodeablePair label reason) =
  formatLabelName label ++ ": cannot encode pair: "
  ++ renderUnencodeabilityReason reason

renderSlapError (OffsetExceedsRange label (ActualOffset actual) (MaxOffset maxOffset)) =
  formatLabelName label ++ ": hunk offset 0x"
  ++ showHex (unOffset actual) ""
  ++ " exceeds maximum offset 0x"
  ++ showHex (unOffset maxOffset) ""

renderSlapError (FileExceedsAddressableRange label (ActualSize actualSize) (MaxAddressableSize maxSize)) =
  formatLabelName label ++ ": input file is "
  ++ show (unFileSize actualSize) ++ " bytes, exceeding the host platform's "
  ++ show (unFileSize maxSize) ++ "-byte addressable range"

renderSlapError (SentinelCollisionUnfixable label (SentinelOffset sentinel)) =
  formatLabelName label ++ ": hunk offset 0x"
  ++ showHex (unOffset sentinel) ""
  ++ " collides with trailer sentinel and cannot be shifted"
  ++ " (no preceding source byte available to prepend)"

renderSlapError (FieldTooLong label name (EncodedLength encodedLength) (MaxLength maxLength)) =
  formatLabelName label ++ ": " ++ fieldNameLabel name
  ++ " too long (" ++ show (unLength encodedLength)
  ++ " bytes, maximum " ++ show (unLength maxLength) ++ ")"

renderSlapError (EncodingFailure label name detail) =
  formatLabelName label ++ ": failed to encode "
  ++ fieldNameLabel name ++ ": " ++ detail

renderSlapError (MissingRequiredField label field) =
  formatLabelName label ++ " requires " ++ fieldName field
  ++ " but source patch doesn't provide it"

renderSlapError (ApplyOutputFieldsWouldBeDropped label drops) =
  "cannot convert to " ++ formatLabelName label ++ ": "
  ++ renderApplyOutputDrops label drops

renderSlapError (DiffRequiresSource label) =
  formatLabelName label
  ++ " requires source+target diff data\nuse --with SOURCE"

renderSlapError (Yay0DecompressionFailed detail) =
  "Yay0 decompression failed: " ++ detail

----------------------------------------------------------------------------
-- renderSlapWarning
----------------------------------------------------------------------------

renderSlapWarning :: SlapWarning -> String

renderSlapWarning (EmptyPatch _label unit) =
  "empty patch (0 " ++ unit ++ ")"

renderSlapWarning (NoEOFMarker _label) =
  "no EOF marker (patch may be truncated)"

renderSlapWarning (ZeroCountRLERecord label (ActionIndex idx)) =
  "note: " ++ formatLabelName label
  ++ ": zero-count RLE record at position " ++ show idx
  ++ " (accepted as no-op)"

renderSlapWarning (OverlappingRecords label (ActionIndex earlier) (ActionIndex later)) =
  "note: " ++ formatLabelName label
  ++ ": record at position " ++ show later
  ++ " overlaps with record at position " ++ show earlier
  ++ " (later record's writes clobber earlier; unusual)"

renderSlapWarning (UnsortedRecords label (ActionIndex idx)) =
  "note: " ++ formatLabelName label
  ++ ": record at position " ++ show idx
  ++ " has a lower offset than the record before it"
  ++ " (unsorted records; applied in wire order)"

renderSlapWarning (IPS32TrailingBytes label (Length n)) =
  "note: " ++ formatLabelName label
  ++ ": dropped " ++ show n ++ " trailing bytes after EEOF marker"

renderSlapWarning (FieldDropped field droppedValue) =
  let rendered = renderDroppedValue droppedValue
  in if null rendered
     then "note: dropping " ++ fieldName field
     else "note: dropping " ++ fieldName field ++ ": " ++ rendered

renderSlapWarning (UndoDataDropped recordCount) =
  "note: dropping undo data (" ++ show recordCount ++ " records)"

renderSlapWarning ValidationBlockDropped =
  "note: dropping validation block (1024 bytes)"

renderSlapWarning (DisabledEntriesDropped entryCount) =
  "note: dropping " ++ show entryCount ++ " disabled entries"

renderSlapWarning BlockDescriptionsDropped =
  "note: dropping block descriptions"

renderSlapWarning (MetadataDropped byteCount) =
  "note: dropping metadata (" ++ show byteCount ++ " bytes)"

renderSlapWarning (DefaultRomType _label) =
  "note: assuming ROM type RAW (override with --rom-type)"

renderSlapWarning (DefaultImageType _label) =
  "note: assuming image type BIN (override with --image-type gi for GI disc images)"

renderSlapWarning IncludingUndoByDefault =
  "note: including undo data (omit with --no-undo)"

renderSlapWarning IncludingValidationByDefault =
  "note: including validation block (omit with --no-validate)"

renderSlapWarning (SourceHashesMissing _label) =
  "note: source verification hashes not available (populate with --with SOURCE)"

renderSlapWarning (FieldTruncated label name (OriginalLength original) (TruncatedLength truncated)) =
  "note: " ++ formatLabelName label ++ " "
  ++ fieldNameLabel name ++ " truncated to fit "
  ++ show (unLength truncated) ++ "-byte field (was "
  ++ show (unLength original) ++ " bytes)"

renderSlapWarning (EncodingGap fromLabel toLabel) =
  "note: " ++ formatLabelName fromLabel
  ++ " text was stored with known encoding; "
  ++ formatLabelName toLabel
  ++ " has no encoding flag; writing bytes as-is"

renderSlapWarning (PlatformNotAvailable label name) =
  "note: platform " ++ name ++ " not available in " ++ formatLabelName label ++ "; using Raw"

renderSlapWarning (PlatformAmbiguous label combined chosen override) =
  "note: " ++ formatLabelName label ++ " ROM type " ++ combined
  ++ " is ambiguous; defaults to " ++ chosen
  ++ " on conversion (override with --rom-type " ++ override ++ ")"

renderSlapWarning (ApplyOOBBlocksSkipped label count firstIndex overshoot declaredSize) =
  formatLabelName label ++ " apply: "
  ++ show count ++ plural count " block writes" " blocks write"
  ++ " past declared target size ("
  ++ show (unFileSize declaredSize) ++ " bytes); first at step #"
  ++ show (unActionIndex firstIndex) ++ ", "
  ++ show (unLength overshoot) ++ plural (unLength overshoot) " byte" " bytes"
  ++ " total overshoot — clipped to target bounds"
  where plural n singular pluralForm = if n == 1 then singular else pluralForm

renderSlapWarning (SubformatConverted label fromSub toSub) =
  "note: " ++ formatLabelName label ++ " "
  ++ fromSub ++ " converted to " ++ toSub

renderSlapWarning OffsetShiftApplied =
  "note: PCHTXT offset_shift applied to absolute offsets; output has no @flag directive"

----------------------------------------------------------------------------
-- Helpers
----------------------------------------------------------------------------

renderUnencodeabilityReason :: UnencodeabilityReason -> String
renderUnencodeabilityReason UPSLastByteDiffers =
  "target's final byte differs from source (with virtual zero-padding);"
  ++ " no terminator byte can be placed past target end"
renderUnencodeabilityReason UPSSourceTailNonZero =
  "source has non-zero bytes past target size;"
  ++ " these cannot be represented in a UPS patch"

-- | Render a trailer marker's raw bytes for inclusion in an error
-- message. The 'StandardIPS' and 'IPS32' markers are ASCII-printable
-- (@"EOF"@, @"EEOF"@), so the common case is the literal string. For
-- a hypothetical future trailer marker that contained any non-
-- printable byte, the renderer falls back to a hex dump rather than
-- emitting raw control characters into the error stream.
renderTrailerMarkerName :: ByteString -> String
renderTrailerMarkerName = renderPrintableASCIIOrHex

-- | Render the apply-output-field-drop refusal body. The single-drop
-- case (today's only case, 'FTruncation') produces one clean sentence;
-- the multi-drop case (trivially available if 'affectsApplyOutput'
-- grows) bullets each field on its own line so nothing gets lost.
renderApplyOutputDrops :: FormatLabel -> [(PatchField, [FormatLabel])] -> String
renderApplyOutputDrops target [singleDrop] = renderOneDrop target singleDrop
renderApplyOutputDrops target manyDrops =
  concatMap (\drop_ -> "\n  - " ++ renderOneDrop target drop_) manyDrops

renderOneDrop :: FormatLabel -> (PatchField, [FormatLabel]) -> String
renderOneDrop target (field, preservers) =
  "the source patch declares a " ++ fieldName field
  ++ ", and " ++ formatLabelName target
  ++ " has no representation for it. " ++ renderPreservers field preservers

renderPreservers :: PatchField -> [FormatLabel] -> String
renderPreservers field [] =
  "No target format preserves " ++ fieldName field ++ "."
renderPreservers field preservers =
  "Targets that preserve " ++ fieldName field ++ ": "
  ++ commaSeparated (map formatLabelName preservers) ++ "."

commaSeparated :: [String] -> String
commaSeparated []      = ""
commaSeparated [x]     = x
commaSeparated (x:xs)  = x ++ ", " ++ commaSeparated xs

commaList :: [String] -> String
commaList []     = ""
commaList [x]    = x
commaList [x, y] = x ++ " or " ++ y
commaList items  = concatMap (++ ", ") (init items) ++ "or " ++ last items
