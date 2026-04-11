{-# LANGUAGE StrictData #-}

module Slap.Error
  ( SlapError(..)
  , SlapWarning(..)
  , ApplyError(..)
  , CursorKind(..)
  , UnencodeabilityReason(..)
  , DroppedValue(..)
  , CreateResult(..)
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
import Slap.Format (hexByteString)
import Slap.Measure (Offset(..), Length(..), FileSize(..),
                     SignedOffset(..), ActionIndex(..),
                     ReadOffset(..), WritePosition(..),
                     RequestedLength(..), RemainingLength(..),
                     ActualSize(..), ExpectedSize(..),
                     RequiredLength(..), ActualLength(..),
                     EncodedLength(..), MaxLength(..),
                     OriginalLength(..), TruncatedLength(..),
                     ActualOffset(..), MaxOffset(..),
                     ExpectedMagic(..), ActualMagic(..),
                     ParsedSizeValue(..), FoundVersion(..),
                     RawFlagByte(..), EncodingMethodByte(..))
import Slap.PatchField (PatchField, fieldName)

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
  | UPSUnencodeablePair FormatLabel UnencodeabilityReason
  | OffsetExceedsRange FormatLabel ActualOffset MaxOffset
  | SentinelCollision FormatLabel Offset
  | FieldTooLong FormatLabel FieldName EncodedLength MaxLength
  | EncodingFailure FormatLabel FieldName String

  -- Convert
  | MissingRequiredField FormatLabel PatchField
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

  -- Interop
  | EBPTruncationMetaConflict

  -- Platform conversion
  | PlatformNotAvailable FormatLabel String  -- target format, platform name
  | PlatformAmbiguous FormatLabel String String String  -- source format, combined name, default name, override value

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

renderSlapError (UPSUnencodeablePair label reason) =
  formatLabelName label ++ ": cannot encode pair: "
  ++ renderUnencodeabilityReason reason

renderSlapError (OffsetExceedsRange label (ActualOffset actual) (MaxOffset maxOffset)) =
  formatLabelName label ++ ": hunk offset 0x"
  ++ showHex (unOffset actual) ""
  ++ " exceeds maximum offset 0x"
  ++ showHex (unOffset maxOffset) ""

renderSlapError (SentinelCollision label sentinel) =
  formatLabelName label ++ ": hunk offset 0x"
  ++ showHex (unOffset sentinel) ""
  ++ " collides with sentinel 0x"
  ++ showHex (unOffset sentinel) ""

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

renderSlapWarning EBPTruncationMetaConflict =
  "note: EBP output has both truncation and metadata; RomPatcher.js treats these as mutually exclusive and may misread this patch"

renderSlapWarning (PlatformNotAvailable label name) =
  "note: platform " ++ name ++ " not available in " ++ formatLabelName label ++ "; using Raw"

renderSlapWarning (PlatformAmbiguous label combined chosen override) =
  "note: " ++ formatLabelName label ++ " ROM type " ++ combined
  ++ " is ambiguous; defaults to " ++ chosen
  ++ " on conversion (override with --rom-type " ++ override ++ ")"

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

commaList :: [String] -> String
commaList []     = ""
commaList [x]    = x
commaList [x, y] = x ++ " or " ++ y
commaList items  = concatMap (++ ", ") (init items) ++ "or " ++ last items
