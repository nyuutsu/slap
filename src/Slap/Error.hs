{-# LANGUAGE StrictData #-}

module Slap.Error
  ( SlapError(..)
  , SlapWarning(..)
  , FieldName(..)
  , fieldNameLabel
  , renderSlapError
  , renderSlapWarning
  ) where

import Data.ByteString (ByteString)
import Data.Word (Word8)
import Numeric (showHex)
import Slap.FormatLabel (FormatLabel, formatLabelName)
import Slap.Checksum (CRC32, showCRC32)
import Slap.Measure (Offset(..), Length(..), FileSize(..))
import Slap.Convert (PatchField, fieldName)

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

----------------------------------------------------------------------------
-- SlapError
----------------------------------------------------------------------------

data SlapError

  -- Detection
  = UnrecognizedFormat
  | AmbiguousDetection [FormatLabel]

  -- Parse: structural
  | InputTooShort FormatLabel Length Length
  | BadMagic FormatLabel ByteString
  | BadVersion FormatLabel Word8
  | UnsupportedSubformat FormatLabel String
  | TruncatedRecord FormatLabel Int Length Length
  | NegativeSize FormatLabel FieldName Int
  | DecompressionFailed FormatLabel String

  -- Parse: integrity
  | PatchCRCMismatch FormatLabel CRC32 CRC32
  | TrailingMagicMismatch FormatLabel ByteString ByteString

  -- Parse: content
  | UnknownFlag FormatLabel FieldName Word8
  | UnsupportedEncodingMethod FormatLabel Word8
  | MalformedTextField FormatLabel String
  | EntryOutsideBlock FormatLabel String

  -- Parse: generic Get monad failures
  | ParseError FormatLabel String

  -- Apply
  | NegativeTargetSize FormatLabel FileSize

  -- Create / Encode
  | OffsetExceedsRange FormatLabel Offset Offset
  | SentinelCollision FormatLabel Offset
  | FieldTooLong FormatLabel FieldName Length Length
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
  | FieldDropped PatchField String
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
  | FieldTruncated FormatLabel FieldName Length Length
  | EncodingGap FormatLabel FormatLabel

  -- Interop
  | EBPTruncationMetaConflict

  -- Format-specific
  | SubformatConverted FormatLabel String String
  | OffsetShiftApplied

  deriving (Show, Eq)

----------------------------------------------------------------------------
-- renderSlapError
----------------------------------------------------------------------------

renderSlapError :: SlapError -> String

renderSlapError UnrecognizedFormat =
  "unknown patch format"

renderSlapError (AmbiguousDetection labels) =
  "ambiguous format: could be "
  ++ commaList (map formatLabelName labels)

renderSlapError (InputTooShort label needed actual) =
  formatLabelName label ++ ": input too short (need "
  ++ show (unLength needed) ++ " bytes, have "
  ++ show (unLength actual) ++ ")"

renderSlapError (BadMagic label actualBytes) =
  "not a " ++ formatLabelName label ++ " file (bad magic: "
  ++ show actualBytes ++ ")"

renderSlapError (BadVersion label versionByte) =
  formatLabelName label ++ ": unsupported version "
  ++ show versionByte

renderSlapError (UnsupportedSubformat label subformat) =
  formatLabelName label ++ ": unsupported subformat: "
  ++ subformat

renderSlapError (TruncatedRecord label recordIndex needed available) =
  formatLabelName label ++ ": record " ++ show recordIndex
  ++ " truncated (need " ++ show (unLength needed)
  ++ " bytes, have " ++ show (unLength available) ++ ")"

renderSlapError (NegativeSize label name value) =
  formatLabelName label ++ ": negative "
  ++ fieldNameLabel name ++ ": " ++ show value

renderSlapError (DecompressionFailed label detail) =
  formatLabelName label ++ ": decompression failed: " ++ detail

renderSlapError (PatchCRCMismatch label stored computed) =
  formatLabelName label ++ ": patch CRC mismatch (stored "
  ++ showCRC32 stored ++ ", computed " ++ showCRC32 computed ++ ")"

renderSlapError (TrailingMagicMismatch label expected actual) =
  formatLabelName label ++ ": trailing magic mismatch (expected "
  ++ show expected ++ ", found " ++ show actual ++ ")"

renderSlapError (UnknownFlag label name flagByte) =
  formatLabelName label ++ ": unknown "
  ++ fieldNameLabel name ++ " flag: 0x"
  ++ showHex flagByte ""

renderSlapError (UnsupportedEncodingMethod label methodByte) =
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

renderSlapError (OffsetExceedsRange label actual maxOffset) =
  formatLabelName label ++ ": hunk offset 0x"
  ++ showHex (unOffset actual) ""
  ++ " exceeds maximum offset 0x"
  ++ showHex (unOffset maxOffset) ""

renderSlapError (SentinelCollision label sentinel) =
  formatLabelName label ++ ": hunk offset 0x"
  ++ showHex (unOffset sentinel) ""
  ++ " collides with sentinel 0x"
  ++ showHex (unOffset sentinel) ""

renderSlapError (FieldTooLong label name encodedLength maxLength) =
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

renderSlapWarning (FieldDropped field description) =
  "note: dropping " ++ fieldName field ++ ": " ++ description

renderSlapWarning (UndoDataDropped recordCount) =
  "note: dropping undo data (" ++ show recordCount ++ " records)"

renderSlapWarning ValidationBlockDropped =
  "note: dropping validation block"

renderSlapWarning (DisabledEntriesDropped entryCount) =
  "note: dropping " ++ show entryCount ++ " disabled entries"

renderSlapWarning BlockDescriptionsDropped =
  "note: dropping block descriptions"

renderSlapWarning (MetadataDropped byteCount) =
  "note: dropping metadata (" ++ show byteCount ++ " bytes)"

renderSlapWarning (DefaultRomType _label) =
  "note: assuming raw ROM type (use --rom-type to specify)"

renderSlapWarning (DefaultImageType _label) =
  "note: assuming default image type (use --image-type to specify)"

renderSlapWarning IncludingUndoByDefault =
  "note: including undo data by default"

renderSlapWarning IncludingValidationByDefault =
  "note: including validation block by default"

renderSlapWarning (SourceHashesMissing label) =
  "note: " ++ formatLabelName label
  ++ " source hashes not available; skipping verification"

renderSlapWarning (FieldTruncated label name actual truncated) =
  "note: " ++ formatLabelName label ++ " "
  ++ fieldNameLabel name ++ " truncated to fit "
  ++ show (unLength truncated) ++ "-byte field (was "
  ++ show (unLength actual) ++ " bytes)"

renderSlapWarning (EncodingGap fromLabel toLabel) =
  "note: " ++ formatLabelName fromLabel
  ++ " text was stored with known encoding; "
  ++ formatLabelName toLabel
  ++ " has no encoding flag; writing bytes as-is"

renderSlapWarning EBPTruncationMetaConflict =
  "note: EBP truncation marker conflicts with metadata fields"

renderSlapWarning (SubformatConverted label fromSub toSub) =
  "note: " ++ formatLabelName label ++ " "
  ++ fromSub ++ " converted to " ++ toSub

renderSlapWarning OffsetShiftApplied =
  "note: PCHTXT offset_shift baked into absolute offsets"

----------------------------------------------------------------------------
-- Helpers
----------------------------------------------------------------------------

commaList :: [String] -> String
commaList []     = ""
commaList [x]    = x
commaList [x, y] = x ++ " or " ++ y
commaList items  = concatMap (++ ", ") (init items) ++ "or " ++ last items
