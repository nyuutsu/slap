module Slap.PPF.Types
    ( PPFVersion(..)
    , PPFImageType(..)
    , fromImageType
    , PPFValidation(..)
    , ValidationBlockBytes(..)
    , PPFRecordCommand(..)
    , PPFRecord(..)
    , PPFFileId(..)
    , PPFPatch(..)
    , validationOffset
    , validationSize
      -- * Named constants
    , ppfDescriptionLength
    , ppfPreambleLength
    , ppf2HeaderLength
    , ppf3MinHeaderLength
    , ppf3MaxRecordPayload
    , ppf4HeaderLength
    , ppf4PostDescriptionLength
    , fileIdMarkerLength
    , fileIdFooterLength
      -- * Labels
    , ppfVersionLabel
    ) where

import Data.ByteString (ByteString)
import Data.Word (Word8)
import Slap.FormatLabel (FormatLabel(..))
import Slap.Measure (Offset(..), Length(..), FileSize)

-- | PPF format version.
data PPFVersion = PPF1 | PPF2 | PPF3 | PPF4
  deriving (Show, Eq, Ord)

-- | PPF3 image type — determines the validation block source offset.
data PPFImageType = BIN | GI
  deriving (Show, Eq)

fromImageType :: PPFImageType -> Word8
fromImageType BIN = 0x00
fromImageType GI  = 0x01

-- | 1024 bytes of source-ROM data sampled at a format-specific offset,
-- stored alongside a PPF3 patch for apply-time sanity checking.  Treated
-- as an opaque blob; the newtype's job is to distinguish "validation
-- bytes" from other ByteString roles in the patch pipeline.
newtype ValidationBlockBytes = ValidationBlockBytes { unValidationBlockBytes :: ByteString }
  deriving (Show, Eq)

-- | Validation data embedded in PPF2/PPF3 headers.
data PPFValidation = PPFValidation
  { validationImageType :: !PPFImageType
  , validationBlock     :: !ValidationBlockBytes  -- ^ 1024 bytes stored in the patch (copied from the target image at creation time)
  } deriving (Show)

-- | Record command type.  Replace is standard for PPF1/2/3; Append exists
-- only in Pyriel's internal format (reverse-engineered from the Suikoden patchers).
data PPFRecordCommand = Replace | Append
  deriving (Show, Eq)

-- | A single patch record.
data PPFRecord = PPFRecord
  { recordOffset  :: !Offset           -- ^ Byte offset in target file
  , recordData    :: !ByteString       -- ^ Replacement bytes
  , recordUndo    :: !(Maybe ByteString) -- ^ Original bytes (PPF3 only, if undo data present)
  , recordCommand :: !PPFRecordCommand    -- ^ Replace or Append (PPF4 only; always Replace for PPF1/2/3)
  } deriving (Show)

-- | Optional File_ID.diz content appended to PPF2/PPF3 files.
newtype PPFFileId = PPFFileId { fileIdContent :: ByteString }
  deriving (Show)

-- | A fully parsed PPF patch.
data PPFPatch = PPFPatch
  { ppfVersion     :: !PPFVersion
  , ppfDescription :: !ByteString      -- ^ 50-byte description field
  , ppfFileSize    :: !(Maybe FileSize)   -- ^ Expected target size (PPF2 only)
  , ppfValidation  :: !(Maybe PPFValidation) -- ^ Block check data (PPF2 always, PPF3 optional)
  , ppfHasUndo     :: !Bool             -- ^ Whether undo data is present (PPF3 only)
  , ppfImageType   :: !(Maybe PPFImageType)  -- ^ PPF3 only (byte 56)
  , ppfRecords     :: ![PPFRecord]
  , ppfFileId      :: !(Maybe PPFFileId)
  } deriving (Show)

-- | Offset in target file where validation block is read from.
validationOffset :: PPFImageType -> Offset
validationOffset BIN = Offset 0x9320
validationOffset GI  = Offset 0x80A0

-- | Size of the validation block.
validationSize :: Length
validationSize = Length 1024

-- | Length of the description field: 50 bytes, space-padded.
ppfDescriptionLength :: Length
ppfDescriptionLength = Length 50

-- | Length of the header preamble before the description field:
-- magic (4) + version (1) + encoding (1).
ppfPreambleLength :: Length
ppfPreambleLength = Length 6

-- | PPF2 header length in bytes (preamble + description + file size
-- field + 1024-byte validation block + 4 bytes padding).
ppf2HeaderLength :: Length
ppf2HeaderLength = Length 1084

-- | Minimum PPF3 header length (without optional validation block).
ppf3MinHeaderLength :: Length
ppf3MinHeaderLength = Length 60

-- | Maximum payload bytes a single PPF3 record can carry. The PPF3
-- record format uses a single-byte size field, capping payload at
-- @0xFF = 255@. Both 'Slap.PPF.Create.encodePPF3' record splitting and
-- the 'Slap.PPF.Create.computeUndo' undo-hunk splitter respect this
-- bound.
ppf3MaxRecordPayload :: Length
ppf3MaxRecordPayload = Length 255

-- | PPF4 header length in bytes.
ppf4HeaderLength :: Length
ppf4HeaderLength = Length 60

-- | Length of the flag/padding bytes after the description field in a
-- PPF4 header. Per Pyriel's source: image_type (1) + validation_flag (1)
-- + undo_flag (1) + expansion (1).
ppf4PostDescriptionLength :: Length
ppf4PostDescriptionLength = Length 4

-- | Length of the "FILE_ID.DIZ" marker prefix in the File_ID.diz trailer.
fileIdMarkerLength :: Length
fileIdMarkerLength = Length 18

-- | Length of the fixed footer after the File_ID.diz content.
fileIdFooterLength :: Length
fileIdFooterLength = Length 16

-- | Map a PPF version to its format label.
ppfVersionLabel :: PPFVersion -> FormatLabel
ppfVersionLabel PPF1 = LabelPPF1
ppfVersionLabel PPF2 = LabelPPF2
ppfVersionLabel PPF3 = LabelPPF3
ppfVersionLabel PPF4 = LabelPPF4
