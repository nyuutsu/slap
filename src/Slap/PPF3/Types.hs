{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DerivingVia #-}

-- | Types for PPF3 patches. PPF3 introduces optional patch-time
-- features that PPF1/PPF2 lack — a per-record undo trail (lets a
-- successful apply be rolled back without the original source) and
-- a configurable image-type byte that switches the validation
-- block's source offset between BIN-style and GameCube ISO-style
-- images. Records use 8-byte LE offsets (vs PPF1/PPF2's 4-byte)
-- and never use the count=0 RLE sentinel.
-- Specified in @ppfdev/PPF3.txt@ in @docs/ppf/upstream/ppf-master.zip@.
module Slap.PPF3.Types
  ( PPF3Patch(..)
  , PPF3Record(..)
  , PPF3ValidationBlock(..)
  , PPF3ImageType(..)
  , ppf3DefaultImageType
  , PPF3CarriedFileId(..)
  , PPF3FileId
  , unPPF3FileId
  , narrowPPF3FileId
  , fromImageType
    -- * Named constants
  , ppf3MagicBytes
  , ppf3PreambleLength
  , ppf3DescriptionLength
  , ppf3PostDescriptionLength
  , ppf3MinHeaderLength
  , ppf3MaxRecordPayload
  , ppf3Limits
  , ppf3RecordHeaderLength
  , ppf3ValidationOffset
  , ppf3ValidationSize
  , ppf3FileIdLengthFieldWidth
  , ppf3FileIdMaxContentLength
  , ppf3FileIdMarkerLength
  , ppf3FileIdFooterLength
    -- * Source/target size-pair rule
  , ppf3RejectIncompatibleSizeChange
  ) where

import Data.Aeson (FromJSON, ToJSON)
import Data.ByteString (ByteString)
import Data.Word (Word8)
import GHC.Generics (Generic, Generically(..))
import Slap.Status (SlapError(..), UnencodeabilityReason(..))
import Slap.FieldName (FieldName(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.Measure (Length(..), Offset(..), FileSize,
                     ActualSize(..), ExpectedSize(..),
                     EncodedLength(..), MaxLength(..), SubstitutionCount, byteLength)
import Slap.Narrow (EncodingLimits(..))
import Slap.Text (EncodedText, EncodingName(..),
                  encodedTextContent, encodeTextLenient)

-- | The image-type byte at PPF3 header offset 56. Drives where
-- in the source ROM the 1024-byte validation block is sampled
-- from: 'BIN' for ordinary PSX CDRWin .bin images, 'GI' for
-- GameCube ISO images (which don't have a Mode-2 sector header
-- offset where the BIN sampling would land in valid data).
data PPF3ImageType = BIN | GI
  deriving (Show, Eq, Generic)
  deriving (ToJSON, FromJSON) via Generically PPF3ImageType

fromImageType :: PPF3ImageType -> Word8
fromImageType BIN = 0x00
fromImageType GI  = 0x01

-- | A PPF3 record. The optional 'ppf3RecordUndo' field carries the
-- pre-patch bytes the writer is overwriting; it is 'Just' if and
-- only if the parent patch's undo flag is set, in which case every
-- record carries an undo payload of the same length as the write
-- payload.
data PPF3Record = PPF3Record
  { ppf3RecordOffset  :: !Offset
  , ppf3RecordPayload :: !ByteString
  , ppf3RecordUndo    :: !(Maybe ByteString)
  } deriving (Show)

-- | The 1024-byte source-ROM block sampled at the offset chosen
-- by 'PPF3ImageType'. Distinct from PPF2's validation block at
-- the type level so the two formats' validation pipelines can't
-- accidentally cross.
newtype PPF3ValidationBlock = PPF3ValidationBlock
  { unPPF3ValidationBlock :: ByteString }
  deriving (Show, Eq)

-- | The FILE_ID.DIZ a parsed patch carries: the trailer's inner content bytes verbatim,
-- the reading made of them under the metadata encoding, and how many byte sequences that reading substituted.
data PPF3CarriedFileId = PPF3CarriedFileId
  { ppf3CarriedFileIdBytes         :: !ByteString
  , ppf3CarriedFileIdText          :: !EncodedText
  , ppf3CarriedFileIdSubstitutions :: !SubstitutionCount
  } deriving (Show, Eq)

-- | A FILE_ID.DIZ validated for emit: typed text whose UTF-8 byte count 'narrowPPF3FileId' has checked against 'ppf3FileIdMaxContentLength'.
-- Constructor private; that narrow is its one producer.
newtype PPF3FileId = PPF3FileId { unPPF3FileId :: EncodedText }
  deriving (Show, Eq)

narrowPPF3FileId :: EncodedText -> Either SlapError PPF3FileId
narrowPPF3FileId description
  | contentLength > ppf3FileIdMaxContentLength =
      Left (FieldTooLong LabelPPF3 FieldFileIdDiz
              (EncodedLength contentLength) (MaxLength ppf3FileIdMaxContentLength))
  | otherwise = Right (PPF3FileId description)
  where
    (encoded, _notices) = encodeTextLenient EncodingUtf8 (encodedTextContent description)
    contentLength       = byteLength encoded

data PPF3Patch = PPF3Patch
  { ppf3Description     :: !EncodedText
    -- ^ 50-byte description field, decoded at parse time under the
    -- chosen metadata encoding (same model as PPF1/PPF2/PPF4). The raw
    -- field carries the encoder's right padding; trailing space/NUL is
    -- stripped at display and metadata extraction.
  , ppf3ImageType       :: !PPF3ImageType
  , ppf3HasUndo         :: !Bool                -- ^ True iff each 'PPF3Record' carries an undo payload
  , ppf3ValidationBlock :: !(Maybe PPF3ValidationBlock)  -- ^ Present iff the block-check flag was set in the header
  , ppf3Records         :: ![PPF3Record]
  , ppf3FileId          :: !(Maybe PPF3CarriedFileId)
  } deriving (Show)

-- | Wire-format magic prefix.
ppf3MagicBytes :: ByteString
ppf3MagicBytes = "PPF3"

-- | Header preamble before the description field: 4 magic + 1 version
-- + 1 encoding = 6 bytes.
ppf3PreambleLength :: Length
ppf3PreambleLength = Length 6

ppf3DescriptionLength :: Length
ppf3DescriptionLength = Length 50

-- | The image type a PPF3 emit assumes when none is chosen.
ppf3DefaultImageType :: PPF3ImageType
ppf3DefaultImageType = BIN

-- | Flag and padding bytes after the description: 1 image type
-- + 1 block-check flag + 1 undo flag + 1 dummy = 4 bytes.
ppf3PostDescriptionLength :: Length
ppf3PostDescriptionLength = Length 4

-- | Minimum PPF3 header length, before any optional 1024-byte
-- validation block: the preamble, the description, and the four
-- post-description flag/padding bytes.
ppf3MinHeaderLength :: Length
ppf3MinHeaderLength =
  ppf3PreambleLength <> ppf3DescriptionLength <> ppf3PostDescriptionLength

-- | Maximum payload bytes a single PPF3 record can carry. The
-- record format uses a single-byte size field, capping payload
-- (and undo-payload) at @0xFF = 255@.
ppf3MaxRecordPayload :: Length
ppf3MaxRecordPayload = Length 255

-- | PPF3's signed 8-byte offset fits slap's 'Int', so the maximum never binds; narrowing rejects a negative offset ('Slap.Narrow.NegativeOffset').
ppf3Limits :: EncodingLimits
ppf3Limits = EncodingLimits
  { maximumOffset = Offset maxBound
  , formatLabel   = LabelPPF3
  }

-- | Fixed per-record header: 8-byte LE offset + 1-byte payload count.
ppf3RecordHeaderLength :: Length
ppf3RecordHeaderLength = Length 9

-- | The source-ROM offset the validation block is read from,
-- depending on the image-type byte.
ppf3ValidationOffset :: PPF3ImageType -> Offset
ppf3ValidationOffset BIN = Offset 0x9320
ppf3ValidationOffset GI  = Offset 0x80A0

ppf3ValidationSize :: Length
ppf3ValidationSize = Length 1024

-- | Width of the FILE_ID.DIZ length field: 2 bytes, little-endian.
ppf3FileIdLengthFieldWidth :: Length
ppf3FileIdLengthFieldWidth = Length 2

-- | The cap on FILE_ID.DIZ content: 3072 bytes, well under the 2-byte length field's 65535 wire width.
-- slap refuses to write more rather than truncate ('narrowPPF3FileId'); reading tolerates a larger one.
-- PPF3.txt states the cap in prose ("A File_ID.diz file cannot exceed 3072 byte"); see docs/ppf/spec.md.
ppf3FileIdMaxContentLength :: Length
ppf3FileIdMaxContentLength = Length 3072

-- | Length of the @"\@BEGIN_FILE_ID.DIZ"@ marker prefix.
ppf3FileIdMarkerLength :: Length
ppf3FileIdMarkerLength = Length 18

-- | Length of the @"\@END_FILE_ID.DIZ"@ marker following the content.
ppf3FileIdFooterLength :: Length
ppf3FileIdFooterLength = Length 16

-- | PPF3 declines (source, target) pairs whose sizes differ. Shrinking
-- has no representation — records only overwrite or add bytes, never
-- remove them. Growth is refused too: PPF3 is built around same-size
-- patching (its optional undo trail only coheres when the file's size
-- is unchanged), so slap keeps to that shape on create. See
-- @docs\/ppf\/spec.md@, "Size-changing patches" under PPF3, for the
-- fuller picture.
--
-- Consumed by 'Slap.Convert.rejectIncompatibleSizeChange' through its
-- 'CreatePPF3' arm.
ppf3RejectIncompatibleSizeChange
  :: FileSize -> FileSize -> Either SlapError ()
ppf3RejectIncompatibleSizeChange sourceSize targetSize
  | sourceSize == targetSize = Right ()
  | sourceSize <  targetSize = Left (UnencodeablePair LabelPPF3
      (TargetGrowsBeyondSource  (ActualSize sourceSize) (ExpectedSize targetSize)))
  | otherwise                = Left (UnencodeablePair LabelPPF3
      (TargetShrinksBelowSource (ActualSize sourceSize) (ExpectedSize targetSize)))
