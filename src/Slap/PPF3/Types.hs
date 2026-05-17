{-# LANGUAGE OverloadedStrings #-}

-- | Types for PPF3 patches. PPF3 introduces optional patch-time
-- features that PPF1/PPF2 lack — a per-record undo trail (lets a
-- successful apply be rolled back without the original source) and
-- a configurable image-type byte that switches the validation
-- block's source offset between BIN-style and GameCube ISO-style
-- images. Records use 8-byte LE offsets (vs PPF1/PPF2's 4-byte)
-- and never use the count=0 RLE sentinel. Specified in
-- @docs/ppf/upstream/ppf-master/ppfdev/PPF3.txt@.
module Slap.PPF3.Types
  ( PPF3Patch(..)
  , PPF3Record(..)
  , PPF3ValidationBlock(..)
  , PPF3ImageType(..)
  , PPF3FileId
  , unPPF3FileId
  , narrowPPF3FileId
  , ppf3FileIdFromParsed
  , fromImageType
    -- * Named constants
  , ppf3MagicBytes
  , ppf3DescriptionLength
  , ppf3MinHeaderLength
  , ppf3MaxRecordPayload
  , ppf3ValidationOffset
  , ppf3ValidationSize
  , ppf3FileIdLengthFieldWidth
  , ppf3FileIdMarkerLength
  , ppf3FileIdFooterLength
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.Word (Word8)
import Slap.Status (SlapError(..))
import Slap.FieldName (FieldName(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.Measure (Length(..), Offset(..))
import Slap.Narrow (narrowToWord16)

-- | The image-type byte at PPF3 header offset 56. Drives where
-- in the source ROM the 1024-byte validation block is sampled
-- from: 'BIN' for ordinary PSX CDRWin .bin images, 'GI' for
-- GameCube ISO images (which don't have a Mode-2 sector header
-- offset where the BIN sampling would land in valid data).
data PPF3ImageType = BIN | GI
  deriving (Show, Eq)

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

-- | FILE_ID.DIZ content optionally appended after the record
-- stream. PPF3's wire trailer uses a 2-byte LE length suffix
-- (vs PPF2's 4-byte). Carries only the inner content bytes whose
-- length has been validated against PPF3's 2-byte LE length
-- field. Constructor private; values come from one of two named
-- producers:
--
-- * 'narrowPPF3FileId' — runtime check, refuses with
--   'Slap.Narrow.FieldValueExceedsBound' if the bytestring's length
--   exceeds @0xFFFF@.
-- * 'ppf3FileIdFromParsed' — parse-time, trusts the wire format's
--   2-byte length field has already constrained the bytestring.
newtype PPF3FileId = PPF3FileId { unPPF3FileId :: ByteString }
  deriving (Show, Eq)

narrowPPF3FileId :: ByteString -> Either SlapError PPF3FileId
narrowPPF3FileId bs = case narrowToWord16 LabelPPF3 FieldFileIdDizLength
                            (ByteString.length bs) of
  Left  failure -> Left (NarrowingError failure)
  Right _       -> Right (PPF3FileId bs)

ppf3FileIdFromParsed :: ByteString -> PPF3FileId
ppf3FileIdFromParsed = PPF3FileId

-- | A fully parsed PPF3 patch.
data PPF3Patch = PPF3Patch
  { ppf3Description     :: !ByteString          -- ^ 50-byte description (raw bytes, space- or null-padded)
  , ppf3ImageType       :: !PPF3ImageType
  , ppf3HasUndo         :: !Bool                -- ^ True iff each 'PPF3Record' carries an undo payload
  , ppf3ValidationBlock :: !(Maybe PPF3ValidationBlock)  -- ^ Present iff the block-check flag was set in the header
  , ppf3Records         :: ![PPF3Record]
  , ppf3FileId          :: !(Maybe PPF3FileId)
  } deriving (Show)

-- | Wire-format magic prefix: ASCII @"PPF3"@.
ppf3MagicBytes :: ByteString
ppf3MagicBytes = "PPF3"

-- | Length of the description field: 50 bytes.
ppf3DescriptionLength :: Length
ppf3DescriptionLength = Length 50

-- | Minimum PPF3 header length, before any optional 1024-byte
-- validation block: 4 magic + 1 version + 1 encoding +
-- 50 description + 1 image type + 1 block-check flag +
-- 1 undo flag + 1 dummy = 60.
ppf3MinHeaderLength :: Length
ppf3MinHeaderLength = Length 60

-- | Maximum payload bytes a single PPF3 record can carry. The
-- record format uses a single-byte size field, capping payload
-- (and undo-payload) at @0xFF = 255@.
ppf3MaxRecordPayload :: Length
ppf3MaxRecordPayload = Length 255

-- | The source-ROM offset the validation block is read from,
-- depending on the image-type byte.
ppf3ValidationOffset :: PPF3ImageType -> Offset
ppf3ValidationOffset BIN = Offset 0x9320
ppf3ValidationOffset GI  = Offset 0x80A0

-- | Size of the validation block, in bytes.
ppf3ValidationSize :: Length
ppf3ValidationSize = Length 1024

-- | Width of the FILE_ID.DIZ length field at the very end of the
-- patch: 2 bytes (LE) in PPF3.
ppf3FileIdLengthFieldWidth :: Length
ppf3FileIdLengthFieldWidth = Length 2

-- | Length of the @\"\@BEGIN_FILE_ID.DIZ\"@ marker prefix.
ppf3FileIdMarkerLength :: Length
ppf3FileIdMarkerLength = Length 18

-- | Length of the @\"\@END_FILE_ID.DIZ\"@ marker following the content.
ppf3FileIdFooterLength :: Length
ppf3FileIdFooterLength = Length 16
