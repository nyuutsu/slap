{-# LANGUAGE OverloadedStrings #-}

-- | Types for PPF2 patches. PPF2 extends PPF1 with file-size and
-- block-validation fields in the header (so an applier can refuse
-- to patch the wrong source ROM) and an optional FILE_ID.DIZ
-- trailer for free-form patch metadata. The record stream wire
-- format is the same as PPF1 (4-byte LE offset, 1-byte count,
-- payload). Specified in @docs/ppf/upstream/pdx-ppf2/ppftools/ppfdev/PPF2.txt@.
module Slap.PPF2.Types
  ( PPF2Patch(..)
  , PPF2Record(..)
  , PPF2ValidationBlock(..)
  , PPF2FileId
  , unPPF2FileId
  , narrowPPF2FileId
  , ppf2FileIdFromParsed
  , PPF2SourceSize
  , unPPF2SourceSize
  , narrowPPF2SourceSize
  , ppf2SourceSizeFromParsed
    -- * Named constants
  , ppf2MagicBytes
  , ppf2DescriptionLength
  , ppf2HeaderLength
  , ppf2ValidationOffset
  , ppf2ValidationSize
  , ppf2MaxRecordPayload
  , ppf2FileIdLengthFieldWidth
  , ppf2FileIdMarkerLength
  , ppf2FileIdFooterLength
    -- * Encoding limits
  , ppf2Limits
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.Word (Word32)
import Slap.Error (SlapError(..))
import Slap.FieldName (FieldName(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.Measure (Length(..), Offset(..), FileSize(..))
import Slap.Narrow (EncodingLimits(..), narrowToWord32)

-- | A PPF2 record. Same wire shape as PPF1: a target-file offset
-- and the bytes to write. The wire-level RLE encoding (count=0
-- sentinel) is decoded at parse time into the same flat payload
-- representation literal records use.
data PPF2Record = PPF2Record
  { ppf2RecordOffset  :: !Offset
  , ppf2RecordPayload :: !ByteString
  } deriving (Show)

-- | The 1024-byte block sampled from the source ROM at offset
-- 'ppf2ValidationOffset' and stored in the patch for at-apply
-- verification. The role newtype keeps this distinct from
-- record-payload bytes elsewhere in the pipeline.
newtype PPF2ValidationBlock = PPF2ValidationBlock
  { unPPF2ValidationBlock :: ByteString }
  deriving (Show, Eq)

-- | FILE_ID.DIZ content optionally appended after the record
-- stream. The wire trailer is
-- @\"\@BEGIN_FILE_ID.DIZ\" <content> \"\@END_FILE_ID.DIZ\" <4-byte LE length>@;
-- this newtype carries only the inner @<content>@ bytes whose
-- length has been validated against PPF2's 4-byte LE length
-- field. Constructor private; values come from one of two named
-- producers:
--
-- * 'narrowPPF2FileId' — runtime check, refuses with
--   'Slap.Narrow.FieldValueExceedsBound' if the bytestring's length
--   exceeds @0xFFFFFFFF@.
-- * 'ppf2FileIdFromParsed' — parse-time, trusts the wire format's
--   4-byte length field has already constrained the bytestring.
newtype PPF2FileId = PPF2FileId { unPPF2FileId :: ByteString }
  deriving (Show, Eq)

narrowPPF2FileId :: ByteString -> Either SlapError PPF2FileId
narrowPPF2FileId bs = case narrowToWord32 LabelPPF2 FieldFileIdDizLength
                            (ByteString.length bs) of
  Left  failure -> Left (NarrowingError failure)
  Right _       -> Right (PPF2FileId bs)

ppf2FileIdFromParsed :: ByteString -> PPF2FileId
ppf2FileIdFromParsed = PPF2FileId

-- | PPF2's 4-byte LE source-ROM-size header field, narrowed from a
-- runtime 'FileSize'. Constructor private; values come from
-- 'narrowPPF2SourceSize' (runtime check) or 'ppf2SourceSizeFromParsed'
-- (parse-time trust).
newtype PPF2SourceSize = PPF2SourceSize { unPPF2SourceSize :: Word32 }
  deriving (Show, Eq)

narrowPPF2SourceSize :: FileSize -> Either SlapError PPF2SourceSize
narrowPPF2SourceSize size =
  case narrowToWord32 LabelPPF2 FieldSourceSize (unFileSize size) of
    Left  failure -> Left (NarrowingError failure)
    Right word    -> Right (PPF2SourceSize word)

ppf2SourceSizeFromParsed :: Word32 -> PPF2SourceSize
ppf2SourceSizeFromParsed = PPF2SourceSize

-- | A fully parsed PPF2 patch.
data PPF2Patch = PPF2Patch
  { ppf2Description     :: !ByteString       -- ^ 50-byte description (space- or null-padded raw bytes)
  , ppf2SourceFileSize  :: !PPF2SourceSize   -- ^ 4-byte LE field at header offset 56; declares the source ROM's expected size
  , ppf2ValidationBlock :: !PPF2ValidationBlock
  , ppf2Records         :: ![PPF2Record]
  , ppf2FileId          :: !(Maybe PPF2FileId)
  } deriving (Show)

-- | Wire-format magic prefix: ASCII @"PPF2"@.
ppf2MagicBytes :: ByteString
ppf2MagicBytes = "PPF2"

-- | Length of the description field: 50 bytes.
ppf2DescriptionLength :: Length
ppf2DescriptionLength = Length 50

-- | Total PPF2 header length: 4 magic + 1 version + 1 encoding +
-- 50 description + 4 source size + 1024 validation block = 1084.
ppf2HeaderLength :: Length
ppf2HeaderLength = Length 1084

-- | The source-ROM offset the validation block is read from. PPF2
-- only supports BIN-style images (PSX CDRWin .bin); the source
-- offset is fixed unlike PPF3's 'PPF3ImageType'-dependent variant.
ppf2ValidationOffset :: Offset
ppf2ValidationOffset = Offset 0x9320

-- | Size of the validation block, in bytes.
ppf2ValidationSize :: Length
ppf2ValidationSize = Length 1024

-- | Maximum payload bytes a single PPF2 record can carry. The record
-- format uses a single-byte count field (literal mode), capping
-- payload at @0xFF = 255@.
ppf2MaxRecordPayload :: Length
ppf2MaxRecordPayload = Length 255

-- | Width of the FILE_ID.DIZ length field at the very end of the
-- patch: 4 bytes (LE) in PPF2. PPF3 uses 2 bytes for the same
-- role.
ppf2FileIdLengthFieldWidth :: Length
ppf2FileIdLengthFieldWidth = Length 4

-- | Length of the @\"\@BEGIN_FILE_ID.DIZ\"@ marker prefix.
ppf2FileIdMarkerLength :: Length
ppf2FileIdMarkerLength = Length 18

-- | Length of the @\"\@END_FILE_ID.DIZ\"@ marker following the content.
ppf2FileIdFooterLength :: Length
ppf2FileIdFooterLength = Length 16

-- | PPF2's wire-format offset cap. The record format's offset field
-- is 4 bytes LE (same shape as PPF1), so offsets ≥ 2^32 cannot be
-- expressed without truncation. Enforced at narrow time so
-- 'Slap.PPF2.Create.encodePPF2' cannot silently emit a truncated
-- offset.
ppf2Limits :: EncodingLimits
ppf2Limits = EncodingLimits
  { maximumOffset = Offset 0xFFFFFFFF
  , formatLabel   = LabelPPF2
  }
