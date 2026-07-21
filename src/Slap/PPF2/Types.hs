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
  , PPF2CarriedFileId(..)
  , PPF2FileId
  , unPPF2FileId
  , narrowPPF2FileId
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
  , ppf2FileIdMaxContentLength
  , ppf2FileIdMarkerLength
  , ppf2FileIdFooterLength
    -- * Encoding limits
  , ppf2Limits
    -- * Source/target size-pair rule
  , ppf2RejectIncompatibleSizeChange
  ) where

import Data.ByteString (ByteString)
import Data.Word (Word32)
import Slap.Status (SlapError(..), UnencodeabilityReason(..))
import Slap.FieldName (FieldName(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.Measure (Length(..), Offset(..), FileSize(..),
                     ActualSize(..), ExpectedSize(..),
                     EncodedLength(..), MaxLength(..), SubstitutionCount, byteLength)
import Slap.Narrow (EncodingLimits(..), NarrowingFailure(FieldValueExceedsBound))
import Slap.Text (EncodedText, EncodingName(..),
                  encodedTextContent, encodeTextLenient)

data PPF2Record = PPF2Record
  { ppf2RecordOffset  :: !Offset
  , ppf2RecordPayload :: !ByteString
  } deriving (Show)

-- | The 1024-byte block sampled from the source ROM at offset
-- 'ppf2ValidationOffset' and stored in the patch for at-apply
-- verification.
newtype PPF2ValidationBlock = PPF2ValidationBlock
  { unPPF2ValidationBlock :: ByteString }
  deriving (Show, Eq)

-- | The FILE_ID.DIZ a parsed patch carries: the trailer's inner content bytes verbatim,
-- the reading made of them under the metadata encoding, and how many byte sequences that reading substituted.
data PPF2CarriedFileId = PPF2CarriedFileId
  { ppf2CarriedFileIdBytes         :: !ByteString
  , ppf2CarriedFileIdText          :: !EncodedText
  , ppf2CarriedFileIdSubstitutions :: !SubstitutionCount
  } deriving (Show, Eq)

-- | A FILE_ID.DIZ validated for emit: typed text whose UTF-8 byte count 'narrowPPF2FileId' has checked against 'ppf2FileIdMaxContentLength'.
-- Constructor private; that narrow is its one producer.
newtype PPF2FileId = PPF2FileId { unPPF2FileId :: EncodedText }
  deriving (Show, Eq)

narrowPPF2FileId :: EncodedText -> Either SlapError PPF2FileId
narrowPPF2FileId description
  | contentLength > ppf2FileIdMaxContentLength =
      Left (FieldTooLong LabelPPF2 FieldFileIdDiz
              (EncodedLength contentLength) (MaxLength ppf2FileIdMaxContentLength))
  | otherwise = Right (PPF2FileId description)
  where
    (encoded, _notices) = encodeTextLenient EncodingUtf8 (encodedTextContent description)
    contentLength       = byteLength encoded

-- | PPF2's 4-byte LE source-ROM-size header field, narrowed from a runtime 'FileSize'.
-- The third of the format's four-byte numbers, and signed for the same reason as the other two:
-- the tools that read it hold a 32-bit number in a Turbo Pascal @Longint@ and have no wider one to reach for.
-- Constructor private; values come from 'narrowPPF2SourceSize' (runtime check)
-- or 'ppf2SourceSizeFromParsed' (parse-time trust).
newtype PPF2SourceSize = PPF2SourceSize { unPPF2SourceSize :: Word32 }
  deriving (Show, Eq)

narrowPPF2SourceSize :: FileSize -> Either SlapError PPF2SourceSize
narrowPPF2SourceSize size
  | declaredSize < 0 || declaredSize > unOffset (maximumOffset ppf2Limits) =
      Left (NarrowingError (FieldValueExceedsBound LabelPPF2 FieldSourceSize
                              (toInteger declaredSize) (toInteger (unOffset (maximumOffset ppf2Limits)))))
  | otherwise = Right (PPF2SourceSize (fromIntegral declaredSize))
  where
    declaredSize = unFileSize size

ppf2SourceSizeFromParsed :: Word32 -> PPF2SourceSize
ppf2SourceSizeFromParsed = PPF2SourceSize

data PPF2Patch = PPF2Patch
  { ppf2Description     :: !EncodedText
    -- ^ 50-byte description field, decoded at parse time under the
    -- chosen metadata encoding (same model as PPF1). The PPF2 spec is
    -- silent on the description's encoding, so slap interprets the
    -- bytes under the user's @--metadata-encoding@ (default UTF-8) and
    -- writes them back as UTF-8.
  , ppf2SourceFileSize  :: !PPF2SourceSize   -- ^ 4-byte LE field at header offset 56; declares the source ROM's expected size
  , ppf2ValidationBlock :: !PPF2ValidationBlock
  , ppf2Records         :: ![PPF2Record]
  , ppf2FileId          :: !(Maybe PPF2CarriedFileId)
  } deriving (Show)

-- | Wire-format magic prefix.
ppf2MagicBytes :: ByteString
ppf2MagicBytes = "PPF2"

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

ppf2ValidationSize :: Length
ppf2ValidationSize = Length 1024

-- | Maximum payload bytes a single PPF2 record can carry. The record
-- format uses a single-byte count field (literal mode), capping
-- payload at @0xFF = 255@.
ppf2MaxRecordPayload :: Length
ppf2MaxRecordPayload = Length 255

-- | Width of the FILE_ID.DIZ length field at the very end of the patch: 4 bytes LE, where PPF3 uses 2 for the same role.
-- Signed, being a Turbo Pascal @Longint@ like every other 32-bit number these tools handle,
-- so the field names at most @0x7FFFFFFF@ and a high-bit value is not a very long DIZ but a negative one.
-- That is a wider bound than 'ppf2FileIdMaxContentLength' by a long way, and reading honours the field rather than the cap.
ppf2FileIdLengthFieldWidth :: Length
ppf2FileIdLengthFieldWidth = Length 4

-- | The cap on FILE_ID.DIZ content: 3072 bytes, far under the 4-byte length field's wire width.
-- slap refuses to write more rather than truncate ('narrowPPF2FileId'); reading tolerates a larger one.
-- (docs/ppf/spec.md, "L ≤ 3072"; PPF2.txt.)
ppf2FileIdMaxContentLength :: Length
ppf2FileIdMaxContentLength = Length 3072

-- | Length of the @"\@BEGIN_FILE_ID.DIZ"@ marker prefix.
ppf2FileIdMarkerLength :: Length
ppf2FileIdMarkerLength = Length 18

-- | Length of the @"\@END_FILE_ID.DIZ"@ marker following the content.
ppf2FileIdFooterLength :: Length
ppf2FileIdFooterLength = Length 16

-- | PPF2's wire-format offset cap. The record's offset field is 4 bytes LE, and @PPF2.txt@ says nothing about its sign.
-- The original tools are Turbo Pascal 6.0, whose only 32-bit integer is the signed @Longint@:
-- the applier hands the field's four bytes straight to @System.Seek(var F; N: Longint)@,
-- and the creator computes its offsets in that same type,
-- so a position above the signed half is not representable anywhere in the toolchain the format came from.
ppf2Limits :: EncodingLimits
ppf2Limits = EncodingLimits
  { maximumOffset = Offset 0x7FFFFFFF
  , formatLabel   = LabelPPF2
  }

-- | PPF2 declines (source, target) pairs whose target is shorter than
-- the source. Shrinking has no representation — PPF2 records only
-- overwrite or add bytes, never remove them. Growth is allowed: PPF2's
-- only same-size signal is the header source-size field, which its own
-- reference applier treats as an advisory identity check, not an
-- integrity rule — so a growing PPF2 patch is within the format's
-- accepted behavior, unlike PPF1\/PPF3. See @docs\/ppf\/spec.md@,
-- "Size-changing patches" under PPF2.
--
-- Consumed by 'Slap.Convert.rejectIncompatibleSizeChange' through its
-- 'CreatePPF2' arm.
ppf2RejectIncompatibleSizeChange
  :: FileSize -> FileSize -> Either SlapError ()
ppf2RejectIncompatibleSizeChange sourceSize targetSize
  | sourceSize <= targetSize = Right ()
  | otherwise                = Left (UnencodeablePair LabelPPF2
      (TargetShrinksBelowSource (ActualSize sourceSize) (ExpectedSize targetSize)))
