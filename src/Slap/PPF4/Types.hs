{-# LANGUAGE OverloadedStrings #-}

module Slap.PPF4.Types
  ( PPF4Patch(..)
  , PPF4Replace(..)
  , PPF4Append(..)
  , ppf4MagicBytes
  , ppf4HeaderLength
  , ppf4PreambleLength
  , ppf4DescriptionLength
  , ppf4PostDescriptionLength
  , ppf4MaxRecordPayload
  , ppf4RecordHeaderLength
  , ppf4MinimumRecordLength
    -- * Encoding limits
  , ppf4Limits
    -- * Source/target size-pair rule
  , ppf4RejectIncompatibleSizeChange
  ) where

import Data.ByteString (ByteString)
import Slap.FormatLabel (FormatLabel(..))
import Slap.Measure (Offset(..), Length(..), FileSize,
                     ActualSize(..), ExpectedSize(..))
import Slap.Narrow (EncodingLimits(..))
import Slap.Status (SlapError(..), UnencodeabilityReason(..))
import Slap.Text (EncodedText)

-- | A fully parsed PPF4 patch.
--
-- PPF4 is a two-phase format: REPLACE records first, then ADD records, with a one-way phase transition.
-- The wire-format ordering (all Replace records before any Append record) is enforced at parse time;
-- values of this type are guaranteed to satisfy that invariant.
--
-- PPF4 has no validation block, no source CRC, no file-size advisory,
-- no undo data, no image type, no File_ID.diz trailer. Those are
-- PPF1/2/3 facts that live on each format's per-version Patch type.
data PPF4Patch = PPF4Patch
  { ppf4Description :: !EncodedText
    -- ^ 50-byte description field, decoded at parse time under the
    -- process locale, so describe-side rendering goes through the same
    -- 'Text' path as the other PPFs. The reference maker never populates
    -- this field (it zero-fills it and takes no description input), so
    -- 'Slap.PPF4.Create' writes it as zero and there is no create-side
    -- description to carry here.
  , ppf4Replaces    :: ![PPF4Replace]
  , ppf4Appends     :: ![PPF4Append]
  } deriving (Show)

-- | A PPF4 Replace record: writes 'replaceData' at 'replaceOffset' in
-- the target. Replace records cannot grow the file; the offset plus
-- the payload length must be in @[0, sourceFileSize]@. Enforced at
-- apply time by 'Slap.PPF4.Apply.applyPPF4', which fails with
-- 'Slap.Status.ApplyReplaceGrowsFile' on violation.
data PPF4Replace = PPF4Replace
  { replaceOffset :: !Offset
  , replaceData   :: !ByteString
  } deriving (Show)

-- | A PPF4 Append record: writes 'appendData' at the end of the file
-- (where "end" is captured before any apply work begins; Replaces
-- cannot extend the file).
-- The wire format spends 4 bytes on a per-record offset field that is dropped at parse time:
-- Append records have no meaningful offset.
newtype PPF4Append = PPF4Append { appendData :: ByteString }
  deriving (Show)

-- | Wire-format magic prefix.
ppf4MagicBytes :: ByteString
ppf4MagicBytes = "PPF4"

-- | PPF4 header length: 6 preamble + 50 description + 4 post-description = 60.
ppf4HeaderLength :: Length
ppf4HeaderLength = Length 60

-- | Length of the header preamble before the description field:
-- magic (4) + version (1) + encoding (1).
ppf4PreambleLength :: Length
ppf4PreambleLength = Length 6

-- | Matches PPF1/PPF2/PPF3's 50-byte description only coincidentally; the PPF4 spec ships the same width independently.
ppf4DescriptionLength :: Length
ppf4DescriptionLength = Length 50

-- | Length of the flag/padding bytes after the description field in a
-- PPF4 header. Per Pyriel's source: image_type (1) + validation_flag (1)
-- + undo_flag (1) + expansion (1).
ppf4PostDescriptionLength :: Length
ppf4PostDescriptionLength = Length 4

-- | Maximum payload bytes a single PPF4 record (Replace or Append) can
-- carry. The record format uses a single-byte count field, capping
-- payload at @0xFF = 255@.
ppf4MaxRecordPayload :: Length
ppf4MaxRecordPayload = Length 255

-- | Fixed per-record header: 1-byte command + 4-byte LE offset
-- + 1-byte payload count. Equal to 'ppf4PreambleLength' by coincidence.
ppf4RecordHeaderLength :: Length
ppf4RecordHeaderLength = Length 6

-- | The smallest a whole record can be: the header plus one payload byte.
-- The reference maker never emits a record without payload, and its applier refuses a trailing run shorter than this,
-- so a stream that ends with fewer bytes than this left over ends mid-record rather than cleanly.
ppf4MinimumRecordLength :: Length
ppf4MinimumRecordLength = Length 7

-- | PPF4's wire-format offset cap. The Replace record's offset field is
-- 4 bytes; offsets ≥ 2^32 cannot be expressed. Append records carry no
-- meaningful offset (the field is written as zero), so this bound only
-- binds Replace records. Enforced at narrow time so
-- 'Slap.PPF4.Create.encodePPF4' cannot silently emit a truncated offset.
ppf4Limits :: EncodingLimits
ppf4Limits = EncodingLimits
  { maximumOffset = Offset 0xFFFFFFFF
  , formatLabel   = LabelPPF4
  }

-- | PPF4 declines (source, target) pairs whose target is shorter than
-- the source. PPF4's wire vocabulary has two record kinds — Replace
-- (bounded to the original target's byte range) and Append (grows the
-- target past the original's end) — and no command for declaring or
-- producing a shorter output. Growth is fine and is what Append
-- exists for; shrinkage is not expressible. See @docs\/ppf\/spec.md@,
-- "Size-changing patches" under PPF4, for the upstream picture.
--
-- Consumed by 'Slap.Convert.rejectIncompatibleSizeChange' through its 'CreatePPF4' arm.
ppf4RejectIncompatibleSizeChange
  :: FileSize -> FileSize -> Either SlapError ()
ppf4RejectIncompatibleSizeChange sourceSize targetSize
  | sourceSize <= targetSize = Right ()
  | otherwise                = Left (UnencodeablePair LabelPPF4
      (TargetShrinksBelowSource (ActualSize sourceSize) (ExpectedSize targetSize)))
