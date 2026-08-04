{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DerivingVia #-}

-- | Types for PPF1 patches. PPF1 is the original Paradox patch format,
-- specified in @docs/ppf/upstream/pdx-ppf1/ppf-doc.txt@: a 56-byte
-- header (magic + version + encoding byte + 50-byte description)
-- followed by an open-ended stream of records, where each record is
-- a 4-byte LE offset, a 1-byte count, and either @count@ payload
-- bytes (literal mode) or — when the count byte is zero — a 2-byte
-- @(data_byte, repeat_count)@ pair (RLE mode).
module Slap.PPF1.Types
  ( PPF1Patch(..)
  , PPF1Record(..)
    -- * Named constants
  , ppf1MagicBytes
  , ppf1DescriptionLength
  , ppf1HeaderLength
  , ppf1MaxRecordPayload
    -- * Encoding limits
  , ppf1Limits
    -- * Source/target size-pair rule
  , ppf1RejectIncompatibleSizeChange
  ) where

import Data.ByteString (ByteString)
import Slap.FormatLabel (FormatLabel(..))
import Slap.Measure (Length(..), Offset(..),
                     FileSize, ActualSize(..), ExpectedSize(..))
import Slap.Narrow (EncodingLimits(..))
import Slap.Status (SlapError(..), UnencodeabilityReason(..))
import Slap.Text (EncodedText)

-- | A single PPF1 record. Both literal and RLE forms expand to the
-- same in-memory shape: a target-file offset and the bytes to write
-- there. The wire-level RLE encoding is decoded at parse time.
data PPF1Record = PPF1Record
  { ppf1RecordOffset  :: !Offset
  , ppf1RecordPayload :: !ByteString
  } deriving (Show)

-- | A fully parsed PPF1 patch. PPF1 carries no validation block, no
-- undo data, no FILE_ID.DIZ — just a description and records.
data PPF1Patch = PPF1Patch
  { ppf1Description :: !EncodedText
    -- ^ 50-byte description field, decoded at parse time under the
    -- chosen metadata encoding. The PPF1 spec leaves the wire field's
    -- encoding undeclared, so slap reads the bytes under the user's
    -- @--metadata-encoding@ (default UTF-8) and writes them back as
    -- UTF-8. Encode-side padding (PPF1\/PPF2: @0x20@, PPF3: @0x00@) is
    -- format-faithful and stays at the format's own @Create.hs@.
  , ppf1Records     :: ![PPF1Record]
  } deriving (Show)

-- | Wire-format magic prefix.
ppf1MagicBytes :: ByteString
ppf1MagicBytes = "PPF1"

ppf1DescriptionLength :: Length
ppf1DescriptionLength = Length 50

-- | Total PPF1 header length: 4 magic + 1 version + 1 encoding + 50 description = 56.
ppf1HeaderLength :: Length
ppf1HeaderLength = Length 56

-- | Maximum payload bytes a single PPF1 record can carry. The record
-- format uses a single-byte count field (literal mode), capping
-- payload at @0xFF = 255@.
ppf1MaxRecordPayload :: Length
ppf1MaxRecordPayload = Length 255

-- | PPF1's wire-format offset cap. The record's offset field is 4 bytes (LE for the PC dialect, BE for the Amiga),
-- and the reference reads it into a C @long@ to hand to @fseek@, whose offset parameter is signed,
-- so the top bit names a position behind the start of the file rather than one past 2 GB.
-- @ppf-doc.txt@ says as much in words: "PPF facilitate patching of iso-files up to 2Gb."
ppf1Limits :: EncodingLimits
ppf1Limits = EncodingLimits
  { maximumOffset = Offset 0x7FFFFFFF
  , formatLabel   = LabelPPF1
  }

-- | PPF1 declines (source, target) pairs whose sizes differ. PPF1's
-- wire format has no command for declaring growth or shrinkage; the
-- spec is silent on the question and the reference maker refuses
-- size mismatch as a maker-side policy. Slap honors the maker-side
-- intent on emit. See @docs\/ppf\/spec.md@, "Size-changing patches"
-- under PPF1, for the full upstream picture.
--
-- Consumed by 'Slap.Convert.rejectIncompatibleSizeChange' through its
-- 'CreatePPF1' arm.
ppf1RejectIncompatibleSizeChange
  :: FileSize -> FileSize -> Either SlapError ()
ppf1RejectIncompatibleSizeChange sourceSize targetSize
  | sourceSize == targetSize = Right ()
  | sourceSize <  targetSize = Left (UnencodeablePair LabelPPF1
      (TargetGrowsBeyondSource  (ActualSize sourceSize) (ExpectedSize targetSize)))
  | otherwise                = Left (UnencodeablePair LabelPPF1
      (TargetShrinksBelowSource (ActualSize sourceSize) (ExpectedSize targetSize)))
