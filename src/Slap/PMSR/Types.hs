{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StrictData #-}

module Slap.PMSR.Types
  ( PMSRRecord(..)
  , PMSRPatch(..)
  , PMSRRecordCount
  , unPMSRRecordCount
  , narrowPMSRRecordCount
    -- * Named constants
  , pmsrMagicBytes
  , pmsrMaxRecordPayload
    -- * Encoding limits
  , pmsrLimits
    -- * Source/target size-pair rule
  , pmsrRejectIncompatibleSizeChange
  ) where

import Data.ByteString (ByteString)
import Data.Vector (Vector)
import Data.Word (Word32)
import Slap.Status (SlapError(..), UnencodeabilityReason(..))
import Slap.FieldName (FieldName(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.Measure (Length(..), Offset(..),
                     FileSize, ActualSize(..), ExpectedSize(..))
import Slap.Narrow (EncodingLimits(..), narrowToWord32)

-- | A single PMSR record: offset + data to write.
data PMSRRecord = PMSRRecord
  { pmsrOffset :: !Offset
  , pmsrData   :: !ByteString
  } deriving (Show)

-- | A parsed PMSR patch.
data PMSRPatch = PMSRPatch
  { pmsrRecords :: Vector PMSRRecord
  } deriving (Show)

-- | PMSR's 4-byte BE record-count header field, narrowed from a
-- runtime 'Int' list length via 'narrowPMSRRecordCount'.
newtype PMSRRecordCount = PMSRRecordCount { unPMSRRecordCount :: Word32 }
  deriving (Show, Eq)

narrowPMSRRecordCount :: Int -> Either SlapError PMSRRecordCount
narrowPMSRRecordCount n =
  case narrowToWord32 LabelPMSR FieldRecordCount n of
    Left  failure -> Left (NarrowingError failure)
    Right word    -> Right (PMSRRecordCount word)

-- | PMSR magic bytes (@"PMSR"@) per Star Rod (Paper Mario 64).
pmsrMagicBytes :: ByteString
pmsrMagicBytes = "PMSR"

-- | PMSR's per-record offset wire field is 4-byte big-endian Word32;
-- offsets must fit in 2^32 bytes. Enforced at narrow time so
-- 'Slap.PMSR.Create.encodePMSR' cannot silently truncate.
pmsrLimits :: EncodingLimits
pmsrLimits = EncodingLimits
  { maximumOffset = Offset 0xFFFFFFFF
  , formatLabel   = LabelPMSR
  }

-- | PMSR's per-record length wire field is 4-byte big-endian Word32;
-- payloads must fit in 2^32 bytes. Enforced at split time so
-- 'Slap.PMSR.Create.encodePMSR' cannot silently truncate.
pmsrMaxRecordPayload :: Length
pmsrMaxRecordPayload = Length 0xFFFFFFFF

-- | PMSR declines (source, target) pairs whose target is shorter than
-- the source. PMSR carries no output-size field; an applier derives the
-- target size as the larger of the source size and the furthest record
-- end, allocates a buffer of that size, copies the source in, then
-- writes the records — so the output is never smaller than the source.
-- Growth is fine; shrinkage has no representation.
--
-- Consumed by 'Slap.Convert.rejectIncompatibleSizeChange' through its
-- 'CreatePMSR' arm.
pmsrRejectIncompatibleSizeChange
  :: FileSize -> FileSize -> Either SlapError ()
pmsrRejectIncompatibleSizeChange sourceSize targetSize
  | sourceSize <= targetSize = Right ()
  | otherwise                = Left (UnencodeablePair LabelPMSR
      (TargetShrinksBelowSource (ActualSize sourceSize) (ExpectedSize targetSize)))
