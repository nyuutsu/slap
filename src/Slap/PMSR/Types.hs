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
import Data.Int (Int64)
import Data.Word (Word32)
import Slap.Status (SlapError(..), UnencodeabilityReason(..))
import Slap.FieldName (FieldName(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.Measure (Length(..), Offset(..),
                     FileSize, ActualSize(..), ExpectedSize(..))
import Slap.Narrow (EncodingLimits(..), NarrowingFailure(FieldValueExceedsBound))

data PMSRRecord = PMSRRecord
  { pmsrOffset :: !Offset
  , pmsrData   :: !ByteString
  } deriving (Show)

data PMSRPatch = PMSRPatch
  { pmsrRecords :: Vector PMSRRecord
  } deriving (Show)

-- | PMSR's 4-byte BE record-count header field, narrowed from a
-- runtime 'Int' list length via 'narrowPMSRRecordCount'.
newtype PMSRRecordCount = PMSRRecordCount { unPMSRRecordCount :: Word32 }
  deriving (Show, Eq)

narrowPMSRRecordCount :: Int -> Either SlapError PMSRRecordCount
narrowPMSRRecordCount recordCount
  | recordCount < 0 || toInteger recordCount > toInteger pmsrMaximumAddressableSize =
      Left (NarrowingError (FieldValueExceedsBound LabelPMSR FieldRecordCount
                              (toInteger recordCount) (toInteger pmsrMaximumAddressableSize)))
  | otherwise = Right (PMSRRecordCount (fromIntegral recordCount))

-- | PMSR magic bytes, per Star Rod (Paper Mario 64).
pmsrMagicBytes :: ByteString
pmsrMagicBytes = "PMSR"

-- | The largest byte position PMSR addresses. Star Rod writes the whole patch through @java.nio.ByteBuffer@,
-- and its three numbers, the record count and each record's offset and length, all go out as @putInt@.
-- That is a Java @int@: signed, 32 bits, big-endian, so the top bit of any of them is a sign rather than magnitude.
-- (@Patcher.java@ in Star Rod Classic, the loop that follows @putInt(MOD_PACKAGE_IDENTIFIER)@.)
pmsrMaximumAddressableSize :: Int64
pmsrMaximumAddressableSize = 0x7FFFFFFF

pmsrLimits :: EncodingLimits
pmsrLimits = EncodingLimits
  { maximumOffset = Offset pmsrMaximumAddressableSize
  , formatLabel   = LabelPMSR
  }

-- | The per-record payload cap, being the same signed 32-bit field as the offset ('pmsrMaximumAddressableSize').
pmsrMaxRecordPayload :: Length
pmsrMaxRecordPayload = Length pmsrMaximumAddressableSize

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
