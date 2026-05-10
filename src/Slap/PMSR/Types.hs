{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StrictData #-}

module Slap.PMSR.Types
  ( PMSRRecord(..)
  , PMSRPatch(..)
    -- * Named constants
  , pmsrMagicBytes
  , pmsrMaxRecordPayload
    -- * Encoding limits
  , pmsrLimits
  ) where

import Data.ByteString (ByteString)
import Data.Vector (Vector)
import Slap.FormatLabel (FormatLabel(..))
import Slap.Measure (Length(..), Offset(..))
import Slap.Narrow (EncodingLimits(..))

-- | A single PMSR record: offset + data to write.
data PMSRRecord = PMSRRecord
  { pmsrOffset :: !Offset
  , pmsrData   :: !ByteString
  } deriving (Show)

-- | A parsed PMSR patch.
data PMSRPatch = PMSRPatch
  { pmsrRecords :: Vector PMSRRecord
  } deriving (Show)

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

-- | PMSR's wire-format payload cap. The record format's length field
-- is 4 bytes BE, so payloads ≥ 2^32 bytes cannot be expressed without
-- truncation. Enforced at split time so 'Slap.PMSR.Create.encodePMSR'
-- cannot silently emit a truncated length.
pmsrMaxRecordPayload :: Length
pmsrMaxRecordPayload = Length 0xFFFFFFFF
