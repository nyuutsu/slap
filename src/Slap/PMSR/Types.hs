{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StrictData #-}

module Slap.PMSR.Types
  ( PMSRRecord(..)
  , PMSRPatch(..)
    -- * Named constants
  , pmsrMagicBytes
  ) where

import Data.ByteString (ByteString)
import Slap.Measure (Offset(..))

-- | A single PMSR record: offset + data to write.
data PMSRRecord = PMSRRecord
  { pmsrOffset :: !Offset
  , pmsrData   :: !ByteString
  } deriving (Show)

-- | A parsed PMSR patch.
data PMSRPatch = PMSRPatch
  { pmsrRecords :: [PMSRRecord]
  } deriving (Show)

-- | PMSR magic bytes (@"PMSR"@) per Star Rod (Paper Mario 64).
pmsrMagicBytes :: ByteString
pmsrMagicBytes = "PMSR"
