{-# LANGUAGE StrictData #-}

module Slap.PMSR.Types
  ( PMSRRecord(..)
  , PMSRPatch(..)
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
