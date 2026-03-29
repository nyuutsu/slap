{-# LANGUAGE StrictData #-}

module Slap.IPS.Types
  ( IPSVariant(..)
  , IPSRecord(..)
  , IPSPatch(..)
  ) where

import Data.ByteString (ByteString)
import Data.Word (Word8)
import Slap.Measure (Offset(..), Length(..), FileSize(..))

data IPSVariant = StandardIPS | IPS32
  deriving (Show, Eq)

data IPSRecord
  = IPSRecord    { ipsRecordOffset :: !Offset, ipsRecordPayload :: !ByteString }
  | IPSRecordRLE { ipsRleOffset :: !Offset, ipsRleCount :: !Length, ipsRleFill :: !Word8 }
  deriving (Show)

data IPSPatch = IPSPatch
  { ipsVariant   :: IPSVariant
  , ipsRecords   :: [IPSRecord]
  , ipsTruncate  :: Maybe FileSize
  , ipsEBPMeta   :: Maybe ByteString  -- raw JSON metadata (EBP format)
  , ipsCleanEOF  :: Bool              -- True if proper EOF/EEOF marker was found
  } deriving (Show)
