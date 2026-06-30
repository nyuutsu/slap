{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StrictData #-}

module Slap.APSGBA.Types
  ( APSGBAPatch(..)
  , APSGBAHeader(..)
  , APSGBARecord(..)
    -- * Wire-format wrappers
  , APSGBASourceSize
  , unAPSGBASourceSize
  , narrowAPSGBASourceSize
  , APSGBATargetSize
  , unAPSGBATargetSize
  , narrowAPSGBATargetSize
    -- * Named constants
  , apsGbaMagicBytes
  , apsGbaHeaderSize
  , apsGbaBlockSize
  , apsGbaRecordSize
  ) where

import Data.ByteString (ByteString)
import Data.Word (Word32)
import Slap.Checksum (CRC16)
import Slap.Status (SlapError(..))
import Slap.FieldName (FieldName(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.Measure (FileSize(..), Offset)
import Slap.Narrow (narrowToWord32)

data APSGBAPatch = APSGBAPatch APSGBAHeader [APSGBARecord]
  deriving (Show)

data APSGBAHeader = APSGBAHeader
  { apsGbaSourceSize :: FileSize
  , apsGbaTargetSize :: FileSize
  } deriving (Show)

data APSGBARecord = APSGBARecord
  { apsGbaOffset    :: Offset
  , apsGbaSourceCRC :: CRC16
  , apsGbaTargetCRC :: CRC16
  , apsGbaXorData   :: ByteString  -- apsGbaBlockSize bytes
  } deriving (Show)

----------------------------------------------------------------------------
-- Wire-format wrappers
----------------------------------------------------------------------------

-- | APS-GBA's 4-byte LE source-ROM-size header field, narrowed from a
-- runtime 'FileSize'. Constructor private; values come from
-- 'narrowAPSGBASourceSize'. APS-GBA has no parser-side exit because
-- the parser does not roundtrip through 'APSGBASourceSize' — its
-- 'APSGBAHeader' carries the raw 'FileSize' instead, since the apply
-- side needs the file-size type directly.
newtype APSGBASourceSize = APSGBASourceSize { unAPSGBASourceSize :: Word32 }
  deriving (Show, Eq)

narrowAPSGBASourceSize :: FileSize -> Either SlapError APSGBASourceSize
narrowAPSGBASourceSize size =
  case narrowToWord32 LabelAPSGBA FieldSourceSize (unFileSize size) of
    Left  failure -> Left (NarrowingError failure)
    Right word    -> Right (APSGBASourceSize word)

-- | APS-GBA's 4-byte LE target-ROM-size header field; sibling to
-- 'APSGBASourceSize'.
newtype APSGBATargetSize = APSGBATargetSize { unAPSGBATargetSize :: Word32 }
  deriving (Show, Eq)

narrowAPSGBATargetSize :: FileSize -> Either SlapError APSGBATargetSize
narrowAPSGBATargetSize size =
  case narrowToWord32 LabelAPSGBA FieldTargetSize (unFileSize size) of
    Left  failure -> Left (NarrowingError failure)
    Right word    -> Right (APSGBATargetSize word)

----------------------------------------------------------------------------
-- Named constants
----------------------------------------------------------------------------

-- | APS-GBA magic bytes (@"APS1"@). Shared prefix with APS-N64
-- (@"APS10"@) — detection must check the longer probe first.
apsGbaMagicBytes :: ByteString
apsGbaMagicBytes = "APS1"

-- | File header size: 4-byte magic + 4-byte source size + 4-byte target size.
apsGbaHeaderSize :: Int
apsGbaHeaderSize = 12

-- | XOR data block size: 65536 bytes (64 KB).
apsGbaBlockSize :: Int
apsGbaBlockSize = 65536

-- | Total record size: block size + 8 bytes of per-record header
-- (4-byte offset + 2-byte source CRC16 + 2-byte target CRC16).
apsGbaRecordSize :: Int
apsGbaRecordSize = apsGbaBlockSize + 8
