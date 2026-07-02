{-# LANGUAGE StrictData #-}

module Slap.DPS.Types
  ( DPSPatch(..)
  , DPSRecord(..)
  , DPSCreateMetadata(..)
  , DPSStability(..)
  , DPSFormatVersion(..)
  , toDPSStability
  , fromDPSStability
  , toDPSFormatVersion
  , fromDPSFormatVersion
    -- * Wire-format wrappers
  , DPSSourceSize
  , unDPSSourceSize
  , narrowDPSSourceSize
  , dpsSourceSizeFromParsed
  , dpsSourceSizeAsFileSize
  , EncodedDPSRecord(..)
  , narrowDPSRecord
  , narrowDPSRecords
    -- * Named constants
  , dpsFieldWidth
  , dpsFieldCount
  , dpsMetadataSize
  , dpsMinimumFileSize
  , dpsVersionOffset
  , dpsStabilityOffset
    -- * Record constants
  , dpsCopyFromROMMode
  , dpsEnclosedDataMode
  , dpsRecordHeaderSize
  , dpsCopyRecordSize
    -- * Derived sizes
  , dpsOutputExtent
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.Word (Word8, Word32)
import Slap.Status (SlapError(..))
import Slap.FieldName (FieldName(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.Measure (Offset(..), Length(..), FileSize(..), FoundVersion(..),
                     advance, byteLength, offsetToFileSize)
import Slap.Narrow (narrowToWord32)
import Slap.Text (EncodedText)

data DPSStability = DPSStable | DPSUnstable
  deriving (Show, Eq)

toDPSStability :: Word8 -> Either String DPSStability
toDPSStability 0 = Right DPSStable
toDPSStability 1 = Right DPSUnstable
toDPSStability flagByte = Left ("unknown stability flag: " ++ show flagByte)

fromDPSStability :: DPSStability -> Word8
fromDPSStability DPSStable   = 0
fromDPSStability DPSUnstable = 1

data DPSFormatVersion = DPSVersion1
  deriving (Show, Eq)

toDPSFormatVersion :: Word8 -> Either SlapError DPSFormatVersion
toDPSFormatVersion 1 = Right DPSVersion1
toDPSFormatVersion byte = Left (BadVersion LabelDPS (FoundVersion byte))

fromDPSFormatVersion :: DPSFormatVersion -> Word8
fromDPSFormatVersion DPSVersion1 = 1

-- | The header fields a DPS create call supplies.
-- Each is typed 'EncodedText' so the encoding decision (locale today; declared-on-the-wire when DPS gains an encoding flag) travels with the value.
data DPSCreateMetadata = DPSCreateMetadata
  { dpsCreateMetadataName    :: !EncodedText
  , dpsCreateMetadataAuthor  :: !EncodedText
  , dpsCreateMetadataVersion :: !EncodedText
  } deriving (Show, Eq)

data DPSPatch = DPSPatch
  { dpsName          :: !EncodedText
    -- ^ Decoded at parse time under the process locale;
    -- re-encoded under the same locale on create via 'Slap.DPS.Create.encodeField'.
  , dpsAuthor        :: !EncodedText
  , dpsVersion       :: !EncodedText
  , dpsStability     :: !DPSStability
  , dpsFormatVersion :: !DPSFormatVersion
  , dpsOriginalSize  :: !DPSSourceSize
  , dpsRecords       :: ![DPSRecord]
  } deriving (Show)

data DPSRecord
  = DPSCopyFromROM
      { dpsCopyOutputOffset :: !Offset
      , dpsCopySourceOffset :: !Offset
      , dpsCopyLength       :: !Length
      }
  | DPSEnclosedData
      { dpsDataOutputOffset :: !Offset
      , dpsDataPayload      :: !ByteString
      }
  deriving (Show)

----------------------------------------------------------------------------
-- Wire-format wrappers
----------------------------------------------------------------------------

-- | DPS's 4-byte LE source-ROM-size header field, narrowed from a runtime 'FileSize'.
-- Values come from 'narrowDPSSourceSize' (runtime check)
-- or 'dpsSourceSizeFromParsed' (parse-time trust, since the field's wire shape constrains the bytestring before it reaches the constructor).
newtype DPSSourceSize = DPSSourceSize { unDPSSourceSize :: Word32 }
  deriving (Show, Eq)

narrowDPSSourceSize :: FileSize -> Either SlapError DPSSourceSize
narrowDPSSourceSize size =
  case narrowToWord32 LabelDPS FieldSourceSize (unFileSize size) of
    Left  failure -> Left (NarrowingError failure)
    Right word    -> Right (DPSSourceSize word)

dpsSourceSizeFromParsed :: Word32 -> DPSSourceSize
dpsSourceSizeFromParsed = DPSSourceSize

-- | Lift a 'DPSSourceSize' back to a 'FileSize' for callers that work
-- in the application's general size type ("Slap.SomePatch"'s
-- file-size verification gate, "Slap.DPS.Describe"'s info line).
-- Word32 → Int is widening on every host slap supports (GHC's 'Int'
-- is always at least 30 bits and is 64 bits on 64-bit hosts), so the
-- conversion never truncates.
dpsSourceSizeAsFileSize :: DPSSourceSize -> FileSize
dpsSourceSizeAsFileSize (DPSSourceSize word) = FileSize (fromIntegral word)

-- | A 'DPSRecord' whose offsets and lengths have been validated against the 4-byte LE wire fields.
-- Values come from 'narrowDPSRecord' / 'narrowDPSRecords' only;
-- the constructors are exported so 'Slap.DPS.Create' can pattern-match the arms, not as a second way to build one.
data EncodedDPSRecord
  = EncodedDPSCopyFromROM
      { encodedDPSCopyOutputOffset :: !Word32
      , encodedDPSCopySourceOffset :: !Word32
      , encodedDPSCopyLength       :: !Word32
      }
  | EncodedDPSEnclosedData
      { encodedDPSDataOutputOffset :: !Word32
      , encodedDPSDataPayload      :: !ByteString
      }
  deriving (Show, Eq)

-- | Validate a 'DPSRecord''s offsets and lengths against the
-- record's 4-byte LE wire fields. The 'EnclosedData' arm also
-- validates the payload's bytestring length, since the wire format
-- writes that count alongside the bytes themselves.
narrowDPSRecord :: DPSRecord -> Either SlapError EncodedDPSRecord
narrowDPSRecord (DPSCopyFromROM outputOffset sourceOffset copyLength) = do
  outputW <- narrowDPSField FieldRecordOutputOffset (unOffset outputOffset)
  sourceW <- narrowDPSField FieldRecordSourceOffset (unOffset sourceOffset)
  lengthW <- narrowDPSField FieldRecordLength       (unLength copyLength)
  pure (EncodedDPSCopyFromROM outputW sourceW lengthW)
narrowDPSRecord (DPSEnclosedData outputOffset payload) = do
  outputW <- narrowDPSField FieldRecordOutputOffset (unOffset outputOffset)
  _       <- narrowDPSField FieldRecordLength (ByteString.length payload)
  pure (EncodedDPSEnclosedData outputW payload)

narrowDPSField :: FieldName -> Int -> Either SlapError Word32
narrowDPSField field value =
  case narrowToWord32 LabelDPS field value of
    Left  failure -> Left (NarrowingError failure)
    Right word    -> Right word

narrowDPSRecords :: [DPSRecord] -> Either SlapError [EncodedDPSRecord]
narrowDPSRecords = traverse narrowDPSRecord

----------------------------------------------------------------------------
-- Named constants
----------------------------------------------------------------------------

-- | Each metadata field (name, author, version) is 64 bytes, null-padded.
dpsFieldWidth :: Length
dpsFieldWidth = Length 64

dpsFieldCount :: Int
dpsFieldCount = 3

-- | Total metadata size: 3 × 64 = 192 bytes.
dpsMetadataSize :: Int
dpsMetadataSize = dpsFieldCount * unLength dpsFieldWidth

-- | Minimum valid DPS file: 192 (metadata) + 1 (flag) + 1 (version) + 4 (orig size).
dpsMinimumFileSize :: Int
dpsMinimumFileSize = dpsMetadataSize + 6

-- | Byte offset of the version field (0-indexed).
dpsVersionOffset :: Int
dpsVersionOffset = dpsMetadataSize + 1

-- | Byte offset of the stability flag (0-indexed).
dpsStabilityOffset :: Int
dpsStabilityOffset = dpsMetadataSize

-- | Mode byte for CopyFromROM records.
dpsCopyFromROMMode :: Word8
dpsCopyFromROMMode = 0

-- | Mode byte for EnclosedData records.
dpsEnclosedDataMode :: Word8
dpsEnclosedDataMode = 1

-- | Shared record header: mode byte + output offset (1 + 4 bytes).
dpsRecordHeaderSize :: Int
dpsRecordHeaderSize = 5

-- | Full CopyFromROM record: mode + outputOffset + sourceOffset + length (1 + 4 + 4 + 4).
dpsCopyRecordSize :: Int
dpsCopyRecordSize = 13

----------------------------------------------------------------------------
-- Derived sizes
----------------------------------------------------------------------------

-- | The minimum output buffer size needed to hold the result of applying
-- a DPS record list: @max(recordOutputOffset + recordLength)@ across all
-- records. Returns @FileSize 0@ for an empty record list — the caller
-- decides whether that means an empty output or a parse-level warning.
dpsOutputExtent :: [DPSRecord] -> FileSize
dpsOutputExtent = foldl' extendMaxWith (FileSize 0)
  where
    extendMaxWith :: FileSize -> DPSRecord -> FileSize
    extendMaxWith currentMax (DPSCopyFromROM outputOffset _sourceOffset copyLength) =
      max currentMax (offsetToFileSize (advance outputOffset copyLength))
    extendMaxWith currentMax (DPSEnclosedData outputOffset payload) =
      max currentMax (offsetToFileSize (advance outputOffset (byteLength payload)))
