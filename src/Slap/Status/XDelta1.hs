{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE StrictData #-}

-- | The xdelta1 wing of the status vocabulary.
module Slap.Status.XDelta1
  ( XDelta1KnownUnsupportedVersion(..)
  , XDelta1ShapeViolation(..)
  , XDelta1SourceListShape(..)
  , XDelta1SourcelessShape(..)
  , XDelta1SourceFlag(..)
  , XDelta1GzipStreamInputs(..)
  , XDelta1DataRecordNameAsRead(..)
  ) where

import Data.Aeson (ToJSON)
import Data.ByteString (ByteString)
import GHC.Generics (Generic, Generically(..))

import Slap.JSON.Bytes (BytesAsBase64(..))

-- | The xdelta1 versions whose magic slap recognizes but whose body shape it does not parse.
data XDelta1KnownUnsupportedVersion
  = XDelta1_1_0_4
  | XDelta1_1_0
  | XDelta1_0_14
  deriving (Eq, Show, Generic)
  deriving (ToJSON) via Generically XDelta1KnownUnsupportedVersion

-- | The off-spec source-list shapes the xdelta1 parser refuses. The nullary constructors are the fixed cases;
-- 'XDelta1TooManySources' carries the count (N >= 3), which is open-ended.
data XDelta1ShapeViolation
  = XDelta1TwoDataSources
  | XDelta1ReversedDataFileOrder
  | XDelta1TwoFileSources
  | XDelta1TooManySources Int
  deriving (Eq, Show, Generic)
  deriving (ToJSON) via Generically XDelta1ShapeViolation

-- | The emitted source-list shape an instruction's wire index indexes into,
-- carried by 'Slap.Status.XDelta1UnknownInstructionTarget' so the refusal can name the indices the patch actually declared.
data XDelta1SourceListShape
  = SourceListDataAndFile  -- ^ index 0 is the data segment, index 1 the file source.
  | SourceListDataOnly     -- ^ index 0 is the data segment; there is no index 1.
  | SourceListFileOnly     -- ^ index 0 is the file source; there is no index 1.
  | SourceListEmpty        -- ^ no valid indices at all.
  deriving (Eq, Show, Generic)
  deriving (ToJSON) via Generically XDelta1SourceListShape

-- | Why an xdelta1 apply never read the handed input, carried by 'Slap.Status.XDelta1InputFileNotConsulted'.
data XDelta1SourcelessShape
  = OutputComesFromDataSegment  -- ^ @[data]@: every instruction reads the patch's own segment.
  | OutputIsEmpty               -- ^ @[]@: the declared target is empty; nothing reads anything.
  deriving (Eq, Show, Generic)
  deriving (ToJSON) via Generically XDelta1SourcelessShape

-- | Which boolean flag on an xdelta1 source record held a non-boolean byte, for 'Slap.Status.XDelta1NonBooleanSourceFlag'.
data XDelta1SourceFlag
  = XDelta1SourceKindFlag        -- ^ the @isdata@ byte
  | XDelta1SourceOffsetModeFlag  -- ^ the @sequential@ byte
  deriving (Show, Eq, Generic)
  deriving (ToJSON) via Generically XDelta1SourceFlag

-- | Which input file(s) an xdelta1 patch expected to be gzip streams, for 'Slap.Status.XDelta1InputPreCompressionUnsupported'.
-- "Neither" is unrepresentable — that is the success path, not a failure shape.
data XDelta1GzipStreamInputs
  = OnlyFromFileWasGzipStream
  | OnlyToFileWasGzipStream
  | BothFilesWereGzipStreams
  deriving (Show, Eq, Generic)
  deriving (ToJSON) via Generically XDelta1GzipStreamInputs

-- | An xdelta1 data-record @name@ field's bytes as read, for 'Slap.Status.XDelta1DataRecordNameDiverges'.
newtype XDelta1DataRecordNameAsRead = XDelta1DataRecordNameAsRead { unXDelta1DataRecordNameAsRead :: ByteString }
  deriving (Show, Eq)
  deriving (ToJSON) via BytesAsBase64
