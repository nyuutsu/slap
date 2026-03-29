{-# LANGUAGE StrictData #-}

module Slap.PPF.Types
    ( Version(..)
    , ImageType(..)
    , fromImageType
    , Validation(..)
    , RecordCommand(..)
    , Record(..)
    , FileId(..)
    , Patch(..)
    , validationOffset
    , validationSize
    ) where

import Data.ByteString (ByteString)
import Data.Word (Word8, Word32)
import Slap.Measure (Offset(..), Length(..))

-- | PPF format version.
data Version = PPF1 | PPF2 | PPF3 | PPF4
  deriving (Show, Eq, Ord)

-- | PPF3 image type — determines the validation block source offset.
data ImageType = BIN | GI
  deriving (Show, Eq)

fromImageType :: ImageType -> Word8
fromImageType BIN = 0x00
fromImageType GI  = 0x01

-- | Validation data embedded in PPF2/PPF3 headers.
data Validation = Validation
  { validationImageType :: ImageType
  , validationBlock     :: ByteString  -- ^ 1024 bytes from the target image
  } deriving (Show)

-- | Record command type.  Replace is standard for PPF1/2/3; Append exists
-- only in Pyriel's internal format (reverse-engineered from the Suikoden patchers).
data RecordCommand = Replace | Append
  deriving (Show, Eq)

-- | A single patch record.
data Record = Record
  { recordOffset  :: !Offset           -- ^ Byte offset in target file
  , recordData    :: !ByteString       -- ^ Replacement bytes
  , recordUndo    :: !(Maybe ByteString) -- ^ Original bytes (PPF3 only, if undo data present)
  , recordCommand :: !RecordCommand    -- ^ Replace or Append (PPF4 only; always Replace for PPF1/2/3)
  } deriving (Show)

-- | Optional File_ID.diz content appended to PPF2/PPF3 files.
newtype FileId = FileId { fileIdContent :: ByteString }
  deriving (Show)

-- | A fully parsed PPF patch.
data Patch = Patch
  { ppfVersion     :: Version
  , ppfDescription :: ByteString      -- ^ 50-byte description field
  , ppfFileSize    :: Maybe Word32     -- ^ Expected target size (PPF2 only)
  , ppfValidation  :: Maybe Validation -- ^ Block check data (PPF2 always, PPF3 optional)
  , ppfHasUndo     :: Bool             -- ^ Whether undo data is present (PPF3 only)
  , ppfImageType   :: Maybe ImageType  -- ^ PPF3 only (byte 56)
  , ppfRecords     :: [Record]
  , ppfFileId      :: Maybe FileId
  } deriving (Show)

-- | Offset in target file where validation block is read from.
validationOffset :: ImageType -> Offset
validationOffset BIN = Offset 0x9320
validationOffset GI  = Offset 0x80A0

-- | Size of the validation block.
validationSize :: Length
validationSize = Length 1024
