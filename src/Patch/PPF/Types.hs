{-# LANGUAGE StrictData #-}

module Patch.PPF.Types where

import Data.ByteString (ByteString)
import Data.Int (Int64)
import Data.Word (Word32)

-- | PPF format version.
data Version = PPF1 | PPF2 | PPF3 | PPF4
  deriving (Show, Eq, Ord)

-- | PPF3 image type — determines the validation block source offset.
data ImageType = BIN | GI
  deriving (Show, Eq)

-- | Validation data embedded in PPF2/PPF3 headers.
data Validation = Validation
  { valImageType :: ImageType
  , valBlock     :: ByteString  -- ^ 1024 bytes from the target image
  } deriving (Show)

-- | Record command type.  Replace is standard for PPF1/2/3; Append exists
-- only in Pyriel's internal format (reverse-engineered from the Suikoden patchers).
data RecordCmd = Replace | Append
  deriving (Show, Eq)

-- | A single patch record.
data Record = Record
  { recOffset :: Int64             -- ^ Byte offset in target file
  , recData   :: ByteString        -- ^ Replacement bytes
  , recUndo   :: Maybe ByteString  -- ^ Original bytes (PPF3 only, if undo data present)
  , recCmd    :: RecordCmd         -- ^ Replace or Append (PPF4 only; always Replace for PPF1/2/3)
  } deriving (Show)

-- | Optional File_ID.diz content appended to PPF2/PPF3 files.
newtype FileId = FileId { fileIdContent :: ByteString }
  deriving (Show)

-- | A fully parsed PPF patch.
data Patch = Patch
  { patchVersion     :: Version
  , patchDescription :: ByteString      -- ^ 50-byte description field
  , patchFileSize    :: Maybe Word32     -- ^ Expected target size (PPF2 only)
  , patchValidation  :: Maybe Validation -- ^ Block check data (PPF2 always, PPF3 optional)
  , patchHasUndo     :: Bool             -- ^ Whether undo data is present (PPF3 only)
  , patchRecords     :: [Record]
  , patchFileId      :: Maybe FileId
  } deriving (Show)

-- | Offset in target file where validation block is read from.
validationOffset :: ImageType -> Int64
validationOffset BIN = 0x9320
validationOffset GI  = 0x80A0

-- | Size of the validation block.
validationSize :: Int
validationSize = 1024
