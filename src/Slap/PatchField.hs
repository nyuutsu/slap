{-# LANGUAGE OverloadedStrings #-}

module Slap.PatchField
  ( PatchField(..)
  , fieldName
  , affectsApplyOutput
  ) where

import Data.Text (Text)

-- | Fields a patch format can provide or require.
data PatchField
  = FieldRecords
  | FieldDescription
  | FieldSourceCRC32
  | FieldSourceMD5
  | FieldSourceSHA1
  | FieldDestinationSize
  | FieldUndoData
  | FieldValidation
  | FieldTruncation
  | FieldEBPMeta
  | FieldRomType
  | FieldImageType
  | FieldFileIdDiz
  | FieldMetadata
  deriving (Eq, Ord, Show)

fieldName :: PatchField -> Text
fieldName FieldRecords         = "records"
fieldName FieldDescription     = "description"
fieldName FieldSourceCRC32     = "source CRC32"
fieldName FieldSourceMD5       = "source MD5"
fieldName FieldSourceSHA1      = "source SHA1"
fieldName FieldDestinationSize = "target file size"
fieldName FieldUndoData        = "undo data"
fieldName FieldValidation      = "validation block"
fieldName FieldTruncation      = "truncation marker"
fieldName FieldEBPMeta         = "EBP metadata"
fieldName FieldRomType         = "ROM type"
fieldName FieldImageType       = "image type"
fieldName FieldFileIdDiz       = "File_ID.diz"
fieldName FieldMetadata        = "metadata"

-- | Whether dropping a field changes the output bytes that the
-- resulting patch produces on apply. Fields that affect apply
-- output cannot be silently dropped on conversion; 'canConvert'
-- refuses any conversion that would lose one present in the source.
-- Other fields (metadata, capability carriers like undo data, etc.)
-- are dropped with a warning via the usual 'conversionNotes'
-- mechanism.
--
-- 'FieldTruncation' is the only field of this kind today: an IPS
-- patch with a truncation marker produces a target file of the
-- declared size on apply, while the same records without truncation
-- produce @max(sourceSize, maxRecordEnd)@. The two apply operations
-- yield different bytes, so the conversion machinery refuses the
-- drop rather than papering over it with a warning. 'FieldUndoData'
-- is deliberately not in this class: undo is a separate operation
-- from apply, and dropping undo data only affects whether a later
-- undo is possible.
affectsApplyOutput :: PatchField -> Bool
affectsApplyOutput FieldTruncation = True
affectsApplyOutput _               = False
