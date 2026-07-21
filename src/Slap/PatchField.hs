{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE OverloadedStrings #-}

module Slap.PatchField
  ( PatchField(..)
  , fieldName
  , affectsApplyOutput
  ) where

import Data.Aeson (ToJSON)
import Data.Text (Text)
import GHC.Generics (Generic, Generically(..))

-- | Fields a patch format can provide or require.
data PatchField
  = FieldRecords
  | FieldDescription
  | FieldSourceCRC32
  | FieldSourceMD5
  | FieldSourceSHA1
  | FieldSourceSize
  | FieldDestinationSize
  | FieldUndoData
  | FieldValidation
  | FieldTruncation
  | FieldEBPMeta
  | FieldRomType
  | FieldImageType
  | FieldFileIdDiz
  | FieldMetadata
  deriving (Eq, Ord, Enum, Bounded, Show, Generic)
  deriving (ToJSON) via Generically PatchField

fieldName :: PatchField -> Text
fieldName FieldRecords         = "records"
fieldName FieldDescription     = "description"
fieldName FieldSourceCRC32     = "source CRC32"
fieldName FieldSourceMD5       = "source MD5"
fieldName FieldSourceSHA1      = "source SHA1"
fieldName FieldSourceSize      = "original file size"
fieldName FieldDestinationSize = "target file size"
fieldName FieldUndoData        = "undo data"
fieldName FieldValidation      = "validation block"
fieldName FieldTruncation      = "truncation marker"
fieldName FieldEBPMeta         = "EBP metadata"
fieldName FieldRomType         = "ROM type"
fieldName FieldImageType       = "image type"
fieldName FieldFileIdDiz       = "File_ID.diz"
fieldName FieldMetadata        = "metadata"

-- | Whether dropping this field changes the bytes apply produces.
-- 'canConvert' refuses a conversion that would drop such a field rather than noting it.
-- 'FieldTruncation' and 'FieldDestinationSize' each pin the output to a declared size;
-- dropping either lets the length fall back to @max(sourceSize, maxRecordEnd)@.
affectsApplyOutput :: PatchField -> Bool
affectsApplyOutput FieldTruncation      = True
affectsApplyOutput FieldDestinationSize = True
affectsApplyOutput _                    = False
