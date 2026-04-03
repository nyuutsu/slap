module Slap.PatchField
  ( PatchField(..)
  , fieldName
  ) where

-- | Fields a patch format can provide or require.
data PatchField
  = FRecords
  | FDescription
  | FSourceCRC32
  | FSourceMD5
  | FSourceSHA1
  | FDestinationSize
  | FUndoData
  | FValidation
  | FTruncation
  | FEBPMeta
  | FRomType
  | FImageType
  | FFileIdDiz
  | FPCHTXTBlocks
  | FMetadata
  deriving (Eq, Ord, Show)

fieldName :: PatchField -> String
fieldName FRecords        = "records"
fieldName FDescription    = "description"
fieldName FSourceCRC32    = "source CRC32"
fieldName FSourceMD5      = "source MD5"
fieldName FSourceSHA1     = "source SHA1"
fieldName FDestinationSize = "target file size"
fieldName FUndoData       = "undo data"
fieldName FValidation     = "validation block"
fieldName FTruncation     = "truncation marker"
fieldName FEBPMeta        = "EBP metadata"
fieldName FRomType        = "ROM type"
fieldName FImageType      = "image type"
fieldName FFileIdDiz      = "File_ID.diz"
fieldName FPCHTXTBlocks   = "PCHTXT blocks"
fieldName FMetadata       = "metadata"
