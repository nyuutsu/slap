module Slap.PatchField
  ( PatchField(..)
  , fieldName
  , affectsApplyOutput
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

-- | Whether dropping a field changes the output bytes that the
-- resulting patch produces on apply. Fields that affect apply
-- output cannot be silently dropped on conversion; 'canConvert'
-- refuses any conversion that would lose one present in the source.
-- Other fields (metadata, capability carriers like undo data, etc.)
-- are dropped with a warning via the usual 'conversionNotes'
-- mechanism.
--
-- 'FTruncation' is the only field of this kind today: an IPS patch
-- with a truncation marker produces a target file of the declared
-- size on apply, while the same records without truncation produce
-- @max(sourceSize, maxRecordEnd)@. The two apply operations yield
-- different bytes, so the conversion machinery refuses the drop
-- rather than papering over it with a warning. 'FUndoData' is
-- deliberately not in this class: undo is a separate operation from
-- apply, and dropping undo data only affects whether a later undo
-- is possible.
affectsApplyOutput :: PatchField -> Bool
affectsApplyOutput FTruncation = True
affectsApplyOutput _           = False
