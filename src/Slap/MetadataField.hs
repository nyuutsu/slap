module Slap.MetadataField
  ( MetadataField(..)
  , metadataFieldName
  , metadataFieldFlagName
  ) where

-- | The user-requestable metadata concepts a patch format may consume
-- at creation time.  Independent of 'Slap.PatchField.PatchField',
-- which is the vocabulary of conversion-correctness over
-- 'Slap.Convert.PatchContents'.  Some concepts overlap between the
-- two vocabularies — both have a notion of "description," for
-- instance — but they participate in different conversations and are
-- typed separately so each enum's role stays unambiguous.
data MetadataField
  = MTitle
  | MAuthor
  | MDescription
  | MVersion
  | MUndoInclusion
  | MValidationInclusion
  | MStability
  | MRomType
  | MImageType
  | MGenre
  | MLanguage
  | MDate
  | MWebsite
  | MPatchEncoding
  | MEmbeddedBlob
  deriving (Eq, Ord, Show)

-- | Human-readable name for prose contexts in error and help messages.
metadataFieldName :: MetadataField -> String
metadataFieldName MTitle               = "title"
metadataFieldName MAuthor              = "author"
metadataFieldName MDescription         = "description"
metadataFieldName MVersion             = "version"
metadataFieldName MUndoInclusion       = "undo data"
metadataFieldName MValidationInclusion = "validation block"
metadataFieldName MStability           = "stability flag"
metadataFieldName MRomType             = "ROM type"
metadataFieldName MImageType           = "image type"
metadataFieldName MGenre               = "genre"
metadataFieldName MLanguage            = "language"
metadataFieldName MDate                = "date"
metadataFieldName MWebsite             = "website"
metadataFieldName MPatchEncoding       = "patch encoding"
metadataFieldName MEmbeddedBlob        = "embedded metadata blob"

-- | The CLI flag name (without leading dashes) that sets each field.
-- Used in rejection messages so the user sees the exact flag they
-- typed in slap's response.
metadataFieldFlagName :: MetadataField -> String
metadataFieldFlagName MTitle               = "title"
metadataFieldFlagName MAuthor              = "author"
metadataFieldFlagName MDescription         = "description"
metadataFieldFlagName MVersion             = "version"
metadataFieldFlagName MUndoInclusion       = "no-undo"
metadataFieldFlagName MValidationInclusion = "no-validate"
metadataFieldFlagName MStability           = "unstable"
metadataFieldFlagName MRomType             = "rom-type"
metadataFieldFlagName MImageType           = "image-type"
metadataFieldFlagName MGenre               = "genre"
metadataFieldFlagName MLanguage            = "language"
metadataFieldFlagName MDate                = "date"
metadataFieldFlagName MWebsite             = "website"
metadataFieldFlagName MPatchEncoding       = "patch-encoding"
metadataFieldFlagName MEmbeddedBlob        = "metadata"
