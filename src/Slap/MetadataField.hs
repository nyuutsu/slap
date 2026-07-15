{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE OverloadedStrings #-}

module Slap.MetadataField
  ( MetadataField(..)
  , metadataFieldName
  , metadataFieldFlagName
  , DroppableField(..)
  , droppableField
  , dropFlagName
  , TypedTextField(..)
  , typedTextField
  , typedTextFlagName
  , MetadataRequest(..)
  , requestFlagName
  , requestField
  ) where

import Data.Aeson (ToJSON)
import Data.Text (Text)
import GHC.Generics (Generic, Generically(..))

-- | The user-requestable metadata concepts a patch format may consume
-- at creation time.  Independent of 'Slap.PatchField.PatchField',
-- which is the vocabulary of conversion-correctness over
-- 'Slap.Convert.PatchContents'.  Some concepts overlap between the
-- two vocabularies — both have a notion of "description," for
-- instance — but they participate in different conversations and are
-- typed separately so each enum's role stays unambiguous.
data MetadataField
  = MetadataTitle
  | MetadataAuthor
  | MetadataDescription
  | MetadataVersion
  | MetadataUndoInclusion
  | MetadataVerificationInclusion
  | MetadataPatchCompression
  | MetadataSecondaryCompressor
  | MetadataStability
  | MetadataRomType
  | MetadataImageType
  | MetadataFileIdDiz
  | MetadataGenre
  | MetadataLanguage
  | MetadataDate
  | MetadataWebsite
  | MetadataTextMode
  | MetadataEmbeddedBlob
  | MetadataXDelta1FromName
  | MetadataXDelta1ToName
  | MetadataWindowSize
  deriving (Eq, Ord, Show, Enum, Bounded, Generic)
  deriving (ToJSON) via Generically MetadataField

-- | Human-readable name for prose contexts in error and help messages.
metadataFieldName :: MetadataField -> Text
metadataFieldName MetadataTitle               = "title"
metadataFieldName MetadataAuthor              = "author"
metadataFieldName MetadataDescription         = "description"
metadataFieldName MetadataVersion             = "version"
metadataFieldName MetadataUndoInclusion       = "undo data"
metadataFieldName MetadataVerificationInclusion = "verification data"
metadataFieldName MetadataPatchCompression    = "patch compression"
metadataFieldName MetadataSecondaryCompressor = "secondary compressor"
metadataFieldName MetadataStability           = "stability flag"
metadataFieldName MetadataRomType             = "ROM type"
metadataFieldName MetadataImageType           = "image type"
metadataFieldName MetadataFileIdDiz           = "FILE_ID.DIZ"
metadataFieldName MetadataGenre               = "genre"
metadataFieldName MetadataLanguage            = "language"
metadataFieldName MetadataDate                = "date"
metadataFieldName MetadataWebsite             = "website"
metadataFieldName MetadataTextMode            = "NINJA2 text mode"
metadataFieldName MetadataEmbeddedBlob        = "embedded metadata blob"
metadataFieldName MetadataXDelta1FromName     = "xdelta1 from-name"
metadataFieldName MetadataXDelta1ToName       = "xdelta1 to-name"
metadataFieldName MetadataWindowSize          = "window size"

-- | The CLI flag (without dashes) that sets each field — one table read by the parser and by the rejection messages,
-- so the flag slap answers with is always a flag the parser accepts.
metadataFieldFlagName :: MetadataField -> Text
metadataFieldFlagName MetadataTitle               = "title"
metadataFieldFlagName MetadataAuthor              = "author"
metadataFieldFlagName MetadataDescription         = "description"
metadataFieldFlagName MetadataVersion             = "patch-version"
metadataFieldFlagName MetadataUndoInclusion       = "no-undo"
metadataFieldFlagName MetadataVerificationInclusion = "omit-verification"
metadataFieldFlagName MetadataPatchCompression    = "no-compress"
metadataFieldFlagName MetadataSecondaryCompressor = "compress-with"
metadataFieldFlagName MetadataStability           = "unstable"
metadataFieldFlagName MetadataRomType             = "rom-type"
metadataFieldFlagName MetadataImageType           = "image-type"
metadataFieldFlagName MetadataFileIdDiz           = "diz"
metadataFieldFlagName MetadataGenre               = "genre"
metadataFieldFlagName MetadataLanguage            = "language"
metadataFieldFlagName MetadataDate                = "date"
metadataFieldFlagName MetadataWebsite             = "website"
metadataFieldFlagName MetadataTextMode            = "ninja2-text-mode"
metadataFieldFlagName MetadataEmbeddedBlob        = "metadata"
metadataFieldFlagName MetadataXDelta1FromName     = "from-name"
metadataFieldFlagName MetadataXDelta1ToName       = "to-name"
metadataFieldFlagName MetadataWindowSize          = "window-size"

-- | The two fields a convert can be asked to leave out; each has its own drop flag.
data DroppableField
  = DroppableFileIdDiz
  | DroppableEmbeddedBlob
  deriving (Eq, Show, Enum, Bounded, Generic)
  deriving (ToJSON) via Generically DroppableField

droppableField :: DroppableField -> MetadataField
droppableField DroppableFileIdDiz    = MetadataFileIdDiz
droppableField DroppableEmbeddedBlob = MetadataEmbeddedBlob

-- | The drop flag (without dashes) — one table read by the parser and by the rejection messages, like 'metadataFieldFlagName'.
dropFlagName :: DroppableField -> Text
dropFlagName DroppableFileIdDiz    = "drop-diz"
dropFlagName DroppableEmbeddedBlob = "drop-metadata"

-- | The fields settable from text typed at the flag itself, each beside its file-taking sibling.
data TypedTextField
  = TypedTextEmbeddedBlob
  | TypedTextFileIdDiz
  deriving (Eq, Show, Enum, Bounded, Generic)
  deriving (ToJSON) via Generically TypedTextField

typedTextField :: TypedTextField -> MetadataField
typedTextField TypedTextEmbeddedBlob = MetadataEmbeddedBlob
typedTextField TypedTextFileIdDiz    = MetadataFileIdDiz

-- | The typed-text flag (without dashes) — one table read by the parser and by the rejection messages, like 'metadataFieldFlagName'.
typedTextFlagName :: TypedTextField -> Text
typedTextFlagName TypedTextEmbeddedBlob = "metadata-text"
typedTextFlagName TypedTextFileIdDiz    = "diz-text"

-- | A metadata request as it arrived. Each arm carries its own flag, so a rejection answers with the flag the user actually typed.
data MetadataRequest
  = SetField MetadataField
  | SetFieldFromText TypedTextField
  | DropField DroppableField
  deriving (Eq, Show, Generic)
  deriving (ToJSON) via Generically MetadataRequest

-- | The flag a request arrived on.
requestFlagName :: MetadataRequest -> Text
requestFlagName (SetField field)         = metadataFieldFlagName field
requestFlagName (SetFieldFromText field) = typedTextFlagName field
requestFlagName (DropField droppable)    = dropFlagName droppable

-- | The field a request is about, for the sentence that names it.
requestField :: MetadataRequest -> MetadataField
requestField (SetField field)         = field
requestField (SetFieldFromText field) = typedTextField field
requestField (DropField droppable)    = droppableField droppable
