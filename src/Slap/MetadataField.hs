{-# LANGUAGE OverloadedStrings #-}

module Slap.MetadataField
  ( MetadataField(..)
  , metadataFieldName
  , metadataFieldFlagName
  ) where

import Data.Text (Text)

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
  | MetadataStability
  | MetadataRomType
  | MetadataImageType
  | MetadataGenre
  | MetadataLanguage
  | MetadataDate
  | MetadataWebsite
  | MetadataPatchEncoding
  | MetadataEmbeddedBlob
  | MetadataXDelta1FromName
  | MetadataXDelta1ToName
  deriving (Eq, Ord, Show)

-- | Human-readable name for prose contexts in error and help messages.
metadataFieldName :: MetadataField -> Text
metadataFieldName MetadataTitle               = "title"
metadataFieldName MetadataAuthor              = "author"
metadataFieldName MetadataDescription         = "description"
metadataFieldName MetadataVersion             = "version"
metadataFieldName MetadataUndoInclusion       = "undo data"
metadataFieldName MetadataVerificationInclusion = "verification data"
metadataFieldName MetadataPatchCompression    = "patch compression"
metadataFieldName MetadataStability           = "stability flag"
metadataFieldName MetadataRomType             = "ROM type"
metadataFieldName MetadataImageType           = "image type"
metadataFieldName MetadataGenre               = "genre"
metadataFieldName MetadataLanguage            = "language"
metadataFieldName MetadataDate                = "date"
metadataFieldName MetadataWebsite             = "website"
metadataFieldName MetadataPatchEncoding       = "patch encoding"
metadataFieldName MetadataEmbeddedBlob        = "embedded metadata blob"
metadataFieldName MetadataXDelta1FromName     = "xdelta1 from-name"
metadataFieldName MetadataXDelta1ToName       = "xdelta1 to-name"

-- | The CLI flag name (without leading dashes) that sets each field.
-- Used in rejection messages so the user sees the exact flag they
-- typed in slap's response.
metadataFieldFlagName :: MetadataField -> Text
metadataFieldFlagName MetadataTitle               = "title"
metadataFieldFlagName MetadataAuthor              = "author"
metadataFieldFlagName MetadataDescription         = "description"
metadataFieldFlagName MetadataVersion             = "version"
metadataFieldFlagName MetadataUndoInclusion       = "no-undo"
metadataFieldFlagName MetadataVerificationInclusion = "no-verify"
metadataFieldFlagName MetadataPatchCompression    = "no-compress"
metadataFieldFlagName MetadataStability           = "unstable"
metadataFieldFlagName MetadataRomType             = "rom-type"
metadataFieldFlagName MetadataImageType           = "image-type"
metadataFieldFlagName MetadataGenre               = "genre"
metadataFieldFlagName MetadataLanguage            = "language"
metadataFieldFlagName MetadataDate                = "date"
metadataFieldFlagName MetadataWebsite             = "website"
metadataFieldFlagName MetadataPatchEncoding       = "patch-encoding"
metadataFieldFlagName MetadataEmbeddedBlob        = "metadata"
metadataFieldFlagName MetadataXDelta1FromName     = "from-name"
metadataFieldFlagName MetadataXDelta1ToName       = "to-name"
