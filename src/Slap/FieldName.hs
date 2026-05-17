{-# LANGUAGE StrictData #-}

-- | Names of header, trailer, and per-record fields used across slap's
-- error and narrowing surfaces. Lifted out of "Slap.Status" so that
-- "Slap.Narrow" can tag 'FieldValueExceedsBound' failures without
-- importing the application-wide error module — keeping 'Slap.Narrow'
-- a leaf of the error graph (and dodging an import cycle).
module Slap.FieldName
  ( FieldName(..)
  , fieldNameLabel
  ) where

data FieldName
  -- Metadata fields
  = FieldTitle
  | FieldAuthor
  | FieldDescription
  | FieldVersion
  | FieldPatchName
  | FieldGenre
  | FieldLanguage
  | FieldDate
  | FieldWebsite
  -- Header fields
  | FieldRomType
  | FieldImageType
  | FieldPatchEncoding
  | FieldStability
  | FieldPatchType
  | FieldImageFormat
  | FieldCartId
  | FieldCountry
  | FieldEncodingMethod
  -- Sizes
  | FieldSourceSize
  | FieldTargetSize
  | FieldDestinationSize
  -- Checksums
  | FieldSourceCRC
  | FieldTargetCRC
  | FieldPatchCRC
  -- Record fields
  | FieldRLERunLength
  | FieldRecordMode
  | FieldRecordOutputOffset
  | FieldRecordSourceOffset
  | FieldRecordLength
  -- Trailer / count fields
  | FieldFileIdDizLength
  | FieldRecordCount
  -- xdelta1 header name fields
  | FieldXDelta1FromName
  | FieldXDelta1ToName
  deriving (Show, Eq, Enum, Bounded)

fieldNameLabel :: FieldName -> String
fieldNameLabel FieldTitle            = "title"
fieldNameLabel FieldAuthor           = "author"
fieldNameLabel FieldDescription      = "description"
fieldNameLabel FieldVersion          = "version"
fieldNameLabel FieldPatchName        = "name"
fieldNameLabel FieldGenre            = "genre"
fieldNameLabel FieldLanguage         = "language"
fieldNameLabel FieldDate             = "date"
fieldNameLabel FieldWebsite          = "website"
fieldNameLabel FieldRomType          = "ROM type"
fieldNameLabel FieldImageType        = "image type"
fieldNameLabel FieldPatchEncoding    = "patch encoding"
fieldNameLabel FieldStability        = "stability flag"
fieldNameLabel FieldPatchType        = "patch type"
fieldNameLabel FieldImageFormat      = "image format"
fieldNameLabel FieldCartId           = "cart ID"
fieldNameLabel FieldCountry          = "country"
fieldNameLabel FieldEncodingMethod   = "encoding method"
fieldNameLabel FieldSourceSize       = "source size"
fieldNameLabel FieldTargetSize       = "target size"
fieldNameLabel FieldDestinationSize  = "destination size"
fieldNameLabel FieldSourceCRC        = "source CRC"
fieldNameLabel FieldTargetCRC        = "target CRC"
fieldNameLabel FieldPatchCRC         = "patch CRC"
fieldNameLabel FieldRLERunLength     = "RLE run length"
fieldNameLabel FieldRecordMode       = "record mode"
fieldNameLabel FieldRecordOutputOffset = "record output offset"
fieldNameLabel FieldRecordSourceOffset = "record source offset"
fieldNameLabel FieldRecordLength       = "record length"
fieldNameLabel FieldFileIdDizLength  = "file_id.diz length"
fieldNameLabel FieldRecordCount      = "record count"
fieldNameLabel FieldXDelta1FromName  = "from-name"
fieldNameLabel FieldXDelta1ToName    = "to-name"
