{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE OverloadedStrings #-}
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

import Data.Aeson (ToJSON)
import Data.Text (Text)
import GHC.Generics (Generic, Generically(..))

data FieldName
  -- Metadata fields
  = FieldTitle
  | FieldAuthor
  | FieldDescription
  | FieldVersion
  | FieldPatchName
  | FieldFileName
  | FieldGenre
  | FieldLanguage
  | FieldDate
  | FieldWebsite
  -- Header fields
  | FieldRomType
  | FieldImageType
  | FieldTextMode
  | FieldOverflowMode
  | FieldStability
  | FieldPatchType
  | FieldImageFormat
  | FieldCartId
  | FieldCountry
  | FieldEncodingMethod
  | FieldReservedHeader
  -- Sizes
  | FieldSourceSize
  | FieldTargetSize
  | FieldDestinationSize
  -- Checksums
  | FieldSourceCRC
  | FieldSourceMD5
  | FieldSourceSHA1
  | FieldTargetCRC
  | FieldPatchCRC
  -- Record fields
  | FieldRLERunLength
  | FieldRecordMode
  | FieldRecordOutputOffset
  | FieldRecordSourceOffset
  | FieldRecordLength
  | FieldOverflowData
  -- Trailer / count fields
  | FieldFileIdDiz
  | FieldRecordCount
  -- Embedded application data
  | FieldAppHeader
  -- xdelta1 header name fields
  | FieldXDelta1FromName
  | FieldXDelta1ToName
  -- xdelta1 wire numbers (all guint32 on the wire; see Slap.XDelta1.Create.narrowXDelta1WireNumber)
  | FieldXDelta1ControlOffset
  | FieldXDelta1TargetLength
  | FieldXDelta1DataSegmentLength
  | FieldXDelta1SourceLength
  | FieldXDelta1InstructionOffset
  | FieldXDelta1InstructionLength
  deriving (Show, Eq, Enum, Bounded, Generic)
  deriving (ToJSON) via Generically FieldName

fieldNameLabel :: FieldName -> Text
fieldNameLabel FieldTitle            = "title"
fieldNameLabel FieldAuthor           = "author"
fieldNameLabel FieldDescription      = "description"
fieldNameLabel FieldVersion          = "version"
fieldNameLabel FieldPatchName        = "name"
fieldNameLabel FieldFileName         = "file name"
fieldNameLabel FieldGenre            = "genre"
fieldNameLabel FieldLanguage         = "language"
fieldNameLabel FieldDate             = "date"
fieldNameLabel FieldWebsite          = "website"
fieldNameLabel FieldRomType          = "ROM type"
fieldNameLabel FieldImageType        = "image type"
fieldNameLabel FieldTextMode         = "NINJA2 text mode"
fieldNameLabel FieldOverflowMode     = "overflow mode"
fieldNameLabel FieldStability        = "stability flag"
fieldNameLabel FieldPatchType        = "patch type"
fieldNameLabel FieldImageFormat      = "image format"
fieldNameLabel FieldCartId           = "cart ID"
fieldNameLabel FieldCountry          = "country"
fieldNameLabel FieldEncodingMethod   = "encoding method"
fieldNameLabel FieldReservedHeader   = "reserved header"
fieldNameLabel FieldSourceSize       = "source size"
fieldNameLabel FieldTargetSize       = "target size"
fieldNameLabel FieldDestinationSize  = "destination size"
fieldNameLabel FieldSourceCRC        = "source CRC"
fieldNameLabel FieldSourceMD5        = "source MD5"
fieldNameLabel FieldSourceSHA1       = "source SHA1"
fieldNameLabel FieldTargetCRC        = "target CRC"
fieldNameLabel FieldPatchCRC         = "patch CRC"
fieldNameLabel FieldRLERunLength     = "RLE run length"
fieldNameLabel FieldRecordMode       = "record mode"
fieldNameLabel FieldRecordOutputOffset = "record output offset"
fieldNameLabel FieldRecordSourceOffset = "record source offset"
fieldNameLabel FieldRecordLength       = "record length"
fieldNameLabel FieldOverflowData       = "overflow data"
fieldNameLabel FieldFileIdDiz        = "file_id.diz"
fieldNameLabel FieldRecordCount      = "record count"
fieldNameLabel FieldAppHeader        = "application header"
fieldNameLabel FieldXDelta1FromName  = "from-name"
fieldNameLabel FieldXDelta1ToName    = "to-name"
fieldNameLabel FieldXDelta1ControlOffset = "control-segment offset"
fieldNameLabel FieldXDelta1TargetLength      = "target length"
fieldNameLabel FieldXDelta1DataSegmentLength = "data-segment length"
fieldNameLabel FieldXDelta1SourceLength      = "source length"
fieldNameLabel FieldXDelta1InstructionOffset = "instruction offset"
fieldNameLabel FieldXDelta1InstructionLength = "instruction length"
