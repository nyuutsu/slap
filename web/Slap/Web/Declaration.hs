{-# LANGUAGE DerivingVia #-}

-- | The crossing's inbound half, mirror of "Slap.Web.Envelope": what the page declares about a request crosses as one JSON buffer,
-- while the files it hands — patches, roms, sources — cross as raw byte buffers beside it, never inside.
-- Each declaration is its verb's request minus those byte payloads, and the builders marry the two halves back together.
module Slap.Web.Declaration
  ( DeclaredApplyRequest(..)
  , DeclaredUndoRequest(..)
  , DeclaredCreateRequest(..)
  , DeclaredConvertRequest(..)
  , applyRequestOf
  , undoRequestOf
  , createRequestOf
  , convertRequestOf
  , decodedDeclaration
  ) where

import Data.Aeson (FromJSON)
import qualified Data.Aeson as Aeson
import Data.ByteString (ByteString)
import GHC.Generics (Generic, Generically(..))

import Slap.Convert (CreateFormat, RequestedConstraints, RequestedDialects, RequestedPatchMetadata)
import Slap.FileContents (InputFileContents, OutputFileContents, PatchFileContents)
import Slap.Header (InputHeaderDirective)
import Slap.Text (EncodingName)
import Slap.Verify (VerificationPolicy)
import Slap.Web (ApplyRequest(..), ConvertRequest(..), CreateRequest(..), MatchedRom(..), UndoRequest(..))

-- | The page is a declaration's only author, so bytes that do not decode are its own defect — answered loudly, never absorbed into a refusal.
decodedDeclaration :: FromJSON declaration => ByteString -> declaration
decodedDeclaration bytes =
  either (\parseError -> error ("Slap.Web: a declaration failed to decode: " <> parseError)) id (Aeson.eitherDecodeStrict bytes)

data DeclaredApplyRequest = DeclaredApplyRequest
  { declaredApplyFraming            :: InputHeaderDirective
  , declaredApplyVerificationPolicy :: VerificationPolicy
  , declaredApplyDialects           :: RequestedDialects
  }
  deriving (Generic)
  deriving (FromJSON) via Generically DeclaredApplyRequest

applyRequestOf :: DeclaredApplyRequest -> PatchFileContents -> InputFileContents -> ApplyRequest
applyRequestOf declared patchBytes romBytes = ApplyRequest
  { applyPatchBytes         = patchBytes
  , applySourceRom          = MatchedRom romBytes (declaredApplyFraming declared)
  , applyVerificationPolicy = declaredApplyVerificationPolicy declared
  , applyDialects           = declaredApplyDialects declared
  }

data DeclaredUndoRequest = DeclaredUndoRequest
  { declaredUndoVerificationPolicy :: VerificationPolicy
  , declaredUndoDialects           :: RequestedDialects
  }
  deriving (Generic)
  deriving (FromJSON) via Generically DeclaredUndoRequest

undoRequestOf :: DeclaredUndoRequest -> PatchFileContents -> OutputFileContents -> UndoRequest
undoRequestOf declared patchBytes patchedBytes = UndoRequest
  { undoPatchBytes         = patchBytes
  , undoPatchedRom         = patchedBytes
  , undoVerificationPolicy = declaredUndoVerificationPolicy declared
  , undoDialects           = declaredUndoDialects declared
  }

data DeclaredCreateRequest = DeclaredCreateRequest
  { declaredCreateTargetFormat :: CreateFormat
  , declaredCreateOriginalName :: FilePath
  , declaredCreateModifiedName :: FilePath
  , declaredCreateMetadata     :: RequestedPatchMetadata
  , declaredCreateConstraints  :: RequestedConstraints
  }
  deriving (Generic)
  deriving (FromJSON) via Generically DeclaredCreateRequest

createRequestOf :: DeclaredCreateRequest -> InputFileContents -> OutputFileContents -> CreateRequest
createRequestOf declared originalBytes modifiedBytes = CreateRequest
  { createTargetFormat = declaredCreateTargetFormat declared
  , createOriginal     = originalBytes
  , createModified     = modifiedBytes
  , createOriginalName = declaredCreateOriginalName declared
  , createModifiedName = declaredCreateModifiedName declared
  , createMetadata     = declaredCreateMetadata declared
  , createConstraints  = declaredCreateConstraints declared
  }

data DeclaredConvertRequest = DeclaredConvertRequest
  { declaredConvertTargetFormat       :: CreateFormat
  , declaredConvertSourceFraming      :: Maybe InputHeaderDirective
    -- ^ The authority on whether a source rides the request; a source buffer handed without this is not read.
  , declaredConvertVerificationPolicy :: VerificationPolicy
  , declaredConvertMetadata           :: RequestedPatchMetadata
  , declaredConvertConstraints        :: RequestedConstraints
  , declaredConvertMetadataEncoding   :: EncodingName
  , declaredConvertDialects           :: RequestedDialects
  }
  deriving (Generic)
  deriving (FromJSON) via Generically DeclaredConvertRequest

convertRequestOf :: DeclaredConvertRequest -> PatchFileContents -> Maybe InputFileContents -> ConvertRequest
convertRequestOf declared patchBytes handedSource = ConvertRequest
  { convertPatchBytes         = patchBytes
  , convertTargetFormat       = declaredConvertTargetFormat declared
  , convertSourceRom          = declaredSourceRom
  , convertVerificationPolicy = declaredConvertVerificationPolicy declared
  , convertMetadata           = declaredConvertMetadata declared
  , convertConstraints        = declaredConvertConstraints declared
  , convertMetadataEncoding   = declaredConvertMetadataEncoding declared
  , convertDialects           = declaredConvertDialects declared
  }
  where
    declaredSourceRom = case (declaredConvertSourceFraming declared, handedSource) of
      (Nothing, Nothing)          -> Nothing
      (Just framing, Just source) -> Just (MatchedRom source framing)
      (Just _, Nothing)           -> error "Slap.Web: the declaration says a source rides, but none was handed"
      (Nothing, Just _)           -> error "Slap.Web: a source was handed that the declaration does not speak of"
