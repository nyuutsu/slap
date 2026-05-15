module Slap.Convert
  ( PatchContents(..)
  , DirectCreate(..)
  , DifferentialCreate(..)
  , CreateFormat(..)
  , RequestedPatchMetadata(..)
  , UndoInclusion(..)
  , VerificationInclusion(..)
  , PatchStability(..)
  , noMetadataRequested
  , RequestedConstraints(..)
  , noConstraintsRequested
  , requestedConstraints
  , acceptedConstraints
  , rejectIncompatibleConstraints
  , RequestedDialects(..)
  , noDialectsRequested
  , requestedDialects
  , acceptedDialects
  , rejectIncompatibleDialects
  , DirectConversionContract(..)
  , ConversionFailure(..)
  , emptyContents
  , provides
  , directConversionContract
  , canConvert
  , conversionNotes
  , convertDirect
  , createPatch
  , createDefaultNotes
  , mergeRequestedMetadata
  , trimNullSpace
  , formatExtension
  , formatName
  , createFormatLabel
  , acceptedMetadataFields
  , requestedMetadataFields
  , rejectIncompatibleMetadata
  , PatchEncoding(..)
  ) where

import qualified Slap.PPF1.Create as PPF1
import Slap.PPF1.Types (PPF1Origin(..), ppf1Limits, ppf1MaxRecordPayload)
import qualified Slap.PPF2.Create as PPF2
import Slap.PPF2.Types (PPF2ValidationBlock(..),
                        narrowPPF2FileId, narrowPPF2SourceSize,
                        ppf2Limits, ppf2MaxRecordPayload,
                        ppf2ValidationOffset, ppf2ValidationSize)
import qualified Slap.PPF3.Create as PPF3
import Slap.PPF3.Types (PPF3ImageType(..), PPF3ValidationBlock(..),
                        narrowPPF3FileId, ppf3MaxRecordPayload)
import qualified Slap.IPS.Create as IPS
import Slap.IPS.Types (IPSVariant(..), OffsetWidth(..), EBPMetadata(..),
                       EBPMetadataFields(..), IPSVariantSpec(..),
                       SMCShapeRequirement(..), isSMCShapedSize,
                       ipsMaxRecordPayload, variantSpec,
                       ipsLimits, ips32Limits, ebpLimits)
import Slap.JSON (jsonPairs, jsonFieldCI)
import qualified Slap.BPS.Create as BPS
import qualified Slap.UPS.Create as UPS
import qualified Slap.APSN64.Types as APSN64
import qualified Slap.APSN64.Create as APSN64
import qualified Slap.APSGBA.Create as APSGBA
import Slap.NINJA2.Types (PatchEncoding(..))
import qualified Slap.NINJA2.Types as NINJA2
import qualified Slap.NINJA2.Create as NINJA2
import qualified Slap.GDIFF.Create as GDIFF
import qualified Slap.XDelta1.Create as XDelta1
import Slap.XDelta1.Types (ResolvedXDelta1FileNames,
                           XDelta1FromName(..), XDelta1ToName(..),
                           XDelta1PatchCompression(..))
import qualified Slap.PMSR.Types as PMSR
import Slap.PMSR.Types (narrowPMSRRecordCount, pmsrMaxRecordPayload)
import qualified Slap.PMSR.Create as PMSR
import qualified Slap.DPS.Types as DPS
import qualified Slap.DPS.Create as DPS
import qualified Slap.NINJA1.Types as NINJA1
import qualified Slap.NINJA1.Create as NINJA1
import Slap.PlatformType (PlatformType(..))
import Slap.Platform (platformToNinja1)
import qualified Slap.PCHTXT.Types as PCHTXT
import qualified Slap.PCHTXT.Create as PCHTXT
import Slap.Binary (diffHunks, md5, sha1)
import Slap.Checksum (CRC32(..), MD5Hash(..), SHA1Hash(..))
import Slap.FFI (crc32)
import Slap.Measure (FileSize(..), Length(..), Offset(..), Hunk(..),
                      SplitHunk, SplitUndoHunk,
                      ActualSize(..), ExpectedSize(..),
                      SentinelOffset(..),
                      splitHunks, splitHunksUnbounded, splitUndoHunks,
                      byteFileSize)
import Slap.Narrow (EncodedHunk, EncodingLimits(..),
                    narrowHunks, narrowHunksUnbounded,
                    narrowUndoHunksUnbounded)
import Slap.Constraint (Constraint(..))
import Slap.Dialect (Dialect(..))
import Slap.Error (SlapError(..), SlapWarning(..), DroppedValue(..), CreateResult(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.MetadataField (MetadataField(..))
import Slap.MetadataInclusion (UndoInclusion(..), VerificationInclusion(..))
import Slap.PatchField (PatchField(..), affectsApplyOutput)
import Slap.FileContents (InputFileContents(..), OutputFileContents(..), PatchFileContents(..))

import Slap.TextEncoding (isValidUtf8, decodeLocaleField)

import Control.Applicative ((<|>))
import Data.Bifunctor (first)
import qualified Data.ByteString as ByteString
import qualified Data.List.NonEmpty as NonEmpty
import Data.Maybe (fromMaybe, isJust, isNothing)
import qualified Data.Set as Set

----------------------------------------------------------------------------
-- Types
----------------------------------------------------------------------------

-- | The direct-target conversion contract: which 'PatchField's a direct
-- format requires the source patch to carry, and which additional fields
-- it can accept.  'canConvert' consults this to decide whether a given
-- 'PatchContents' can be source-lessly converted to the target format
-- without dropping apply-output-affecting data.
--
-- Differential targets use a different conversion path (apply-and-recreate via
-- @--with INPUT@), so this contract only covers direct formats.
data DirectConversionContract = DirectConversionContract
  { contractRequiredFields :: Set.Set PatchField
  , contractAcceptedFields :: Set.Set PatchField
  }

-- | Universal representation of a direct patch's contents.
data PatchContents = PatchContents
  { contentsRecords     :: [Hunk]
  , contentsDescription :: Maybe ByteString.ByteString
  , contentsSourceCRC32 :: Maybe CRC32
  , contentsSourceMD5   :: Maybe MD5Hash
  , contentsSourceSHA1  :: Maybe SHA1Hash
  , contentsDestinationSize    :: Maybe FileSize
  , contentsValidation  :: Maybe ByteString.ByteString
    -- ^ Raw 1024-byte validation-block bytes (PPF2/PPF3). Cross-cutting,
    -- so plain bytes; per-format role newtypes wrap on emit.
  , contentsUndoData    :: Maybe [SplitUndoHunk]
  , contentsTruncation  :: Maybe FileSize
  , contentsEBPMeta     :: Maybe ByteString.ByteString
  , contentsRomType     :: Maybe PlatformType
  , contentsImageType   :: Maybe PPF3ImageType
  , contentsFileIdDiz   :: Maybe ByteString.ByteString
    -- ^ Raw FILE_ID.DIZ bytes (PPF2/PPF3). Per-format wire trailers
    -- differ in length-field width; the bytes themselves are the same
    -- across formats.
  , contentsPCHTXTBlocks :: Maybe [PCHTXT.PCHTXTBlock]
  , contentsNINJA1Compressed :: Maybe Bool  -- patch used compressed subformat (BZ/TZ)
  , contentsMetadata :: Maybe ByteString.ByteString
    -- ^ Arbitrary metadata blob (BPS). Most formats don't carry this.
  , contentsPatchEncoding :: Maybe PatchEncoding
    -- ^ Text encoding of description/metadata fields, when the source
    -- format carries an encoding flag (e.g. NINJA2 PATCH_ENC).  Nothing
    -- for formats with opaque byte fields (PPF, DPS, APSN64).
  }

-- | Direct creation target.  Some format families have multiple creation
-- variants: IPS has three (IPS, IPS32, EBP) distinguished by offset width
-- and metadata; PPF exposes only version 3.
data DirectCreate
  = CreateIPS | CreateIPS32 | CreateEBP | CreatePPF1 | CreatePPF2 | CreatePPF3
  | CreateNINJA1 | CreatePMSR | CreatePCHTXT | CreateAPSN64
  deriving (Show, Eq, Enum, Bounded)

-- | Differential creation target.  Formats slap can parse but not yet
-- create (VCDIFF, BSDiff) belong to DifferentialFormat (the
-- format taxonomy) but not here (slap's current creation capability).
data DifferentialCreate
  = CreateBPS | CreateUPS | CreateDPS | CreateNINJA2
  | CreateAPSGBA | CreateGDIFF | CreateXDelta1
  deriving (Show, Eq)

-- | Target format for patch creation or conversion.
data CreateFormat
  = CreateDirect DirectCreate
  | CreateDifferential DifferentialCreate
  deriving (Show, Eq)

-- | User intent about what metadata should end up in an emitted patch.
-- Built from CLI flags in 'app/Main.hs' (and from parsed source patches
-- during conversion), then consumed by 'createPatch' /
-- 'encodeDirect'.  Every 'Maybe' field's 'Nothing' means "the user
-- didn't specify; let the format pick its default"; a 'Just' carries
-- an explicit request.
--
-- Direct-format consumption: 'CreateIPS' and 'CreateIPS32' consume
-- nothing from this record — they have no metadata channel.
-- 'CreateEBP' consumes 'requestedTitle', 'requestedAuthor', and
-- 'requestedDescription' (woven into the trailing JSON blob via
-- 'IPS.buildEBPMetadataJSON').  'CreatePPF3' consumes
-- 'requestedDescription' (the 50-byte header field),
-- 'requestedUndoInclusion', 'requestedVerificationInclusion' (gates
-- the validation block), and 'requestedImageType' (selects the
-- validation offset).
-- 'CreateNINJA1' consumes 'requestedRomType' (mapped through
-- 'Slap.Platform.platformToNinja1'); the compression flag rides in
-- 'PatchContents' rather than this record.  'CreatePMSR' consumes
-- nothing.  'CreatePCHTXT' consumes 'requestedDescription'.
-- 'CreateAPSN64' consumes 'requestedDescription' (50-byte header
-- field).
--
-- Differential-format consumption is read directly out of 'createPatch'\'s
-- differential arm: 'CreateBPS' consumes 'requestedEmbeddedBlob';
-- 'CreateXDelta1' consumes 'requestedVerificationInclusion' (gates
-- @FLAG_NO_VERIFY@ and the per-source MD5 fields) and
-- 'requestedPatchCompression' (gates @FLAG_PATCH_COMPRESSED@ and
-- gzip-deflation of the data and control segments); 'CreateUPS',
-- 'CreateAPSGBA', and 'CreateGDIFF' consume nothing; 'CreateDPS'
-- consumes 'requestedTitle'\/'requestedDescription' (name),
-- 'requestedAuthor', 'requestedVersion', and 'requestedStability';
-- 'CreateNINJA2' consumes the full title\/author\/version\/description
-- block plus 'requestedGenre', 'requestedLanguage', 'requestedDate',
-- 'requestedWebsite', 'requestedRomType', and 'requestedPatchEncoding'.
data RequestedPatchMetadata = RequestedPatchMetadata
  { requestedTitle                :: Maybe String
  , requestedAuthor               :: Maybe String
  , requestedDescription          :: Maybe String
  , requestedVersion              :: Maybe String
  , requestedUndoInclusion        :: Maybe UndoInclusion
  , requestedVerificationInclusion :: Maybe VerificationInclusion
  , requestedPatchCompression     :: Maybe XDelta1PatchCompression
    -- ^ xdelta1 only: 'Just' 'UncompressedPatch' means the user
    -- asked for @--no-compress@; absent means \"let the format pick
    -- its default,\" which for xdelta1 is 'CompressedPatch'.
  , requestedStability            :: Maybe PatchStability
  , requestedRomType              :: Maybe PlatformType
    -- ^ Shared platform type: NINJA1 and NINJA2 define different
    -- ROM type enumerations (18 vs 10 values, diverging at byte 2).
    -- PlatformType represents the union; format-specific conversion
    -- (platformToNinja1, platformToNinja2) handles lossy mappings.
  , requestedImageType            :: Maybe PPF3ImageType
  , requestedGenre                :: Maybe String
  , requestedLanguage             :: Maybe String
  , requestedDate                 :: Maybe String
  , requestedWebsite              :: Maybe String
  , requestedPatchEncoding        :: Maybe PatchEncoding
  , requestedEmbeddedBlob         :: Maybe ByteString.ByteString
    -- ^ Contents of the user's @--metadata FILE@ flag.  Today only BPS
    -- consumes this; the name keeps the concept ("a raw blob to embed")
    -- separate from the format that currently uses it.
  , requestedXDelta1FromName      :: Maybe XDelta1FromName
    -- ^ xdelta1 only: user-supplied @--from-name TEXT@, already
    -- locale-encoded so the bytes match canonical xdelta's wire
    -- shape. This is the unresolved input: the porcelain runs
    -- 'Slap.XDelta1.Types.resolveXDelta1FileNames' (create) or
    -- 'Slap.XDelta1.Types.requireXDelta1FileNames' (convert) on
    -- these two fields to produce the typed
    -- 'Slap.XDelta1.Types.ResolvedXDelta1FileNames' passed to
    -- 'createPatch'.
  , requestedXDelta1ToName        :: Maybe XDelta1ToName
    -- ^ xdelta1 only: counterpart to 'requestedXDelta1FromName' for
    -- the to-name slot.
  }

-- | Stability flag for DPS patches.
--
-- DPS carries a single byte indicating whether the patch author considers the
-- patch suitable for distribution. Slap does not interpret the flag beyond
-- relaying the user's declaration to the emitted patch.
data PatchStability
  = StablePatch
  | UnstablePatch
  deriving (Show, Eq)

stabilityToDPS :: PatchStability -> DPS.DPSStability
stabilityToDPS UnstablePatch = DPS.DPSUnstable
stabilityToDPS StablePatch   = DPS.DPSStable

noMetadataRequested :: RequestedPatchMetadata
noMetadataRequested = RequestedPatchMetadata
  { requestedTitle               = Nothing
  , requestedAuthor              = Nothing
  , requestedDescription         = Nothing
  , requestedVersion             = Nothing
  , requestedUndoInclusion        = Nothing
  , requestedVerificationInclusion = Nothing
  , requestedPatchCompression     = Nothing
  , requestedStability           = Nothing
  , requestedRomType             = Nothing
  , requestedImageType           = Nothing
  , requestedGenre               = Nothing
  , requestedLanguage            = Nothing
  , requestedDate                = Nothing
  , requestedWebsite             = Nothing
  , requestedPatchEncoding       = Nothing
  , requestedEmbeddedBlob        = Nothing
  , requestedXDelta1FromName     = Nothing
  , requestedXDelta1ToName       = Nothing
  }

-- | Merge two metadata records: first (CLI) wins for each field, then
-- second (source patch).
mergeRequestedMetadata :: RequestedPatchMetadata -> RequestedPatchMetadata -> RequestedPatchMetadata
mergeRequestedMetadata cli source = RequestedPatchMetadata
  { requestedTitle               = requestedTitle cli               <|> requestedTitle source
  , requestedAuthor              = requestedAuthor cli              <|> requestedAuthor source
  , requestedDescription         = requestedDescription cli         <|> requestedDescription source
  , requestedVersion             = requestedVersion cli             <|> requestedVersion source
  , requestedUndoInclusion        = requestedUndoInclusion cli        <|> requestedUndoInclusion source
  , requestedVerificationInclusion = requestedVerificationInclusion cli <|> requestedVerificationInclusion source
  , requestedPatchCompression     = requestedPatchCompression cli     <|> requestedPatchCompression source
  , requestedStability           = requestedStability cli           <|> requestedStability source
  , requestedRomType             = requestedRomType cli             <|> requestedRomType source
  , requestedImageType           = requestedImageType cli           <|> requestedImageType source
  , requestedGenre               = requestedGenre cli               <|> requestedGenre source
  , requestedLanguage            = requestedLanguage cli            <|> requestedLanguage source
  , requestedDate                = requestedDate cli                <|> requestedDate source
  , requestedWebsite             = requestedWebsite cli             <|> requestedWebsite source
  , requestedPatchEncoding       = requestedPatchEncoding cli       <|> requestedPatchEncoding source
  , requestedEmbeddedBlob        = requestedEmbeddedBlob cli        <|> requestedEmbeddedBlob source
  , requestedXDelta1FromName     = requestedXDelta1FromName cli     <|> requestedXDelta1FromName source
  , requestedXDelta1ToName       = requestedXDelta1ToName cli       <|> requestedXDelta1ToName source
  }

----------------------------------------------------------------------------
-- PatchContents helpers
----------------------------------------------------------------------------

emptyContents :: [Hunk] -> PatchContents
emptyContents records = PatchContents
  { contentsRecords     = records
  , contentsDescription = Nothing
  , contentsSourceCRC32 = Nothing
  , contentsSourceMD5   = Nothing
  , contentsSourceSHA1  = Nothing
  , contentsDestinationSize    = Nothing
  , contentsValidation  = Nothing
  , contentsUndoData    = Nothing
  , contentsTruncation  = Nothing
  , contentsEBPMeta     = Nothing
  , contentsRomType     = Nothing
  , contentsImageType   = Nothing
  , contentsFileIdDiz   = Nothing
  , contentsPCHTXTBlocks = Nothing
  , contentsNINJA1Compressed = Nothing
  , contentsMetadata = Nothing
  , contentsPatchEncoding = Nothing
  }

provides :: PatchContents -> Set.Set PatchField
provides contents = Set.fromList $ [FieldRecords]
  ++ [FieldDescription  | isJust (contentsDescription contents)]
  ++ [FieldSourceCRC32  | isJust (contentsSourceCRC32 contents)]
  ++ [FieldSourceMD5    | isJust (contentsSourceMD5 contents)]
  ++ [FieldSourceSHA1   | isJust (contentsSourceSHA1 contents)]
  ++ [FieldDestinationSize     | isJust (contentsDestinationSize contents)]
  ++ [FieldUndoData     | isJust (contentsUndoData contents)]
  ++ [FieldValidation   | isJust (contentsValidation contents)]
  ++ [FieldTruncation   | isJust (contentsTruncation contents)]
  ++ [FieldEBPMeta      | isJust (contentsEBPMeta contents)]
  ++ [FieldRomType      | isJust (contentsRomType contents)]
  ++ [FieldImageType    | isJust (contentsImageType contents)]
  ++ [FieldFileIdDiz    | isJust (contentsFileIdDiz contents)]
  ++ [FieldPCHTXTBlocks | isJust (contentsPCHTXTBlocks contents)]
  ++ [FieldMetadata     | isJust (contentsMetadata contents)]

-- | Which 'UndoInclusion' a 'PatchContents' carries today.  Used on the
-- conversion path when the user didn't specify: if the source patch
-- already had undo data, inherit the choice to include it.
inferUndoInclusion :: PatchContents -> UndoInclusion
inferUndoInclusion contents = if isJust (contentsUndoData contents)
                                then IncludeUndoData
                                else OmitUndoData

-- | Which 'VerificationInclusion' a 'PatchContents' carries today.
-- Used on the conversion path when the user didn't specify: if the
-- source patch already had a validation block (or, eventually, an
-- xdelta1-style MD5 verification stamp; today 'PatchContents' only
-- carries the PPF3-style validation block via 'contentsValidation'),
-- inherit the choice to include verification data in the target.
inferVerificationInclusion :: PatchContents -> VerificationInclusion
inferVerificationInclusion contents = if isJust (contentsValidation contents)
                                        then IncludeVerification
                                        else OmitVerification

----------------------------------------------------------------------------
-- Format specs
----------------------------------------------------------------------------

-- | Build the conversion contract for a given direct target.  The
-- 'UndoInclusion' and 'VerificationInclusion' parameters shape PPF3's
-- /required/ set: both fields are optional in the wire format, so
-- whether the source patch must carry them depends on whether the
-- user asked for undo or verification data to be included in the
-- output.
directConversionContract :: DirectCreate -> UndoInclusion -> VerificationInclusion -> DirectConversionContract
directConversionContract target undoChoice verificationChoice = case target of
  CreateIPS     -> DirectConversionContract (requiredFields []) (acceptedFields [FieldTruncation])
  CreateIPS32   -> DirectConversionContract (requiredFields []) (acceptedFields [])
  CreateEBP     -> DirectConversionContract (requiredFields []) (acceptedFields [FieldDescription, FieldEBPMeta])
  CreatePPF1    -> DirectConversionContract (requiredFields []) (acceptedFields [FieldDescription])
  CreatePPF2    -> DirectConversionContract (requiredFields [FieldValidation])
                             (acceptedFields [FieldDescription, FieldFileIdDiz])
  CreatePPF3    -> DirectConversionContract (requiredFields $ [FieldUndoData     | undoChoice         == IncludeUndoData]
                                 ++ [FieldValidation | verificationChoice == IncludeVerification])
                             (acceptedFields [FieldDescription, FieldImageType, FieldFileIdDiz])
  CreateNINJA1  -> DirectConversionContract (requiredFields []) (acceptedFields [FieldSourceCRC32, FieldSourceMD5, FieldSourceSHA1, FieldRomType])
  CreatePMSR    -> DirectConversionContract (requiredFields []) (acceptedFields [])
  CreatePCHTXT  -> DirectConversionContract (requiredFields []) (acceptedFields [FieldDescription, FieldPCHTXTBlocks])
  CreateAPSN64  -> DirectConversionContract (requiredFields [FieldDestinationSize]) (acceptedFields [FieldDescription])
  where
    requiredFields extra = Set.fromList (FieldRecords : extra)
    acceptedFields = Set.fromList

----------------------------------------------------------------------------
-- Metadata-field acceptance (CLI rejection)
----------------------------------------------------------------------------

-- | The user-requestable metadata concepts a target format actually
-- consumes during creation.  Used to reject incoherent flag/format
-- combinations: a user setting @--rom-type@ with @--format ips@ is
-- asking for something IPS can't represent, so creation fails before
-- any IO.
--
-- Direct-format entries derive from the per-format reads inside
-- 'buildContents' and 'encodeDirect'; differential-format entries
-- derive from the per-format reads inside 'createPatch'.  An entry here means
-- "the format-specific encoder reads this field"; absence means
-- "setting this field on the CLI would do nothing observable for this
-- format."
acceptedMetadataFields :: CreateFormat -> Set.Set MetadataField
acceptedMetadataFields (CreateDirect format) = case format of
  CreateIPS    -> Set.empty
  CreateIPS32  -> Set.empty
  CreateEBP    -> Set.fromList [MetadataTitle, MetadataAuthor, MetadataDescription]
  CreatePPF1   -> Set.fromList [MetadataDescription]
  CreatePPF2   -> Set.fromList [MetadataDescription]
  CreatePPF3   -> Set.fromList [MetadataDescription, MetadataImageType, MetadataUndoInclusion, MetadataVerificationInclusion]
  CreateNINJA1 -> Set.fromList [MetadataRomType]
  CreatePMSR   -> Set.empty
  CreatePCHTXT -> Set.fromList [MetadataDescription]
  CreateAPSN64 -> Set.fromList [MetadataDescription]
acceptedMetadataFields (CreateDifferential format) = case format of
  CreateBPS     -> Set.fromList [MetadataEmbeddedBlob]
  CreateUPS     -> Set.empty
  CreateDPS     -> Set.fromList [MetadataTitle, MetadataAuthor, MetadataVersion, MetadataStability]
  CreateNINJA2  -> Set.fromList
    [ MetadataTitle, MetadataAuthor, MetadataVersion, MetadataDescription, MetadataGenre, MetadataLanguage
    , MetadataDate, MetadataWebsite, MetadataRomType, MetadataPatchEncoding ]
  CreateAPSGBA  -> Set.empty
  CreateGDIFF   -> Set.empty
  CreateXDelta1 -> Set.fromList [MetadataVerificationInclusion, MetadataPatchCompression,
                                 MetadataXDelta1FromName, MetadataXDelta1ToName]

-- | The 'MetadataField's the user explicitly set on a
-- 'RequestedPatchMetadata'. A 'Maybe' field counts as set when 'Just'.
requestedMetadataFields :: RequestedPatchMetadata -> Set.Set MetadataField
requestedMetadataFields meta = Set.fromList $ concat
  [ [MetadataTitle                | isJust (requestedTitle                meta)]
  , [MetadataAuthor               | isJust (requestedAuthor               meta)]
  , [MetadataDescription          | isJust (requestedDescription          meta)]
  , [MetadataVersion              | isJust (requestedVersion              meta)]
  , [MetadataUndoInclusion        | isJust (requestedUndoInclusion        meta)]
  , [MetadataVerificationInclusion | isJust (requestedVerificationInclusion meta)]
  , [MetadataPatchCompression     | isJust (requestedPatchCompression     meta)]
  , [MetadataStability           | isJust (requestedStability           meta)]
  , [MetadataRomType             | isJust (requestedRomType             meta)]
  , [MetadataImageType           | isJust (requestedImageType           meta)]
  , [MetadataGenre               | isJust (requestedGenre               meta)]
  , [MetadataLanguage            | isJust (requestedLanguage            meta)]
  , [MetadataDate                | isJust (requestedDate                meta)]
  , [MetadataWebsite             | isJust (requestedWebsite             meta)]
  , [MetadataPatchEncoding       | isJust (requestedPatchEncoding       meta)]
  , [MetadataEmbeddedBlob        | isJust (requestedEmbeddedBlob        meta)]
  , [MetadataXDelta1FromName     | isJust (requestedXDelta1FromName     meta)]
  , [MetadataXDelta1ToName       | isJust (requestedXDelta1ToName       meta)]
  ]

-- | Reject any metadata field set by the user that the target format
-- doesn't consume. Reports every offending field in one error so users
-- see all flag mistakes in a single run.
rejectIncompatibleMetadata
  :: CreateFormat
  -> RequestedPatchMetadata
  -> Either SlapError ()
rejectIncompatibleMetadata format meta =
  case NonEmpty.nonEmpty (Set.toList (requestedMetadataFields meta `Set.difference` acceptedMetadataFields format)) of
    Nothing      -> Right ()
    Just rejects -> Left (MetadataFieldRejected rejects (createFormatLabel format))

----------------------------------------------------------------------------
-- Constraints (CLI rejection / encoder gates)
----------------------------------------------------------------------------

-- | The constraint bag the user assembled from CLI flags, parallel
-- to 'RequestedPatchMetadata' but for refuse-gates rather than
-- embedded properties. 'requestedSMCShape' is the only field today;
-- future constraints land here.
--
-- Unlike 'RequestedPatchMetadata', constraints carry no source-patch
-- inheritance step — they're an entirely CLI-set concept and are
-- not read from a parsed source patch during convert. A source
-- patch's encoder couldn't have known about the user's downstream
-- requirements when it was created, so there's nothing meaningful
-- to inherit.
data RequestedConstraints = RequestedConstraints
  { requestedSMCShape :: SMCShapeRequirement
  }
  deriving (Show, Eq)

noConstraintsRequested :: RequestedConstraints
noConstraintsRequested = RequestedConstraints
  { requestedSMCShape = AllowAnyTruncationShape
  }

-- | The 'Constraint's the user explicitly opted into.
-- 'AllowAnyTruncationShape' is the not-specified state.
requestedConstraints :: RequestedConstraints -> Set.Set Constraint
requestedConstraints constraints = Set.fromList $ concat
  [ [SMCShapeConstraint | requestedSMCShape constraints == RequireSMCShapedTruncation]
  ]

-- | The 'Constraint's a target format can honor. Pattern-matched
-- exhaustively across both 'CreateDirect' and 'CreateDifferential' so
-- that adding a constructor anywhere — a new format, or a new
-- constraint — fires '-Wincomplete-patterns' on every case that
-- needs a decision. This is non-cosmetic: a wildcard would silently
-- reject a half-wired constraint against every format and slap would
-- volunteer no signal.
acceptedConstraints :: CreateFormat -> Set.Set Constraint
acceptedConstraints (CreateDirect format) = case format of
  CreateIPS    -> Set.singleton SMCShapeConstraint
  CreateIPS32  -> Set.empty
  CreateEBP    -> Set.empty
  CreatePPF1   -> Set.empty
  CreatePPF2   -> Set.empty
  CreatePPF3   -> Set.empty
  CreateNINJA1 -> Set.empty
  CreatePMSR   -> Set.empty
  CreatePCHTXT -> Set.empty
  CreateAPSN64 -> Set.empty
acceptedConstraints (CreateDifferential format) = case format of
  CreateBPS     -> Set.empty
  CreateUPS     -> Set.empty
  CreateDPS     -> Set.empty
  CreateNINJA2  -> Set.empty
  CreateAPSGBA  -> Set.empty
  CreateGDIFF   -> Set.empty
  CreateXDelta1 -> Set.empty

-- | Reject any constraint the user opted into that the target format
-- doesn't honor. Same shape as 'rejectIncompatibleMetadata'.
rejectIncompatibleConstraints
  :: CreateFormat -> RequestedConstraints -> Either SlapError ()
rejectIncompatibleConstraints format constraints =
  case NonEmpty.nonEmpty (Set.toList (requestedConstraints constraints `Set.difference` acceptedConstraints format)) of
    Nothing      -> Right ()
    Just rejects -> Left (ConstraintNotSupported rejects (createFormatLabel format))

-- | Refuse to emit an IPS truncation marker whose declared size
-- doesn't satisfy SNESTool's shape filter, when the user has opted
-- in. Parallel to 'rejectTruncation'. A no-op when constraints don't
-- request the gate or when 'contentsTruncation' is 'Nothing'.
rejectNonSMCShapedTruncation
  :: RequestedConstraints -> PatchContents -> Either SlapError ()
rejectNonSMCShapedTruncation constraints contents
  | requestedSMCShape constraints /= RequireSMCShapedTruncation = Right ()
  | otherwise = case contentsTruncation contents of
      Nothing                          -> Right ()
      Just size | isSMCShapedSize size -> Right ()
                | otherwise            -> Left (TruncationViolatesSMCShape size)

----------------------------------------------------------------------------
-- Dialects (parser/encoder wire-format configuration)
----------------------------------------------------------------------------

-- | The dialect bag the user assembled from CLI flags, parallel to
-- 'RequestedConstraints' but for parser/encoder wire-format configuration
-- rather than refuse-gates. 'requestedPPF1Origin' is the only field
-- today; future dialect axes land here.
--
-- Like 'RequestedConstraints' and unlike 'RequestedPatchMetadata',
-- dialects carry no source-patch inheritance step — they're an
-- entirely CLI-set concept. A source patch can't tell us how to
-- decode itself: if it could, the dialect axis wouldn't exist.
data RequestedDialects = RequestedDialects
  { requestedPPF1Origin :: PPF1Origin
  }
  deriving (Show, Eq)

noDialectsRequested :: RequestedDialects
noDialectsRequested = RequestedDialects
  { requestedPPF1Origin = PPF1OriginPC
  }

-- | The 'Dialect' axes the user explicitly toggled away from default.
-- 'PPF1OriginPC' is the not-specified state, mirroring how
-- 'RequestedConstraints' treats 'AllowAnyTruncationShape'.
requestedDialects :: RequestedDialects -> Set.Set Dialect
requestedDialects dialects = Set.fromList $ concat
  [ [PPF1OriginAxis | requestedPPF1Origin dialects /= PPF1OriginPC]
  ]

-- | The 'Dialect' axes a 'FormatLabel' admits. Unlike the
-- create-only matrices ('acceptedMetadataFields', 'acceptedConstraints')
-- this is keyed on 'FormatLabel' rather than 'CreateFormat': dialects
-- are relevant on both parse and create paths, and the union of two
-- labels' dialect sets defines what a 'convert' chain can honor end
-- to end. Pattern-matched exhaustively across all 'FormatLabel'
-- constructors so adding a label or a dialect axis fires
-- '-Wincomplete-patterns' on every case that needs a decision.
acceptedDialects :: FormatLabel -> Set.Set Dialect
acceptedDialects LabelPPF1    = Set.singleton PPF1OriginAxis
acceptedDialects LabelIPS     = Set.empty
acceptedDialects LabelIPS32   = Set.empty
acceptedDialects LabelEBP     = Set.empty
acceptedDialects LabelBPS     = Set.empty
acceptedDialects LabelUPS     = Set.empty
acceptedDialects LabelPPF2    = Set.empty
acceptedDialects LabelPPF3    = Set.empty
acceptedDialects LabelPPF4    = Set.empty
acceptedDialects LabelVCDIFF  = Set.empty
acceptedDialects LabelBSDiff  = Set.empty
acceptedDialects LabelAPSN64  = Set.empty
acceptedDialects LabelAPSGBA  = Set.empty
acceptedDialects LabelNINJA1  = Set.empty
acceptedDialects LabelNINJA2  = Set.empty
acceptedDialects LabelGDIFF   = Set.empty
acceptedDialects LabelXDelta1 = Set.empty
acceptedDialects LabelDPS     = Set.empty
acceptedDialects LabelPMSR    = Set.empty
acceptedDialects LabelPCHTXT  = Set.empty

-- | Reject any dialect axis the user toggled that the given accepted
-- set doesn't admit. Caller computes the accepted set: a single label's
-- 'acceptedDialects' for apply/undo/info/explain/create, the union of
-- input-and-output labels' sets for convert. The 'FormatLabel' arm
-- names the format reported in the error message; for convert this is
-- conventionally the @--to@ target.
rejectIncompatibleDialects
  :: Set.Set Dialect -> FormatLabel -> RequestedDialects
  -> Either SlapError ()
rejectIncompatibleDialects accepted reportedLabel dialects =
  case NonEmpty.nonEmpty (Set.toList (requestedDialects dialects `Set.difference` accepted)) of
    Nothing      -> Right ()
    Just rejects -> Left (DialectNotSupported rejects reportedLabel)

----------------------------------------------------------------------------
-- Contract checking
----------------------------------------------------------------------------

-- | Why 'canConvert' refused to sign off on a conversion. Two
-- mutually exclusive failure modes, distinguished because they
-- point the caller at different corrective actions.
data ConversionFailure
  = -- | The target format lists fields as required that the source
    -- patch doesn't provide. Corrective action: populate the
    -- missing fields (e.g. hash a source ROM via @--with INPUT@
    -- for NINJA1) or choose a target that doesn't require them.
    RequirementsMissing (Set.Set PatchField)

    -- | The source patch carries one or more fields that affect the
    -- output bytes of the apply operation (see
    -- 'Slap.PatchField.affectsApplyOutput') and that the target
    -- format has no wire representation for. Silently dropping
    -- them would change what the resulting patch produces on
    -- apply, so the conversion is refused at the contract layer
    -- rather than papered over with a warning. Corrective action:
    -- choose a target that preserves the field.
  | ApplyOutputFieldsDropped (Set.Set PatchField)
  deriving (Eq, Show)

canConvert :: PatchContents -> DirectConversionContract -> Either ConversionFailure ()
canConvert contents contract =
  let have = provides contents
      need = contractRequiredFields contract
      kept = need `Set.union` contractAcceptedFields contract
      droppedApplyOutput = Set.filter affectsApplyOutput
                             (have `Set.difference` kept)
      missing = need `Set.difference` have
  in if not (Set.null droppedApplyOutput)
       -- Apply-output violations are the sharper signal: the resulting
       -- patch would apply to produce different bytes. Surface this
       -- first even when requirements are also unmet.
       then Left (ApplyOutputFieldsDropped droppedApplyOutput)
     else if not (Set.null missing)
       then Left (RequirementsMissing missing)
     else Right ()

-- | Every direct creation target, used to scan 'directConversionContract'
-- for formats that preserve a given 'PatchField'. Derived from the
-- constructors of 'DirectCreate' via @Enum@\/@Bounded@, so adding a
-- constructor extends this list automatically.
allDirectTargets :: [DirectCreate]
allDirectTargets = [minBound..maxBound]

-- | Direct creation targets whose 'directConversionContract' accepts the
-- given 'PatchField'. Used by 'convertDirect' to populate the
-- @Targets that preserve ...@ clause of the
-- 'ApplyOutputFieldsWouldBeDropped' refusal message; dynamic so
-- future additions to the format table get picked up automatically.
--
-- 'IncludeUndoData' and 'IncludeVerification' only influence PPF3's
-- /required/ set, not its /accepted/ set, so we pass the @Include@
-- constructors for both without affecting the answer.
preservingDirectTargets :: PatchField -> [FormatLabel]
preservingDirectTargets field =
  [ directLabel target
  | target <- allDirectTargets
  , let contract = directConversionContract target IncludeUndoData IncludeVerification
        accepted = contractRequiredFields contract `Set.union` contractAcceptedFields contract
  , field `Set.member` accepted
  ]

----------------------------------------------------------------------------
-- Conversion notes (dropped-field warnings)
----------------------------------------------------------------------------

conversionNotes :: PatchContents -> DirectCreate -> DirectConversionContract -> RequestedPatchMetadata -> [SlapWarning]
conversionNotes contents target contract meta =
  let have = provides contents
      kept = contractRequiredFields contract `Set.union` contractAcceptedFields contract
      dropped = have `Set.difference` kept `Set.difference` Set.singleton FieldRecords
      droppedNotes = concatMap (fieldNote contents) (Set.toList dropped)
      defaultNotes = defaultAssumptionNotes target meta (contentsRomType contents) (contentsImageType contents)
      hashNotes = ninja1HashNotes contents target
      encodingNotes = encodingGapNotes contents target
  in droppedNotes ++ defaultNotes ++ hashNotes ++ encodingNotes

-- | Warn when converting from a format with known text encoding to one
-- without an encoding flag.  The bytes are copied unchanged — but the
-- target has no way to record what encoding they are.
encodingGapNotes :: PatchContents -> DirectCreate -> [SlapWarning]
encodingGapNotes contents target = case contentsPatchEncoding contents of
  Just _ | isJust (contentsDescription contents)
         , target `elem` [CreatePPF3, CreateAPSN64]
         -> [EncodingGap LabelNINJA2 (directLabel target)]
  _ -> []

-- | Warn when encodeDirect defaults romType or imageType because neither the
-- CLI flags nor the source patch provided a value.
defaultAssumptionNotes :: DirectCreate -> RequestedPatchMetadata -> Maybe PlatformType -> Maybe PPF3ImageType -> [SlapWarning]
defaultAssumptionNotes target meta sourceRomType sourceImageType = concat
  [ [ DefaultRomType LabelNINJA1
    | target == CreateNINJA1
    , Nothing <- [requestedRomType meta <|> sourceRomType] ]
  , [ DefaultImageType LabelPPF3
    | target == CreatePPF3
    , Nothing <- [requestedImageType meta <|> sourceImageType] ]
  ]

-- | Default-assumption notes for the create and --with convert paths,
-- where no source PatchContents is available.
createDefaultNotes :: CreateFormat -> RequestedPatchMetadata -> [SlapWarning]
createDefaultNotes (CreateDirect target) meta = defaultAssumptionNotes target meta Nothing Nothing
  ++ undoVerificationNotes target meta
createDefaultNotes (CreateDifferential _) _ = []

-- | Warn when undo / verification are included by default (no CLI
-- flag, no inherited source value). Same pattern as rom-type
-- defaulting to RAW.
undoVerificationNotes :: DirectCreate -> RequestedPatchMetadata -> [SlapWarning]
undoVerificationNotes CreatePPF3 meta = concat
  [ [ IncludingUndoByDefault         | Nothing <- [requestedUndoInclusion         meta] ]
  , [ IncludingVerificationByDefault | Nothing <- [requestedVerificationInclusion meta] ]
  ]
undoVerificationNotes _ _ = []

-- | Note when converting to NINJA1 without source verification hashes.
ninja1HashNotes :: PatchContents -> DirectCreate -> [SlapWarning]
ninja1HashNotes contents CreateNINJA1
  | isNothing (contentsSourceCRC32 contents)
    || isNothing (contentsSourceMD5 contents)
    || isNothing (contentsSourceSHA1 contents)
  = [SourceHashesMissing LabelNINJA1]
ninja1HashNotes _ _ = []

fieldNote :: PatchContents -> PatchField -> [SlapWarning]
fieldNote contents field = case field of
  FieldRecords -> []
  FieldSourceCRC32 -> case contentsSourceCRC32 contents of
    Just crc | crc /= CRC32 0 -> [FieldDropped FieldSourceCRC32 (DroppedCRC crc)]
    _ -> []
  FieldSourceMD5 -> case contentsSourceMD5 contents of
    Just hash | not (ByteString.all (== 0) (unMD5Hash hash)) -> [FieldDropped FieldSourceMD5 (DroppedMD5 hash)]
    _ -> []
  FieldSourceSHA1 -> case contentsSourceSHA1 contents of
    Just hash | not (ByteString.all (== 0) (unSHA1Hash hash)) -> [FieldDropped FieldSourceSHA1 (DroppedSHA1 hash)]
    _ -> []
  FieldDescription -> case contentsDescription contents of
    Just description | not (ByteString.all (\byte -> byte == 0x20 || byte == 0) description) ->
      [FieldDropped FieldDescription (DroppedDescription (trimNullSpace (decodeLocaleField description)))]
    _ -> []
  FieldUndoData -> case contentsUndoData contents of
    Just undoRecords -> [UndoDataDropped (length undoRecords)]
    Nothing -> []
  FieldValidation -> [ValidationBlockDropped | isJust (contentsValidation contents)]
  FieldDestinationSize -> case contentsDestinationSize contents of
    Just targetSize -> [FieldDropped FieldDestinationSize (DroppedSize targetSize)]
    Nothing -> []
  FieldTruncation -> [FieldDropped FieldTruncation DroppedEmpty | isJust (contentsTruncation contents)]
  FieldEBPMeta -> [FieldDropped FieldEBPMeta DroppedEmpty | isJust (contentsEBPMeta contents)]
  FieldRomType -> [FieldDropped FieldRomType DroppedEmpty | isJust (contentsRomType contents)]
  FieldImageType -> [FieldDropped FieldImageType DroppedEmpty | isJust (contentsImageType contents)]
  FieldFileIdDiz -> [FieldDropped FieldFileIdDiz DroppedEmpty | isJust (contentsFileIdDiz contents)]
  FieldPCHTXTBlocks -> case contentsPCHTXTBlocks contents of
    Just blocks ->
      let disabled = sum (map (length . PCHTXT.pchtxtBlockEntries)
                              (filter (not . PCHTXT.pchtxtBlockEnabled) blocks))
          hasDescriptions = any (isJust . PCHTXT.pchtxtBlockDescription) blocks
      in concat
        [ [DisabledEntriesDropped disabled | disabled > 0]
        , [BlockDescriptionsDropped | hasDescriptions]
        ]
    Nothing -> []
  FieldMetadata -> case contentsMetadata contents of
    Just metadataBlob | not (ByteString.null metadataBlob) -> [MetadataDropped (ByteString.length metadataBlob)]
    _ -> []

----------------------------------------------------------------------------
-- Direct conversion (direct → direct)
----------------------------------------------------------------------------

-- | Convert parsed patch contents to a target format without the source ROM.
convertDirect :: PatchContents -> CreateFormat -> RequestedPatchMetadata
              -> RequestedConstraints
              -> RequestedDialects
              -> Either SlapError CreateResult
convertDirect _ (CreateDifferential target) _ _ _ = Left (DiffRequiresSource (differentialLabel target))
convertDirect contents (CreateDirect target) meta constraints dialects = do
  let undoChoice         = fromMaybe (inferUndoInclusion         contents) (requestedUndoInclusion         meta)
      verificationChoice = fromMaybe (inferVerificationInclusion contents) (requestedVerificationInclusion meta)
      contract           = directConversionContract target undoChoice verificationChoice
  case canConvert contents contract of
    Left (RequirementsMissing missing) ->
      Left (MissingRequiredField (directLabel target) (Set.findMin missing))
    Left (ApplyOutputFieldsDropped fields) ->
      Left (ApplyOutputFieldsWouldBeDropped (directLabel target)
              [(field, preservingDirectTargets field) | field <- Set.toList fields])
    Right () -> do
      -- Source-less path: 'encodeDirect' still runs 'resolveSentinelCollisions'
      -- but with an empty 'InputFileContents', so any record sitting on the
      -- variant's trailer sentinel produces 'SentinelCollisionUnfixable' rather
      -- than silently passing through.
      let notes = conversionNotes contents target contract meta
      encoded <- encodeDirect contents (InputFileContents ByteString.empty) target meta (encodingLimits target) constraints dialects
      Right CreateResult
        { resultBytes    = resultBytes encoded
        , resultWarnings = notes ++ resultWarnings encoded
        }

-- | Per-format wire-format offset bound, consulted by the @narrow@
-- helper inside 'encodeDirect'. Each 'Just' entry pairs the format's
-- maximum addressable offset with its 'FormatLabel' so an overflow
-- surfaces as 'NarrowingError' tagged with the right format. The
-- 'Nothing' entries name formats whose wire encoding has no per-record
-- offset cap; their arms in 'encodeDirect' route through
-- 'narrowHunksUnbounded' instead.
encodingLimits :: DirectCreate -> Maybe EncodingLimits
encodingLimits CreateIPS     = Just ipsLimits
encodingLimits CreateIPS32   = Just ips32Limits
encodingLimits CreateEBP     = Just ebpLimits
encodingLimits CreateAPSN64  = Just APSN64.apsN64Limits
encodingLimits CreatePCHTXT  = Just PCHTXT.pchtxtLimits
encodingLimits CreatePMSR    = Just PMSR.pmsrLimits
encodingLimits CreatePPF1    = Just ppf1Limits
encodingLimits CreatePPF2    = Just ppf2Limits
encodingLimits CreatePPF3    = Nothing  -- Int64-shaped offset, no per-record cap
encodingLimits CreateNINJA1  = Nothing  -- variable-width length-of-offset, no per-record cap

-- | Encode PatchContents into the target format.
-- Validation (offset range, sentinel collision) runs after format-specific
-- splitting, so split-induced sentinel collisions are caught.
encodeDirect :: PatchContents -> InputFileContents -> DirectCreate -> RequestedPatchMetadata
             -> Maybe EncodingLimits -> RequestedConstraints -> RequestedDialects
             -> Either SlapError CreateResult
encodeDirect contents source target meta limits constraints dialects = case target of
  CreateIPS -> do
    resolvedRaw <- resolveIPSSentinel LabelIPS StandardIPS
                     (splitHunks ipsMaxRecordPayload (contentsRecords contents))
    records <- narrow (splitHunks ipsMaxRecordPayload resolvedRaw)
    rejectNonSMCShapedTruncation constraints contents
    Right (CreateResult
            (IPS.encodeIPSPatch StandardIPS records (contentsTruncation contents))
            [])
  CreateIPS32 -> do
    rejectTruncation LabelIPS32 contents source
    resolvedRaw <- resolveIPSSentinel LabelIPS32 IPS32
                     (splitHunks ipsMaxRecordPayload (contentsRecords contents))
    records <- narrow (splitHunks ipsMaxRecordPayload resolvedRaw)
    -- IPS32 has no community-recognized truncation marker; encodeIPSPatch
    -- silently drops the truncation argument for IPS32, but we pass
    -- 'Nothing' explicitly here to make the decision visible at the call
    -- site.
    Right (CreateResult
            (IPS.encodeIPSPatch IPS32 records Nothing)
            [])
  CreateEBP -> do
    rejectTruncation LabelEBP contents source
    resolvedRaw <- resolveIPSSentinel LabelEBP StandardIPS
                     (splitHunks ipsMaxRecordPayload (contentsRecords contents))
    records <- narrow (splitHunks ipsMaxRecordPayload resolvedRaw)
    -- Pass through raw EBP JSON when metadata values match what the JSON
    -- already provides.  This detects CLI overrides: if the user changed
    -- a field, the values diverge and we rebuild the JSON.
    let passthrough = case contentsEBPMeta contents of
          Nothing -> Nothing
          Just raw ->
            let pairs = jsonPairs raw
                normalizeEmpty (Just value) = if null value then Nothing else Just value
                normalizeEmpty Nothing  = Nothing
            in if cliDescription == normalizeEmpty (jsonFieldCI pairs "description")
                  && cliTitle == normalizeEmpty (jsonFieldCI pairs "title")
                  && cliAuthor == normalizeEmpty (jsonFieldCI pairs "author")
               then Just raw
               else Nothing
        ebpMetadataBytes = case passthrough of
          Just raw -> raw
          Nothing  -> IPS.buildEBPMetadataJSON EBPMetadataFields
                        { ebpMetadataTitle       = ebpTitle
                        , ebpMetadataAuthor      = ebpAuthor
                        , ebpMetadataDescription = description
                        }
    Right (CreateResult
            (IPS.encodeEBPPatch records (EBPMetadata ebpMetadataBytes))
            [])
  CreatePPF1 -> do
    rejectTruncation LabelPPF1 contents source
    records <- narrow (splitHunks ppf1MaxRecordPayload (contentsRecords contents))
    Right (PPF1.encodePPF1 (requestedPPF1Origin dialects) records description)
  CreatePPF2 -> do
    rejectTruncation LabelPPF2 contents source
    -- The validation block lives on 'contentsValidation' regardless
    -- of how it got there: 'buildContents' extracts it from source
    -- bytes for the create path, and 'parseSomePatchFromPPF2' carries
    -- it across from a parsed PPF2 source patch for the convert path.
    -- Either way, if it isn't present here the source ROM is too
    -- short to supply one — buildContents only populates the field
    -- when source length exceeds the 'ppf2ValidationOffset + ppf2ValidationSize'
    -- threshold, and the parse path always populates it from a
    -- well-formed PPF2 patch (PPF2's wire format mandates the block).
    case contentsValidation contents of
      Nothing -> Left (SourceTooSmallForPPF2Validation LabelPPF2
                         (ActualSize (byteFileSize (unInputFileContents source)))
                         (ExpectedSize (FileSize (unOffset ppf2ValidationOffset
                                                + unLength ppf2ValidationSize))))
      Just validationBytes -> do
        sourceSize <- narrowPPF2SourceSize $
          if ByteString.null (unInputFileContents source)
            -- Source-less convert: 'contentsDestinationSize' carries the
            -- size value the parsed source patch had in its header.
            then fromMaybe (FileSize 0) (contentsDestinationSize contents)
            else byteFileSize (unInputFileContents source)
        records <- narrow (splitHunks ppf2MaxRecordPayload (contentsRecords contents))
        let ppf2Result = PPF2.encodePPF2
                           records
                           description
                           sourceSize
                           (PPF2ValidationBlock validationBytes)
        case contentsFileIdDiz contents of
          Nothing  -> Right ppf2Result
          Just diz -> do
            fid <- narrowPPF2FileId diz
            Right ppf2Result { resultBytes = PatchFileContents
                          (unPatchFileContents (resultBytes ppf2Result)
                           <> PPF2.encodeFileIdDiz fid) }
  CreatePPF3 -> do
    -- PPF3's offset is Int64-shaped on the wire; the offset bound is
    -- 'Nothing' in 'encodingLimits', so 'narrow' here delegates to
    -- 'narrowHunksUnbounded'. Payload is still capped at
    -- 'ppf3MaxRecordPayload'. The parallel undo pipeline shares that
    -- "no offset cap" property, so the undo hunks narrow via
    -- 'narrowUndoHunksUnbounded'.
    records <- narrow (splitHunks ppf3MaxRecordPayload (contentsRecords contents))
    let undoEncoded = fmap narrowUndoHunksUnbounded (contentsUndoData contents)
        ppfResult   = PPF3.encodePPF3 records description undoEncoded
                        (fmap PPF3ValidationBlock (contentsValidation contents))
                        imageType
    case contentsFileIdDiz contents of
      Nothing  -> Right ppfResult
      Just diz -> do
        fid <- narrowPPF3FileId diz
        Right ppfResult { resultBytes = PatchFileContents
                      (unPatchFileContents (resultBytes ppfResult)
                       <> PPF3.encodeFileIdDiz fid) }
  CreateNINJA1 -> do
    resolvedRaw <- NINJA1.resolveSentinelCollisions LabelNINJA1
                     NINJA1.ninja1SentinelOffset source
                     (splitHunksUnbounded (contentsRecords contents))
    -- Second pass is a no-op for NINJA1 (no per-record cap); kept for
    -- type uniformity with the IPS arms above, where it closes a real
    -- overflow hazard.
    records <- narrow (splitHunksUnbounded resolvedRaw)
    let crc      = fromMaybe (CRC32 0) (contentsSourceCRC32 contents)
        md5Hash  = fromMaybe (MD5Hash  (ByteString.replicate 16 0)) (contentsSourceMD5 contents)
        sha1Hash = fromMaybe (SHA1Hash (ByteString.replicate 20 0)) (contentsSourceSHA1 contents)
    Right (CreateResult (NINJA1.encodeNINJA1 records crc md5Hash sha1Hash ninja1Type
             (fromMaybe False (contentsNINJA1Compressed contents))) platformWarnings)
  CreatePMSR -> do
    count   <- narrowPMSRRecordCount (length (contentsRecords contents))
    records <- narrow (splitHunks pmsrMaxRecordPayload (contentsRecords contents))
    Right (CreateResult (PMSR.encodePMSR count records) [])
  CreatePCHTXT -> case contentsPCHTXTBlocks contents of
    Just blocks -> Right (CreateResult (PCHTXT.encodePCHTXTBlocks blocks pchtxtDescription) [])
    Nothing -> do
      -- PCHTXT is text with no per-record length field; payloads
      -- have no wire-format cap, so split is the unbounded opt-out.
      records <- narrow (splitHunksUnbounded (contentsRecords contents))
      Right (CreateResult (PCHTXT.encodePCHTXT records pchtxtDescription) [])
  CreateAPSN64 -> do
    records <- narrow (splitHunks APSN64.apsN64MaxChunkSize (contentsRecords contents))
    case contentsDestinationSize contents of
      Just targetSize ->
        Right (APSN64.encodeAPSN64 records (fromIntegral (unFileSize targetSize)) (APSN64.APSN64Description apsDescription))
      Nothing -> Left (MissingRequiredField LabelAPSN64 FieldDestinationSize)
  where
    narrow :: [SplitHunk] -> Either SlapError [EncodedHunk]
    narrow = case limits of
      Nothing  -> Right . narrowHunksUnbounded
      Just lim -> first NarrowingError . narrowHunks lim
    resolveIPSSentinel :: FormatLabel -> IPSVariant -> [SplitHunk]
                       -> Either SlapError [Hunk]
    resolveIPSSentinel label variant =
      IPS.resolveSentinelCollisions label
        (SentinelOffset (ipsVariantSentinel (variantSpec variant)))
        source
    rejectTruncation :: FormatLabel -> PatchContents -> InputFileContents -> Either SlapError ()
    rejectTruncation label patchContents (InputFileContents sourceBytes) =
      case contentsTruncation patchContents of
        Just truncatedTargetSize ->
          Left (CannotExpressTargetShrinkage label
                  (ActualSize (byteFileSize sourceBytes))
                  (ExpectedSize truncatedTargetSize))
        Nothing -> Right ()
    cliDescription   = requestedDescription meta
    cliTitle  = requestedTitle meta
    cliAuthor = requestedAuthor meta
    description   = resolveDescription DescriptionSources
      { descriptionSourceCLI      = cliDescription
      , descriptionSourceEBPMeta  = contentsEBPMeta contents
      , descriptionSourceRawBytes = contentsDescription contents
      , descriptionSourceFallback = ""
      }
    apsDescription = resolveDescription DescriptionSources
      { descriptionSourceCLI      = cliDescription
      , descriptionSourceEBPMeta  = Nothing
      , descriptionSourceRawBytes = contentsDescription contents
      , descriptionSourceFallback = replicate 50 ' '
      }
    pchtxtDescription = cliDescription <|> fmap decodeLocaleField (contentsDescription contents)
    ebpFieldPairs = maybe [] jsonPairs (contentsEBPMeta contents)
    ebpTitle  = resolveField cliTitle ebpFieldPairs "title"
    ebpAuthor = resolveField cliAuthor ebpFieldPairs "author"
    -- CLI flag > PatchContents > format default
    (ninja1Type, platformWarnings) = maybe (NINJA1.RomRAW, []) platformToNinja1 (requestedRomType meta <|> contentsRomType contents)
    imageType   = fromMaybe BIN (requestedImageType meta <|> contentsImageType contents)

----------------------------------------------------------------------------
-- Create
----------------------------------------------------------------------------

-- | The dynamic create entry point: dispatches on 'CreateFormat' to the
-- direct pipeline (universal 'PatchContents' assembly, then 'encodeDirect')
-- or to the appropriate per-format differential creator. The optional
-- 'PatchContents' carries structural data from the source patch (EBP JSON,
-- File_ID.diz, PCHTXT blocks, NINJA1 compression flag) for inheritance in
-- the @--with@ conversion path.
--
-- The 'Maybe' 'ResolvedXDelta1FileNames' is the porcelain's resolved
-- pair of xdelta1 file names: it is 'Just' exactly when the target
-- is xdelta1 (the resolution runs in 'app\/Main.hs' via
-- 'Slap.XDelta1.Types.resolveXDelta1FileNames' or
-- 'requireXDelta1FileNames' before this entry point is called).
-- Non-xdelta1 arms ignore it. The xdelta1 arm pattern-matches and
-- refuses with 'XDelta1ConvertRequiresNames' if it's 'Nothing' —
-- which should never happen if the porcelain did its job; the
-- refusal is the graceful structured-error fallback for a programmer
-- contract violation, not an 'error' crash.
createPatch :: CreateFormat
            -> Maybe ResolvedXDelta1FileNames
            -> InputFileContents -> OutputFileContents
            -> RequestedPatchMetadata -> Maybe PatchContents
            -> RequestedConstraints -> RequestedDialects
            -> Either SlapError CreateResult
createPatch (CreateDirect format) _resolvedNames source target meta sourceContents constraints dialects =
  let contents = buildContents format source target meta sourceContents
  in encodeDirect contents source format meta (encodingLimits format) constraints dialects
createPatch (CreateDifferential format) maybeResolvedNames source target meta sourceContents _constraints _dialects = case format of
  -- The constraints parameter is unused on the differential arm: today
  -- no differential format honors any constraint ('acceptedConstraints'
  -- returns 'Set.empty' for every 'CreateDifferential' constructor),
  -- and any user-requested constraint against a differential format is
  -- rejected upstream by 'rejectIncompatibleConstraints' in 'doCreate'
  -- / 'doConvert' before this arm runs. The parameter stays in the
  -- signature for shape-symmetry with the direct arm; when a future
  -- constraint becomes differential-honorable, both the matrix entry
  -- in 'acceptedConstraints' and this arm's plumbing change at once.
  CreateBPS    -> BPS.createBPS source target (fromMaybe ByteString.empty (requestedEmbeddedBlob meta))
  CreateUPS    -> UPS.createUPS source target
  CreateDPS    -> DPS.createDPS source target
                    (DPS.DPSMetadata
                      { DPS.dpsMetadataName    = fromMaybe "" (requestedTitle meta)
                      , DPS.dpsMetadataAuthor  = fromMaybe "" (requestedAuthor meta)
                      , DPS.dpsMetadataVersion = fromMaybe "" (requestedVersion meta)
                      })
                    (maybe DPS.DPSStable stabilityToDPS (requestedStability meta))
  CreateNINJA2 -> do
    -- When source patch has opaque description bytes, detect encoding
    -- via isValidUtf8: valid → PATCH_ENC=1, invalid → PATCH_ENC=0.
    -- If source already has known encoding, respect it.
    let detectedEncoding = case sourceContents >>= contentsPatchEncoding of
          Just patchEncoding -> patchEncoding
          Nothing  -> case sourceContents >>= contentsDescription of
            Just descBytes | not (isValidUtf8 descBytes) -> PatchEncodingSystem
            _ -> fromMaybe PatchEncodingUTF8 (requestedPatchEncoding meta)
        ninja2Meta = NINJA2.NINJA2Metadata
          { NINJA2.ninja2MetadataAuthor      = requestedAuthor meta
          , NINJA2.ninja2MetadataVersion     = requestedVersion meta
          , NINJA2.ninja2MetadataTitle       = requestedTitle meta
          , NINJA2.ninja2MetadataGenre       = requestedGenre meta
          , NINJA2.ninja2MetadataLanguage    = requestedLanguage meta
          , NINJA2.ninja2MetadataDate        = requestedDate meta
          , NINJA2.ninja2MetadataWebsite     = requestedWebsite meta
          , NINJA2.ninja2MetadataDescription = requestedDescription meta
          , NINJA2.ninja2MetadataEncoding    = detectedEncoding
          , NINJA2.ninja2MetadataPlatform    = requestedRomType meta
          }
    NINJA2.createNINJA2 source target ninja2Meta
  CreateAPSGBA  -> APSGBA.createAPSGBA source target
  CreateGDIFF   -> GDIFF.createGDIFF source target
  CreateXDelta1 -> case maybeResolvedNames of
    Just resolvedNames ->
      XDelta1.createXDelta1 verificationChoice compressionChoice resolvedNames source target
    -- The 'Nothing' branch is the typed escape hatch for a porcelain
    -- contract violation (the caller chose 'CreateXDelta1' but didn't
    -- run a resolver upstream). 'LabelXDelta1' as the \"source\" label
    -- is the truthful answer: there is no convert-source format in
    -- scope, and the rendered message reads as a generic refusal
    -- rather than a crash.
    Nothing -> Left (XDelta1ConvertRequiresNames LabelXDelta1)
    where
      verificationChoice = fromMaybe IncludeVerification (requestedVerificationInclusion meta)
      compressionChoice  = fromMaybe CompressedPatch     (requestedPatchCompression     meta)

-- | Build PatchContents from source and target bytes for a direct format.
-- The optional source 'PatchContents' carries structural data (EBP JSON,
-- File_ID.diz, PCHTXT blocks, NINJA1 compression flag) from the original
-- patch for inheritance during @--with@ conversion.
buildContents :: DirectCreate -> InputFileContents -> OutputFileContents
              -> RequestedPatchMetadata -> Maybe PatchContents -> PatchContents
buildContents format inputFileContents@(InputFileContents source) outputFileContents@(OutputFileContents target) meta sourceContents = PatchContents
  { contentsRecords     = patchHunks
  , contentsDescription = Nothing
  , contentsSourceCRC32 = if needs FieldSourceCRC32 then Just (crc32 hashSource) else Nothing
  , contentsSourceMD5   = if needs FieldSourceMD5   then Just (md5 hashSource)   else Nothing
  , contentsSourceSHA1  = if needs FieldSourceSHA1  then Just (sha1 hashSource)  else Nothing
  , contentsDestinationSize    = if needs FieldDestinationSize
                    then Just (byteFileSize target)
                    else Nothing
  , contentsValidation  = if needs FieldValidation && ByteString.length source > validationOffset + 1024
                    then Just (ByteString.take 1024 (ByteString.drop validationOffset source))
                    else Nothing
  , contentsUndoData    = if needs FieldUndoData
                    then Just (splitUndoHunks ppf3MaxRecordPayload source patchHunks)
                    else Nothing
  -- Populated whenever the target is smaller than the source regardless
  -- of whether the target format carries a truncation marker: formats
  -- that can't express truncation (IPS32, EBP) rely on this field being
  -- set so 'rejectTruncation' in 'encodeDirect' can refuse the encoding
  -- rather than silently produce a non-truncating patch.
  , contentsTruncation  = if ByteString.length target < ByteString.length source
                    then Just (byteFileSize target)
                    else Nothing
  -- Structural inheritance: preserve format-specific data from the source patch
  , contentsEBPMeta          = sourceContents >>= contentsEBPMeta
  , contentsFileIdDiz        = sourceContents >>= contentsFileIdDiz
  , contentsPCHTXTBlocks     = sourceContents >>= contentsPCHTXTBlocks
  , contentsNINJA1Compressed = sourceContents >>= contentsNINJA1Compressed
  , contentsRomType     = Nothing
  , contentsImageType   = Nothing
  , contentsMetadata    = Nothing
  , contentsPatchEncoding = Nothing
  }
  where
    patchHunks = case format of
      CreateIPS    -> ipsHunks Offset24
      CreateIPS32  -> ipsHunks Offset32
      CreateEBP    -> ipsHunks Offset24
      CreatePPF1   -> diffHunks inputFileContents outputFileContents
      CreatePPF2   -> diffHunks inputFileContents outputFileContents
      CreatePPF3   -> diffHunks inputFileContents outputFileContents
      CreateNINJA1 -> diffHunks inputFileContents outputFileContents
      CreatePMSR   -> diffHunks inputFileContents outputFileContents
      CreatePCHTXT -> diffHunks inputFileContents outputFileContents
      CreateAPSN64 -> diffHunks inputFileContents outputFileContents
    ipsHunks width = IPS.optimalIPSRecords width
                       inputFileContents outputFileContents
    hashSource   = case format of
      CreateIPS    -> source
      CreateIPS32  -> source
      CreateEBP    -> source
      CreatePPF1   -> source
      CreatePPF2   -> source
      CreatePPF3   -> source
      CreateNINJA1 -> NINJA1.ninja1HashInput source
      CreatePMSR   -> source
      CreatePCHTXT -> source
      CreateAPSN64 -> source
    validationOffset = case requestedImageType meta of
                         Just GI -> 0x80A0
                         _       -> 0x9320
    undoChoice         = fromMaybe IncludeUndoData     (requestedUndoInclusion         meta)
    verificationChoice = fromMaybe IncludeVerification (requestedVerificationInclusion meta)
    contract           = directConversionContract format undoChoice verificationChoice
    allFields = contractRequiredFields contract `Set.union` contractAcceptedFields contract
    needs field = field `Set.member` allFields

----------------------------------------------------------------------------
-- Internal helpers
----------------------------------------------------------------------------

-- | Sources for 'resolveDescription' to consider, in priority order:
-- CLI flag wins over EBP metadata, EBP metadata wins over raw
-- description bytes, raw bytes win over fallback.
data DescriptionSources = DescriptionSources
  { descriptionSourceCLI      :: !(Maybe String)
  , descriptionSourceEBPMeta  :: !(Maybe ByteString.ByteString)
  , descriptionSourceRawBytes :: !(Maybe ByteString.ByteString)
  , descriptionSourceFallback :: !String
  }

-- | Resolve a description from CLI flag, EBP metadata, raw description, or default.
resolveDescription :: DescriptionSources -> String
resolveDescription sources
  | Just description <- descriptionSourceCLI sources = description
  | Just meta <- descriptionSourceEBPMeta sources
  , Just description <- jsonFieldCI (jsonPairs meta) "description"
  , not (null description) = description
  | Just raw <- descriptionSourceRawBytes sources = trimNullSpace (decodeLocaleField raw)
  | otherwise = descriptionSourceFallback sources

-- | Resolve a single EBP field: CLI flag wins, then fall back to source metadata.
resolveField :: Maybe String -> [(String, String)] -> String -> String
resolveField cliValue pairs key
  | Just provided <- cliValue = provided
  | Just value <- jsonFieldCI pairs key = value
  | otherwise = ""

trimNullSpace :: String -> String
trimNullSpace = reverse . dropWhile (\char -> char == ' ' || char == '\0') . reverse

----------------------------------------------------------------------------
-- Format metadata
----------------------------------------------------------------------------

formatExtension :: CreateFormat -> String
formatExtension (CreateDirect format) = directExtension format
formatExtension (CreateDifferential format) = differentialExtension format

formatName :: CreateFormat -> String
formatName (CreateDirect format) = directName format
formatName (CreateDifferential format) = differentialName format

-- | Per-format metadata used by 'Slap.Convert's wrapper functions and
-- by error-construction sites that need to tag errors with the
-- offending format. Both 'directFormatInfo' and 'differentialFormatInfo'
-- return this same shape; the type-level distinction between
-- 'DirectCreate' and 'DifferentialCreate' lives at the input.
data FormatInfo = FormatInfo
  { formatInfoExtension :: String
  , formatInfoName      :: String
  , formatInfoLabel     :: FormatLabel
  }

directFormatInfo :: DirectCreate -> FormatInfo
directFormatInfo CreateIPS    = FormatInfo ".ips"    "IPS"       LabelIPS
directFormatInfo CreateIPS32  = FormatInfo ".ips"    "IPS32"     LabelIPS32
directFormatInfo CreateEBP    = FormatInfo ".ebp"    "EBP"       LabelEBP
directFormatInfo CreatePPF1   = FormatInfo ".ppf"    "PPF1"      LabelPPF1
directFormatInfo CreatePPF2   = FormatInfo ".ppf"    "PPF2"      LabelPPF2
directFormatInfo CreatePPF3   = FormatInfo ".ppf"    "PPF3"      LabelPPF3
directFormatInfo CreateNINJA1 = FormatInfo ".rup"    "NINJA1"    LabelNINJA1
directFormatInfo CreatePMSR   = FormatInfo ".pmsr"   "PMSR"      LabelPMSR
directFormatInfo CreatePCHTXT = FormatInfo ".pchtxt" "PCHTXT"    LabelPCHTXT
directFormatInfo CreateAPSN64 = FormatInfo ".aps"    "APS (N64)" LabelAPSN64

differentialFormatInfo :: DifferentialCreate -> FormatInfo
differentialFormatInfo CreateBPS     = FormatInfo ".bps"     "BPS"       LabelBPS
differentialFormatInfo CreateUPS     = FormatInfo ".ups"     "UPS"       LabelUPS
differentialFormatInfo CreateDPS     = FormatInfo ".dps"     "DPS"       LabelDPS
differentialFormatInfo CreateNINJA2  = FormatInfo ".rup"     "NINJA2"    LabelNINJA2
differentialFormatInfo CreateAPSGBA  = FormatInfo ".aps"     "APS (GBA)" LabelAPSGBA
differentialFormatInfo CreateGDIFF   = FormatInfo ".gdiff"   "GDIFF"     LabelGDIFF
differentialFormatInfo CreateXDelta1 = FormatInfo ".xdelta1" "XDelta1"   LabelXDelta1

directExtension :: DirectCreate -> String
directExtension = formatInfoExtension . directFormatInfo

directName :: DirectCreate -> String
directName = formatInfoName . directFormatInfo

directLabel :: DirectCreate -> FormatLabel
directLabel = formatInfoLabel . directFormatInfo

differentialExtension :: DifferentialCreate -> String
differentialExtension = formatInfoExtension . differentialFormatInfo

differentialName :: DifferentialCreate -> String
differentialName = formatInfoName . differentialFormatInfo

differentialLabel :: DifferentialCreate -> FormatLabel
differentialLabel = formatInfoLabel . differentialFormatInfo

-- | Unified 'FormatLabel' for any 'CreateFormat'.  Fans out across the
-- direct/differential split so callers needing one label per target
-- (notably 'rejectIncompatibleMetadata' and its render path) don't have
-- to pattern-match the wrapper themselves.
createFormatLabel :: CreateFormat -> FormatLabel
createFormatLabel (CreateDirect format)       = directLabel format
createFormatLabel (CreateDifferential format) = differentialLabel format
