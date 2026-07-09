{-# LANGUAGE OverloadedStrings #-}

module Slap.Convert
  ( PatchContents(..)
  , NINJA1Compression(..)
  , DirectCreate(..)
  , DifferentialCreate(..)
  , CreateFormat(..)
  , RequestedPatchMetadata(..)
  , FileIdDizRequest(..)
  , UndoInclusion(..)
  , VerificationInclusion(..)
  , CompressionInclusion(..)
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
  , createDefaultAdvisories
  , mergeRequestedMetadata
  , formatExtension
  , formatName
  , createFormatLabel
  , TokenVisibility(..)
  , createFormatTokens
  , advertisedCreateFormats
  , lookupCreateFormatToken
  , acceptedMetadataFields
  , requestedMetadataFields
  , rejectIncompatibleMetadata
  , xdelta3CompressionEmission
  , rejectUnencodableSecondaryCompressor
  , TextMode(..)
  ) where

import qualified Slap.PPF1.Create as PPF1
import Slap.PPF1.Types (PPF1Origin(..), ppf1Limits, ppf1MaxRecordPayload,
                        ppf1RejectIncompatibleSizeChange)
import qualified Slap.PPF2.Create as PPF2
import Slap.PPF2.Types (PPF2ValidationBlock(..),
                        narrowPPF2FileId, narrowPPF2SourceSize,
                        ppf2Limits, ppf2MaxRecordPayload,
                        ppf2ValidationOffset, ppf2ValidationSize,
                        ppf2RejectIncompatibleSizeChange)
import qualified Slap.PPF3.Create as PPF3
import Slap.PPF3.Types (PPF3ImageType(..), PPF3ValidationBlock(..),
                        narrowPPF3FileId, ppf3MaxRecordPayload, ppf3Limits,
                        ppf3ValidationOffset,
                        ppf3RejectIncompatibleSizeChange)
import qualified Slap.PPF4.Create as PPF4
import Slap.PPF4.Types (PPF4Append(..), ppf4Limits, ppf4MaxRecordPayload,
                        ppf4RejectIncompatibleSizeChange)
import qualified Slap.IPS.Create as IPS
import Slap.IPS.Types (IPSVariant(..), OffsetWidth(..), EBPMetadata(..),
                       IPSVariantSpec(..),
                       SMCShapeRequirement(..), isSMCShapedSize,
                       ipsMaxRecordPayload, variantSpec,
                       ipsLimits, ips32Limits, ebpLimits,
                       ipsRejectIncompatibleSizeChange,
                       ips32RejectIncompatibleSizeChange,
                       ebpRejectIncompatibleSizeChange)
import qualified Slap.BPS.Create as BPS
import qualified Slap.UPS.Create as UPS
import qualified Slap.APSN64.Types as APSN64
import qualified Slap.APSN64.Create as APSN64
import qualified Slap.APSGBA.Create as APSGBA
import qualified Slap.BSDiff.Create as BSDiff
import Slap.NINJA2.Types (TextMode(..))
import qualified Slap.NINJA2.Types as NINJA2
import qualified Slap.NINJA2.Create as NINJA2
import qualified Slap.GDIFF.Create as GDIFF
import qualified Slap.VCDIFF.Create as VCDIFF
import Slap.VCDIFF.Create (WindowCompressionEmission(..))
import Slap.VCDIFF.Types (EmissionWindowSize, unEmissionWindowSize, RFCWindowing(..),
                          defaultXDelta3WindowSize, xdelta3ReferenceDecoderWindowCap)
import Slap.VCDIFF.SecondaryCompression
  (XDelta3SecondaryCompressor(..), encodableSectionCompressor, compressionAlgorithmOf)
import qualified Slap.XDelta1.Create as XDelta1
import Slap.XDelta1.Types (ResolvedXDelta1FileNames,
                           XDelta1FromName(..), XDelta1ToName(..))
import qualified Slap.PMSR.Types as PMSR
import Slap.PMSR.Types (narrowPMSRRecordCount, pmsrMaxRecordPayload,
                       pmsrRejectIncompatibleSizeChange)
import qualified Slap.PMSR.Create as PMSR
import qualified Slap.DPS.Types as DPS
import qualified Slap.DPS.Create as DPS
import qualified Slap.NINJA1.Types as NINJA1
import Slap.NINJA1.Types (NINJA1Compression(..), ninja1RejectIncompatibleSizeChange)
import qualified Slap.NINJA1.Create as NINJA1
import Slap.PlatformType (PlatformType(..))
import Slap.Platform (platformToNINJA1)
import Slap.Binary (diffHunks, md5, sha1)
import Slap.Checksum (CRC32(..), MD5Hash(..), SHA1Hash(..))
import Slap.FFI (crc32)
import Slap.Measure (FileSize(..), Length(..), Offset(..), Hunk(..),
                      SplitHunk, SplitUndoHunk,
                      ActualSize(..), ExpectedSize(..),
                      SentinelOffset(..), MaxLength(..),
                      splitHunks, splitHunksUnbounded, splitUndoHunks,
                      splitPayload, byteFileSize, byteLength)
import Slap.Narrow (EncodedHunk, EncodingLimits(..),
                    narrowHunks, narrowUndoHunks)
import Slap.Constraint (Constraint(..))
import Slap.Dialect (Dialect(..))
import Slap.Status (SlapError(..), SlapAdvisory(..), UndoRecordCount(..), DroppedValue(..),
                    DroppedDescriptionText(..), CreateResult(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.MetadataField (MetadataField(..))
import Slap.MetadataInclusion (UndoInclusion(..), VerificationInclusion(..), CompressionInclusion(..))
import Slap.PatchField (PatchField(..), affectsApplyOutput)
import Slap.FileContents (InputFileContents(..), OutputFileContents(..), PatchFileContents(..))

import Slap.Text (EncodedText(..), EncodingName(..),
                  encodedTextContent)

import Control.Applicative ((<|>))
import Data.Bifunctor (first)
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.Char (toLower)
import qualified Data.List.NonEmpty as NonEmpty
import Data.Maybe (fromMaybe, isJust, isNothing)
import qualified Data.Set as Set
import qualified Data.Text as Text

----------------------------------------------------------------------------
-- Types
----------------------------------------------------------------------------

-- | Which 'PatchField's a direct format requires the source patch to
-- carry, and which additional fields it can accept.
-- A source-less convert is admissible only when the source 'PatchContents'
-- supplies every required field without dropping apply-output-affecting data.
data DirectConversionContract = DirectConversionContract
  { contractRequiredFields :: Set.Set PatchField
  , contractAcceptedFields :: Set.Set PatchField
  }

-- | Universal representation of a direct patch's contents.
data PatchContents = PatchContents
  { contentsRecords     :: [Hunk]
  , contentsDescription :: Maybe EncodedText
    -- ^ Typed description carried across the convert seam. The
    -- encoding tag stays attached end-to-end so a downstream re-encode
    -- can route through whichever encoder the target format wants
    -- without having to re-guess what the source's encoding context
    -- was.
  , contentsSourceCRC32 :: Maybe CRC32
  , contentsSourceMD5   :: Maybe MD5Hash
  , contentsSourceSHA1  :: Maybe SHA1Hash
  , contentsDestinationSize    :: Maybe FileSize
  , contentsValidation  :: Maybe ByteString
    -- ^ Raw 1024-byte validation-block bytes (PPF2/PPF3). Cross-cutting,
    -- so plain bytes; per-format role newtypes wrap on emit.
  , contentsUndoData    :: Maybe [SplitUndoHunk]
  , contentsTruncation  :: Maybe FileSize
  , contentsEBPMetadata :: Maybe EBPMetadata
    -- ^ Parsed EBP metadata flowing across the convert seam.
    -- Populated by 'Slap.SomePatch' when the source patch is EBP
    -- (so the source's title/author/description/patcher carry into a convert-to-EBP), 'Nothing' otherwise.
  , contentsRomType     :: Maybe PlatformType
  , contentsImageType   :: Maybe PPF3ImageType
    -- | The image format of a source APS-N64 Type-1 patch, if any —
    -- the marker that drives the 'APSN64Type1HeaderDropped' convert warning.
  , contentsAPSN64ImageFormat :: Maybe APSN64.APSImageFormat
  , contentsFileIdDiz   :: Maybe EncodedText
    -- ^ Typed FILE_ID.DIZ content (PPF2/PPF3).
    -- The encoding tag is preserved through the seam.
  , contentsNINJA1Compression :: Maybe NINJA1Compression
    -- ^ Whether a NINJA1 source used the compressed (BZ/TZ) subformat,
    -- carried across the convert seam so a NINJA1 target can preserve it.
  , contentsMetadata :: Maybe ByteString
    -- ^ Arbitrary metadata blob (BPS). Most formats don't carry this.
  }

-- | Direct creation target.  Some format families have multiple creation
-- variants: IPS has three (IPS, IPS32, EBP) distinguished by offset width
-- and metadata.
data DirectCreate
  = CreateIPS | CreateIPS32 | CreateEBP | CreatePPF1 | CreatePPF2 | CreatePPF3
  | CreatePPF4 | CreateNINJA1 | CreatePMSR | CreateAPSN64
  deriving (Show, Eq, Enum, Bounded)

-- | Differential creation target: every differential format slap
-- parses, it also creates.
data DifferentialCreate
  = CreateBPS | CreateUPS | CreateDPS | CreateNINJA2
  | CreateAPSGBA | CreateGDIFF | CreateBSDiff | CreateXDelta1
  | CreateRFCVCDIFF | CreateXDelta3
  deriving (Show, Eq)

-- | Target format for patch creation or conversion.
data CreateFormat
  = CreateDirect DirectCreate
  | CreateDifferential DifferentialCreate
  deriving (Show, Eq)

-- | User intent about what metadata should end up in an emitted patch.
-- Built from CLI flags in 'app/CLI.hs' (and from parsed source patches
-- during conversion), then consumed by 'createPatch' /
-- 'encodeDirect'.  Every 'Maybe' field's 'Nothing' means "the user
-- didn't specify; let the format pick its default"; a 'Just' carries
-- an explicit request.
--
-- Which target consumes which field is the 'acceptedMetadataFields'
-- matrix; the per-arm reading is in 'createPatch' / 'encodeDirect'.
data RequestedPatchMetadata = RequestedPatchMetadata
  { requestedTitle                :: Maybe EncodedText
    -- ^ The CLI parser wraps incoming text as @'EncodedText' 'EncodingUtf8'@;
    -- the create-side encoders (DPS, NINJA2) consume it directly via 'Slap.Text.encodeTextBounded'.
  , requestedAuthor               :: Maybe EncodedText
  , requestedDescription          :: Maybe EncodedText
  , requestedVersion              :: Maybe EncodedText
  , requestedUndoInclusion        :: Maybe UndoInclusion
  , requestedVerificationInclusion :: Maybe VerificationInclusion
  , requestedPatchCompression     :: Maybe CompressionInclusion
    -- ^ 'Just' 'OmitCompression' means the user asked for @--no-compress@;
    -- absent means "let the format pick its default," which is compressed
    -- for both consumers: xdelta1 (the gzip patch envelope) and
    -- xdelta3 (secondary compression of the window sections).
  , requestedSecondaryCompressor  :: Maybe XDelta3SecondaryCompressor
    -- ^ xdelta3 only: the secondary compressor to encode with — the user's @--compress-with ALGORITHM@,
    -- or, on convert, the source patch's own declaration, inherited like any other metadata.
    -- Absent means LZMA, the canonical tool's own default. A source's FGK never lands here:
    -- the xdelta3 extraction in "Slap.SomePatch" carries a declaration only where slap can encode with it,
    -- so inheritance cannot steer into the refusal reserved for an explicit request.
  , requestedStability            :: Maybe PatchStability
  , requestedRomType              :: Maybe PlatformType
    -- ^ NINJA1 and NINJA2 define different ROM type enumerations (18 vs 10 values, diverging at byte 2);
    -- 'PlatformType' unions them, and 'Slap.Platform' owns the lossy per-format mappings.
  , requestedImageType            :: Maybe PPF3ImageType
  , requestedFileIdDiz            :: FileIdDizRequest
    -- ^ PPF2/PPF3 FILE_ID.DIZ: carry the source's, set it, or drop it.
  , requestedGenre                :: Maybe EncodedText
    -- ^ NINJA2-only metadata text. Typed across the convert seam so
    -- the source-patch's encoding tag rides through into the
    -- NINJA2 create path, where 'Slap.Text.encodeTextBounded'
    -- transcodes it under whichever 'TextMode' the target
    -- declares for the new patch.
  , requestedLanguage             :: Maybe EncodedText
  , requestedDate                 :: Maybe EncodedText
  , requestedWebsite              :: Maybe EncodedText
  , requestedTextMode             :: Maybe TextMode
    -- ^ NINJA2 wire encoding the user wants the output patch to
    -- declare. CLI-provided value overrides whatever the source
    -- patch's metadata fields tagged themselves as; absent means
    -- "inherit from the source if its tags agree, otherwise UTF-8"
    -- (see the @CreateNINJA2@ arm of 'createPatch').
  , requestedEmbeddedBlob         :: Maybe ByteString
    -- ^ Contents of the user's @--metadata FILE@ flag: a raw blob to
    -- embed verbatim.
  , requestedXDelta1FromName      :: Maybe XDelta1FromName
    -- ^ xdelta1 only: user-supplied @--from-name TEXT@, already
    -- locale-encoded so the bytes match canonical xdelta's wire
    -- shape. This is the unresolved input; the porcelain resolves it.
  , requestedXDelta1ToName        :: Maybe XDelta1ToName
    -- ^ xdelta1 only: counterpart to 'requestedXDelta1FromName' for
    -- the to-name slot.
  , requestedWindowSize           :: Maybe EmissionWindowSize
    -- ^ The window size a VCDIFF create slices its output by — the user's @--window-size SIZE@.
    -- Absent means each arc's own default: 8 MiB windows for xdelta3 ('defaultXDelta3WindowSize'),
    -- one window spanning everything for RFC VCDIFF ('OneWholeTargetWindow', which has the why).
    -- Never inherited on convert, unlike the compressor:
    -- a compressor is one declared wire fact, while a source patch declares no window size —
    -- its windows each carry their own, so there is no single fact to carry, and extraction leaves this 'Nothing'.
  }

-- | What to do with a PPF2/PPF3 FILE_ID.DIZ on create or convert:
-- keep whatever the source carried, replace it, or drop it.
data FileIdDizRequest
  = InheritFileIdDiz
  | SetFileIdDiz EncodedText
  | DropFileIdDiz
  deriving (Eq, Show)

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

-- | Empty 'EncodedText' tagged 'EncodingUtf8', for fallbacks when a 'Maybe EncodedText' slot in 'RequestedPatchMetadata' is 'Nothing'.
-- Empty text is zero bytes under any encoding, so UTF-8 is the natural tag for "no content."
emptyEncodedText :: EncodedText
emptyEncodedText = EncodedText EncodingUtf8 Text.empty

noMetadataRequested :: RequestedPatchMetadata
noMetadataRequested = RequestedPatchMetadata
  { requestedTitle               = Nothing
  , requestedAuthor              = Nothing
  , requestedDescription         = Nothing
  , requestedVersion             = Nothing
  , requestedUndoInclusion        = Nothing
  , requestedVerificationInclusion = Nothing
  , requestedPatchCompression     = Nothing
  , requestedSecondaryCompressor  = Nothing
  , requestedStability           = Nothing
  , requestedRomType             = Nothing
  , requestedImageType           = Nothing
  , requestedFileIdDiz           = InheritFileIdDiz
  , requestedGenre               = Nothing
  , requestedLanguage            = Nothing
  , requestedDate                = Nothing
  , requestedWebsite             = Nothing
  , requestedTextMode            = Nothing
  , requestedEmbeddedBlob        = Nothing
  , requestedXDelta1FromName     = Nothing
  , requestedXDelta1ToName       = Nothing
  , requestedWindowSize          = Nothing
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
  , requestedSecondaryCompressor  = requestedSecondaryCompressor cli  <|> requestedSecondaryCompressor source
  , requestedStability           = requestedStability cli           <|> requestedStability source
  , requestedRomType             = requestedRomType cli             <|> requestedRomType source
  , requestedImageType           = requestedImageType cli           <|> requestedImageType source
  , requestedFileIdDiz           = case requestedFileIdDiz cli of
                                     InheritFileIdDiz -> requestedFileIdDiz source
                                     chosen           -> chosen
  , requestedGenre               = requestedGenre cli               <|> requestedGenre source
  , requestedLanguage            = requestedLanguage cli            <|> requestedLanguage source
  , requestedDate                = requestedDate cli                <|> requestedDate source
  , requestedWebsite             = requestedWebsite cli             <|> requestedWebsite source
  , requestedTextMode            = requestedTextMode cli            <|> requestedTextMode source
  , requestedEmbeddedBlob        = requestedEmbeddedBlob cli        <|> requestedEmbeddedBlob source
  , requestedWindowSize          = requestedWindowSize cli          <|> requestedWindowSize source
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
  , contentsEBPMetadata = Nothing
  , contentsRomType     = Nothing
  , contentsImageType   = Nothing
  , contentsAPSN64ImageFormat = Nothing
  , contentsFileIdDiz   = Nothing
  , contentsNINJA1Compression = Nothing
  , contentsMetadata = Nothing
  }

-- | A zeroed checksum, or an empty text\/blob, is the formats' wire
-- idiom for "absent": such a value counts as not carried.
carries :: PatchContents -> PatchField -> Bool
carries contents field = case field of
  FieldRecords         -> True
  FieldDescription     -> maybe False (not . Text.null . encodedTextContent) (contentsDescription contents)
  FieldSourceCRC32     -> maybe False (/= CRC32 0)                     (contentsSourceCRC32 contents)
  FieldSourceMD5       -> maybe False (not . allZeroBytes . unMD5Hash)  (contentsSourceMD5 contents)
  FieldSourceSHA1      -> maybe False (not . allZeroBytes . unSHA1Hash) (contentsSourceSHA1 contents)
  FieldDestinationSize -> isJust (contentsDestinationSize contents)
  FieldUndoData        -> isJust (contentsUndoData contents)
  FieldValidation      -> isJust (contentsValidation contents)
  FieldTruncation      -> isJust (contentsTruncation contents)
  FieldEBPMeta         -> isJust (contentsEBPMetadata contents)
  FieldRomType         -> isJust (contentsRomType contents)
  FieldImageType       -> isJust (contentsImageType contents)
  FieldFileIdDiz       -> isJust (contentsFileIdDiz contents)
  FieldMetadata        -> maybe False (not . ByteString.null) (contentsMetadata contents)
  where
    allZeroBytes = ByteString.all (== 0)

provides :: PatchContents -> Set.Set PatchField
provides contents = Set.fromList (filter (carries contents) [minBound .. maxBound])

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
  CreatePPF4    -> DirectConversionContract (requiredFields []) (acceptedFields [])
  CreateNINJA1  -> DirectConversionContract (requiredFields []) (acceptedFields [FieldSourceCRC32, FieldSourceMD5, FieldSourceSHA1, FieldRomType])
  CreatePMSR    -> DirectConversionContract (requiredFields []) (acceptedFields [])
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
  CreatePPF2   -> Set.fromList [MetadataDescription, MetadataFileIdDiz]
  CreatePPF3   -> Set.fromList [MetadataDescription, MetadataImageType, MetadataFileIdDiz, MetadataUndoInclusion, MetadataVerificationInclusion]
  CreatePPF4   -> Set.empty
  CreateNINJA1 -> Set.fromList [MetadataRomType]
  CreatePMSR   -> Set.empty
  CreateAPSN64 -> Set.fromList [MetadataDescription]
acceptedMetadataFields (CreateDifferential format) = case format of
  CreateBPS     -> Set.fromList [MetadataEmbeddedBlob]
  CreateUPS     -> Set.empty
  CreateDPS     -> Set.fromList [MetadataTitle, MetadataAuthor, MetadataVersion, MetadataStability]
  CreateNINJA2  -> Set.fromList
    [ MetadataTitle, MetadataAuthor, MetadataVersion, MetadataDescription, MetadataGenre, MetadataLanguage
    , MetadataDate, MetadataWebsite, MetadataRomType, MetadataTextMode ]
  CreateAPSGBA  -> Set.empty
  CreateGDIFF   -> Set.empty
  CreateBSDiff  -> Set.empty
  CreateXDelta1 -> Set.fromList [MetadataVerificationInclusion, MetadataPatchCompression,
                                 MetadataXDelta1FromName, MetadataXDelta1ToName]
  CreateRFCVCDIFF -> Set.fromList [MetadataWindowSize]
  CreateXDelta3   -> Set.fromList [MetadataVerificationInclusion, MetadataPatchCompression,
                                   MetadataSecondaryCompressor, MetadataEmbeddedBlob,
                                   MetadataWindowSize]

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
  , [MetadataSecondaryCompressor  | isJust (requestedSecondaryCompressor  meta)]
  , [MetadataStability           | isJust (requestedStability           meta)]
  , [MetadataRomType             | isJust (requestedRomType             meta)]
  , [MetadataImageType           | isJust (requestedImageType           meta)]
  , [MetadataFileIdDiz           | requestedFileIdDiz meta /= InheritFileIdDiz]
  , [MetadataGenre               | isJust (requestedGenre               meta)]
  , [MetadataLanguage            | isJust (requestedLanguage            meta)]
  , [MetadataDate                | isJust (requestedDate                meta)]
  , [MetadataWebsite             | isJust (requestedWebsite             meta)]
  , [MetadataTextMode            | isJust (requestedTextMode            meta)]
  , [MetadataEmbeddedBlob        | isJust (requestedEmbeddedBlob        meta)]
  , [MetadataXDelta1FromName     | isJust (requestedXDelta1FromName     meta)]
  , [MetadataXDelta1ToName       | isJust (requestedXDelta1ToName       meta)]
  , [MetadataWindowSize          | isJust (requestedWindowSize          meta)]
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

-- | Fold the two compression requests into xdelta3's emission choice:
-- @--no-compress@ wins, a selected compressor is honored when slap can encode with it,
-- and the default is LZMA — the canonical tool's own default.
-- The one refusal is a compressor slap decodes but does not yet encode
-- ('Slap.VCDIFF.SecondaryCompression.encodableSectionCompressor' knows which).
xdelta3CompressionEmission :: RequestedPatchMetadata -> Either SlapError WindowCompressionEmission
xdelta3CompressionEmission meta =
  case fromMaybe IncludeCompression (requestedPatchCompression meta) of
    OmitCompression    -> Right EmitSectionsPlain
    IncludeCompression ->
      let algorithm = fromMaybe SecondaryLZMA (requestedSecondaryCompressor meta)
      in case encodableSectionCompressor algorithm of
           Just compressor -> Right (CompressSectionsWith compressor)
           Nothing         -> Left (XDelta3CompressorEncodingUnsupported (compressionAlgorithmOf algorithm))

-- | The value-level half of the @--compress-with@ gate, beside the concept-level 'rejectIncompatibleMetadata':
-- for an xdelta3 target, refuse a selected compressor slap cannot encode with, before any file is read.
-- Other targets pass through — a selection they can't consume is already the concept-level rejection's to make.
rejectUnencodableSecondaryCompressor :: CreateFormat -> RequestedPatchMetadata -> Either SlapError ()
rejectUnencodableSecondaryCompressor (CreateDifferential CreateXDelta3) meta =
  () <$ xdelta3CompressionEmission meta
rejectUnencodableSecondaryCompressor _ _ = Right ()

----------------------------------------------------------------------------
-- Constraints (CLI rejection / encoder gates)
----------------------------------------------------------------------------

-- | The constraint bag the user assembled from CLI flags, parallel to 'RequestedPatchMetadata' but for refuse-gates rather than embedded properties.
-- 'requestedSMCShape' is the only field today; future constraints land here.
-- Unlike 'RequestedPatchMetadata', constraints are entirely CLI-set, never inherited from a parsed source patch.
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
-- needs a decision.
acceptedConstraints :: CreateFormat -> Set.Set Constraint
acceptedConstraints (CreateDirect format) = case format of
  CreateIPS    -> Set.singleton SMCShapeConstraint
  CreateIPS32  -> Set.empty
  CreateEBP    -> Set.empty
  CreatePPF1   -> Set.empty
  CreatePPF2   -> Set.empty
  CreatePPF3   -> Set.empty
  CreatePPF4   -> Set.empty
  CreateNINJA1 -> Set.empty
  CreatePMSR   -> Set.empty
  CreateAPSN64 -> Set.empty
acceptedConstraints (CreateDifferential format) = case format of
  CreateBPS     -> Set.empty
  CreateUPS     -> Set.empty
  CreateDPS     -> Set.empty
  CreateNINJA2  -> Set.empty
  CreateAPSGBA  -> Set.empty
  CreateGDIFF   -> Set.empty
  CreateBSDiff  -> Set.empty
  CreateXDelta1 -> Set.empty
  CreateRFCVCDIFF -> Set.empty
  CreateXDelta3   -> Set.empty

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
-- in. A no-op when constraints don't request the gate or when
-- 'contentsTruncation' is 'Nothing'.
rejectNonSMCShapedTruncation
  :: RequestedConstraints -> PatchContents -> Either SlapError ()
rejectNonSMCShapedTruncation constraints contents
  | requestedSMCShape constraints /= RequireSMCShapedTruncation = Right ()
  | otherwise = case contentsTruncation contents of
      Nothing                          -> Right ()
      Just size | isSMCShapedSize size -> Right ()
                | otherwise            -> Left (TruncationViolatesSMCShape size)

----------------------------------------------------------------------------
-- Source/target size-pair refusal (per-format wire-rule dispatch)
----------------------------------------------------------------------------

-- | Run the target format's source\/target size-pair rule. Pattern-
-- matched exhaustively across 'DirectCreate' so adding a constructor
-- fires @-Wincomplete-patterns@ and forces an explicit decision; each
-- arm dispatches to the format's own
-- @\<format\>RejectIncompatibleSizeChange@ checker, or routes to
-- 'acceptsAnySizeChange' when the format imposes no size-pair
-- refusal.
--
-- Differential formats are absent from this dispatcher by design.
-- Every differential format slap can emit carries source and target
-- sizes natively in its wire shape, so any (source, target) pair is
-- representable and none refuses on size grounds.
--
-- Called as a precondition of 'createPatch'\'s 'CreateDirect' arm,
-- once per create, with the actual source\/target byte counts in
-- hand. Source-less convert ('convertDirect') does not invoke this
-- dispatcher — it has no source bytes to size against.
rejectIncompatibleSizeChange
  :: DirectCreate -> FileSize -> FileSize -> Either SlapError ()
rejectIncompatibleSizeChange CreatePPF1   = ppf1RejectIncompatibleSizeChange
rejectIncompatibleSizeChange CreatePPF2   = ppf2RejectIncompatibleSizeChange
rejectIncompatibleSizeChange CreatePPF3   = ppf3RejectIncompatibleSizeChange
rejectIncompatibleSizeChange CreatePPF4   = ppf4RejectIncompatibleSizeChange
rejectIncompatibleSizeChange CreateIPS32  = ips32RejectIncompatibleSizeChange
rejectIncompatibleSizeChange CreateEBP    = ebpRejectIncompatibleSizeChange
rejectIncompatibleSizeChange CreateNINJA1 = ninja1RejectIncompatibleSizeChange
rejectIncompatibleSizeChange CreatePMSR   = pmsrRejectIncompatibleSizeChange
rejectIncompatibleSizeChange CreateIPS    = ipsRejectIncompatibleSizeChange
rejectIncompatibleSizeChange CreateAPSN64 = acceptsAnySizeChange

-- | Leaf consumed by 'rejectIncompatibleSizeChange' for formats that
-- impose no source\/target size-pair refusal. Pulled out so the
-- permissive rows of the dispatcher read declaratively instead of as
-- anonymous lambdas.
acceptsAnySizeChange :: FileSize -> FileSize -> Either SlapError ()
acceptsAnySizeChange _sourceSize _targetSize = Right ()

----------------------------------------------------------------------------
-- Dialects (parser/encoder wire-format configuration)
----------------------------------------------------------------------------

-- | The dialect bag the user assembled from CLI flags, parallel to 'RequestedConstraints' but for parser/encoder wire-format configuration rather than refuse-gates.
-- 'requestedPPF1Origin' is the only field today; future dialect axes land here.
-- Like 'RequestedConstraints', dialects are entirely CLI-set: a source patch can't tell us how to decode itself; if it could, the dialect axis wouldn't exist.
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

-- | Every direct creation target, used to scan 'directConversionContract' for formats that preserve a given 'PatchField'.
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

conversionNotes :: PatchContents -> DirectCreate -> DirectConversionContract -> RequestedPatchMetadata -> [SlapAdvisory]
conversionNotes contents target contract meta =
  let have = provides contents
      kept = contractRequiredFields contract `Set.union` contractAcceptedFields contract
      dropped = have `Set.difference` kept `Set.difference` Set.singleton FieldRecords
      droppedNotes = concatMap (fieldNote contents) (Set.toList dropped)
      defaultAdvisories = defaultAssumptionAdvisories target meta (contentsRomType contents) (contentsImageType contents)
      hashAdvisories = ninja1HashAdvisories contents target
      apsN64Type1Notes = [APSN64Type1HeaderDropped | isJust (contentsAPSN64ImageFormat contents)]
  in droppedNotes ++ defaultAdvisories ++ hashAdvisories ++ apsN64Type1Notes

-- | Warn when encodeDirect defaults romType or imageType because neither the
-- CLI flags nor the source patch provided a value.
defaultAssumptionAdvisories :: DirectCreate -> RequestedPatchMetadata -> Maybe PlatformType -> Maybe PPF3ImageType -> [SlapAdvisory]
defaultAssumptionAdvisories target meta sourceRomType sourceImageType = concat
  [ [ DefaultRomType LabelNINJA1
    | target == CreateNINJA1
    , Nothing <- [requestedRomType meta <|> sourceRomType] ]
  , [ DefaultImageType LabelPPF3
    | target == CreatePPF3
    , Nothing <- [requestedImageType meta <|> sourceImageType] ]
  ]

-- | Default-assumption notes for the create and --with convert paths,
-- where no source PatchContents is available.
createDefaultAdvisories :: CreateFormat -> RequestedPatchMetadata -> [SlapAdvisory]
createDefaultAdvisories format meta =
  droppedEmbeddedBlobAdvisories format meta ++ windowSizeAdvisories format meta ++ case format of
    CreateDirect target  -> defaultAssumptionAdvisories target meta Nothing Nothing
                            ++ undoVerificationAdvisories target meta
    CreateDifferential _ -> []

-- | The note for an xdelta3 create asked (@--window-size@) for windows past what the widespread reference build decodes:
-- the patch is valid and the create proceeds; the user hears which decoder will decline the result.
-- xdelta3's alone — an RFC VCDIFF create has no reference decoder to name, so it honors any window size silently.
windowSizeAdvisories :: CreateFormat -> RequestedPatchMetadata -> [SlapAdvisory]
windowSizeAdvisories (CreateDifferential CreateXDelta3) meta =
  [ XDelta3WindowSizePastReferenceDecoder
      (Length (unEmissionWindowSize requested))
      (MaxLength (Length (unEmissionWindowSize xdelta3ReferenceDecoderWindowCap)))
  | Just requested <- [requestedWindowSize meta]
  , requested > xdelta3ReferenceDecoderWindowCap ]
windowSizeAdvisories _ _ = []

-- | A metadata blob the target format can't carry is dropped —
-- an advisory, not a refusal, since it doesn't change the applied output.
-- It covers the BPS metadata blob and the xdelta3 appheader alike, both riding 'requestedEmbeddedBlob'.
droppedEmbeddedBlobAdvisories :: CreateFormat -> RequestedPatchMetadata -> [SlapAdvisory]
droppedEmbeddedBlobAdvisories format meta =
  [ MetadataDropped (byteLength blob)
  | Just blob <- [requestedEmbeddedBlob meta]
  , MetadataEmbeddedBlob `Set.notMember` acceptedMetadataFields format
  ]

-- | The FILE_ID.DIZ to emit: the request overrides the source-inherited DIZ.
effectiveFileIdDiz :: RequestedPatchMetadata -> PatchContents -> Maybe EncodedText
effectiveFileIdDiz meta contents = case requestedFileIdDiz meta of
  InheritFileIdDiz -> contentsFileIdDiz contents
  SetFileIdDiz diz -> Just diz
  DropFileIdDiz    -> Nothing

-- | Warn when undo / verification are included by default (no CLI
-- flag, no inherited source value). Same pattern as rom-type
-- defaulting to RAW.
undoVerificationAdvisories :: DirectCreate -> RequestedPatchMetadata -> [SlapAdvisory]
undoVerificationAdvisories CreatePPF3 meta = concat
  [ [ IncludingUndoByDefault         | Nothing <- [requestedUndoInclusion         meta] ]
  , [ IncludingVerificationByDefault | Nothing <- [requestedVerificationInclusion meta] ]
  ]
undoVerificationAdvisories _ _ = []

-- | Note when converting to NINJA1 without source verification hashes.
ninja1HashAdvisories :: PatchContents -> DirectCreate -> [SlapAdvisory]
ninja1HashAdvisories contents CreateNINJA1
  | isNothing (contentsSourceCRC32 contents)
    || isNothing (contentsSourceMD5 contents)
    || isNothing (contentsSourceSHA1 contents)
  = [SourceHashesMissing LabelNINJA1]
ninja1HashAdvisories _ _ = []

fieldNote :: PatchContents -> PatchField -> [SlapAdvisory]
fieldNote contents field = case field of
  FieldRecords -> []
  FieldSourceCRC32 -> case contentsSourceCRC32 contents of
    Just crc -> [FieldDropped FieldSourceCRC32 (DroppedCRC crc)]
    Nothing -> []
  FieldSourceMD5 -> case contentsSourceMD5 contents of
    Just hash -> [FieldDropped FieldSourceMD5 (DroppedMD5 hash)]
    Nothing -> []
  FieldSourceSHA1 -> case contentsSourceSHA1 contents of
    Just hash -> [FieldDropped FieldSourceSHA1 (DroppedSHA1 hash)]
    Nothing -> []
  FieldDescription -> case contentsDescription contents of
    Just description -> [FieldDropped FieldDescription
                          (DroppedDescription (DroppedDescriptionText (encodedTextContent description)))]
    Nothing -> []
  FieldUndoData -> case contentsUndoData contents of
    Just undoRecords -> [UndoDataDropped (UndoRecordCount (length undoRecords))]
    Nothing -> []
  FieldValidation -> [ValidationBlockDropped | isJust (contentsValidation contents)]
  FieldDestinationSize -> case contentsDestinationSize contents of
    Just targetSize -> [FieldDropped FieldDestinationSize (DroppedSize targetSize)]
    Nothing -> []
  FieldTruncation -> [FieldDropped FieldTruncation DroppedEmpty | isJust (contentsTruncation contents)]
  FieldEBPMeta -> [FieldDropped FieldEBPMeta DroppedEmpty | isJust (contentsEBPMetadata contents)]
  FieldRomType -> [FieldDropped FieldRomType DroppedEmpty | isJust (contentsRomType contents)]
  FieldImageType -> [FieldDropped FieldImageType DroppedEmpty | isJust (contentsImageType contents)]
  FieldFileIdDiz -> [FieldDropped FieldFileIdDiz DroppedEmpty | isJust (contentsFileIdDiz contents)]
  FieldMetadata -> case contentsMetadata contents of
    Just metadataBlob -> [MetadataDropped (byteLength metadataBlob)]
    Nothing -> []

----------------------------------------------------------------------------
-- Direct conversion (direct → direct)
----------------------------------------------------------------------------

-- | Convert parsed patch contents to a target format without the source ROM.
convertDirect :: PatchContents -> CreateFormat -> RequestedPatchMetadata
              -> RequestedConstraints
              -> RequestedDialects
              -> Either SlapError CreateResult
convertDirect _ (CreateDifferential target) _ _ _ = Left (DiffRequiresSource (differentialLabel target))
-- PPF4 splits its records into in-place writes and appended bytes by
-- where they fall relative to the source's size. A source-less convert
-- has the source patch's records but not the source's size, so it can't
-- make that split; refuse and point at the --with path (which applies
-- the source patch and re-diffs against real bytes via createPatch).
convertDirect _ (CreateDirect CreatePPF4) _ _ _ = Left (PPF4ConvertRequiresSource LabelPPF4)
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
      -- with an empty 'InputFileContents', so a record on the variant's
      -- trailer sentinel produces 'SentinelCollisionUnfixable'.
      let notes = conversionNotes contents target contract meta
      encoded <- encodeDirect contents (InputFileContents ByteString.empty) target meta (encodingLimits target) constraints dialects
      Right CreateResult
        { resultBytes    = resultBytes encoded
        , resultAdvisories = notes ++ resultAdvisories encoded
        }

-- | The offset bound the @narrow@ helper checks each format's hunks against.
-- Each pairs a maximum offset with a 'FormatLabel', so an out-of-range or negative offset surfaces as 'NarrowingError' naming the right format.
encodingLimits :: DirectCreate -> EncodingLimits
encodingLimits CreateIPS     = ipsLimits
encodingLimits CreateIPS32   = ips32Limits
encodingLimits CreateEBP     = ebpLimits
encodingLimits CreateAPSN64  = APSN64.apsN64Limits
encodingLimits CreatePMSR    = PMSR.pmsrLimits
encodingLimits CreatePPF1    = ppf1Limits
encodingLimits CreatePPF2    = ppf2Limits
encodingLimits CreatePPF3    = ppf3Limits
encodingLimits CreatePPF4    = ppf4Limits
encodingLimits CreateNINJA1  = NINJA1.ninja1Limits

-- | Validation (offset range, sentinel collision) runs after format-specific splitting,
-- so split-induced sentinel collisions are caught.
encodeDirect :: PatchContents -> InputFileContents -> DirectCreate -> RequestedPatchMetadata
             -> EncodingLimits -> RequestedConstraints -> RequestedDialects
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
    resolvedRaw <- resolveIPSSentinel LabelIPS32 IPS32
                     (splitHunks ipsMaxRecordPayload (contentsRecords contents))
    records <- narrow (splitHunks ipsMaxRecordPayload resolvedRaw)
    -- IPS32 has no truncation marker; 'encodeIPSPatch' drops the
    -- truncation argument for IPS32, so pass 'Nothing' explicitly.
    Right (CreateResult
            (IPS.encodeIPSPatch IPS32 records Nothing)
            [])
  CreateEBP -> do
    resolvedRaw <- resolveIPSSentinel LabelEBP StandardIPS
                     (splitHunks ipsMaxRecordPayload (contentsRecords contents))
    records <- narrow (splitHunks ipsMaxRecordPayload resolvedRaw)
    -- Rebuild the canonical EBP metadata from the typed values here
    -- and hand it to the encoder, which serializes via
    -- 'IPS.buildEBPMetadataJSON'. The source patch's wire bytes no
    -- longer flow through; 'resolveEBPField' / 'resolveDescription'
    -- pull the resolved content out of 'contentsEBPMetadata'.
    let metadata = EBPMetadata
          { ebpMetadataTitle       = Just ebpTitle
          , ebpMetadataAuthor      = Just ebpAuthor
          , ebpMetadataDescription = Just descriptionTyped
          , ebpMetadataPatcher     = Just slapPatcherIdentity
          }
    Right (CreateResult
            (IPS.encodeEBPPatch records metadata)
            [])
  CreatePPF1 -> do
    records <- narrow (splitHunks ppf1MaxRecordPayload (contentsRecords contents))
    Right (PPF1.encodePPF1 (requestedPPF1Origin dialects) records descriptionTyped)
  CreatePPF2 -> do
    -- The validation block lives on 'contentsValidation' regardless
    -- of source: 'buildContents' extracts it from source bytes for the
    -- create path; the parse path carries it across from a PPF2 source
    -- patch, where PPF2's wire format mandates the block so it is
    -- always present. Absent here therefore means the create path's
    -- source ROM was too short to supply one.
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
                           descriptionTyped
                           sourceSize
                           (PPF2ValidationBlock validationBytes)
        case effectiveFileIdDiz meta contents of
          Nothing  -> Right ppf2Result
          Just diz -> do
            fid <- narrowPPF2FileId diz
            let (trailerBytes, trailerAdvisories) = PPF2.encodeFileIdDiz fid
            Right ppf2Result
              { resultBytes = PatchFileContents
                  (unPatchFileContents (resultBytes ppf2Result) <> trailerBytes)
              , resultAdvisories = resultAdvisories ppf2Result ++ trailerAdvisories
              }
  CreatePPF3 -> do
    records <- narrow (splitHunks ppf3MaxRecordPayload (contentsRecords contents))
    undoEncoded <- traverse (first NarrowingError . narrowUndoHunks ppf3Limits)
                            (contentsUndoData contents)
    let ppfResult   = PPF3.encodePPF3 records descriptionTyped undoEncoded
                        (fmap PPF3ValidationBlock (contentsValidation contents))
                        imageType
    case effectiveFileIdDiz meta contents of
      Nothing  -> Right ppfResult
      Just diz -> do
        fid <- narrowPPF3FileId diz
        let (trailerBytes, trailerAdvisories) = PPF3.encodeFileIdDiz fid
        Right ppfResult
          { resultBytes = PatchFileContents
              (unPatchFileContents (resultBytes ppfResult) <> trailerBytes)
          , resultAdvisories = resultAdvisories ppfResult ++ trailerAdvisories
          }
  CreatePPF4 -> do
    -- PPF4's two phases come from where each hunk falls relative to the
    -- source's length: hunks within @[0, sourceLength)@ overwrite source
    -- bytes (Replace records), hunks at or past @sourceLength@ extend the
    -- file (Append records). This split is valid only because these
    -- hunks were produced by 'diffHunks' against this very source — the
    -- create and @--with@-convert paths. Source-less convert to PPF4 is
    -- refused upstream in 'convertDirect', because its records' offsets
    -- are relative to a source we don't hold and so can't be split.
    let (replaceHunks, appendHunks) =
          PPF4.partitionPPF4Phases (byteFileSize (unInputFileContents source))
                                   (contentsRecords contents)
    -- Replace offsets are bounded ('encodingLimits' supplies 'ppf4Limits'),
    -- so 'narrow' validates them. Append records carry no offset, so they
    -- skip narrowing entirely — splitting caps their payloads at the
    -- single-byte count, and 'PPF4Append' wraps the bare payload.
    replaceRecords <- narrow (splitHunks ppf4MaxRecordPayload replaceHunks)
    let appendRecords = map (PPF4Append . splitPayload)
                            (splitHunks ppf4MaxRecordPayload appendHunks)
    Right (PPF4.encodePPF4 replaceRecords appendRecords)
  CreateNINJA1 -> do
    resolvedRaw <- NINJA1.resolveSentinelCollisions LabelNINJA1
                     NINJA1.ninja1SentinelOffset source
                     (splitHunksUnbounded (contentsRecords contents))
    -- 'splitHunksUnbounded' skips only the payload cap; 'narrow' still checks the offset.
    records <- narrow (splitHunksUnbounded resolvedRaw)
    let crc      = fromMaybe (CRC32 0) (contentsSourceCRC32 contents)
        md5Hash  = fromMaybe (MD5Hash  (ByteString.replicate 16 0)) (contentsSourceMD5 contents)
        sha1Hash = fromMaybe (SHA1Hash (ByteString.replicate 20 0)) (contentsSourceSHA1 contents)
    Right (CreateResult (NINJA1.encodeNINJA1 records crc md5Hash sha1Hash ninja1Type
             (fromMaybe NINJA1Uncompressed (contentsNINJA1Compression contents))) platformAdvisories)
  CreatePMSR -> do
    count   <- narrowPMSRRecordCount (length (contentsRecords contents))
    records <- narrow (splitHunks pmsrMaxRecordPayload (contentsRecords contents))
    Right (CreateResult (PMSR.encodePMSR count records) [])
  CreateAPSN64 -> do
    records <- narrow (splitHunks APSN64.apsN64MaxChunkSize (contentsRecords contents))
    case contentsDestinationSize contents of
      Just targetSize -> do
        destinationSize <- APSN64.narrowAPSN64DestinationSize targetSize
        Right (APSN64.encodeAPSN64 records destinationSize apsDescription)
      Nothing -> Left (MissingRequiredField LabelAPSN64 FieldDestinationSize)
  where
    narrow :: [SplitHunk] -> Either SlapError [EncodedHunk]
    narrow = first NarrowingError . narrowHunks limits
    resolveIPSSentinel :: FormatLabel -> IPSVariant -> [SplitHunk]
                       -> Either SlapError [Hunk]
    resolveIPSSentinel label variant =
      IPS.resolveSentinelCollisions label
        (SentinelOffset (ipsVariantSentinel (variantSpec variant)))
        source
    cliDescription   = requestedDescription meta
    cliTitle  = requestedTitle meta
    cliAuthor = requestedAuthor meta
    -- The shared description resolver returns a typed 'EncodedText'
    -- that every direct format consumes without further unwrapping.
    descriptionTyped = resolveDescription DescriptionSources
      { descriptionSourceCLI       = cliDescription
      , descriptionSourceEBPMetadata   = contentsEBPMetadata contents
      , descriptionSourceTypedText = contentsDescription contents
      , descriptionSourceFallback  = EncodedText EncodingUtf8 Text.empty
      }
    -- APSN64's description padding belongs to the format encoder
    -- ('Slap.APSN64.Create.padDescription', which space-pads to 50 bytes),
    -- so the fallback here is just empty 'EncodedText'.
    apsDescription = resolveDescription DescriptionSources
      { descriptionSourceCLI       = cliDescription
      , descriptionSourceEBPMetadata   = Nothing
      , descriptionSourceTypedText = contentsDescription contents
      , descriptionSourceFallback  = EncodedText EncodingUtf8 Text.empty
      }
    ebpSource = contentsEBPMetadata contents
    ebpTitle  = resolveEBPField cliTitle  (ebpSource >>= ebpMetadataTitle)
    ebpAuthor = resolveEBPField cliAuthor (ebpSource >>= ebpMetadataAuthor)
    -- CLI flag > PatchContents > format default
    (ninja1Type, platformAdvisories) = maybe (NINJA1.RomRAW, []) platformToNINJA1 (requestedRomType meta <|> contentsRomType contents)
    imageType   = fromMaybe BIN (requestedImageType meta <|> contentsImageType contents)

----------------------------------------------------------------------------
-- Create
----------------------------------------------------------------------------

-- | The dynamic create entry point: dispatches on 'CreateFormat' to the
-- direct pipeline (universal 'PatchContents' assembly, then 'encodeDirect')
-- or to the appropriate per-format differential creator. The optional
-- 'PatchContents' carries structural data from the source patch (EBP JSON,
-- File_ID.diz, NINJA1 compression flag) for inheritance in
-- the @--with@ conversion path.
--
-- The 'Maybe' 'ResolvedXDelta1FileNames' is the porcelain's resolved
-- pair of xdelta1 file names: it is 'Just' exactly when the target
-- is xdelta1 (the resolution runs in 'app\/Main.hs' via
-- 'Slap.XDelta1.Types.resolveXDelta1FileNames' or
-- 'requireXDelta1FileNames' before this entry point is called).
-- Non-xdelta1 arms ignore it.
-- The xdelta1 arm pattern-matches and turns a 'Nothing' into a typed 'XDelta1ConvertRequiresNames' refusal rather than an 'error' crash.
createPatch :: CreateFormat
            -> Maybe ResolvedXDelta1FileNames
            -> InputFileContents -> OutputFileContents
            -> RequestedPatchMetadata -> Maybe PatchContents
            -> RequestedConstraints -> RequestedDialects
            -> Either SlapError CreateResult
createPatch (CreateDirect format) _resolvedNames source target meta sourceContents constraints dialects = do
  rejectIncompatibleSizeChange format
    (byteFileSize (unInputFileContents  source))
    (byteFileSize (unOutputFileContents target))
  let contents = buildContents format source target meta sourceContents
  encodeDirect contents source format meta (encodingLimits format) constraints dialects
createPatch (CreateDifferential format) maybeResolvedNames source target meta _sourceContents _constraints _dialects = case format of
  -- The constraints parameter is unused on the differential arm:
  -- 'acceptedConstraints' is empty for every 'CreateDifferential'
  -- format, and a requested constraint is rejected upstream by
  -- 'rejectIncompatibleConstraints' before this arm runs. It stays in
  -- the signature for shape-symmetry with the direct arm.
  CreateBPS    -> BPS.createBPS source target (fromMaybe ByteString.empty (requestedEmbeddedBlob meta))
  CreateUPS    -> UPS.createUPS source target
  CreateDPS    -> DPS.createDPS source target
                    (DPS.DPSCreateMetadata
                      { DPS.dpsCreateMetadataName    = fromMaybe emptyEncodedText (requestedTitle meta)
                      , DPS.dpsCreateMetadataAuthor  = fromMaybe emptyEncodedText (requestedAuthor meta)
                      , DPS.dpsCreateMetadataVersion = fromMaybe emptyEncodedText (requestedVersion meta)
                      })
                    (maybe DPS.DPSStable stabilityToDPS (requestedStability meta))
  CreateNINJA2 -> do
    -- Pick the wire @PATCH_ENC@ byte for the output patch.
    -- The CLI flag wins outright; otherwise UTF-8, the portable default (the field bytes are written UTF-8 regardless, so a UTF-8 declaration matches the bytes).
    let detectedTextMode = fromMaybe TextModeUTF8 (requestedTextMode meta)
        ninja2Meta = NINJA2.NINJA2CreateMetadata
          { NINJA2.ninja2CreateMetadataAuthor      = requestedAuthor      meta
          , NINJA2.ninja2CreateMetadataVersion     = requestedVersion     meta
          , NINJA2.ninja2CreateMetadataTitle       = requestedTitle       meta
          , NINJA2.ninja2CreateMetadataGenre       = requestedGenre       meta
          , NINJA2.ninja2CreateMetadataLanguage    = requestedLanguage    meta
          , NINJA2.ninja2CreateMetadataDate        = requestedDate        meta
          , NINJA2.ninja2CreateMetadataWebsite     = requestedWebsite     meta
          , NINJA2.ninja2CreateMetadataDescription = requestedDescription meta
          , NINJA2.ninja2CreateTextMode           = detectedTextMode
          , NINJA2.ninja2CreateMetadataPlatform    = requestedRomType     meta
          }
    NINJA2.createNINJA2 source target ninja2Meta
  CreateAPSGBA  -> APSGBA.createAPSGBA source target
  CreateGDIFF   -> GDIFF.createGDIFF source target
  CreateBSDiff  -> BSDiff.createBSDiff source target
  CreateRFCVCDIFF ->
    VCDIFF.createRFCVCDIFF
      (maybe OneWholeTargetWindow SlicedIntoWindows (requestedWindowSize meta))
      source target
  CreateXDelta3 -> do
    compressionEmission <- xdelta3CompressionEmission meta
    VCDIFF.createXDelta3 verificationChoice compressionEmission windowChoice (requestedEmbeddedBlob meta) source target
    where
      verificationChoice = fromMaybe IncludeVerification (requestedVerificationInclusion meta)
      windowChoice       = fromMaybe defaultXDelta3WindowSize (requestedWindowSize meta)
  CreateXDelta1 -> case maybeResolvedNames of
    Just resolvedNames ->
      XDelta1.createXDelta1 verificationChoice compressionChoice resolvedNames source target
    -- The 'Nothing' branch gives a typed refusal when no resolver ran upstream.
    -- 'LabelXDelta1' as the "source" label is the truthful answer: there is no convert-source format in scope,
    -- so the rendered message reads as a refusal rather than a crash.
    Nothing -> Left (XDelta1ConvertRequiresNames LabelXDelta1)
    where
      verificationChoice = fromMaybe IncludeVerification (requestedVerificationInclusion meta)
      compressionChoice  = fromMaybe IncludeCompression  (requestedPatchCompression     meta)

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
  -- The block occupies [validationOffset, validationOffset + 1024), so a source ending exactly at validationOffset + 1024 supplies it whole: the bound is '>=', not '>'.
  -- The same sum is the minimum 'SourceTooSmallForPPF2Validation' enforces in 'encodeDirect', so '>=' keeps this in step with what that encoder accepts.
  , contentsValidation  = if needs FieldValidation && ByteString.length source >= validationOffset + 1024
                    then Just (ByteString.take 1024 (ByteString.drop validationOffset source))
                    else Nothing
  , contentsUndoData    = if needs FieldUndoData
                    then Just (splitUndoHunks ppf3MaxRecordPayload source patchHunks)
                    else Nothing
  -- The truncated target size when @target < source@.
  -- Not the shrinkage-refusal path: that is 'rejectIncompatibleSizeChange' and each format's '<format>RejectIncompatibleSizeChange' checker.
  , contentsTruncation  = if ByteString.length target < ByteString.length source
                    then Just (byteFileSize target)
                    else Nothing
  -- Structural inheritance: preserve format-specific data from the source patch
  , contentsEBPMetadata      = sourceContents >>= contentsEBPMetadata
  , contentsFileIdDiz        = sourceContents >>= contentsFileIdDiz
  , contentsNINJA1Compression = sourceContents >>= contentsNINJA1Compression
  , contentsAPSN64ImageFormat = sourceContents >>= contentsAPSN64ImageFormat
  , contentsRomType     = Nothing
  , contentsImageType   = Nothing
  , contentsMetadata    = Nothing
  }
  where
    patchHunks = case format of
      CreateIPS    -> ipsHunks Offset24
      CreateIPS32  -> ipsHunks Offset32
      CreateEBP    -> ipsHunks Offset24
      CreatePPF1   -> diffHunks inputFileContents outputFileContents
      CreatePPF2   -> diffHunks inputFileContents outputFileContents
      CreatePPF3   -> diffHunks inputFileContents outputFileContents
      CreatePPF4   -> diffHunks inputFileContents outputFileContents
      CreateNINJA1 -> diffHunks inputFileContents outputFileContents
      CreatePMSR   -> diffHunks inputFileContents outputFileContents
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
      CreatePPF4   -> source
      CreateNINJA1 -> NINJA1.ninja1HashInput source
      CreatePMSR   -> source
      CreateAPSN64 -> source
    validationOffset = unOffset (ppf3ValidationOffset (fromMaybe BIN (requestedImageType meta)))
    undoChoice         = fromMaybe IncludeUndoData     (requestedUndoInclusion         meta)
    verificationChoice = fromMaybe IncludeVerification (requestedVerificationInclusion meta)
    contract           = directConversionContract format undoChoice verificationChoice
    allFields = contractRequiredFields contract `Set.union` contractAcceptedFields contract
    needs field = field `Set.member` allFields

----------------------------------------------------------------------------
-- Internal helpers
----------------------------------------------------------------------------

-- | Sources for 'resolveDescription' to consider, in priority order:
-- CLI flag wins over EBP metadata, EBP metadata wins over typed
-- source description, source wins over fallback.
data DescriptionSources = DescriptionSources
  { descriptionSourceCLI       :: !(Maybe EncodedText)
  , descriptionSourceEBPMetadata   :: !(Maybe EBPMetadata)
  , descriptionSourceTypedText :: !(Maybe EncodedText)
  , descriptionSourceFallback  :: !EncodedText
  }

-- | The typed value travels end-to-end,
-- so the format-specific encoder can route a re-encode through the tag the source declared:
-- UTF-8 for EBP JSON, the chosen metadata encoding for fields whose format leaves the encoding undeclared.
resolveDescription :: DescriptionSources -> EncodedText
resolveDescription sources
  | Just description <- descriptionSourceCLI sources = description
  | Just ebp <- descriptionSourceEBPMetadata sources
  , Just description <- ebpMetadataDescription ebp
  , not (Text.null (encodedTextContent description))
  = description
  | Just typed <- descriptionSourceTypedText sources = typed
  | otherwise = descriptionSourceFallback sources

-- | Resolve a single EBP field: the CLI flag wins, then the value from the EBP metadata view, then the empty string.
-- The two callers feed in the title and author fields.
-- Every arm is 'EncodedText' tagged 'EncodingUtf8', matching the JSON the consumer ('IPS.buildEBPMetadataJSON') emits (JSON is UTF-8 by spec).
resolveEBPField :: Maybe EncodedText -> Maybe EncodedText -> EncodedText
resolveEBPField cliValue ebpValue
  | Just provided <- cliValue  = provided
  | Just value    <- ebpValue  = value
  | otherwise                  = EncodedText EncodingUtf8 Text.empty

-- | The @patcher@ field slap writes into every EBP metadata blob it emits: the project's name, tagged 'EncodingUtf8'.
-- A named constant rather than inlined at the one call site, so the bytes that identify a slap-emitted EBP have a single home.
slapPatcherIdentity :: EncodedText
slapPatcherIdentity = EncodedText EncodingUtf8 (Text.pack "slap")

----------------------------------------------------------------------------
-- Format metadata
----------------------------------------------------------------------------

-- | Whether a create-format token is advertised in help text ('Canonical') or accepted quietly ('Alias').
data TokenVisibility = Canonical | Alias

-- | Source of truth for slap's create-format tokens, shared by the CLI parser, the advertised help list,
-- and the test harness's spec files — one table, so what the parser accepts, what we tell users to type,
-- and what a spec row may name cannot drift apart.
-- Tokens are 'String' because both consumers are 'String' seams: optparse argv and spec-file lines.
createFormatTokens :: [(String, CreateFormat, TokenVisibility)]
createFormatTokens =
  [ ("bps",     CreateDifferential CreateBPS,    Canonical)
  , ("ips",     CreateDirect       CreateIPS,    Canonical)
  , ("ips32",   CreateDirect       CreateIPS32,  Canonical)
  , ("ebp",     CreateDirect       CreateEBP,    Canonical)
  , ("ups",     CreateDifferential CreateUPS,    Canonical)
  , ("ppf1",    CreateDirect       CreatePPF1,   Canonical)
  , ("ppf2",    CreateDirect       CreatePPF2,   Canonical)
  , ("ppf3",    CreateDirect       CreatePPF3,   Canonical)
  , ("ppf4",    CreateDirect       CreatePPF4,   Canonical)
  , ("ppf",     CreateDirect       CreatePPF3,   Alias)
  , ("pmsr",    CreateDirect       CreatePMSR,   Canonical)
  , ("ninja1",  CreateDirect       CreateNINJA1, Canonical)
  , ("dps",     CreateDifferential CreateDPS,    Canonical)
  , ("ninja2",  CreateDifferential CreateNINJA2, Canonical)
  , ("aps-n64", CreateDirect       CreateAPSN64, Canonical)
  , ("apsn64",  CreateDirect       CreateAPSN64, Alias)
  , ("aps-gba", CreateDifferential CreateAPSGBA, Canonical)
  , ("apsgba",  CreateDifferential CreateAPSGBA, Alias)
  , ("gdiff",   CreateDifferential CreateGDIFF,  Canonical)
  , ("bsdiff",  CreateDifferential CreateBSDiff, Canonical)
  , ("xdelta1", CreateDifferential CreateXDelta1, Canonical)
  , ("rfc-vcdiff", CreateDifferential CreateRFCVCDIFF, Canonical)
  , ("xdelta3", CreateDifferential CreateXDelta3, Canonical)
    -- A bare .xdelta in the wild is essentially always xdelta3's, so the bare alias follows it.
  , ("xdelta",  CreateDifferential CreateXDelta3, Alias)
  ]

-- | The tokens users are told about: the 'Canonical' rows, in table order.
advertisedCreateFormats :: [String]
advertisedCreateFormats =
  [token | (token, _format, Canonical) <- createFormatTokens]

-- | The 'CreateFormat' a token names, matched case-insensitively; 'Nothing' for a token outside the table.
lookupCreateFormatToken :: String -> Maybe CreateFormat
lookupCreateFormatToken input =
  lookup (map toLower input)
         [(token, format) | (token, format, _visibility) <- createFormatTokens]

formatExtension :: CreateFormat -> String
formatExtension (CreateDirect format) = directExtension format
formatExtension (CreateDifferential format) = differentialExtension format

formatName :: CreateFormat -> Text.Text
formatName (CreateDirect format) = directName format
formatName (CreateDifferential format) = differentialName format

-- | Per-format metadata used by 'Slap.Convert's wrapper functions and
-- by error-construction sites that need to tag errors with the
-- offending format. Both 'directFormatInfo' and 'differentialFormatInfo'
-- return this same shape; the type-level distinction between
-- 'DirectCreate' and 'DifferentialCreate' lives at the input.
--
-- 'formatInfoExtension' stays 'String' because it threads through
-- 'System.FilePath.replaceExtension'; 'formatInfoName' is display
-- text and is typed 'Text'.
data FormatInfo = FormatInfo
  { formatInfoExtension :: String
  , formatInfoName      :: Text.Text
  , formatInfoLabel     :: FormatLabel
  }

directFormatInfo :: DirectCreate -> FormatInfo
directFormatInfo CreateIPS    = FormatInfo ".ips"    "IPS"       LabelIPS
directFormatInfo CreateIPS32  = FormatInfo ".ips"    "IPS32"     LabelIPS32
directFormatInfo CreateEBP    = FormatInfo ".ebp"    "EBP"       LabelEBP
directFormatInfo CreatePPF1   = FormatInfo ".ppf"    "PPF1"      LabelPPF1
directFormatInfo CreatePPF2   = FormatInfo ".ppf"    "PPF2"      LabelPPF2
directFormatInfo CreatePPF3   = FormatInfo ".ppf"    "PPF3"      LabelPPF3
directFormatInfo CreatePPF4   = FormatInfo ".ppf"    "PPF4"      LabelPPF4
directFormatInfo CreateNINJA1 = FormatInfo ".rup"    "NINJA1"    LabelNINJA1
directFormatInfo CreatePMSR   = FormatInfo ".pmsr"   "PMSR"      LabelPMSR
directFormatInfo CreateAPSN64 = FormatInfo ".aps"    "APS (N64)" LabelAPSN64

differentialFormatInfo :: DifferentialCreate -> FormatInfo
differentialFormatInfo CreateBPS     = FormatInfo ".bps"     "BPS"       LabelBPS
differentialFormatInfo CreateUPS     = FormatInfo ".ups"     "UPS"       LabelUPS
differentialFormatInfo CreateDPS     = FormatInfo ".dps"     "DPS"       LabelDPS
differentialFormatInfo CreateNINJA2  = FormatInfo ".rup"     "NINJA2"    LabelNINJA2
differentialFormatInfo CreateAPSGBA  = FormatInfo ".aps"     "APS (GBA)" LabelAPSGBA
differentialFormatInfo CreateGDIFF   = FormatInfo ".gdiff"   "GDIFF"     LabelGDIFF
differentialFormatInfo CreateBSDiff  = FormatInfo ".bsdiff"  "BSDiff"    LabelBSDiff
differentialFormatInfo CreateXDelta1 = FormatInfo ".xdelta1" "XDelta1"   LabelXDelta1
differentialFormatInfo CreateRFCVCDIFF = FormatInfo ".rfc-vcdiff" "VCDIFF" LabelVCDIFF
differentialFormatInfo CreateXDelta3   = FormatInfo ".xdelta"      "xdelta3" LabelVCDIFF

directExtension :: DirectCreate -> String
directExtension = formatInfoExtension . directFormatInfo

directName :: DirectCreate -> Text.Text
directName = formatInfoName . directFormatInfo

directLabel :: DirectCreate -> FormatLabel
directLabel = formatInfoLabel . directFormatInfo

differentialExtension :: DifferentialCreate -> String
differentialExtension = formatInfoExtension . differentialFormatInfo

differentialName :: DifferentialCreate -> Text.Text
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
