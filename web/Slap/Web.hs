-- | The boundary a browser front end talks to: what @app/Main.hs@ orchestrates, minus argv and the filesystem,
-- handing structured answers up instead of rendered text. Glue only — every rule it appears to know, it is asking the engine for.
module Slap.Web
  ( -- * What exists
    Surface(..)
  , FormatDescription(..)
  , ConsoleHeaderDescription(..)
  , describeSurface
  , DroppedFileClass(..)
  , classifyDroppedFile
  , PatchIdentity(..)
  , UndoAnswer(..)
  , identifyPatch
  , RomFacts(..)
  , describeRom
    -- * Ask, then do
  , MatchedRom(..)
  , CreateRequest(..)
  , ConvertRequest(..)
  , Verdict(..)
  , Gap(..)
  , Resolution(..)
  , checkCreate
  , checkConvert
  ) where

import Data.List.NonEmpty (NonEmpty(..))
import qualified Data.List.NonEmpty as NonEmpty
import Data.Maybe (catMaybes)
import Data.Set (Set)
import qualified Data.Set as Set
import Data.Text (Text)

import Slap.Binary (md5, sha1)
import Slap.Checksum (CRC32, MD5Hash, SHA1Hash)
import Slap.Constraint (Constraint)
import Slap.Convert (CreateFormat(..), DifferentialCreate(CreateXDelta1), RequestedConstraints,
                     RequestedDialects, RequestedPatchMetadata(..), TokenVisibility(Canonical),
                     acceptedConstraints, acceptedDialects, acceptedMetadataFields, createFormatTokens,
                     mergeRequestedMetadata, metadataRequests, rejectCrossPlatformRomTypeRetag,
                     rejectIncompatibleConstraints, rejectIncompatibleDialects,
                     rejectIncompatibleMetadataRequests, rejectIncompatibleSizeChange,
                     rejectUnencodableSecondaryCompressor, verdictOnDirectConversion)
import Slap.Detect (DroppedFileClass(..), classifyDroppedFile)
import Slap.Dialect (Dialect)
import Slap.FFI (crc32)
import Slap.FieldName (FieldName(FieldXDelta1FromName, FieldXDelta1ToName))
import Slap.FileContents (InputFileContents(..), OutputFileContents(..), PatchFileContents)
import Slap.FormatLabel (FormatLabel)
import Slap.Header (ConsoleHeader, InputHeaderDirective, consoleHeaderLength, consoleHeaderName,
                    consoleHeaderToken)
import Slap.Measure (FileSize, Length, byteFileSize)
import Slap.MetadataField (MetadataField(..), requestField)
import Slap.PatchField (PatchField)
import Slap.SomePatch (PatchIdentity(..), PatchKind(..), SomePatch, UndoAnswer(..), parseSome,
                       patchExtractedMeta, patchFormat, patchIdentity, patchKind)
import Slap.Status (SlapError(..), SourceRequiredCause(..))
import Slap.Text (AdvertisedEncodingFamily, EncodingName, advertisedEncodings)
import Slap.VCDIFF.SecondaryCompression (secondaryCompressorTokens)
import Slap.Verify (VerificationPolicy)
import Slap.XDelta1.Types (requireXDelta1FileNames, unXDelta1FromName, unXDelta1ToName)

----------------------------------------------------------------------------
-- What exists
----------------------------------------------------------------------------

-- | Everything a front end builds its controls from, read off the engine's own tables so what the page offers cannot drift from what slap accepts.
data Surface = Surface
  { surfaceFormats        :: [FormatDescription]
  , surfaceEncodings      :: [AdvertisedEncodingFamily]
  , surfaceConsoleHeaders :: [ConsoleHeaderDescription]
  }
  deriving (Eq, Show)

data FormatDescription = FormatDescription
  { formatCreateTarget     :: CreateFormat
  , formatToken            :: String
  , formatAcceptedFields   :: Set MetadataField
  , formatConstraints      :: Set Constraint
  , formatSecondaryChoices :: [String]
    -- ^ What @--compress-with@ can choose when this is the target; empty for a format without a secondary compressor.
    -- Per-format rather than one global vocabulary, so a second compressor-bearing format's own algorithms would have a home.
  }
  deriving (Eq, Show)

data ConsoleHeaderDescription = ConsoleHeaderDescription
  { describedConsoleHeader :: ConsoleHeader
  , consoleToken           :: String
  , consoleName            :: Text
  , consoleWidth           :: Length
  }
  deriving (Eq, Show)

describeSurface :: Surface
describeSurface = Surface
  { surfaceFormats        = [describeCreateTarget token target | (token, target, Canonical) <- createFormatTokens]
  , surfaceEncodings      = advertisedEncodings
  , surfaceConsoleHeaders = map describeConsoleHeader [minBound .. maxBound]
  }

describeCreateTarget :: String -> CreateFormat -> FormatDescription
describeCreateTarget token target = FormatDescription
  { formatCreateTarget     = target
  , formatToken            = token
  , formatAcceptedFields   = acceptedMetadataFields target
  , formatConstraints      = acceptedConstraints target
  , formatSecondaryChoices =
      if MetadataSecondaryCompressor `Set.member` acceptedMetadataFields target
        then map fst secondaryCompressorTokens
        else []
  }

describeConsoleHeader :: ConsoleHeader -> ConsoleHeaderDescription
describeConsoleHeader console = ConsoleHeaderDescription
  { describedConsoleHeader = console
  , consoleToken           = consoleHeaderToken console
  , consoleName            = consoleHeaderName console
  , consoleWidth           = consoleHeaderLength console
  }

-- | A dialect axis can change the parse itself ('Slap.Dialect.PPF1OriginAxis' decides how record offsets are read),
-- so identity is a projection of the full parse, never of the magic alone.
identifyPatch :: RequestedDialects -> EncodingName -> PatchFileContents -> Either SlapError PatchIdentity
identifyPatch dialects metadataEncoding patchBytes = patchIdentity <$> parseSome dialects metadataEncoding patchBytes

-- | What a front end shows the moment a rom is chosen, before any patch exists.
data RomFacts = RomFacts
  { romSize  :: FileSize
  , romCRC32 :: CRC32
  , romMD5   :: MD5Hash
  , romSHA1  :: SHA1Hash
  }
  deriving (Eq, Show)

describeRom :: InputFileContents -> RomFacts
describeRom (InputFileContents romBytes) = RomFacts
  { romSize  = byteFileSize romBytes
  , romCRC32 = crc32 romBytes
  , romMD5   = md5 romBytes
  , romSHA1  = sha1 romBytes
  }

----------------------------------------------------------------------------
-- Ask, then do — the emit checks
----------------------------------------------------------------------------

-- Only create and convert have a check, because only they can be teed up and still be impossible.
-- The check produces nothing and is safe to call on every input change; the act is what the button owns.
-- Every refusal the act can raise from the request's own content is judged here;
-- only a refusal derived from the bytes — sentinel collisions, offset overflow, a post-apply size pair — may surface first at the act.

-- | A ROM handed over to be matched against a patch's expectations. The header directive travels with the ROM, not the verb;
-- create's ROMs define the patch rather than match one, so they are plain contents with no field for a directive to live in.
data MatchedRom = MatchedRom
  { matchedRomBytes   :: InputFileContents
  , matchedRomFraming :: InputHeaderDirective
  }
  deriving (Eq, Show)

data CreateRequest = CreateRequest
  { createTargetFormat :: CreateFormat
  , createOriginal     :: InputFileContents
  , createModified     :: OutputFileContents
  , createMetadata     :: RequestedPatchMetadata
  , createConstraints  :: RequestedConstraints
  }

-- No dialect field: the one axis is read-side only and create parses nothing, so an incoherent toggle is unrepresentable rather than refused.

data ConvertRequest = ConvertRequest
  { convertPatchBytes         :: PatchFileContents
  , convertTargetFormat       :: CreateFormat
  , convertSourceRom          :: Maybe MatchedRom      -- ^ the @--with@ lane
  , convertVerificationPolicy :: VerificationPolicy    -- ^ how the act treats a provided source; the check verifies nothing
  , convertMetadata           :: RequestedPatchMetadata
  , convertConstraints        :: RequestedConstraints
  , convertMetadataEncoding   :: EncodingName
  , convertDialects           :: RequestedDialects
  }

data Verdict
  = Ready
  | Blocked (NonEmpty Gap)  -- ^ @Blocked []@ would be representable and meaningless; the 'NonEmpty' closes it
  deriving (Eq, Show)

-- | A reason the emit would be incorrect, beside the amendments that would close it.
-- A gap can close more than one way: handing over the source ROM can dissolve a requirement rather than satisfy it by typing.
data Gap = Gap
  { gapReason      :: SlapError            -- ^ slap's own words; the UI composes no sentence of its own
  , gapResolutions :: NonEmpty Resolution  -- ^ computed, not guessed
  }
  deriving (Eq, Show)

data Resolution
  = ProvideSourceRom
    -- ^ The missing fields can be computed by applying and re-diffing against real bytes.
  | ChooseTargetPreserving PatchField [FormatLabel]
    -- ^ The source carries a field this target cannot hold without changing the applied bytes;
    -- these targets would keep it ('Slap.Convert.preservingDirectTargets' computes them).
  | ChooseDifferentFormat
    -- ^ The size change is beyond this format's wire.
  | DropConstraint Constraint
  | DropMetadataField MetadataField
  | DropDialect Dialect
  | ProvideMetadataField MetadataField
    -- ^ A field only the person can supply: xdelta1's name pair, converting from a source that carries none.
  | AmendMetadataField MetadataField
    -- ^ The field is supplied and refused as given (a name past its wire field's ceiling); a different value closes the gap.
  deriving (Eq, Show)

-- | The one request-content judgment not made here is xdelta1's file-name pair,
-- whose create-side resolution falls back to file names this request does not carry.
checkCreate :: CreateRequest -> Verdict
checkCreate request = verdictOf $ catMaybes
  [ metadataRequestsGap    (createTargetFormat request) (createMetadata request)
  , secondaryCompressorGap (createTargetFormat request) (createMetadata request)
  , constraintsGap         (createTargetFormat request) (createConstraints request)
  , sizeChangeGap          (createTargetFormat request) (createOriginal request) (createModified request)
  ]

-- | A parse failure is the 'Left', never a 'Gap': a gap means the named emit would be incorrect and the request can be amended toward it;
-- a refused parse means no emit was ever named, so there is nothing to negotiate. A source ROM in hand clears the conversion-path gaps.
checkConvert :: ConvertRequest -> Either SlapError Verdict
checkConvert request = do
  parsed <- parseSome (convertDialects request) (convertMetadataEncoding request) (convertPatchBytes request)
  let mergedMeta = mergeRequestedMetadata (convertMetadata request) (patchExtractedMeta parsed)
  pure . verdictOf $ catMaybes
    [ metadataRequestsGap    (convertTargetFormat request) (convertMetadata request)
    , secondaryCompressorGap (convertTargetFormat request) (convertMetadata request)
    , constraintsGap         (convertTargetFormat request) (convertConstraints request)
    , dialectsGap            (patchFormat parsed) (convertDialects request)
    , romTypeRetagGap        (convertMetadata request) (patchExtractedMeta parsed)
    , xdelta1NamesGap        (convertTargetFormat request) (patchFormat parsed) mergedMeta
    , conversionPathGap      request parsed mergedMeta
    ]

verdictOf :: [Gap] -> Verdict
verdictOf = maybe Ready Blocked . NonEmpty.nonEmpty

-- | Each judgment's engine function refuses within a documented vocabulary;
-- a constructor from outside it is a broken contract, answered loudly rather than absorbed into a guessed resolution.
refusalOutsideJudgmentVocabulary :: SlapError -> a
refusalOutsideJudgmentVocabulary refusal =
  error ("Slap.Web: a check's judgment refused outside its vocabulary: " <> show refusal)

metadataRequestsGap :: CreateFormat -> RequestedPatchMetadata -> Maybe Gap
metadataRequestsGap target meta =
  case rejectIncompatibleMetadataRequests target (metadataRequests meta) of
    Right () -> Nothing
    Left refusal@(MetadataFieldRejected rejectedRequests _) ->
      Just (Gap refusal (NonEmpty.map (DropMetadataField . requestField) rejectedRequests))
    Left foreignRefusal -> refusalOutsideJudgmentVocabulary foreignRefusal

-- | Dropping the selection resolves the refusal: the fallback is LZMA, which slap encodes with.
secondaryCompressorGap :: CreateFormat -> RequestedPatchMetadata -> Maybe Gap
secondaryCompressorGap target meta =
  case rejectUnencodableSecondaryCompressor target meta of
    Right () -> Nothing
    Left refusal -> Just (Gap refusal (DropMetadataField MetadataSecondaryCompressor :| []))

constraintsGap :: CreateFormat -> RequestedConstraints -> Maybe Gap
constraintsGap target constraints =
  case rejectIncompatibleConstraints target constraints of
    Right () -> Nothing
    Left refusal@(ConstraintNotSupported rejectedConstraints _) ->
      Just (Gap refusal (NonEmpty.map DropConstraint rejectedConstraints))
    Left foreignRefusal -> refusalOutsideJudgmentVocabulary foreignRefusal

sizeChangeGap :: CreateFormat -> InputFileContents -> OutputFileContents -> Maybe Gap
sizeChangeGap (CreateDifferential _) _ _ = Nothing
sizeChangeGap (CreateDirect target) (InputFileContents originalBytes) (OutputFileContents modifiedBytes) =
  case rejectIncompatibleSizeChange target (byteFileSize originalBytes) (byteFileSize modifiedBytes) of
    Right () -> Nothing
    Left refusal -> Just (Gap refusal (ChooseDifferentFormat :| []))

dialectsGap :: FormatLabel -> RequestedDialects -> Maybe Gap
dialectsGap sourceFormat dialects =
  case rejectIncompatibleDialects (acceptedDialects sourceFormat) sourceFormat dialects of
    Right () -> Nothing
    Left refusal@(DialectNotSupported rejectedAxes _) ->
      Just (Gap refusal (NonEmpty.map DropDialect rejectedAxes))
    Left foreignRefusal -> refusalOutsideJudgmentVocabulary foreignRefusal

-- | Dropping the ROM-type request leaves the source patch's own platform in charge, which is never a retag.
romTypeRetagGap :: RequestedPatchMetadata -> RequestedPatchMetadata -> Maybe Gap
romTypeRetagGap requestMeta extractedMeta =
  case rejectCrossPlatformRomTypeRetag requestMeta extractedMeta of
    Right () -> Nothing
    Left refusal -> Just (Gap refusal (DropMetadataField MetadataRomType :| []))

xdelta1NamesGap :: CreateFormat -> FormatLabel -> RequestedPatchMetadata -> Maybe Gap
xdelta1NamesGap (CreateDifferential CreateXDelta1) sourceFormat mergedMeta =
  case requireXDelta1FileNames mergedFromName mergedToName sourceFormat of
    Right _ -> Nothing
    Left refusal@(XDelta1ConvertRequiresNames _) -> Just (Gap refusal provideEachMissingName)
    Left refusal@(FieldTooLong _ FieldXDelta1FromName _ _) ->
      Just (Gap refusal (AmendMetadataField MetadataXDelta1FromName :| []))
    Left refusal@(FieldTooLong _ FieldXDelta1ToName _ _) ->
      Just (Gap refusal (AmendMetadataField MetadataXDelta1ToName :| []))
    Left foreignRefusal -> refusalOutsideJudgmentVocabulary foreignRefusal
  where
    mergedFromName = unXDelta1FromName <$> requestedXDelta1FromName mergedMeta
    mergedToName   = unXDelta1ToName   <$> requestedXDelta1ToName   mergedMeta
    provideEachMissingName = case (mergedFromName, mergedToName) of
      (Nothing, Nothing) -> ProvideMetadataField MetadataXDelta1FromName :| [ProvideMetadataField MetadataXDelta1ToName]
      (Nothing, Just _)  -> ProvideMetadataField MetadataXDelta1FromName :| []
      (Just _,  Nothing) -> ProvideMetadataField MetadataXDelta1ToName :| []
      (Just _,  Just _)  -> error "Slap.Web: requireXDelta1FileNames demanded names that are both present"
xdelta1NamesGap _ _ _ = Nothing

conversionPathGap :: ConvertRequest -> SomePatch -> RequestedPatchMetadata -> Maybe Gap
conversionPathGap request parsed mergedMeta = case convertSourceRom request of
  Just _  -> Nothing
  Nothing -> case patchKind parsed of
    Direct (Just contents) ->
      case verdictOnDirectConversion contents (convertTargetFormat request) mergedMeta of
        Right _ -> Nothing
        Left refusal -> Just (Gap refusal (directConversionResolutions refusal))
    Direct Nothing -> Just (sourceRequiredGap SourcePatchNotReencodable)
    Differential   -> Just (sourceRequiredGap SourcePatchIsDifferential)
  where
    sourceRequiredGap cause =
      Gap (ConvertRequiresSource (patchFormat parsed) cause) (ProvideSourceRom :| [])

directConversionResolutions :: SlapError -> NonEmpty Resolution
directConversionResolutions refusal = case refusal of
  DiffRequiresSource _        -> ProvideSourceRom :| []
  PPF4ConvertRequiresSource _ -> ProvideSourceRom :| []
  MissingRequiredFields _ _   -> ProvideSourceRom :| []
  ApplyOutputFieldsWouldBeDropped _ droppedPairs ->
    NonEmpty.prependList
      [ChooseTargetPreserving field preservers | (field, preservers) <- droppedPairs]
      (ProvideSourceRom :| [])
  _ -> refusalOutsideJudgmentVocabulary refusal
