{-# LANGUAGE DerivingVia #-}

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
  , ApplyRequest(..)
  , UndoRequest(..)
  , SourceReport(..)
  , HeaderRescueCandidate(..)
  , checkApply
  , checkUndo
  , PatchedRom(..)
  , RevertedRom(..)
  , VerdictStanding(..)
  , applyPatch
  , undoPatch
  , CreateRequest(..)
  , ConvertRequest(..)
  , Verdict(..)
  , Gap(..)
  , Resolution(..)
  , checkCreate
  , checkConvert
  , CreatedPatch(..)
  , createPatch
  , convertPatch
    -- * Read
  , InspectRequest(..)
  , PatchInfo
  , inspectPatch
  , AnalyzeRequest(..)
  , PatchExplanation(..)
  , PatchAnalysis
  , analyzePatch
  ) where

import Data.Aeson (ToJSON)
import Data.List.NonEmpty (NonEmpty(..))
import qualified Data.List.NonEmpty as NonEmpty
import Data.Maybe (catMaybes)
import Data.Set (Set)
import qualified Data.Set as Set
import Data.Text (Text)
import GHC.Generics (Generic, Generically(..))

import Slap.Binary (md5, sha1)
import Slap.Checksum (CRC32, MD5Hash, SHA1Hash)
import Slap.Constraint (Constraint)
import Slap.Convert (CreateFormat(..), DifferentialCreate(CreateXDelta1),
                     RequestedConstraints, RequestedDialects, RequestedPatchMetadata(..),
                     TokenVisibility(Canonical), acceptedConstraints, acceptedDialects,
                     acceptedMetadataFields, convertDirect, createDefaultAdvisories,
                     createFormatTokens, mergeRequestedMetadata, metadataRequests,
                     noDialectsRequested, rejectCrossPlatformRomTypeRetag,
                     rejectIncompatibleConstraints, rejectIncompatibleDialects,
                     rejectIncompatibleMetadataRequests, rejectIncompatibleSizeChange,
                     rejectUnencodableSecondaryCompressor, verdictOnDirectConversion)
import qualified Slap.Create as Create
import Slap.Detect (DroppedFileClass(..), classifyDroppedFile)
import Slap.Dialect (Dialect)
import Slap.Display.Analysis (PatchAnalysis)
import Slap.Display.Info (InputSideVerdict(..), OutputSideVerdict(..), PatchInfo)
import Slap.FFI (crc32)
import Slap.FieldName (FieldName(FieldXDelta1FromName, FieldXDelta1ToName))
import Slap.FileContents (InputFileContents(..), OutputFileContents(..), PatchFileContents)
import Slap.FormatLabel (FormatLabel)
import Slap.Header (ConsoleHeader, InputHeaderDirective, consoleHeaderLength,
                    consoleHeaderName, consoleHeaderToken)
import Slap.Apply (PatchedRom(..), VerdictStanding(..), runPreparedApply)
import Slap.Measure (FileSize, Length, byteFileSize)
import Slap.MetadataField (MetadataField(..), requestField)
import Slap.PatchField (PatchField)
import qualified Slap.Preflight as Preflight
import Slap.Preflight (HeaderRescueCandidate(..), PreparedApplySource(..), SourceReport(..),
                       prepareApplySource, weighUndoInput)
import Slap.SomePatch (PatchIdentity(..), PatchKind(..), SomePatch, UndoAnswer(..),
                       UndoAvailability(..), UndoStrategy, parseSome, patchAdvisories,
                       patchAnalysis, patchContentsOf, patchExtractedMeta, patchFormat, patchIdentity,
                       patchInfo, patchKind, patchSourceAdvisories, patchUndo, patchVerification, runUndo)
import Slap.Status (CreateResult(..), Outcome(..), SlapAdvisory, SlapError(..),
                    SourceRequiredCause(..))
import Slap.Text (AdvertisedEncodingFamily, EncodingName(EncodingUtf8), advertisedEncodings)
import Slap.VCDIFF.SecondaryCompression (secondaryCompressorTokens)
import Slap.Verify (VerificationPolicy, VerificationVerdict, Weighing, flipSpokenSides,
                    judgeWeighing, verdictOnWeighing, weighSource)
import Slap.XDelta1.Types (ResolvedXDelta1FileNames, requireXDelta1FileNames,
                           resolveXDelta1FileNames, unXDelta1FromName, unXDelta1ToName)

----------------------------------------------------------------------------
-- What exists
----------------------------------------------------------------------------

-- | Everything a front end builds its controls from, read off the engine's own tables so what the page offers cannot drift from what slap accepts.
data Surface = Surface
  { surfaceFormats        :: [FormatDescription]
  , surfaceEncodings      :: [AdvertisedEncodingFamily]
  , surfaceConsoleHeaders :: [ConsoleHeaderDescription]
  }
  deriving (Eq, Show, Generic)
  deriving (ToJSON) via Generically Surface

data FormatDescription = FormatDescription
  { formatCreateTarget     :: CreateFormat
  , formatToken            :: String
  , formatAcceptedFields   :: Set MetadataField
  , formatConstraints      :: Set Constraint
  , formatSecondaryChoices :: [String]
    -- ^ What @--compress-with@ can choose when this is the target; empty for a format without a secondary compressor.
    -- Per-format rather than one global vocabulary, so a second compressor-bearing format's own algorithms would have a home.
  }
  deriving (Eq, Show, Generic)
  deriving (ToJSON) via Generically FormatDescription

data ConsoleHeaderDescription = ConsoleHeaderDescription
  { describedConsoleHeader :: ConsoleHeader
  , consoleToken           :: String
  , consoleName            :: Text
  , consoleWidth           :: Length
  }
  deriving (Eq, Show, Generic)
  deriving (ToJSON) via Generically ConsoleHeaderDescription

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
-- Ask, then do — apply and undo
----------------------------------------------------------------------------

-- The acts answer in an 'Outcome' so a refusal keeps its narration:
-- whatever the run said before refusing — the reframe's note, normalization's advisories, the rescue's hints — rides beside the 'Left'.

-- | A ROM handed over to be matched against a patch's expectations. The header directive travels with the ROM, not the verb;
-- create's ROMs define the patch rather than match one, so they are plain contents with no field for a directive to live in.
data MatchedRom = MatchedRom
  { matchedRomBytes   :: InputFileContents
  , matchedRomFraming :: InputHeaderDirective
  }
  deriving (Eq, Show)

data ApplyRequest = ApplyRequest
  { applyPatchBytes         :: PatchFileContents
  , applySourceRom          :: MatchedRom
  , applyVerificationPolicy :: VerificationPolicy
  , applyDialects           :: RequestedDialects
  }

data UndoRequest = UndoRequest
  { undoPatchBytes         :: PatchFileContents
  , undoPatchedRom         :: OutputFileContents  -- ^ the file as handed; undo takes no framing directive
  , undoVerificationPolicy :: VerificationPolicy
  , undoDialects           :: RequestedDialects
  }

-- | Parse under the caller's metadata encoding, then judge the same dialect coherence the CLI judges before it does anything else.
-- info and explain carry a chosen encoding because they render metadata; apply and undo render none, so 'parseForRun' pins UTF-8.
parseUnderEncoding :: RequestedDialects -> EncodingName -> PatchFileContents -> Either SlapError SomePatch
parseUnderEncoding dialects metadataEncoding patchBytes = do
  parsed <- parseSome dialects metadataEncoding patchBytes
  rejectIncompatibleDialects (acceptedDialects (patchFormat parsed)) (patchFormat parsed) dialects
  pure parsed

parseForRun :: RequestedDialects -> PatchFileContents -> Either SlapError SomePatch
parseForRun dialects = parseUnderEncoding dialects EncodingUtf8

checkApply :: ApplyRequest -> Either SlapError SourceReport
checkApply request = do
  parsed <- parseForRun (applyDialects request) (applyPatchBytes request)
  Preflight.checkApply parsed (matchedRomFraming (applySourceRom request))
                       (unInputFileContents (matchedRomBytes (applySourceRom request)))

checkUndo :: UndoRequest -> Either SlapError VerificationVerdict
checkUndo request = do
  parsed <- parseForRun (undoDialects request) (undoPatchBytes request)
  pure (Preflight.checkUndo parsed (unOutputFileContents (undoPatchedRom request)))

-- | No standing field: undo neither normalizes nor restores, so its verdicts always describe the files exchanged.
data RevertedRom = RevertedRom
  { revertedRomBytes         :: InputFileContents
  , revertedRomInputVerdict  :: InputSideVerdict
  , revertedRomOutputVerdict :: OutputSideVerdict
  }
  deriving (Eq, Show)

applyPatch :: ApplyRequest -> IO (Outcome (Either SlapError PatchedRom))
applyPatch request = case parseForRun (applyDialects request) (applyPatchBytes request) of
  Left refusal -> pure (Outcome (Left refusal) [])
  Right parsed ->
    case prepareApplySource (applyVerificationPolicy request) parsed directive handedBytes of
      Left refusal   -> pure (Outcome (Left refusal) (patchAdvisories parsed))
      Right prepared -> do
        runOutcome <- runPreparedApply (applyVerificationPolicy request) directive parsed prepared
        pure runOutcome
          { outcomeAdvisories = patchAdvisories parsed ++ preparedAdvisories prepared ++ outcomeAdvisories runOutcome }
  where
    directive   = matchedRomFraming (applySourceRom request)
    handedBytes = unInputFileContents (matchedRomBytes (applySourceRom request))

undoPatch :: UndoRequest -> Outcome (Either SlapError RevertedRom)
undoPatch request = case parseForRun (undoDialects request) (undoPatchBytes request) of
  Left refusal -> Outcome (Left refusal) []
  Right parsed -> case patchUndo parsed of
    UndoBySelfInversion undo -> undoUsing request parsed undo
    UndoFromCarriedData undo -> undoUsing request parsed undo
    UndoAbsentFromPatch      -> Outcome (Left (PatchCarriesNoUndoData (patchFormat parsed))) (patchAdvisories parsed)
    UndoUnsupportedByFormat  -> Outcome (Left (NoUndoForFormat (patchFormat parsed))) (patchAdvisories parsed)

undoUsing :: UndoRequest -> SomePatch -> UndoStrategy -> Outcome (Either SlapError RevertedRom)
undoUsing request parsed undo = case outcomeValue handedJudgment of
  Left refusal -> Outcome (Left refusal) narrationBeforeRun
  Right () -> case runUndo undo (undoPatchedRom request) of
    Left undoRefusal  -> Outcome (Left undoRefusal) narrationBeforeRun
    Right undoOutcome -> judgeRevertedSource request parsed handedWeighing
                           (narrationBeforeRun ++ outcomeAdvisories undoOutcome) (outcomeValue undoOutcome)
  where
    handedWeighing     = weighUndoInput parsed (unOutputFileContents (undoPatchedRom request))
    handedJudgment     = judgeWeighing (undoVerificationPolicy request) handedWeighing
    narrationBeforeRun = patchAdvisories parsed ++ outcomeAdvisories handedJudgment

judgeRevertedSource
  :: UndoRequest -> SomePatch -> Weighing -> [SlapAdvisory] -> InputFileContents
  -> Outcome (Either SlapError RevertedRom)
judgeRevertedSource request parsed handedWeighing narration revertedSource = case outcomeValue revertedJudgment of
  Left refusal -> Outcome (Left refusal) narrated
  Right ()     -> Outcome (Right reverted) narrated
  where
    revertedWeighing = flipSpokenSides (weighSource (patchVerification parsed) revertedSource)
    revertedJudgment = judgeWeighing (undoVerificationPolicy request) revertedWeighing
    narrated = narration ++ outcomeAdvisories revertedJudgment
    reverted = RevertedRom
      { revertedRomBytes         = revertedSource
      , revertedRomInputVerdict  = InputSideVerdict (verdictOnWeighing handedWeighing)
      , revertedRomOutputVerdict = OutputSideVerdict (verdictOnWeighing revertedWeighing)
      }

----------------------------------------------------------------------------
-- Ask, then do — the emit checks
----------------------------------------------------------------------------

-- Only create and convert have a check, because only they can be teed up and still be impossible.
-- The check produces nothing and is safe to call on every input change; the act is what the button owns.
-- Every refusal the act can raise from the request's own content is judged here;
-- only a refusal derived from the bytes — sentinel collisions, offset overflow, a post-apply size pair — may surface first at the act.

data CreateRequest = CreateRequest
  { createTargetFormat :: CreateFormat
  , createOriginal     :: InputFileContents
  , createModified     :: OutputFileContents
  , createOriginalName :: FilePath
    -- ^ The dropped files' own names. xdelta1 embeds a name pair and defaults to these,
    -- as the CLI defaults to its paths' basenames.
  , createModifiedName :: FilePath
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
  deriving (Eq, Show, Generic)
  deriving (ToJSON) via Generically Verdict

-- | A reason the emit would be incorrect, beside the amendments that would close it.
-- A gap can close more than one way: handing over the source ROM can dissolve a requirement rather than satisfy it by typing.
data Gap = Gap
  { gapReason      :: SlapError            -- ^ slap's own words; the UI composes no sentence of its own
  , gapResolutions :: NonEmpty Resolution  -- ^ computed, not guessed
  }
  deriving (Eq, Show, Generic)
  deriving (ToJSON) via Generically Gap

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
  deriving (Eq, Show, Generic)
  deriving (ToJSON) via Generically Resolution

checkCreate :: CreateRequest -> Verdict
checkCreate request = verdictOf $ catMaybes
  [ metadataRequestsGap    (createTargetFormat request) (createMetadata request)
  , secondaryCompressorGap (createTargetFormat request) (createMetadata request)
  , constraintsGap         (createTargetFormat request) (createConstraints request)
  , sizeChangeGap          (createTargetFormat request) (createOriginal request) (createModified request)
  , xdelta1CreateNamesGap  request
  ]

-- | A parse failure is the 'Left', never a 'Gap': a gap means the named emit would be incorrect and the request can be amended toward it;
-- a refused parse means no emit was ever named, so there is nothing to negotiate. A source ROM in hand clears the conversion-path gaps.
checkConvert :: ConvertRequest -> Either SlapError Verdict
checkConvert = fmap judgedVerdict . judgeConvert

-- | What convert's check learns, kept for the act.
data JudgedConvert = JudgedConvert
  { judgedPatch      :: SomePatch
  , judgedMergedMeta :: RequestedPatchMetadata
  , judgedVerdict    :: Verdict
  }

judgeConvert :: ConvertRequest -> Either SlapError JudgedConvert
judgeConvert request = do
  parsed <- parseSome (convertDialects request) (convertMetadataEncoding request) (convertPatchBytes request)
  let mergedMeta = mergeRequestedMetadata (convertMetadata request) (patchExtractedMeta parsed)
  pure JudgedConvert
    { judgedPatch      = parsed
    , judgedMergedMeta = mergedMeta
    , judgedVerdict    = verdictOf $ catMaybes
        [ metadataRequestsGap    (convertTargetFormat request) (convertMetadata request)
        , secondaryCompressorGap (convertTargetFormat request) (convertMetadata request)
        , constraintsGap         (convertTargetFormat request) (convertConstraints request)
        , dialectsGap            (patchFormat parsed) (convertDialects request)
        , romTypeRetagGap        (convertMetadata request) (patchExtractedMeta parsed)
        , xdelta1NamesGap        (convertTargetFormat request) (patchFormat parsed) mergedMeta
        , conversionPathGap      request parsed mergedMeta
        ]
    }

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

xdelta1CreateNamesGap :: CreateRequest -> Maybe Gap
xdelta1CreateNamesGap request = case resolveCreateXDelta1Names request of
  Right _ -> Nothing
  Left refusal@(FieldTooLong _ FieldXDelta1FromName _ _) ->
    Just (Gap refusal (AmendMetadataField MetadataXDelta1FromName :| []))
  Left refusal@(FieldTooLong _ FieldXDelta1ToName _ _) ->
    Just (Gap refusal (AmendMetadataField MetadataXDelta1ToName :| []))
  Left foreignRefusal -> refusalOutsideJudgmentVocabulary foreignRefusal

resolveCreateXDelta1Names :: CreateRequest -> Either SlapError (Maybe ResolvedXDelta1FileNames)
resolveCreateXDelta1Names request = case createTargetFormat request of
  CreateDifferential CreateXDelta1 -> fmap Just $
    resolveXDelta1FileNames
      (unXDelta1FromName <$> requestedXDelta1FromName (createMetadata request))
      (unXDelta1ToName   <$> requestedXDelta1ToName   (createMetadata request))
      (createOriginalName request)
      (createModifiedName request)
  _ -> Right Nothing

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

----------------------------------------------------------------------------
-- Ask, then do — the emit acts
----------------------------------------------------------------------------

data CreatedPatch = CreatedPatch
  { createdPatchBytes  :: PatchFileContents
  , createdPatchFormat :: CreateFormat  -- ^ so the browser can name the download
  }
  deriving (Eq, Show)

-- | Proceeds only on its own check's 'Ready', so the act and the check cannot disagree.
createPatch :: CreateRequest -> Outcome (Either SlapError CreatedPatch)
createPatch request = case checkCreate request of
  Blocked (gap :| _) -> Outcome (Left (gapReason gap)) []
  Ready -> case resolveCreateXDelta1Names request of
    Left refusal -> Outcome (Left refusal) []
    Right resolvedNames ->
      case Create.createPatch (createTargetFormat request) resolvedNames (createOriginal request)
                              (createModified request) (createMetadata request) Nothing
                              (createConstraints request) noDialectsRequested of
        Left refusal -> Outcome (Left refusal) defaultAdvisories
        Right (CreateResult patchBytes createAdvisories) ->
          Outcome (Right (CreatedPatch patchBytes (createTargetFormat request)))
                  (defaultAdvisories ++ createAdvisories)
  where
    defaultAdvisories =
      createDefaultAdvisories (createTargetFormat request) (createMetadata request) (createOriginal request)

-- | IO for the same reason 'applyPatch' is: the @--with@ lane applies the patch before re-diffing.
convertPatch :: ConvertRequest -> IO (Outcome (Either SlapError CreatedPatch))
convertPatch request = case judgeConvert request of
  Left refusal -> pure (Outcome (Left refusal) [])
  Right judged -> case judgedVerdict judged of
    Blocked (gap :| _) -> pure (Outcome (Left (gapReason gap)) [])
    Ready -> case resolveConvertXDelta1Names request judged of
      Left refusal -> pure (Outcome (Left refusal) [])
      Right resolvedNames -> case convertSourceRom request of
        Nothing         -> pure (convertWithoutSource request judged)
        Just matchedRom -> convertApplyAndRecreate request judged resolvedNames matchedRom

resolveConvertXDelta1Names :: ConvertRequest -> JudgedConvert -> Either SlapError (Maybe ResolvedXDelta1FileNames)
resolveConvertXDelta1Names request judged = case convertTargetFormat request of
  CreateDifferential CreateXDelta1 -> fmap Just $
    requireXDelta1FileNames
      (unXDelta1FromName <$> requestedXDelta1FromName (judgedMergedMeta judged))
      (unXDelta1ToName   <$> requestedXDelta1ToName   (judgedMergedMeta judged))
      (patchFormat (judgedPatch judged))
  _ -> Right Nothing

convertWithoutSource :: ConvertRequest -> JudgedConvert -> Outcome (Either SlapError CreatedPatch)
convertWithoutSource request judged = case patchKind parsed of
  Direct (Just contents) ->
    case convertDirect contents (convertTargetFormat request) (judgedMergedMeta judged)
                       (convertConstraints request) noDialectsRequested of
      Left refusal -> Outcome (Left refusal) narration
      Right (CreateResult patchBytes convertAdvisories) ->
        Outcome (Right (CreatedPatch patchBytes (convertTargetFormat request)))
                (narration ++ patchSourceAdvisories parsed ++ convertAdvisories)
  Direct Nothing -> refuseNeedingSource SourcePatchNotReencodable
  Differential   -> refuseNeedingSource SourcePatchIsDifferential
  where
    parsed    = judgedPatch judged
    narration = patchAdvisories parsed
    refuseNeedingSource cause =
      Outcome (Left (ConvertRequiresSource (patchFormat parsed) cause)) narration

convertApplyAndRecreate
  :: ConvertRequest -> JudgedConvert -> Maybe ResolvedXDelta1FileNames -> MatchedRom
  -> IO (Outcome (Either SlapError CreatedPatch))
convertApplyAndRecreate request judged resolvedNames matchedRom =
  case prepareApplySource (convertVerificationPolicy request) parsed (matchedRomFraming matchedRom) handedBytes of
    Left refusal   -> pure (Outcome (Left refusal) (patchAdvisories parsed))
    Right prepared -> do
      runOutcome <- runPreparedApply (convertVerificationPolicy request) (matchedRomFraming matchedRom) parsed prepared
      let narration = patchAdvisories parsed ++ preparedAdvisories prepared ++ outcomeAdvisories runOutcome
      pure $ case outcomeValue runOutcome of
        Left refusal  -> Outcome (Left refusal) narration
        Right patched -> recreateFromApplied request judged resolvedNames prepared patched narration
  where
    parsed      = judgedPatch judged
    handedBytes = unInputFileContents (matchedRomBytes matchedRom)

-- | The re-create diffs the framed source against the restored apply output,
-- reproducing end to end what applying the source patch would really produce.
recreateFromApplied
  :: ConvertRequest -> JudgedConvert -> Maybe ResolvedXDelta1FileNames -> PreparedApplySource -> PatchedRom
  -> [SlapAdvisory]
  -> Outcome (Either SlapError CreatedPatch)
recreateFromApplied request judged resolvedNames prepared patched narration =
  case Create.createPatch (convertTargetFormat request) resolvedNames framedInput
                          (patchedRomBytes patched) (judgedMergedMeta judged) (patchContentsOf parsed)
                          (convertConstraints request) noDialectsRequested of
    Left refusal -> Outcome (Left refusal) narration
    Right (CreateResult patchBytes createAdvisories) ->
      Outcome (Right (CreatedPatch patchBytes (convertTargetFormat request)))
              (narration ++ patchSourceAdvisories parsed
                         ++ createDefaultAdvisories (convertTargetFormat request) (judgedMergedMeta judged) framedInput
                         ++ createAdvisories)
  where
    parsed      = judgedPatch judged
    framedInput = InputFileContents (preparedFramedInput prepared)

----------------------------------------------------------------------------
-- Read
----------------------------------------------------------------------------

-- Neither read has a check: reading is not an emit and cannot be underspecified.
-- A read answers in 'Outcome' rather than a bare 'Either' because a parse can succeed and still warn, and that narration must survive.

data InspectRequest = InspectRequest
  { inspectPatchBytes       :: PatchFileContents
  , inspectMetadataEncoding :: EncodingName
  , inspectDialects         :: RequestedDialects
  }

inspectPatch :: InspectRequest -> Outcome (Either SlapError PatchInfo)
inspectPatch request =
  case parseUnderEncoding (inspectDialects request) (inspectMetadataEncoding request) (inspectPatchBytes request) of
    Left refusal -> Outcome (Left refusal) []
    Right parsed -> Outcome (Right (patchInfo parsed)) (patchAdvisories parsed)

data AnalyzeRequest = AnalyzeRequest
  { analyzePatchBytes       :: PatchFileContents
  , analyzeMetadataEncoding :: EncodingName
  , analyzeDialects         :: RequestedDialects
  }

data PatchExplanation = PatchExplanation
  { explanationInfo     :: PatchInfo
  , explanationAnalysis :: PatchAnalysis
  }
  deriving (Generic)
  deriving (ToJSON) via Generically PatchExplanation

-- | explain is info-plus: one parse yields both, so the page fills the screen with a single read.
-- The structured analysis crosses, not rendered text — the terminal dump and the page's structure bar stay two renderers over one model.
analyzePatch :: AnalyzeRequest -> Outcome (Either SlapError PatchExplanation)
analyzePatch request =
  case parseUnderEncoding (analyzeDialects request) (analyzeMetadataEncoding request) (analyzePatchBytes request) of
    Left refusal -> Outcome (Left refusal) []
    Right parsed -> Outcome (Right (PatchExplanation (patchInfo parsed) (patchAnalysis parsed))) (patchAdvisories parsed)
