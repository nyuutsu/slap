{-# LANGUAGE OverloadedStrings #-}

-- | The slap-web boundary: native props over everything that crosses it.
module Props.Web (webTests) where

import Slap.Convert (CreateFormat(..), DifferentialCreate(..), DirectCreate(..),
                     CompressionInclusion(OmitCompression),
                     EmbeddedBlobContents(..), EmbeddedBlobRequest(SetEmbeddedBlob, SetEmbeddedTypedText),
                     FileIdDizRequest(SetFileIdDizFromText, DropFileIdDiz),
                     RequestedDialects(..),
                     RequestedPatchMetadata(..), UndoInclusion(OmitUndoData),
                     advertisedCreateFormats, convertDirect, fieldTruncationForewarnings, lookupCreateFormatToken,
                     noConstraintsRequested, noDialectsRequested, noMetadataRequested)
import Slap.Checksum (CRC32(..), MD5Hash(..), SHA1Hash(..))
import Slap.Constraint (Constraint(..))
import qualified Slap.Create as Create
import Slap.Dialect (Dialect(..))
import Slap.Display.Analysis (PatchAnalysis(..), renderAnalysisFull)
import Slap.Display.Common (InfoLine(..), Tally(..))
import Slap.Display.Info (InputSideVerdict(..), OutputSideVerdict(..), infoLines, infoTally, infoUndeclaredTextFields)
import Slap.FileContents (InputFileContents(..), OutputFileContents(..), PatchFileContents(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.Header (HeaderAdjustment(HeaderComesOff), InputHeaderDirective(TakeInputAsIs))
import Slap.Measure (ActualMagic(..), FileSize(..))
import Slap.MetadataField (MetadataField(..), MetadataRequest(..))
import qualified Slap.NINJA1.Types as NINJA1
import qualified Slap.NINJA2.Types as NINJA2
import Slap.Platform (platformToNINJA1, platformToNINJA2)
import Slap.PlatformType (PlatformType(PlatformRaw))
import Slap.PPF1.Types (PPF1Origin(PPF1OriginAmiga))
import Slap.SomePatch (parseSome, patchAdvisories, patchAnalysis, patchContentsOf, patchInfo)
import Slap.Status (CarriedFileCount(..), CreateResult(..), Outcome(..), SlapAdvisory(..), SlapError(..),
                    SourceRequiredCause(..), UnencodeabilityReason(..),
                    noAdvisories, renderSlapAdvisory, renderSlapError)
import Slap.Status.VCDIFF (VCDIFFShapeViolation(..))
import Slap.Surface (metadataFieldKind)
import Slap.Text (EncodedText(..), EncodingName(..), resolveEncodingName)
import Slap.FieldName (FieldName(FieldFileIdDiz))
import Slap.VCDIFF.SecondaryCompression (XDelta3SecondaryCompressor(SecondaryDJW), secondaryCompressorTokens)
import Slap.VCDIFF.Types (defaultXDelta3WindowSize)
import Slap.Verify (VerificationPolicy(EnforceVerification), VerificationVerdict(..))
import Slap.Web
import Slap.Web.Declaration (DeclaredIdentifyRequest(..), analyzeRequestOf, applyRequestOf,
                             createRequestOf, inspectRequestOf)
import Slap.Web.Envelope (encodeEnvelope, encodeEnvelopeAndTail, speakCreatedPatch,
                          speakPatchIdentity, speakPatchedRom, speakRevertedRom, speakVerdict)
import Slap.XDelta1.Types (XDelta1FromName(..))

import qualified Data.Aeson as Aeson
import qualified Data.Aeson.Key as AesonKey
import qualified Data.Aeson.KeyMap as AesonKeyMap
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.List (isPrefixOf, nub)
import Data.List.NonEmpty (NonEmpty(..))
import qualified Data.Set as Set
import qualified Data.Text as Text
import qualified Data.Vector as Vector
import Test.Tasty
import Test.Tasty.HUnit

import Props.Helpers (assertFailureT)

webTests :: TestTree
webTests = testGroup "Web"
  [ testCase "the format census is the advertised token list"      test_formatCensusMatchesAdvertisedTokens
  , testCase "every format row's token names its own target"       test_tokenNamesItsOwnTarget
  , testCase "every format row carries a name and a dotted extension" test_formatRowNamesAndExtensions
  , testCase "xdelta3 is the one row with secondary choices"       test_secondaryChoicesCensus
  , testCase "the metadata field roster covers every field once"   test_metadataFieldRosterCensus
  , testCase "the window default crosses on exactly the vcdiff rows" test_formatWindowDefaults
  , testCase "text ceilings cross beside the fields they bound"    test_formatTextCeilingCensus
  , testCase "choice defaults cross on exactly the defaulting rows" test_formatChoiceDefaultCensus
  , testCase "the console census covers every header once"         test_consoleCensusCoversEveryHeader
  , testCase "a created BPS identifies across the boundary"        test_identifyCreatedBPS
  , testCase "unrecognized bytes refuse with the engine's own error" test_identifyUnrecognizedBytes
  , testCase "a dropped file sorts by recognition alone"           test_classifySortsBothWays
  , testCase "describeRom reproduces the published digests of a known input" test_describeRomKnownAnswers
  , testGroup "apply and undo"
      [ testCase "the right rom reports a match with no rescue"           test_checkApplyMatches
      , testCase "applying to the right rom hands back the target"        test_applyRightRom
      , testCase "a headered rom differs, and the rescue names the peel"  test_headeredRomRescue
      , testCase "the proven peel is carried out, narrated"               test_provenPeelCarriedOut
      , testCase "checkUndo weighs the handed file crosswise"             test_checkUndoCrosswise
      , testCase "undo peels a UPS back to the original"                  test_undoPeelsUPS
      , testCase "the two undo refusals arrive distinct"                  test_undoRefusalsDistinct
      , testCase "a stale toggle refuses the act exactly as its check"    test_applyDialectAgreement
      ]
  , testGroup "a multi-file bundle"
      [ testCase "its identity carries the impediment"          test_multiFileIdentity
      , testCase "info counts the bundle; explain offers no walk" test_multiFileDisplay
      , testCase "every act and check refuses with the one impediment" test_multiFileActsRefuse
      ]
  , testGroup "emit checks"
      [ testCase "a plain BPS create is Ready"                          test_checkCreateBPSReady
      , testCase "a title aimed at IPS gaps with its own drop"          test_checkCreateTitleOnIPS
      , testCase "a growing PPF1 pair gaps toward a different format"   test_checkCreatePPF1Grow
      , testCase "a PPF2 source below the validation floor gaps early"  test_checkCreatePPF2Floor
      , testCase "an over-cap FILE_ID.DIZ gaps toward amendment"        test_checkCreateOverCapDiz
      , testCase "a compressor beside no-compress gaps with either drop" test_checkCreateCompressorPair
      , testCase "an IPS grow past record reach gaps on sizes alone"    test_checkCreateIPSGrowPastReach
      , testCase "forewarnings speak the act's own losses"              test_forewarningsMatchActLosses
      , testCase "IPS to bps without a source asks for one"             test_checkConvertIPSToBPSNeedsSource
      , testCase "the same conversion with a source in hand is Ready"   test_checkConvertIPSToBPSWithSource
      , testCase "a differential source without a source rom asks too"  test_checkConvertBPSToIPSNeedsSource
      , testCase "a stale Amiga toggle gaps with its own drop"          test_checkConvertStaleAmigaToggle
      , testCase "an unparseable patch is the Left, not a gap"          test_checkConvertUnrecognized
      , testCase "an over-cap DIZ typed at convert gaps before the act" test_checkConvertTypedOverCapDiz
      , testCase "an inherited over-cap DIZ gaps, and dropping it clears" test_checkConvertInheritedOverCapDiz
      , testCase "the with-source PPF2 floor is judged at the framed size" test_checkConvertWithSourcePPF2Floor
      ]
  , testGroup "emit acts"
      [ testCase "the create act mirrors the engine create byte for byte" test_createActMirrorsEngine
      , testCase "the create act refuses exactly as its check"            test_createActAgreement
      , testCase "xdelta1 create falls back to the dropped files' names"  test_xdelta1NameFallback
      , testCase "an overlong explicit name gaps toward amendment"        test_xdelta1OverlongName
      , testCase "a sourceless convert emits the new format"              test_convertActSourceless
      , testCase "a with-source convert equals the direct create"         test_convertActWithSource
      , testCase "the proven peel crosses convert too"                    test_convertActRescue
      , testCase "the convert act refuses exactly as its check"           test_convertActAgreement
      ]
  , testGroup "read"
      [ testCase "inspect hands back the engine's own info"          test_inspectMirrorsEngineInfo
      , testCase "both reads carry the parse's advisories across"    test_readsCarryAdvisories
      , testCase "the two reads agree on the info from one parse"    test_readsAgreeOnInfo
      , testCase "analyze's structure renders as the engine's own"   test_analyzeMirrorsEngineAnalysis
      , testCase "the chosen encoding reaches the reading"           test_inspectThreadsEncoding
      , testCase "an unparseable patch is the Left on both reads"    test_readsRefuseUnrecognized
      , testCase "a stale dialect refuses both reads, as the CLI"    test_readsRefuseStaleDialect
      , testCase "encoding-governed readings announce themselves"    test_undeclaredTextSignal
      ]
  , testGroup "envelope"
      [ testCase "the info crosses as structure under Right"                 test_envelopeCarriesInfo
      , testCase "a refusal crosses spoken: its tag beside slap's sentence"  test_envelopeSpeaksRefusal
      , testCase "an advisory crosses with severity and sentence beside it"  test_envelopeSpeaksAdvisory
      , testCase "a blocked check crosses each gap spoken"                   test_envelopeSpeaksBlockedVerdict
      , testCase "a choice field crosses as token-value pairs"               test_envelopeChoicePairs
      , testCase "byte fields cross as base64"                               test_envelopeBytesAsBase64
      , testCase "a lone nullary constructor crosses as its name"            test_envelopeNamesLoneConstructor
      , testCase "the identity crosses with its undo answer spoken by name"  test_envelopeCarriesIdentity
      , testCase "the sorting answer crosses as its name"                    test_envelopeNamesSortingAnswer
      , testCase "the surface crosses with the engine's own format census"   test_envelopeCarriesSurface
      , testCase "the explanation crosses: info beside the structured walk"  test_envelopeCarriesExplanation
      ]
  , testGroup "declaration"
      [ testCase "a declaration beside handed bytes drives the same check"    test_declarationDrivesCheckApply
      , testCase "omitted Maybe fields decode as unrequested metadata"        test_declarationTerseMetadata
      , testCase "an encoding name arrives resolved, as the CLI resolves it"  test_declarationEncodingName
      , testCase "the identify declaration drives the same identity"          test_declarationDrivesIdentify
      , testCase "the read declarations drive the same envelopes"             test_declarationDrivesReads
      , testCase "blob bytes arrive through base64"                           test_declarationBlobBase64
      ]
  , testGroup "tail"
      [ testCase "an act's output bytes ride the tail, spoken for in the envelope"  test_tailCarriesThePatchedRom
      , testCase "a refusal's tail is empty, its envelope still narrated"           test_tailEmptyOnRefusal
      , testCase "a created patch's tail identifies as its own format"              test_tailIdentifiesCreatedPatch
      ]
  ]

test_formatCensusMatchesAdvertisedTokens :: Assertion
test_formatCensusMatchesAdvertisedTokens =
  map formatToken (surfaceFormats describeSurface) @?= advertisedCreateFormats

test_tokenNamesItsOwnTarget :: Assertion
test_tokenNamesItsOwnTarget = sequence_
  [ assertEqual (formatToken row) (Just (formatCreateTarget row)) (lookupCreateFormatToken (formatToken row))
  | row <- surfaceFormats describeSurface ]

test_formatRowNamesAndExtensions :: Assertion
test_formatRowNamesAndExtensions = sequence_
  [ do assertBool (formatToken row <> " has no display name")       (not (Text.null (formatDisplayName row)))
       assertBool (formatToken row <> " has an undotted extension") ("." `isPrefixOf` formatFileExtension row)
  | row <- surfaceFormats describeSurface ]

test_metadataFieldRosterCensus :: Assertion
test_metadataFieldRosterCensus =
  map describedMetadataField (surfaceMetadataFields describeSurface) @?= [minBound .. maxBound]

test_formatTextCeilingCensus :: Assertion
test_formatTextCeilingCensus =
  [ (formatToken row, length (formatTextFieldCeilings row))
  | row <- surfaceFormats describeSurface, not (null (formatTextFieldCeilings row)) ]
    @?= [("ppf1", 1), ("ppf2", 1), ("ppf3", 1), ("dps", 3), ("ninja2", 8), ("aps-n64", 1)]

test_formatChoiceDefaultCensus :: Assertion
test_formatChoiceDefaultCensus = do
  [ (formatToken row, formatChoiceDefaults row)
    | row <- surfaceFormats describeSurface, not (null (formatChoiceDefaults row)) ]
    @?= [ ("ppf3",    [(MetadataImageType, "bin")])
        , ("ninja1",  [(MetadataRomType, "raw")])
        , ("ninja2",  [(MetadataRomType, "raw"), (MetadataTextMode, "utf8")])
        , ("xdelta3", [(MetadataSecondaryCompressor, "lzma")])
        ]
  -- the raw rows claim what the emissions' own absent arms produce
  platformToNINJA1 PlatformRaw @?= (NINJA1.RomRAW, [])
  platformToNINJA2 PlatformRaw @?= (NINJA2.NINJA2Raw, [])

test_formatWindowDefaults :: Assertion
test_formatWindowDefaults =
  [ (formatToken row, windowDefault)
  | row <- surfaceFormats describeSurface, Just windowDefault <- [formatWindowDefault row] ]
    @?= [("rfc-vcdiff", OneWindowWholeTarget), ("xdelta3", WindowsOfBytes defaultXDelta3WindowSize)]

test_secondaryChoicesCensus :: Assertion
test_secondaryChoicesCensus = do
  [formatToken row | row <- surfaceFormats describeSurface, not (null (formatSecondaryChoices row))] @?= ["xdelta3"]
  sequence_
    [ formatSecondaryChoices row @?= secondaryCompressorTokens
    | row <- surfaceFormats describeSurface, formatToken row == "xdelta3" ]

test_consoleCensusCoversEveryHeader :: Assertion
test_consoleCensusCoversEveryHeader = do
  let censusRows = surfaceConsoleHeaders describeSurface
  map describedConsoleHeader censusRows @?= [minBound .. maxBound]
  assertBool "console tokens collide" (nub (map consoleToken censusRows) == map consoleToken censusRows)

test_identifyCreatedBPS :: Assertion
test_identifyCreatedBPS = do
  bpsPatch <- createdFixturePatch (CreateDifferential CreateBPS) noMetadataRequested
  identifyPatch noDialectsRequested EncodingUtf8 bpsPatch
    @?= Right PatchIdentity { identifiedFormat       = LabelBPS
                            , applicableDialects     = Set.empty
                            , identifiedUndo         = FormatHasNoUndo
                            , identifiedImpediment   = Nothing }

test_identifyUnrecognizedBytes :: Assertion
test_identifyUnrecognizedBytes =
  identifyPatch noDialectsRequested EncodingUtf8 (PatchFileContents "this file is nobody's patch")
    @?= Left UnrecognizedFormat

test_classifySortsBothWays :: Assertion
test_classifySortsBothWays = do
  PatchFileContents patchBytes <- createdFixturePatch (CreateDifferential CreateBPS) noMetadataRequested
  droppedFileAnswerFor (classifyDroppedFile patchBytes)                      @?= SortsAsPatch
  droppedFileAnswerFor (classifyDroppedFile "this file is nobody's patch") @?= SortsAsRom

fixtureSourceBytes, fixtureTargetBytes :: ByteString
fixtureSourceBytes = ByteString.pack [0 .. 63]
fixtureTargetBytes = ByteString.pack ([0 .. 31] <> [0xAA] <> [33 .. 63])

createdFixturePatch :: CreateFormat -> RequestedPatchMetadata -> IO PatchFileContents
createdFixturePatch format meta =
  case Create.createPatch format Nothing (InputFileContents fixtureSourceBytes) (OutputFileContents fixtureTargetBytes)
                          meta Nothing noConstraintsRequested noDialectsRequested of
    Left slapError -> assertFailureT ("create: " <> renderSlapError slapError)
    Right (CreateResult patchBytes _advisories) -> pure patchBytes

plainApplyRequest :: PatchFileContents -> ByteString -> ApplyRequest
plainApplyRequest patchBytes romBytes = ApplyRequest
  { applyPatchBytes         = patchBytes
  , applySourceRom          = MatchedRom (InputFileContents romBytes) TakeInputAsIs
  , applyVerificationPolicy = EnforceVerification
  , applyDialects           = noDialectsRequested
  }

plainUndoRequest :: PatchFileContents -> ByteString -> UndoRequest
plainUndoRequest patchBytes handedBytes = UndoRequest
  { undoPatchBytes         = patchBytes
  , undoPatchedRom         = OutputFileContents handedBytes
  , undoVerificationPolicy = EnforceVerification
  , undoDialects           = noDialectsRequested
  }

test_checkApplyMatches :: Assertion
test_checkApplyMatches = do
  bpsPatch <- createdFixturePatch (CreateDifferential CreateBPS) noMetadataRequested
  case checkApply (plainApplyRequest bpsPatch fixtureSourceBytes) of
    Right (SourceReport (VerdictMatches _) []) -> pure ()
    other -> assertFailure ("unexpected report: " <> show other)

test_applyRightRom :: Assertion
test_applyRightRom = do
  bpsPatch <- createdFixturePatch (CreateDifferential CreateBPS) noMetadataRequested
  Outcome applied _advisories <- applyPatch (plainApplyRequest bpsPatch fixtureSourceBytes)
  case applied of
    Left refusal -> assertFailureT ("apply: " <> renderSlapError refusal)
    Right patched -> do
      patchedRomBytes patched @?= OutputFileContents fixtureTargetBytes
      patchedRomVerdictStanding patched @?= VerdictsDescribeTheFiles
      case (patchedRomInputVerdict patched, patchedRomOutputVerdict patched) of
        (InputSideVerdict (VerdictMatches _), OutputSideVerdict (VerdictMatches _)) -> pure ()
        verdicts -> assertFailure ("unexpected verdicts: " <> show verdicts)

test_headeredRomRescue :: Assertion
test_headeredRomRescue = do
  bpsPatch <- createdFixturePatch (CreateDifferential CreateBPS) noMetadataRequested
  case checkApply (plainApplyRequest bpsPatch headeredFixtureSource) of
    Right (SourceReport (VerdictDiffers _) [candidate]) -> rescueAdjustment candidate @?= HeaderComesOff
    other -> assertFailure ("unexpected report: " <> show other)

test_provenPeelCarriedOut :: Assertion
test_provenPeelCarriedOut = do
  bpsPatch <- createdFixturePatch (CreateDifferential CreateBPS) noMetadataRequested
  Outcome applied advisories <- applyPatch (plainApplyRequest bpsPatch headeredFixtureSource)
  case applied of
    Left refusal -> assertFailureT ("apply: " <> renderSlapError refusal)
    Right patched -> do
      patchedRomBytes patched @?= OutputFileContents fixtureTargetBytes
      assertBool "no reframe narration" (any isReframeNote advisories)
  where
    isReframeNote InputReframedToMatchPatch{} = True
    isReframeNote _                           = False

headeredFixtureSource :: ByteString
headeredFixtureSource = ByteString.replicate 512 0x00 <> fixtureSourceBytes

test_checkUndoCrosswise :: Assertion
test_checkUndoCrosswise = do
  upsPatch <- createdFixturePatch (CreateDifferential CreateUPS) noMetadataRequested
  case checkUndo (plainUndoRequest upsPatch fixtureTargetBytes) of
    Right (VerdictMatches _) -> pure ()
    other -> assertFailure ("unexpected verdict: " <> show other)

test_undoPeelsUPS :: Assertion
test_undoPeelsUPS = do
  upsPatch <- createdFixturePatch (CreateDifferential CreateUPS) noMetadataRequested
  case outcomeValue (undoPatch (plainUndoRequest upsPatch fixtureTargetBytes)) of
    Left refusal   -> assertFailureT ("undo: " <> renderSlapError refusal)
    Right reverted -> revertedRomBytes reverted @?= InputFileContents fixtureSourceBytes

test_undoRefusalsDistinct :: Assertion
test_undoRefusalsDistinct = do
  bpsPatch <- createdFixturePatch (CreateDifferential CreateBPS) noMetadataRequested
  outcomeValue (undoPatch (plainUndoRequest bpsPatch fixtureTargetBytes))
    @?= Left (NoUndoForFormat LabelBPS)
  ppf3Patch <- createdFixturePatch (CreateDirect CreatePPF3)
                                   noMetadataRequested { requestedUndoInclusion = Just OmitUndoData }
  outcomeValue (undoPatch (plainUndoRequest ppf3Patch fixtureTargetBytes))
    @?= Left (PatchCarriesNoUndoData LabelPPF3)

test_applyDialectAgreement :: Assertion
test_applyDialectAgreement = do
  bpsPatch <- createdFixturePatch (CreateDifferential CreateBPS) noMetadataRequested
  let request = (plainApplyRequest bpsPatch fixtureSourceBytes)
        { applyDialects = RequestedDialects { requestedPPF1Origin = PPF1OriginAmiga } }
  Outcome applied _advisories <- applyPatch request
  case (checkApply request, applied) of
    (Left checkRefusal, Left actRefusal) -> actRefusal @?= checkRefusal
    other -> assertFailure ("expected two refusals: " <> show other)

-- | Two files in one patch: a one-record file, then a two-record file. slap's own create never writes one.
multiFileNINJA2Wire :: ByteString
multiFileNINJA2Wire =
     NINJA2.ninja2MagicBytes
  <> ByteString.pack [0]           -- PATCH_ENC: encoding undeclared
  <> ByteString.replicate 2041 0   -- the fixed header's text fields, all empty
  <> openFileCommand 4
  <> xorRecordCommand 0 0xAA
  <> openFileCommand 2
  <> xorRecordCommand 0 0xBB
  <> xorRecordCommand 1 0xCC
  <> ByteString.pack [0x00]        -- END
  where
    openFileCommand size = ByteString.pack
      [ 0x01                       -- OPEN_NEW_FILE
      , 0x00                       -- file name, zero length
      , 0x00                       -- rom type: raw
      , 0x01, size, 0x01, size     -- source and target size, equal so no overflow follows
      ] <> ByteString.replicate 32 0   -- both MD5s absent
    xorRecordCommand offset maskByte = ByteString.pack
      [ 0x02, 0x01, offset, 0x01, 0x01, maskByte ]   -- one XOR byte at the offset

multiFileImpediment :: SlapError
multiFileImpediment = PatchCarriesMultipleFiles LabelNINJA2 (CarriedFileCount 2)

test_multiFileIdentity :: Assertion
test_multiFileIdentity =
  identifyPatch noDialectsRequested EncodingUtf8 (PatchFileContents multiFileNINJA2Wire)
    @?= Right PatchIdentity { identifiedFormat       = LabelNINJA2
                            , applicableDialects     = Set.empty
                            , identifiedUndo         = PatchIsItsOwnReverse
                            , identifiedImpediment   = Just multiFileImpediment }

test_multiFileDisplay :: Assertion
test_multiFileDisplay =
  case parseSome noDialectsRequested EncodingUtf8 (PatchFileContents multiFileNINJA2Wire) of
    Left refusal -> assertFailureT ("parse: " <> renderSlapError refusal)
    Right parsed -> do
      infoTally (patchInfo parsed) @?= Tally 3
      elem (InfoLine "files" "2") (infoLines (patchInfo parsed)) @? "no files row in info"
      null (analysisSections (patchAnalysis parsed)) @? "a bundle offered a walk"

test_multiFileActsRefuse :: Assertion
test_multiFileActsRefuse = do
  let patchBytes = PatchFileContents multiFileNINJA2Wire
  checkApply (plainApplyRequest patchBytes fixtureSourceBytes) @?= Left multiFileImpediment
  checkUndo (plainUndoRequest patchBytes fixtureTargetBytes) @?= Left multiFileImpediment
  checkConvert (plainConvertRequest patchBytes (CreateDifferential CreateBPS)) @?= Left multiFileImpediment
  Outcome applied _advisories <- applyPatch (plainApplyRequest patchBytes fixtureSourceBytes)
  case applied of
    Left refusal -> refusal @?= multiFileImpediment
    Right _      -> assertFailure "apply ran a multi-file bundle"
  outcomeValue (undoPatch (plainUndoRequest patchBytes fixtureTargetBytes))
    @?= Left multiFileImpediment

plainCreateRequest :: CreateFormat -> CreateRequest
plainCreateRequest target = CreateRequest
  { createTargetFormat = target
  , createOriginal     = InputFileContents fixtureSourceBytes
  , createModified     = OutputFileContents fixtureTargetBytes
  , createOriginalName = "fixture-source.bin"
  , createModifiedName = "fixture-target.bin"
  , createMetadata     = noMetadataRequested
  , createConstraints  = noConstraintsRequested
  }

plainConvertRequest :: PatchFileContents -> CreateFormat -> ConvertRequest
plainConvertRequest patchBytes target = ConvertRequest
  { convertPatchBytes         = patchBytes
  , convertTargetFormat       = target
  , convertSourceRom          = Nothing
  , convertVerificationPolicy = EnforceVerification
  , convertMetadata           = noMetadataRequested
  , convertConstraints        = noConstraintsRequested
  , convertMetadataEncoding   = EncodingUtf8
  , convertDialects           = noDialectsRequested
  }

test_checkCreateBPSReady :: Assertion
test_checkCreateBPSReady =
  checkCreate (plainCreateRequest (CreateDifferential CreateBPS)) @?= Ready

test_checkCreateTitleOnIPS :: Assertion
test_checkCreateTitleOnIPS =
  checkCreate request @?= Blocked
    (Gap (MetadataFieldRejected (SetField MetadataTitle :| []) LabelIPS)
         (DropMetadataField MetadataTitle :| []) :| [])
  where
    request = (plainCreateRequest (CreateDirect CreateIPS))
      { createMetadata = noMetadataRequested { requestedTitle = Just (EncodedText EncodingUtf8 "title") } }

test_checkCreatePPF1Grow :: Assertion
test_checkCreatePPF1Grow =
  case checkCreate request of
    Blocked (Gap (UnencodeablePair LabelPPF1 _) resolutions :| []) ->
      resolutions @?= ChooseDifferentFormat :| []
    other -> assertFailure ("unexpected verdict: " <> show other)
  where
    request = (plainCreateRequest (CreateDirect CreatePPF1))
      { createOriginal = InputFileContents (ByteString.replicate 4 0x00)
      , createModified = OutputFileContents (ByteString.replicate 8 0xFF)
      }

test_checkCreatePPF2Floor :: Assertion
test_checkCreatePPF2Floor = do
  gapRefusal <- case checkCreate request of
    Blocked (Gap refusal@(SourceTooSmallForPPF2Validation {}) (ChooseDifferentFormat :| []) :| []) -> pure refusal
    other -> assertFailure ("unexpected verdict: " <> show other)
  case Create.createPatch (CreateDirect CreatePPF2) Nothing (createOriginal request) (createModified request)
                          (createMetadata request) Nothing noConstraintsRequested noDialectsRequested of
    Left actRefusal -> actRefusal @?= gapRefusal
    Right _         -> assertFailure "the act emitted below the floor"
  where
    request = plainCreateRequest (CreateDirect CreatePPF2)

test_checkCreateOverCapDiz :: Assertion
test_checkCreateOverCapDiz =
  case checkCreate request of
    Blocked (Gap (FieldTooLong LabelPPF3 FieldFileIdDiz _ _) resolutions :| []) ->
      resolutions @?= AmendMetadataField MetadataFileIdDiz :| []
    other -> assertFailure ("unexpected verdict: " <> show other)
  where
    request = (plainCreateRequest (CreateDirect CreatePPF3))
      { createMetadata = noMetadataRequested
          { requestedFileIdDiz = SetFileIdDizFromText (EncodedText EncodingUtf8 (Text.replicate 4000 "D")) } }

test_checkCreateCompressorPair :: Assertion
test_checkCreateCompressorPair =
  checkCreate request @?= Blocked
    (Gap SecondaryCompressorRequestedWithCompressionOff
         (DropMetadataField MetadataSecondaryCompressor :| [DropMetadataField MetadataPatchCompression]) :| [])
  where
    request = (plainCreateRequest (CreateDifferential CreateXDelta3))
      { createMetadata = noMetadataRequested
          { requestedPatchCompression    = Just OmitCompression
          , requestedSecondaryCompressor = Just SecondaryDJW } }

test_checkCreateIPSGrowPastReach :: Assertion
test_checkCreateIPSGrowPastReach = do
  case checkCreate (grownTo 0x100FFFF) of
    Blocked (Gap (UnencodeablePair LabelIPS (GrowthReachesPastAddressableRange _ _)) resolutions :| []) ->
      resolutions @?= ChooseDifferentFormat :| []
    other -> assertFailure ("unexpected verdict: " <> show other)
  checkCreate (grownTo 0x100FFFE) @?= Ready
  where
    grownTo grownSize = (plainCreateRequest (CreateDirect CreateIPS))
      { createModified = OutputFileContents (ByteString.replicate grownSize 0x00) }

test_forewarningsMatchActLosses :: Assertion
test_forewarningsMatchActLosses = sequence_
  [ do let forewarnings = fieldTruncationForewarnings format overLongEverywhere
       assertBool (show format <> ": nothing forewarned") (not (null forewarnings))
       actAdvisories <- case Create.createPatch format Nothing sourceSeat targetSeat overLongEverywhere
                                                Nothing noConstraintsRequested noDialectsRequested of
         Left slapError -> assertFailureT ("create: " <> renderSlapError slapError)
         Right (CreateResult _ advisories) -> pure advisories
       [advisory | advisory <- actAdvisories, isFieldLoss advisory] @?= forewarnings
  | (format, sourceSeat, targetSeat) <- formatSeats ]
  where
    longText = Just (EncodedText EncodingUtf8 (Text.replicate 3000 "x"))
    overLongEverywhere = noMetadataRequested
      { requestedTitle = longText, requestedAuthor = longText, requestedVersion = longText
      , requestedDescription = longText, requestedGenre = longText, requestedLanguage = longText
      , requestedDate = longText, requestedWebsite = longText }
    isFieldLoss advisory = case advisory of
      FieldTruncated {}          -> True
      FieldEncodedSubstituted {} -> True
      _                          -> False
    plainSource = InputFileContents fixtureSourceBytes
    plainTarget = OutputFileContents fixtureTargetBytes
    ppf2Source  = InputFileContents  (ByteString.replicate 40000 0x00)
    ppf2Target  = OutputFileContents (ByteString.replicate 40000 0x01)
    formatSeats =
      [ (CreateDirect CreatePPF1,         plainSource, plainTarget)
      , (CreateDirect CreatePPF2,         ppf2Source,  ppf2Target)
      , (CreateDirect CreatePPF3,         plainSource, plainTarget)
      , (CreateDirect CreateAPSN64,       plainSource, plainTarget)
      , (CreateDifferential CreateDPS,    plainSource, plainTarget)
      , (CreateDifferential CreateNINJA2, plainSource, plainTarget)
      ]

test_checkConvertIPSToBPSNeedsSource :: Assertion
test_checkConvertIPSToBPSNeedsSource = do
  ipsPatch <- createdFixturePatch (CreateDirect CreateIPS) noMetadataRequested
  checkConvert (plainConvertRequest ipsPatch (CreateDifferential CreateBPS))
    @?= Right (Blocked (Gap (DiffRequiresSource LabelBPS) (ProvideSourceRom :| []) :| []))

test_checkConvertIPSToBPSWithSource :: Assertion
test_checkConvertIPSToBPSWithSource = do
  ipsPatch <- createdFixturePatch (CreateDirect CreateIPS) noMetadataRequested
  let request = (plainConvertRequest ipsPatch (CreateDifferential CreateBPS))
        { convertSourceRom = Just (MatchedRom (InputFileContents fixtureSourceBytes) TakeInputAsIs) }
  checkConvert request @?= Right Ready

test_checkConvertBPSToIPSNeedsSource :: Assertion
test_checkConvertBPSToIPSNeedsSource = do
  bpsPatch <- createdFixturePatch (CreateDifferential CreateBPS) noMetadataRequested
  checkConvert (plainConvertRequest bpsPatch (CreateDirect CreateIPS))
    @?= Right (Blocked (Gap (ConvertRequiresSource LabelBPS SourcePatchIsDifferential)
                            (ProvideSourceRom :| []) :| []))

test_checkConvertStaleAmigaToggle :: Assertion
test_checkConvertStaleAmigaToggle = do
  bpsPatch <- createdFixturePatch (CreateDifferential CreateBPS) noMetadataRequested
  let request = (plainConvertRequest bpsPatch (CreateDifferential CreateBPS))
        { convertSourceRom = Just (MatchedRom (InputFileContents fixtureSourceBytes) TakeInputAsIs)
        , convertDialects  = RequestedDialects { requestedPPF1Origin = PPF1OriginAmiga }
        }
  checkConvert request
    @?= Right (Blocked (Gap (DialectNotSupported (PPF1OriginAxis :| []) LabelBPS)
                            (DropDialect PPF1OriginAxis :| []) :| []))

test_checkConvertUnrecognized :: Assertion
test_checkConvertUnrecognized =
  checkConvert (plainConvertRequest (PatchFileContents "this file is nobody's patch") (CreateDifferential CreateBPS))
    @?= Left UnrecognizedFormat

-- | The check and the engine emission judge one DIZ view, so their refusals must be one refusal.
assertDizGapMatchesEmission :: ConvertRequest -> Assertion
assertDizGapMatchesEmission request = do
  gapRefusal <- case checkConvert request of
    Right (Blocked (Gap refusal@(FieldTooLong LabelPPF3 FieldFileIdDiz _ _) resolutions :| [])) -> do
      resolutions @?= AmendMetadataField MetadataFileIdDiz :| [DropMetadataField MetadataFileIdDiz]
      pure refusal
    other -> assertFailure ("unexpected verdict: " <> show other)
  parsed   <- either (assertFailureT . renderSlapError) pure
                     (parseSome noDialectsRequested EncodingUtf8 (convertPatchBytes request))
  contents <- maybe (assertFailure "the source patch carries no contents") pure (patchContentsOf parsed)
  case convertDirect contents (convertTargetFormat request) (convertMetadata request)
                     noConstraintsRequested noDialectsRequested of
    Left actRefusal -> actRefusal @?= gapRefusal
    Right _         -> assertFailure "the emission wrote an over-cap DIZ"

test_checkConvertTypedOverCapDiz :: Assertion
test_checkConvertTypedOverCapDiz = do
  ipsPatch <- createdFixturePatch (CreateDirect CreateIPS) noMetadataRequested
  assertDizGapMatchesEmission (plainConvertRequest ipsPatch (CreateDirect CreatePPF3))
    { convertMetadata = noMetadataRequested
        { requestedFileIdDiz = SetFileIdDizFromText (EncodedText EncodingUtf8 (Text.replicate 4000 "D")) } }

test_checkConvertInheritedOverCapDiz :: Assertion
test_checkConvertInheritedOverCapDiz = do
  PatchFileContents cleanPPF3 <- createdFixturePatch (CreateDirect CreatePPF3) noMetadataRequested
  -- 'createPatch' refuses an over-cap DIZ, so the wild shape is built by hand:
  -- 3073 content bytes, one past the cap, spelled little-endian in the trailer's length field.
  let overCapTrailer = "@BEGIN_FILE_ID.DIZ" <> ByteString.replicate 3073 0x44
                       <> "@END_FILE_ID.DIZ" <> ByteString.pack [0x01, 0x0C]
      dizPatch = PatchFileContents (cleanPPF3 <> overCapTrailer)
  assertDizGapMatchesEmission (plainConvertRequest dizPatch (CreateDirect CreatePPF3))
  checkConvert (plainConvertRequest dizPatch (CreateDirect CreatePPF3))
      { convertMetadata = noMetadataRequested { requestedFileIdDiz = DropFileIdDiz } }
    @?= Right Ready

test_checkConvertWithSourcePPF2Floor :: Assertion
test_checkConvertWithSourcePPF2Floor = do
  ipsPatch <- createdFixturePatch (CreateDirect CreateIPS) noMetadataRequested
  let request = (plainConvertRequest ipsPatch (CreateDirect CreatePPF2))
        { convertSourceRom = Just (MatchedRom (InputFileContents fixtureSourceBytes) TakeInputAsIs) }
  gapRefusal <- case checkConvert request of
    Right (Blocked (Gap refusal@(SourceTooSmallForPPF2Validation {}) (ChooseDifferentFormat :| []) :| [])) ->
      pure refusal
    other -> assertFailure ("unexpected verdict: " <> show other)
  parsed <- either (assertFailureT . renderSlapError) pure
                   (parseSome noDialectsRequested EncodingUtf8 ipsPatch)
  case Create.createPatch (CreateDirect CreatePPF2) Nothing (InputFileContents fixtureSourceBytes)
                          (OutputFileContents fixtureTargetBytes) noMetadataRequested (patchContentsOf parsed)
                          noConstraintsRequested noDialectsRequested of
    Left actRefusal -> actRefusal @?= gapRefusal
    Right _         -> assertFailure "the act emitted below the floor"

test_createActMirrorsEngine :: Assertion
test_createActMirrorsEngine = do
  fixturePatch <- createdFixturePatch (CreateDifferential CreateBPS) noMetadataRequested
  case outcomeValue (createPatch (plainCreateRequest (CreateDifferential CreateBPS))) of
    Left refusal  -> assertFailureT ("create: " <> renderSlapError refusal)
    Right created -> do
      createdPatchBytes created @?= fixturePatch
      createdPatchFormat created @?= CreateDifferential CreateBPS

test_createActAgreement :: Assertion
test_createActAgreement =
  case (checkCreate request, outcomeValue (createPatch request)) of
    (Blocked (gap :| _), Left refusal) -> refusal @?= gapReason gap
    other -> assertFailure ("expected a blocked check and a refusing act: " <> show other)
  where
    request = (plainCreateRequest (CreateDirect CreateIPS))
      { createMetadata = noMetadataRequested { requestedTitle = Just (EncodedText EncodingUtf8 "title") } }

test_xdelta1NameFallback :: Assertion
test_xdelta1NameFallback = do
  let request = plainCreateRequest (CreateDifferential CreateXDelta1)
  checkCreate request @?= Ready
  case outcomeValue (createPatch request) of
    Left refusal  -> assertFailureT ("create: " <> renderSlapError refusal)
    Right created -> identifyPatch noDialectsRequested EncodingUtf8 (createdPatchBytes created)
                       @?= Right PatchIdentity { identifiedFormat       = LabelXDelta1
                                               , applicableDialects     = Set.empty
                                               , identifiedUndo         = FormatHasNoUndo
                                               , identifiedImpediment   = Nothing }

test_xdelta1OverlongName :: Assertion
test_xdelta1OverlongName =
  case checkCreate request of
    Blocked (Gap (FieldTooLong _ _ _ _) resolutions :| []) ->
      resolutions @?= AmendMetadataField MetadataXDelta1FromName :| []
    other -> assertFailure ("unexpected verdict: " <> show other)
  where
    request = (plainCreateRequest (CreateDifferential CreateXDelta1))
      { createMetadata = noMetadataRequested
          { requestedXDelta1FromName =
              Just (XDelta1FromName (EncodedText EncodingUtf8 (Text.replicate 70000 "a"))) } }

test_convertActSourceless :: Assertion
test_convertActSourceless = do
  ipsPatch <- createdFixturePatch (CreateDirect CreateIPS) noMetadataRequested
  Outcome converted _advisories <- convertPatch (plainConvertRequest ipsPatch (CreateDirect CreateIPS32))
  case converted of
    Left refusal  -> assertFailureT ("convert: " <> renderSlapError refusal)
    Right created -> fmap identifiedFormat (identifyPatch noDialectsRequested EncodingUtf8 (createdPatchBytes created))
                       @?= Right LabelIPS32

test_convertActWithSource :: Assertion
test_convertActWithSource = do
  ipsPatch     <- createdFixturePatch (CreateDirect CreateIPS) noMetadataRequested
  directCreate <- createdFixturePatch (CreateDifferential CreateBPS) noMetadataRequested
  let request = (plainConvertRequest ipsPatch (CreateDifferential CreateBPS))
        { convertSourceRom = Just (MatchedRom (InputFileContents fixtureSourceBytes) TakeInputAsIs) }
  Outcome converted _advisories <- convertPatch request
  case converted of
    Left refusal  -> assertFailureT ("convert: " <> renderSlapError refusal)
    Right created -> createdPatchBytes created @?= directCreate

test_convertActRescue :: Assertion
test_convertActRescue = do
  bpsPatch     <- createdFixturePatch (CreateDifferential CreateBPS) noMetadataRequested
  directCreate <- createdFixturePatch (CreateDifferential CreateUPS) noMetadataRequested
  let request = (plainConvertRequest bpsPatch (CreateDifferential CreateUPS))
        { convertSourceRom = Just (MatchedRom (InputFileContents headeredFixtureSource) TakeInputAsIs) }
  Outcome converted advisories <- convertPatch request
  case converted of
    Left refusal  -> assertFailureT ("convert: " <> renderSlapError refusal)
    Right created -> do
      createdPatchBytes created @?= directCreate
      assertBool "no reframe narration" (any isReframeNote advisories)
  where
    isReframeNote InputReframedToMatchPatch{} = True
    isReframeNote _                           = False

test_convertActAgreement :: Assertion
test_convertActAgreement = do
  bpsPatch <- createdFixturePatch (CreateDifferential CreateBPS) noMetadataRequested
  let request = plainConvertRequest bpsPatch (CreateDirect CreateIPS)
  Outcome converted _advisories <- convertPatch request
  case (checkConvert request, converted) of
    (Right (Blocked (gap :| _)), Left refusal) -> refusal @?= gapReason gap
    other -> assertFailure ("expected a blocked check and a refusing act: " <> show other)

plainInspectRequest :: PatchFileContents -> InspectRequest
plainInspectRequest patchBytes = InspectRequest
  { inspectPatchBytes       = patchBytes
  , inspectMetadataEncoding = EncodingUtf8
  , inspectDialects         = noDialectsRequested
  }

plainAnalyzeRequest :: PatchFileContents -> AnalyzeRequest
plainAnalyzeRequest patchBytes = AnalyzeRequest
  { analyzePatchBytes       = patchBytes
  , analyzeMetadataEncoding = EncodingUtf8
  , analyzeDialects         = noDialectsRequested
  }

test_inspectMirrorsEngineInfo :: Assertion
test_inspectMirrorsEngineInfo = do
  bpsPatch    <- createdFixturePatch (CreateDifferential CreateBPS) noMetadataRequested
  engineParse <- either (assertFailureT . renderSlapError) pure (parseSome noDialectsRequested EncodingUtf8 bpsPatch)
  outcomeValue (inspectPatch (plainInspectRequest bpsPatch)) @?= Right (patchInfo engineParse)

test_readsCarryAdvisories :: Assertion
test_readsCarryAdvisories = do
  ips32Patch <- createdFixturePatch (CreateDirect CreateIPS32) noMetadataRequested
  let PatchFileContents ips32Bytes = ips32Patch
      withJunk = PatchFileContents (ips32Bytes <> ByteString.replicate 16 0x7A)
      engineAdvisories = either (const []) patchAdvisories (parseSome noDialectsRequested EncodingUtf8 withJunk)
      Outcome _ inspectAdvisories = inspectPatch (plainInspectRequest withJunk)
      Outcome _ analyzeAdvisories = analyzePatch (plainAnalyzeRequest withJunk)
  assertBool "the trailing junk raised nothing to carry" (not (null engineAdvisories))
  inspectAdvisories @?= engineAdvisories
  analyzeAdvisories @?= engineAdvisories

test_readsAgreeOnInfo :: Assertion
test_readsAgreeOnInfo = do
  bpsPatch <- createdFixturePatch (CreateDifferential CreateBPS) noMetadataRequested
  let inspected = outcomeValue (inspectPatch (plainInspectRequest bpsPatch))
  case outcomeValue (analyzePatch (plainAnalyzeRequest bpsPatch)) of
    Left refusal      -> assertFailureT ("analyze: " <> renderSlapError refusal)
    Right explanation -> Right (explanationInfo explanation) @?= inspected

test_analyzeMirrorsEngineAnalysis :: Assertion
test_analyzeMirrorsEngineAnalysis = do
  bpsPatch    <- createdFixturePatch (CreateDifferential CreateBPS) noMetadataRequested
  engineParse <- either (assertFailureT . renderSlapError) pure (parseSome noDialectsRequested EncodingUtf8 bpsPatch)
  case outcomeValue (analyzePatch (plainAnalyzeRequest bpsPatch)) of
    Left refusal      -> assertFailureT ("analyze: " <> renderSlapError refusal)
    Right explanation ->
      renderAnalysisFull (explanationInfo explanation) (explanationAnalysis explanation) Nothing
        @?= renderAnalysisFull (patchInfo engineParse) (patchAnalysis engineParse) Nothing

-- | A verbatim blob of 0xA9 reads as U+FFFD under UTF-8 and as "©" under Latin-1,
-- so a read that ignored the chosen encoding would return the same info both ways — that it differs is the encoding reaching the reading.
test_inspectThreadsEncoding :: Assertion
test_inspectThreadsEncoding = do
  bpsPatch <- createdFixturePatch (CreateDifferential CreateBPS)
                                  noMetadataRequested { requestedEmbeddedBlob = SetEmbeddedBlob (EmbeddedBlobContents (ByteString.pack [0xA9])) }
  let underUtf8   = outcomeValue (inspectPatch (plainInspectRequest bpsPatch))
      underLatin1 = outcomeValue (inspectPatch (plainInspectRequest bpsPatch) { inspectMetadataEncoding = latin1 })
  assertBool "the two encodings read the blob the same, so the encoding never reached the reading" (underUtf8 /= underLatin1)
  where
    latin1 = either (const (error "iso-8859-1 is advertised")) EncodingNamed (resolveEncodingName "iso-8859-1")

test_readsRefuseUnrecognized :: Assertion
test_readsRefuseUnrecognized = do
  outcomeValue (inspectPatch (plainInspectRequest nobodysPatch)) @?= Left UnrecognizedFormat
  case outcomeValue (analyzePatch (plainAnalyzeRequest nobodysPatch)) of
    Left refusal -> refusal @?= UnrecognizedFormat
    Right _      -> assertFailure "analyze accepted a file that is nobody's patch"
  where
    nobodysPatch = PatchFileContents "this file is nobody's patch"

-- | The reads route their dialect judgment through 'parseUnderEncoding', so a read refuses a stale toggle.
test_readsRefuseStaleDialect :: Assertion
test_readsRefuseStaleDialect = do
  bpsPatch <- createdFixturePatch (CreateDifferential CreateBPS) noMetadataRequested
  let staleDialects = RequestedDialects { requestedPPF1Origin = PPF1OriginAmiga }
      staleRefusal   = DialectNotSupported (PPF1OriginAxis :| []) LabelBPS
  outcomeValue (inspectPatch (plainInspectRequest bpsPatch) { inspectDialects = staleDialects })
    @?= Left staleRefusal
  case outcomeValue (analyzePatch (plainAnalyzeRequest bpsPatch) { analyzeDialects = staleDialects }) of
    Left refusal -> refusal @?= staleRefusal
    Right _      -> assertFailure "analyze accepted a stale dialect"

-- | The per-patch gate for a frontend's encoding control:
-- a patch with no undeclared-encoding text announces nothing, and only the blob-carrying BPS names its one governed reading.
test_undeclaredTextSignal :: Assertion
test_undeclaredTextSignal = do
  upsPatch  <- createdFixturePatch (CreateDifferential CreateUPS) noMetadataRequested
  bpsQuiet  <- createdFixturePatch (CreateDifferential CreateBPS) noMetadataRequested
  bpsNoted  <- createdFixturePatch (CreateDifferential CreateBPS)
                 noMetadataRequested { requestedEmbeddedBlob = SetEmbeddedTypedText "a note" }
  let announcedBy patchBytes =
        fmap infoUndeclaredTextFields (outcomeValue (inspectPatch (plainInspectRequest patchBytes)))
  announcedBy upsPatch @?= Right []
  announcedBy bpsQuiet @?= Right []
  announcedBy bpsNoted @?= Right ["embedded data"]

-- | The nine digits are the CRC catalogs' standard check input; every digest below is the published one.
-- The field newtypes already forbid swapping one hash for another; this catches hashing the wrong bytes.
test_describeRomKnownAnswers :: Assertion
test_describeRomKnownAnswers =
  describeRom (InputFileContents "123456789")
    @?= RomFacts
          { romSize  = FileSize 9
          , romCRC32 = CRC32 0xcbf43926
          , romMD5   = MD5Hash  (ByteString.pack [ 0x25, 0xf9, 0xe7, 0x94, 0x32, 0x3b, 0x45, 0x38
                                                 , 0x85, 0xf5, 0x18, 0x1f, 0x1b, 0x62, 0x4d, 0x0b ])
          , romSHA1  = SHA1Hash (ByteString.pack [ 0xf7, 0xc3, 0xbc, 0x1d, 0x80, 0x8e, 0x04, 0x73, 0x2a, 0xdf
                                                 , 0x67, 0x99, 0x65, 0xcc, 0xc3, 0x4c, 0xa7, 0xae, 0x34, 0x41 ])
          }

test_envelopeCarriesInfo :: Assertion
test_envelopeCarriesInfo = do
  bpsPatch <- createdFixturePatch (CreateDifferential CreateBPS) noMetadataRequested
  envelope <- decodedEnvelope (inspectPatch (plainInspectRequest bpsPatch))
  carriedLabel <- jsonPath ["envelopeAnswer", "Right", "infoFormat", "formatLabel"] envelope
  carriedLabel @?= Aeson.String "LabelBPS"

test_envelopeSpeaksRefusal :: Assertion
test_envelopeSpeaksRefusal = do
  envelope <- decodedEnvelope (inspectPatch (plainInspectRequest (PatchFileContents "this file is nobody's patch")))
  carriedTag      <- jsonPath ["envelopeAnswer", "Left", "spokenError", "tag"] envelope
  carriedSentence <- jsonPath ["envelopeAnswer", "Left", "spokenErrorSentence"] envelope
  carriedTag      @?= Aeson.String "UnrecognizedFormat"
  carriedSentence @?= Aeson.String (renderSlapError UnrecognizedFormat)

test_envelopeSpeaksAdvisory :: Assertion
test_envelopeSpeaksAdvisory = do
  ips32Patch <- createdFixturePatch (CreateDirect CreateIPS32) noMetadataRequested
  let PatchFileContents ips32Bytes = ips32Patch
      withJunk = PatchFileContents (ips32Bytes <> ByteString.replicate 16 0x7A)
      outcome  = inspectPatch (plainInspectRequest withJunk)
  spokenFirst <- case outcomeAdvisories outcome of
    firstAdvisory : _ -> pure firstAdvisory
    []                -> assertFailure "the trailing junk raised nothing to carry"
  envelope <- decodedEnvelope outcome
  crossings <- jsonPath ["envelopeAdvisories"] envelope
  firstCrossing <- case crossings of
    Aeson.Array elements -> case Vector.toList elements of
      firstElement : _ -> pure firstElement
      []               -> assertFailure "the envelope carries no advisories"
    other -> assertFailure ("expected an advisory array: " <> show other)
  carriedTag      <- jsonPath ["spokenAdvisory", "tag"] firstCrossing
  carriedSeverity <- jsonPath ["spokenAdvisorySeverity"] firstCrossing
  carriedSentence <- jsonPath ["spokenAdvisorySentence"] firstCrossing
  carriedTag      @?= Aeson.String "IPS32TrailingBytes"
  carriedSeverity @?= Aeson.String "SeverityWarning"
  carriedSentence @?= Aeson.String (renderSlapAdvisory spokenFirst)

test_envelopeSpeaksBlockedVerdict :: Assertion
test_envelopeSpeaksBlockedVerdict = do
  envelope <- decodedEnvelope (noAdvisories (Right (speakVerdict (checkCreate request))))
  verdictTag <- jsonPath ["envelopeAnswer", "Right", "tag"] envelope
  verdictTag @?= Aeson.String "SpokenBlocked"
  gaps <- jsonPath ["envelopeAnswer", "Right", "contents"] envelope
  firstGap <- case gaps of
    Aeson.Array elements -> case Vector.toList elements of
      firstElement : _ -> pure firstElement
      []               -> assertFailure "the blocked verdict carries no gaps"
    other -> assertFailure ("expected a gap array: " <> show other)
  gapSentence    <- jsonPath ["spokenGapReason", "spokenErrorSentence"] firstGap
  gapResolutions <- jsonPath ["spokenGapResolutions"] firstGap
  gapSentence    @?= Aeson.String (renderSlapError (MetadataFieldRejected (SetField MetadataTitle :| []) LabelIPS))
  gapResolutions @?= Aeson.toJSON [DropMetadataField MetadataTitle]
  where
    request = (plainCreateRequest (CreateDirect CreateIPS))
      { createMetadata = noMetadataRequested { requestedTitle = Just (EncodedText EncodingUtf8 "title") } }

test_envelopeChoicePairs :: Assertion
test_envelopeChoicePairs = do
  pinnedShape <- maybe (assertFailure "the pinned shape is not readable JSON") pure (Aeson.decode
    "{\"tag\":\"ChoiceField\",\"contents\":{\"tag\":\"ImageTypeChoices\",\"contents\":[[\"bin\",\"BIN\"],[\"gi\",\"GI\"]]}}")
  Aeson.toJSON (metadataFieldKind MetadataImageType) @?= (pinnedShape :: Aeson.Value)

test_envelopeBytesAsBase64 :: Assertion
test_envelopeBytesAsBase64 = Aeson.toJSON (ActualMagic "PATCH") @?= Aeson.String "UEFUQ0g="

test_envelopeCarriesSurface :: Assertion
test_envelopeCarriesSurface = do
  envelope <- decodedEnvelope (noAdvisories (Right describeSurface))
  crossedFormats <- jsonPath ["envelopeAnswer", "Right", "surfaceFormats"] envelope
  case crossedFormats of
    Aeson.Array rows -> Vector.length rows @?= length (surfaceFormats describeSurface)
    other            -> assertFailure ("expected a format array: " <> show other)

test_envelopeCarriesExplanation :: Assertion
test_envelopeCarriesExplanation = do
  bpsPatch <- createdFixturePatch (CreateDifferential CreateBPS) noMetadataRequested
  envelope <- decodedEnvelope (analyzePatch (plainAnalyzeRequest bpsPatch))
  carriedLabel <- jsonPath ["envelopeAnswer", "Right", "explanationInfo", "infoFormat", "formatLabel"] envelope
  carriedLabel @?= Aeson.String "LabelBPS"
  crossedSections <- jsonPath ["envelopeAnswer", "Right", "explanationAnalysis", "analysisSections"] envelope
  case crossedSections of
    Aeson.Array sections -> assertBool "the walk crossed with no sections" (not (Vector.null sections))
    other                -> assertFailure ("expected a section array: " <> show other)

test_envelopeNamesLoneConstructor :: Assertion
test_envelopeNamesLoneConstructor = do
  Aeson.toJSON SMCShapeConstraint          @?= Aeson.String "SMCShapeConstraint"
  Aeson.toJSON PPF1OriginAxis              @?= Aeson.String "PPF1OriginAxis"
  Aeson.toJSON VCDIFFNestedCustomCodeTable @?= Aeson.String "VCDIFFNestedCustomCodeTable"

test_envelopeCarriesIdentity :: Assertion
test_envelopeCarriesIdentity = do
  upsPatch <- createdFixturePatch (CreateDifferential CreateUPS) noMetadataRequested
  identity <- either (assertFailureT . renderSlapError) pure (identifyPatch noDialectsRequested EncodingUtf8 upsPatch)
  envelope <- maybe (assertFailure "the identity envelope is not readable JSON") pure
                    (Aeson.decodeStrict (encodeEnvelope (noAdvisories (Right (speakPatchIdentity identity)))))
  crossedFormat <- jsonPath ["envelopeAnswer", "Right", "spokenIdentityFormat"] envelope
  crossedFormat @?= Aeson.String "LabelUPS"
  crossedName <- jsonPath ["envelopeAnswer", "Right", "spokenIdentityFormatName"] envelope
  crossedName @?= Aeson.String "UPS"
  crossedUndo <- jsonPath ["envelopeAnswer", "Right", "spokenIdentityUndo"] envelope
  crossedUndo @?= Aeson.String "PatchIsItsOwnReverse"

test_envelopeNamesSortingAnswer :: Assertion
test_envelopeNamesSortingAnswer = do
  Aeson.toJSON SortsAsPatch @?= Aeson.String "SortsAsPatch"
  Aeson.toJSON SortsAsRom   @?= Aeson.String "SortsAsRom"

test_declarationDrivesCheckApply :: Assertion
test_declarationDrivesCheckApply = do
  bpsPatch <- createdFixturePatch (CreateDifferential CreateBPS) noMetadataRequested
  declared <- decodedFromJSON "{\"declaredApplyFraming\":{\"tag\":\"TakeInputAsIs\"},\"declaredApplyVerificationPolicy\":\"EnforceVerification\",\
                              \\"declaredApplyDialects\":{\"requestedPPF1Origin\":\"PPF1OriginPC\"}}"
  checkApply (applyRequestOf declared bpsPatch (InputFileContents fixtureSourceBytes))
    @?= checkApply (plainApplyRequest bpsPatch fixtureSourceBytes)

test_declarationTerseMetadata :: Assertion
test_declarationTerseMetadata = do
  declared <- decodedFromJSON "{\"declaredCreateTargetFormat\":{\"tag\":\"CreateDifferential\",\"contents\":\"CreateBPS\"},\
                              \\"declaredCreateOriginalName\":\"original.gbc\",\"declaredCreateModifiedName\":\"modified.gbc\",\
                              \\"declaredCreateMetadata\":{\"requestedFileIdDiz\":{\"tag\":\"InheritFileIdDiz\"},\
                                                          \\"requestedEmbeddedBlob\":{\"tag\":\"InheritEmbeddedBlob\"}},\
                              \\"declaredCreateConstraints\":{\"requestedSMCShape\":\"AllowAnyTruncationShape\"}}"
  let request = createRequestOf declared (InputFileContents fixtureSourceBytes) (OutputFileContents fixtureTargetBytes)
  requestedTitle (createMetadata request)      @?= Nothing
  requestedWindowSize (createMetadata request) @?= Nothing
  checkCreate request                          @?= Ready

test_declarationEncodingName :: Assertion
test_declarationEncodingName = do
  decoded  <- decodedFromJSON "\"shift-jis\""
  expected <- case resolveEncodingName "shift-jis" of
    Right named -> pure (EncodingNamed named)
    Left _      -> assertFailure "shift-jis did not resolve"
  decoded @?= (expected :: EncodingName)

test_declarationBlobBase64 :: Assertion
test_declarationBlobBase64 = do
  decoded <- decodedFromJSON "{\"tag\":\"SetEmbeddedBlob\",\"contents\":\"qg==\"}"
  decoded @?= SetEmbeddedBlob (EmbeddedBlobContents (ByteString.pack [0xAA]))

test_declarationDrivesIdentify :: Assertion
test_declarationDrivesIdentify = do
  bpsPatch <- createdFixturePatch (CreateDifferential CreateBPS) noMetadataRequested
  declared <- decodedFromJSON "{\"declaredIdentifyDialects\":{\"requestedPPF1Origin\":\"PPF1OriginPC\"},\
                              \\"declaredIdentifyMetadataEncoding\":\"utf-8\"}"
  identifyPatch (declaredIdentifyDialects declared) (declaredIdentifyMetadataEncoding declared) bpsPatch
    @?= identifyPatch noDialectsRequested EncodingUtf8 bpsPatch

-- The envelopes' bytes are the wire meaning, so byte equality is exactly the claim:
-- a declaration beside handed bytes drives the same read the directly built request does.
test_declarationDrivesReads :: Assertion
test_declarationDrivesReads = do
  bpsPatch <- createdFixturePatch (CreateDifferential CreateBPS) noMetadataRequested
  declaredInspect <- decodedFromJSON "{\"declaredInspectMetadataEncoding\":\"utf-8\",\
                                     \\"declaredInspectDialects\":{\"requestedPPF1Origin\":\"PPF1OriginPC\"}}"
  declaredAnalyze <- decodedFromJSON "{\"declaredAnalyzeMetadataEncoding\":\"utf-8\",\
                                     \\"declaredAnalyzeDialects\":{\"requestedPPF1Origin\":\"PPF1OriginPC\"}}"
  encodeEnvelope (inspectPatch (inspectRequestOf declaredInspect bpsPatch))
    @?= encodeEnvelope (inspectPatch (plainInspectRequest bpsPatch))
  encodeEnvelope (analyzePatch (analyzeRequestOf declaredAnalyze bpsPatch))
    @?= encodeEnvelope (analyzePatch (plainAnalyzeRequest bpsPatch))

decodedFromJSON :: Aeson.FromJSON value => ByteString -> IO value
decodedFromJSON json = either (assertFailure . ("did not decode: " <>)) pure (Aeson.eitherDecodeStrict json)

test_tailCarriesThePatchedRom :: Assertion
test_tailCarriesThePatchedRom = do
  bpsPatch <- createdFixturePatch (CreateDifferential CreateBPS) noMetadataRequested
  outcome  <- applyPatch (plainApplyRequest bpsPatch fixtureSourceBytes)
  let (envelopeBytes, tailBytes) = encodeEnvelopeAndTail speakPatchedRom outcome
  tailBytes @?= fixtureTargetBytes
  envelope <- maybe (assertFailure "the envelope is not readable JSON") pure (Aeson.decodeStrict envelopeBytes)
  carriedStanding <- jsonPath ["envelopeAnswer", "Right", "spokenPatchedRomStanding"] envelope
  carriedStanding @?= Aeson.String "VerdictsDescribeTheFiles"

test_tailEmptyOnRefusal :: Assertion
test_tailEmptyOnRefusal = do
  bpsPatch <- createdFixturePatch (CreateDifferential CreateBPS) noMetadataRequested
  let (envelopeBytes, tailBytes) = encodeEnvelopeAndTail speakRevertedRom (undoPatch (plainUndoRequest bpsPatch fixtureSourceBytes))
  tailBytes @?= ByteString.empty
  envelope <- maybe (assertFailure "the envelope is not readable JSON") pure (Aeson.decodeStrict envelopeBytes)
  carriedTag <- jsonPath ["envelopeAnswer", "Left", "spokenError", "tag"] envelope
  carriedTag @?= Aeson.String "NoUndoForFormat"

test_tailIdentifiesCreatedPatch :: Assertion
test_tailIdentifiesCreatedPatch = do
  created <- case outcomeValue (createPatch (plainCreateRequest (CreateDifferential CreateBPS))) of
    Left refusal  -> assertFailureT ("create: " <> renderSlapError refusal)
    Right created -> pure created
  let (_envelopeBytes, tailBytes) = encodeEnvelopeAndTail speakCreatedPatch (noAdvisories (Right created))
  identifiedFormat <$> identifyPatch noDialectsRequested EncodingUtf8 (PatchFileContents tailBytes)
    @?= Right LabelBPS

decodedEnvelope :: Aeson.ToJSON answer => Outcome (Either SlapError answer) -> IO Aeson.Value
decodedEnvelope outcome =
  maybe (assertFailure "the envelope is not readable JSON") pure (Aeson.decodeStrict (encodeEnvelope outcome))

jsonPath :: [String] -> Aeson.Value -> IO Aeson.Value
jsonPath [] value = pure value
jsonPath (name : deeper) (Aeson.Object object) =
  case AesonKeyMap.lookup (AesonKey.fromString name) object of
    Just inner -> jsonPath deeper inner
    Nothing    -> assertFailure ("no field " <> name <> " in " <> show (AesonKeyMap.keys object))
jsonPath (name : _) other = assertFailure ("looked for " <> name <> " in a non-object: " <> show other)
