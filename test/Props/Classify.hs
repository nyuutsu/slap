{-# LANGUAGE OverloadedStrings #-}

-- | 'classifyDroppedFile' and 'patchIdentity', walked through every creatable format.
module Props.Classify (classifyTests) where

import Slap.Binary (word32BEBytes)
import Slap.BPS.Types (bpsMagicBytes)
import Slap.Convert (CreateFormat(..), DirectCreate(..), DifferentialCreate(..),
                     RequestedPatchMetadata(..), UndoInclusion(..), acceptedDialects,
                     noMetadataRequested, noConstraintsRequested, noDialectsRequested)
import Slap.Create (createPatch)
import Slap.Compression.Yay0 (isYay0)
import Slap.Detect (DroppedFileClass(..), classifyDroppedFile)
import Slap.Dialect (Dialect(..))
import Slap.FileContents (InputFileContents(..), OutputFileContents(..), PatchFileContents(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.IPS.Types (ipsMagicBytes)
import Slap.PPF3.Types (ppf3MagicBytes)
import Slap.SomePatch (PatchIdentity(..), SomePatch, UndoAnswer(..), parseSome, patchIdentity)
import Slap.Status (CreateResult(..), SlapError(..), renderSlapError)
import Slap.Text (EncodingName(EncodingUtf8))
import Slap.UPS.Types (upsMagicBytes)
import Slap.XDelta1.Types (ResolvedXDelta1FileNames, resolveXDelta1FileNames)

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.Set as Set
import qualified Data.Text as Text
import Test.Tasty
import Test.Tasty.HUnit
import Test.Tasty.QuickCheck

import Props.Helpers

classifyTests :: TestTree
classifyTests = testGroup "Classify"
  [ testGroup "created patches sort and identify"
      [ classifyAndIdentifyCase row | row <- identityExpectations ]
  , testProperty "classification agrees with parse recognition" prop_classificationAgreesWithParse
  , testCase "PPF1 identity offers the origin axis" test_ppf1IdentityOffersOriginAxis
  , testCase "PPF3 without undo data answers AuthorOmittedUndoData" test_ppf3WithoutUndoAnswersAuthorOmitted
  , testCase "a Yay0 envelope sorts into the patch slot even around garbage" test_yay0EnvelopeSortsAsPatch
  , testCase "a Yay0 envelope holding another Yay0 envelope is refused" test_nestedYay0EnvelopeRefused
  ]

-- | One row per creatable format: the fixture pair to create from,
-- and the identity facts the created patch must project.
data IdentityExpectation = IdentityExpectation
  { expectationName    :: String
  , expectationFormat  :: CreateFormat
  , expectationFixture :: (ByteString, ByteString)
  , expectedLabel      :: FormatLabel
  , expectedUndo       :: UndoAnswer
  }

-- | 64 bytes with one substitution — small enough to read in a failure, real enough to make every encoder emit a record.
standardFixture :: (ByteString, ByteString)
standardFixture =
  ( ByteString.pack [0 .. 63]
  , ByteString.pack ([0 .. 31] ++ [0xAA] ++ [33 .. 63]) )

-- | PPF2 embeds a validation block read from a fixed source region, so its source must reach past that region.
ppf2Fixture :: (ByteString, ByteString)
ppf2Fixture =
  ( ByteString.replicate 40960 0x55
  , ByteString.concat [ByteString.replicate 100 0x55, ByteString.singleton 0xAA, ByteString.replicate 40859 0x55] )

identityExpectations :: [IdentityExpectation]
identityExpectations =
  [ IdentityExpectation "BPS"        (CreateDifferential CreateBPS)       standardFixture LabelBPS    FormatHasNoUndo
  , IdentityExpectation "IPS"        (CreateDirect       CreateIPS)       standardFixture LabelIPS    FormatHasNoUndo
  , IdentityExpectation "IPS32"      (CreateDirect       CreateIPS32)     standardFixture LabelIPS32  FormatHasNoUndo
  , IdentityExpectation "EBP"        (CreateDirect       CreateEBP)       standardFixture LabelEBP    FormatHasNoUndo
  , IdentityExpectation "UPS"        (CreateDifferential CreateUPS)       standardFixture LabelUPS    PatchIsItsOwnReverse
  , IdentityExpectation "PPF1"       (CreateDirect       CreatePPF1)      standardFixture LabelPPF1   FormatHasNoUndo
  , IdentityExpectation "PPF2"       (CreateDirect       CreatePPF2)      ppf2Fixture     LabelPPF2   FormatHasNoUndo
  , IdentityExpectation "PPF3"       (CreateDirect       CreatePPF3)      standardFixture LabelPPF3   PatchCarriesUndoData
  , IdentityExpectation "PPF4"       (CreateDirect       CreatePPF4)      standardFixture LabelPPF4   FormatHasNoUndo
  , IdentityExpectation "PMSR"       (CreateDirect       CreatePMSR)      standardFixture LabelPMSR   FormatHasNoUndo
  , IdentityExpectation "NINJA1"     (CreateDirect       CreateNINJA1)    standardFixture LabelNINJA1 FormatHasNoUndo
  , IdentityExpectation "DPS"        (CreateDifferential CreateDPS)       standardFixture LabelDPS    FormatHasNoUndo
  , IdentityExpectation "NINJA2"     (CreateDifferential CreateNINJA2)    standardFixture LabelNINJA2 FormatHasNoUndo
  , IdentityExpectation "APS-N64"    (CreateDirect       CreateAPSN64)    standardFixture LabelAPSN64 FormatHasNoUndo
  , IdentityExpectation "APS-GBA"    (CreateDifferential CreateAPSGBA)    standardFixture LabelAPSGBA FormatHasNoUndo
  , IdentityExpectation "GDIFF"      (CreateDifferential CreateGDIFF)     standardFixture LabelGDIFF  FormatHasNoUndo
  , IdentityExpectation "BSDiff"     (CreateDifferential CreateBSDiff)    standardFixture LabelBSDiff FormatHasNoUndo
  , IdentityExpectation "rfc-vcdiff" (CreateDifferential CreateRFCVCDIFF) standardFixture LabelVCDIFF  FormatHasNoUndo
  , IdentityExpectation "xdelta3"    (CreateDifferential CreateXDelta3)   standardFixture LabelVCDIFF  FormatHasNoUndo
  , IdentityExpectation "xdelta1"    (CreateDifferential CreateXDelta1)   standardFixture LabelXDelta1 FormatHasNoUndo
  ]

classifyAndIdentifyCase :: IdentityExpectation -> TestTree
classifyAndIdentifyCase expectation = testCase (expectationName expectation) $ do
  parsed <- createAndParse (expectationFormat expectation) (expectationFixture expectation) noMetadataRequested
  let identity = patchIdentity parsed
  assertEqual "format"   (expectedLabel expectation)                    (identifiedFormat identity)
  assertEqual "dialects" (acceptedDialects (expectedLabel expectation)) (applicableDialects identity)
  assertEqual "undo"     (expectedUndo expectation)                     (identifiedUndo identity)

-- | The classify assertion rides along: every row's created bytes must sort into the patch slot before they parse.
createAndParse :: CreateFormat -> (ByteString, ByteString) -> RequestedPatchMetadata -> IO SomePatch
createAndParse format (sourceBytes, targetBytes) meta =
  case createPatch format (fixtureXDelta1Names format) (InputFileContents sourceBytes) (OutputFileContents targetBytes) meta Nothing noConstraintsRequested noDialectsRequested of
    Left slapError -> assertFailureT ("create: " <> renderSlapError slapError)
    Right (CreateResult patchBytes _) -> do
      assertEqual "classify" (DroppedPatch patchBytes) (classifyDroppedFile (unPatchFileContents patchBytes))
      case parseSome noDialectsRequested EncodingUtf8 patchBytes of
        Left slapError -> assertFailureT ("parse: " <> renderSlapError slapError)
        Right parsed   -> pure parsed

-- | xdelta1 embeds a file-name pair the porcelain resolves from paths; the fixture resolves two literal basenames.
-- Two non-empty literals always resolve, so the 'error' arm firing means the resolver itself broke.
fixtureXDelta1Names :: CreateFormat -> Maybe ResolvedXDelta1FileNames
fixtureXDelta1Names (CreateDifferential CreateXDelta1) =
  case resolveXDelta1FileNames Nothing Nothing "fixture-source.bin" "fixture-target.bin" of
    Right resolved -> Just resolved
    Left slapError -> error ("fixtureXDelta1Names: " ++ Text.unpack (renderSlapError slapError))
fixtureXDelta1Names _ = Nothing

-- | Rom-classified bytes are exactly the ones 'parseSome' calls unrecognized.
-- The one asymmetry is the Yay0 envelope: it sorts as a patch on its prefix alone,
-- while the parse's answer depends on the bytes inside.
prop_classificationAgreesWithParse :: Property
prop_classificationAgreesWithParse = forAll genClassificationCandidate $ \rawBytes ->
  case classifyDroppedFile rawBytes of
    DroppedRom _ -> case parseSome noDialectsRequested EncodingUtf8 (PatchFileContents rawBytes) of
      Left UnrecognizedFormat -> property True
      Left otherError -> counterexample ("rom-classified bytes refused differently: " <> Text.unpack (renderSlapError otherError)) False
      Right _         -> counterexample "rom-classified bytes parsed as a patch" False
    DroppedPatch _ -> case parseSome noDialectsRequested EncodingUtf8 (PatchFileContents rawBytes) of
      Left UnrecognizedFormat | not (isYay0 rawBytes) ->
        counterexample "patch-classified bytes came back unrecognized" False
      _ -> property True

-- | Random bytes, a quarter of them wearing a recognizable prefix over a random tail —
-- unstructured bytes essentially never spell one, and the prefixed cases are where the agreement's patch arm lives.
genClassificationCandidate :: Gen ByteString
genClassificationCandidate = frequency
  [ (3, genByteString)
  , (1, (<>) <$> elements recognizablePrefixes <*> genByteString)
  ]
  where
    recognizablePrefixes = ["Yay0", ipsMagicBytes, bpsMagicBytes, upsMagicBytes, ppf3MagicBytes]

test_ppf1IdentityOffersOriginAxis :: IO ()
test_ppf1IdentityOffersOriginAxis = do
  parsed <- createAndParse (CreateDirect CreatePPF1) standardFixture noMetadataRequested
  assertEqual "dialects" (Set.singleton PPF1OriginAxis) (applicableDialects (patchIdentity parsed))

test_ppf3WithoutUndoAnswersAuthorOmitted :: IO ()
test_ppf3WithoutUndoAnswersAuthorOmitted = do
  parsed <- createAndParse (CreateDirect CreatePPF3) standardFixture
              noMetadataRequested { requestedUndoInclusion = Just OmitUndoData }
  assertEqual "undo" AuthorOmittedUndoData (identifiedUndo (patchIdentity parsed))

test_yay0EnvelopeSortsAsPatch :: IO ()
test_yay0EnvelopeSortsAsPatch = do
  let envelopeBytes = "Yay0" <> ByteString.replicate 16 0
  case classifyDroppedFile envelopeBytes of
    DroppedPatch _ -> pure ()
    DroppedRom _   -> assertFailure "Yay0 envelope sorted into the rom slot"

test_nestedYay0EnvelopeRefused :: IO ()
test_nestedYay0EnvelopeRefused =
  case parseSome noDialectsRequested EncodingUtf8 (PatchFileContents nestedEnvelope) of
    Left NestedYay0Envelope -> pure ()
    Left otherError         -> assertFailureT ("refused differently: " <> renderSlapError otherError)
    Right _                 -> assertFailure "a Yay0 envelope holding another Yay0 envelope parsed as a patch"
  where
    nestedEnvelope = yay0EnvelopeOfLiterals ("Yay0" <> ByteString.replicate 12 0)

-- | Wrap @payload@ as a real Yay0 stream spelling every byte as a literal:
-- all-ones command bytes, an empty link table, and the payload verbatim as chunk data.
yay0EnvelopeOfLiterals :: ByteString -> ByteString
yay0EnvelopeOfLiterals payload =
  "Yay0"
  <> word32BEBytes (fromIntegral (ByteString.length payload))
  <> word32BEBytes chunkDataOffset
  <> word32BEBytes chunkDataOffset
  <> ByteString.replicate commandByteCount 0xFF
  <> payload
  where
    commandByteCount = (ByteString.length payload + 7) `div` 8
    chunkDataOffset  = fromIntegral (16 + commandByteCount)
