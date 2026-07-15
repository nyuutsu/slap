{-# LANGUAGE OverloadedStrings #-}

-- | The slap-web boundary: the surface census, the identity projection crossing it, and the emit checks.
module Props.Web (webTests) where

import Slap.Convert (CreateFormat(..), DifferentialCreate(..), DirectCreate(..),
                     RequestedDialects(..), RequestedPatchMetadata(..), advertisedCreateFormats,
                     lookupCreateFormatToken, noConstraintsRequested, noDialectsRequested,
                     noMetadataRequested)
import Slap.Checksum (CRC32(..), MD5Hash(..), SHA1Hash(..))
import Slap.Create (createPatch)
import Slap.Dialect (Dialect(..))
import Slap.FileContents (InputFileContents(..), OutputFileContents(..), PatchFileContents(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.Header (InputHeaderDirective(TakeInputAsIs))
import Slap.Measure (FileSize(..))
import Slap.MetadataField (MetadataField(..), MetadataRequest(..))
import Slap.PPF1.Types (PPF1Origin(PPF1OriginAmiga))
import Slap.Status (CreateResult(..), SlapError(..), SourceRequiredCause(..), renderSlapError)
import Slap.Text (EncodedText(..), EncodingName(EncodingUtf8))
import Slap.VCDIFF.SecondaryCompression (secondaryCompressorTokens)
import Slap.Verify (VerificationPolicy(EnforceVerification))
import Slap.Web

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.List (nub)
import Data.List.NonEmpty (NonEmpty(..))
import qualified Data.Set as Set
import Test.Tasty
import Test.Tasty.HUnit

import Props.Helpers (assertFailureT)

webTests :: TestTree
webTests = testGroup "Web"
  [ testCase "the format census is the advertised token list"      test_formatCensusMatchesAdvertisedTokens
  , testCase "every format row's token names its own target"       test_tokenNamesItsOwnTarget
  , testCase "xdelta3 is the one row with secondary choices"       test_secondaryChoicesCensus
  , testCase "the console census covers every header once"         test_consoleCensusCoversEveryHeader
  , testCase "a created BPS identifies across the boundary"        test_identifyCreatedBPS
  , testCase "unrecognized bytes refuse with the engine's own error" test_identifyUnrecognizedBytes
  , testCase "describeRom reproduces the published digests of a known input" test_describeRomKnownAnswers
  , testGroup "emit checks"
      [ testCase "a plain BPS create is Ready"                          test_checkCreateBPSReady
      , testCase "a title aimed at IPS gaps with its own drop"          test_checkCreateTitleOnIPS
      , testCase "a growing PPF1 pair gaps toward a different format"   test_checkCreatePPF1Grow
      , testCase "IPS to bps without a source asks for one"             test_checkConvertIPSToBPSNeedsSource
      , testCase "the same conversion with a source in hand is Ready"   test_checkConvertIPSToBPSWithSource
      , testCase "a differential source without a source rom asks too"  test_checkConvertBPSToIPSNeedsSource
      , testCase "a stale Amiga toggle gaps with its own drop"          test_checkConvertStaleAmigaToggle
      , testCase "an unparseable patch is the Left, not a gap"          test_checkConvertUnrecognized
      ]
  ]

test_formatCensusMatchesAdvertisedTokens :: Assertion
test_formatCensusMatchesAdvertisedTokens =
  map formatToken (surfaceFormats describeSurface) @?= advertisedCreateFormats

test_tokenNamesItsOwnTarget :: Assertion
test_tokenNamesItsOwnTarget = sequence_
  [ assertEqual (formatToken row) (Just (formatCreateTarget row)) (lookupCreateFormatToken (formatToken row))
  | row <- surfaceFormats describeSurface ]

test_secondaryChoicesCensus :: Assertion
test_secondaryChoicesCensus = do
  [formatToken row | row <- surfaceFormats describeSurface, not (null (formatSecondaryChoices row))] @?= ["xdelta3"]
  sequence_
    [ formatSecondaryChoices row @?= map fst secondaryCompressorTokens
    | row <- surfaceFormats describeSurface, formatToken row == "xdelta3" ]

test_consoleCensusCoversEveryHeader :: Assertion
test_consoleCensusCoversEveryHeader = do
  let censusRows = surfaceConsoleHeaders describeSurface
  map describedConsoleHeader censusRows @?= [minBound .. maxBound]
  assertBool "console tokens collide" (nub (map consoleToken censusRows) == map consoleToken censusRows)

test_identifyCreatedBPS :: Assertion
test_identifyCreatedBPS = do
  bpsPatch <- createdFixturePatch (CreateDifferential CreateBPS)
  identifyPatch noDialectsRequested EncodingUtf8 bpsPatch
    @?= Right PatchIdentity { identifiedFormat   = LabelBPS
                            , applicableDialects = Set.empty
                            , identifiedUndo     = FormatHasNoUndo }

test_identifyUnrecognizedBytes :: Assertion
test_identifyUnrecognizedBytes =
  identifyPatch noDialectsRequested EncodingUtf8 (PatchFileContents "this file is nobody's patch")
    @?= Left UnrecognizedFormat

fixtureSourceBytes, fixtureTargetBytes :: ByteString
fixtureSourceBytes = ByteString.pack [0 .. 63]
fixtureTargetBytes = ByteString.pack ([0 .. 31] <> [0xAA] <> [33 .. 63])

createdFixturePatch :: CreateFormat -> IO PatchFileContents
createdFixturePatch format =
  case createPatch format Nothing (InputFileContents fixtureSourceBytes) (OutputFileContents fixtureTargetBytes)
                    noMetadataRequested Nothing noConstraintsRequested noDialectsRequested of
    Left slapError -> assertFailureT ("create: " <> renderSlapError slapError)
    Right (CreateResult patchBytes _advisories) -> pure patchBytes

plainCreateRequest :: CreateFormat -> CreateRequest
plainCreateRequest target = CreateRequest
  { createTargetFormat = target
  , createOriginal     = InputFileContents fixtureSourceBytes
  , createModified     = OutputFileContents fixtureTargetBytes
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

test_checkConvertIPSToBPSNeedsSource :: Assertion
test_checkConvertIPSToBPSNeedsSource = do
  ipsPatch <- createdFixturePatch (CreateDirect CreateIPS)
  checkConvert (plainConvertRequest ipsPatch (CreateDifferential CreateBPS))
    @?= Right (Blocked (Gap (DiffRequiresSource LabelBPS) (ProvideSourceRom :| []) :| []))

test_checkConvertIPSToBPSWithSource :: Assertion
test_checkConvertIPSToBPSWithSource = do
  ipsPatch <- createdFixturePatch (CreateDirect CreateIPS)
  let request = (plainConvertRequest ipsPatch (CreateDifferential CreateBPS))
        { convertSourceRom = Just (MatchedRom (InputFileContents fixtureSourceBytes) TakeInputAsIs) }
  checkConvert request @?= Right Ready

test_checkConvertBPSToIPSNeedsSource :: Assertion
test_checkConvertBPSToIPSNeedsSource = do
  bpsPatch <- createdFixturePatch (CreateDifferential CreateBPS)
  checkConvert (plainConvertRequest bpsPatch (CreateDirect CreateIPS))
    @?= Right (Blocked (Gap (ConvertRequiresSource LabelBPS SourcePatchIsDifferential)
                            (ProvideSourceRom :| []) :| []))

test_checkConvertStaleAmigaToggle :: Assertion
test_checkConvertStaleAmigaToggle = do
  bpsPatch <- createdFixturePatch (CreateDifferential CreateBPS)
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
