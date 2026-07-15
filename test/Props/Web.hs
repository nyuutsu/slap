{-# LANGUAGE OverloadedStrings #-}

-- | The slap-web boundary: the surface census, and the identity projection crossing it.
module Props.Web (webTests) where

import Slap.Convert (CreateFormat(..), DifferentialCreate(..), advertisedCreateFormats,
                     lookupCreateFormatToken, noConstraintsRequested, noDialectsRequested,
                     noMetadataRequested)
import Slap.Checksum (CRC32(..), MD5Hash(..), SHA1Hash(..))
import Slap.Create (createPatch)
import Slap.FileContents (InputFileContents(..), OutputFileContents(..), PatchFileContents(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.Measure (FileSize(..))
import Slap.Status (CreateResult(..), SlapError(..), renderSlapError)
import Slap.Text (EncodingName(EncodingUtf8))
import Slap.VCDIFF.SecondaryCompression (secondaryCompressorTokens)
import Slap.Web

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.List (nub)
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
test_identifyCreatedBPS =
  case createPatch (CreateDifferential CreateBPS) Nothing (InputFileContents sourceBytes) (OutputFileContents targetBytes)
                   noMetadataRequested Nothing noConstraintsRequested noDialectsRequested of
    Left slapError -> assertFailureT ("create: " <> renderSlapError slapError)
    Right (CreateResult patchBytes _advisories) ->
      identifyPatch noDialectsRequested EncodingUtf8 patchBytes
        @?= Right PatchIdentity { identifiedFormat   = LabelBPS
                                , applicableDialects = Set.empty
                                , identifiedUndo     = FormatHasNoUndo }
  where
    sourceBytes, targetBytes :: ByteString
    sourceBytes = ByteString.pack [0 .. 63]
    targetBytes = ByteString.pack ([0 .. 31] <> [0xAA] <> [33 .. 63])

test_identifyUnrecognizedBytes :: Assertion
test_identifyUnrecognizedBytes =
  identifyPatch noDialectsRequested EncodingUtf8 (PatchFileContents "this file is nobody's patch")
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
