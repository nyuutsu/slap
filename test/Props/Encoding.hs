-- | Per-format metadata/field encoding tests.
--
-- These test the text-encoding layer where it meets specific formats:
-- PPF3 description (locale-bounded), DPS name/author/version (locale,
-- one field per overflow), APS-N64 description (locale), RUP title/
-- author/description (UTF-8 or system, selectable via PATCH_ENC byte),
-- EBP JSON metadata (UTF-8). Also: EncodingGap warnings when a
-- PatchContents with a known encoding flows through a format that
-- doesn't carry the encoding flag; and UTF-8 inference for opaque
-- description bytes during RUP creation.
module Props.Encoding (encodingTests) where

import Slap.IPS.Create (buildEBPMetadataJSON)
import Slap.IPS.Describe (jsonPairs, jsonFieldCI)
import qualified Slap.PPF.Parse as PPF
import qualified Slap.PPF.Types as PPF
import qualified Slap.PPF.Create as PPF
import qualified Slap.DPS.Types as DPS
import qualified Slap.DPS.Parse as DPS
import qualified Slap.DPS.Create as DPS
import qualified Slap.APSN64.Types as APSN64
import qualified Slap.APSN64.Parse as APSN64
import qualified Slap.APSN64.Create as APSN64
import qualified Slap.RUP.Types as RUP
import qualified Slap.RUP.Parse as RUP
import qualified Slap.RUP.Create as RUP

import Slap.Binary (trimNull)
import Slap.Error (SlapWarning(..), CreateResult(..), FieldName(..), renderSlapError)
import Slap.FormatLabel (FormatLabel(..))
import Slap.Measure (Offset(..), Length(..), FileSize(..), Hunk(..))
import Slap.FileContents (SourceFileContents(..), TargetFileContents(..))
import Slap.TextEncoding (isValidUtf8, encodeUtf8Field, encodeLocaleField, decodeLocaleField)
import Slap.Convert (PatchContents(..), DirectCreate(..), DiffCreate(..), CreateFormat(..),
                     PatchEncoding(..), emptyContents, formatSpecification,
                     defaultMeta, convertDirect, conversionNotes, createFromMemory)

import qualified Data.ByteString as ByteString
import Data.Maybe (fromMaybe)
import Test.Tasty
import Test.Tasty.HUnit
import Test.Tasty.QuickCheck

import Props.Helpers

encodingTests :: TestTree
encodingTests = testGroup "Encoding"
  [ testGroup "EBP"
      [ testCase "non-ascii-utf8" test_ebpUtf8
      ]
  , testGroup "PPF3"
      [ testCase "non-ascii-round-trip" test_ppf3NonAsciiRoundTrip
      , testCase "overflow-warning" test_ppf3OverflowWarning
      , testCase "empty-description" test_ppf3EmptyDescription
      , testCase "encoding-gap-ppf3" test_encodingGapPPF3
      ]
  , testGroup "DPS"
      [ testCase "non-ascii-round-trip" test_dpsNonAsciiRoundTrip
      , testCase "overflow-per-field" test_dpsOverflowPerField
      , testCase "all-fields-overflow" test_dpsAllFieldsOverflow
      ]
  , testGroup "APS-N64"
      [ testCase "non-ascii-round-trip" test_apsN64NonAsciiRoundTrip
      , testCase "overflow-warning" test_apsN64OverflowWarning
      , testCase "encoding-gap-apsn64" test_encodingGapAPSN64
      ]
  , testGroup "RUP"
      [ testProperty "round-trip-utf8" prop_rupUTF8RoundTrip
      , testProperty "round-trip-system" prop_rupSystemRoundTrip
      , testProperty "non-ascii-utf8" prop_rupNonAsciiUTF8
      , testProperty "field-overflow-truncated" prop_rupFieldOverflow
      , testProperty "patch-enc-byte-utf8" prop_rupPatchEncByteUTF8
      , testProperty "patch-enc-byte-system" prop_rupPatchEncByteSystem
      , testProperty "utf8-decode-round-trip" prop_rupUTF8Decode
      , testCase "non-ascii-system" test_rupNonAsciiSystem
      , testCase "utf8-inference-valid" test_utf8InferenceValid
      , testCase "utf8-inference-invalid" test_utf8InferenceInvalid
      ]
  , testGroup "Conversion"
      [ testCase "metadata-round-trip" test_conversionMetadataRoundTrip
      ]
  ]

----------------------------------------------------------------------------
-- EBP
----------------------------------------------------------------------------

-- | EBP JSON metadata must round-trip non-ASCII characters through UTF-8.
test_ebpUtf8 :: IO ()
test_ebpUtf8 = do
  let json = buildEBPMetadataJSON "Pok\xE9mon" "Andr\xE9" "\xDCn\xEFc\xF6d\xE9 \x2122"
      pairs = jsonPairs json
  assertEqual "title" (Just "Pok\xE9mon") (jsonFieldCI pairs "title")
  assertEqual "author" (Just "Andr\xE9") (jsonFieldCI pairs "author")
  assertEqual "description" (Just "\xDCn\xEFc\xF6d\xE9 \x2122") (jsonFieldCI pairs "description")

----------------------------------------------------------------------------
-- PPF3
----------------------------------------------------------------------------

-- | PPF3 create -> parse -> decode with non-ASCII description.
test_ppf3NonAsciiRoundTrip :: IO ()
test_ppf3NonAsciiRoundTrip = do
  let description = "Pok\xE9mon Andr\xE9"
      CreateResult patchBytes _ = PPF.encodePPF3 [] description Nothing Nothing PPF.BIN
  case PPF.parsePatch patchBytes of
    Left slapError -> assertFailure ("parse: " ++ renderSlapError slapError)
    Right parsed ->
      let decoded = decodeLocaleField (trimNull (PPF.ppfDescription parsed))
      in assertEqual "description round-trip" description decoded

-- | PPF3 create with overlong description produces FieldTruncated warning.
test_ppf3OverflowWarning :: IO ()
test_ppf3OverflowWarning = do
  let longDescription = replicate 60 'A'
      CreateResult patchBytes warnings = PPF.encodePPF3 [] longDescription Nothing Nothing PPF.BIN
      hasFieldTruncated = any (isFieldTruncatedFor LabelPPF3) warnings
  assertBool "expected FieldTruncated warning" hasFieldTruncated
  case PPF.parsePatch patchBytes of
    Left slapError -> assertFailure ("parse: " ++ renderSlapError slapError)
    Right parsed ->
      assertBool "description at most 50 bytes"
        (ByteString.length (PPF.ppfDescription parsed) <= unLength PPF.ppfDescriptionLength)

-- | PPF3 create with empty description: no warnings, empty after trimming.
test_ppf3EmptyDescription :: IO ()
test_ppf3EmptyDescription = do
  let CreateResult patchBytes warnings = PPF.encodePPF3 [] "" Nothing Nothing PPF.BIN
  assertBool "no FieldTruncated warning" (not (any (isFieldTruncatedFor LabelPPF3) warnings))
  case PPF.parsePatch patchBytes of
    Left slapError -> assertFailure ("parse: " ++ renderSlapError slapError)
    Right parsed ->
      assertEqual "empty description" "" (decodeLocaleField (trimNull (PPF.ppfDescription parsed)))

-- | EncodingGap warning: PatchContents with known encoding into PPF3 (no encoding flag).
test_encodingGapPPF3 :: IO ()
test_encodingGapPPF3 = do
  let contents = (emptyContents [Hunk (Offset 0) (ByteString.pack [1])])
        { contentsPatchEncoding = Just PatchEncodingUTF8
        , contentsDescription   = Just (encodeLocaleField "hello")
        }
      spec = formatSpecification CreatePPF3 False False
      warnings = conversionNotes contents CreatePPF3 spec defaultMeta
      hasEncodingGap = any isEncodingGap warnings
  assertBool "expected EncodingGap warning for PPF3" hasEncodingGap
  where
    isEncodingGap (EncodingGap _ _) = True
    isEncodingGap _                 = False

----------------------------------------------------------------------------
-- DPS
----------------------------------------------------------------------------

test_dpsNonAsciiRoundTrip :: IO ()
test_dpsNonAsciiRoundTrip = do
  let source = ByteString.pack [0]
      target = ByteString.pack [1]
      CreateResult patchBytes _ = DPS.createDPS (SourceFileContents source) (TargetFileContents target) "Pok\xE9mon" "Andr\xE9" "1.0" DPS.DPSStable
  case DPS.parseDPS patchBytes of
    Left slapError -> assertFailure ("parse: " ++ renderSlapError slapError)
    Right parsed -> do
      assertEqual "name"    "Pok\xE9mon" (decodeLocaleField (DPS.dpsName parsed))
      assertEqual "author"  "Andr\xE9"   (decodeLocaleField (DPS.dpsAuthor parsed))
      assertEqual "version" "1.0"        (decodeLocaleField (DPS.dpsVersion parsed))

test_dpsOverflowPerField :: IO ()
test_dpsOverflowPerField = do
  let source = ByteString.pack [0]
      target = ByteString.pack [1]
      longName = replicate 80 'A'
      CreateResult patchBytes warnings = DPS.createDPS (SourceFileContents source) (TargetFileContents target) longName "ok" "1.0" DPS.DPSStable
      truncatedWarnings = filter (isFieldTruncatedFor LabelDPS) warnings
  assertEqual "exactly one FieldTruncated" 1 (length truncatedWarnings)
  assertBool "truncated field is name"
    (all (\warning -> case warning of FieldTruncated _ FieldPatchName _ _ -> True; _ -> False) truncatedWarnings)
  case DPS.parseDPS patchBytes of
    Left slapError -> assertFailure ("parse: " ++ renderSlapError slapError)
    Right parsed -> do
      assertBool "name at most 64 bytes" (ByteString.length (DPS.dpsName parsed) <= DPS.dpsFieldWidth)
      assertEqual "author intact"  "ok"  (decodeLocaleField (DPS.dpsAuthor parsed))
      assertEqual "version intact" "1.0" (decodeLocaleField (DPS.dpsVersion parsed))

test_dpsAllFieldsOverflow :: IO ()
test_dpsAllFieldsOverflow = do
  let source = ByteString.pack [0]
      target = ByteString.pack [1]
      longField = replicate 80 'A'
      CreateResult _ warnings = DPS.createDPS (SourceFileContents source) (TargetFileContents target) longField longField longField DPS.DPSStable
      truncatedWarnings = filter (isFieldTruncatedFor LabelDPS) warnings
  assertEqual "exactly three FieldTruncated" 3 (length truncatedWarnings)

----------------------------------------------------------------------------
-- APS-N64
----------------------------------------------------------------------------

test_apsN64NonAsciiRoundTrip :: IO ()
test_apsN64NonAsciiRoundTrip = do
  let description = "Pok\xE9mon"
      CreateResult patchBytes _ = APSN64.encodeAPSN64 [] 256 description
  case APSN64.parseAPSN64 patchBytes of
    Left slapError -> assertFailure ("parse: " ++ renderSlapError slapError)
    Right (APSN64.APSN64Patch header _) ->
      assertEqual "description round-trip" description
        (decodeLocaleField (trimNull (APSN64.apsN64Description header)))

test_apsN64OverflowWarning :: IO ()
test_apsN64OverflowWarning = do
  let longDescription = replicate 60 'A'
      CreateResult _ warnings = APSN64.encodeAPSN64 [] 256 longDescription
      hasFieldTruncated = any (isFieldTruncatedFor LabelAPSN64) warnings
  assertBool "expected FieldTruncated warning" hasFieldTruncated

test_encodingGapAPSN64 :: IO ()
test_encodingGapAPSN64 = do
  let contents = (emptyContents [Hunk (Offset 0) (ByteString.pack [1])])
        { contentsPatchEncoding = Just PatchEncodingUTF8
        , contentsDescription   = Just (encodeLocaleField "hello")
        , contentsDestinationSize = Just (FileSize 256)
        }
      spec = formatSpecification CreateAPSN64 False False
      warnings = conversionNotes contents CreateAPSN64 spec defaultMeta
      hasEncodingGap = any isEncodingGap warnings
  assertBool "expected EncodingGap warning for APS-N64" hasEncodingGap
  where
    isEncodingGap (EncodingGap _ _) = True
    isEncodingGap _                 = False

----------------------------------------------------------------------------
-- RUP
----------------------------------------------------------------------------

prop_rupUTF8RoundTrip :: Property
prop_rupUTF8RoundTrip = forAll genPair $ \(source, target) ->
  let info = emptyRupInfo { RUP.rupTitle = Just (RUP.encodeRUPString RUP.PatchEncodingUTF8 "Test Patch")
                          , RUP.rupAuthor = Just (RUP.encodeRUPString RUP.PatchEncodingUTF8 "slap") }
      patch = RUP.createRUP (SourceFileContents source) (TargetFileContents target) info RUP.Ninja2Raw RUP.PatchEncodingUTF8
  in case RUP.parseRUP patch of
       Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
       Right parsed ->
         fmap (RUP.decodeRUPField RUP.PatchEncodingUTF8) (RUP.rupTitle (RUP.rupHeader parsed)) === Just "Test Patch" .&&.
         fmap (RUP.decodeRUPField RUP.PatchEncodingUTF8) (RUP.rupAuthor (RUP.rupHeader parsed)) === Just "slap"

prop_rupSystemRoundTrip :: Property
prop_rupSystemRoundTrip = forAll genPair $ \(source, target) ->
  let info = emptyRupInfo { RUP.rupTitle = Just (RUP.encodeRUPString RUP.PatchEncodingSystem "Test Patch")
                          , RUP.rupAuthor = Just (RUP.encodeRUPString RUP.PatchEncodingSystem "slap") }
      patch = RUP.createRUP (SourceFileContents source) (TargetFileContents target) info RUP.Ninja2Raw RUP.PatchEncodingSystem
  in case RUP.parseRUP patch of
       Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
       Right parsed ->
         fmap (RUP.decodeRUPField RUP.PatchEncodingSystem) (RUP.rupTitle (RUP.rupHeader parsed)) === Just "Test Patch" .&&.
         fmap (RUP.decodeRUPField RUP.PatchEncodingSystem) (RUP.rupAuthor (RUP.rupHeader parsed)) === Just "slap"

prop_rupNonAsciiUTF8 :: Property
prop_rupNonAsciiUTF8 = forAll genPair $ \(source, target) ->
  let titleStr = "Pok\233mon \241"
      info = emptyRupInfo { RUP.rupTitle = Just (RUP.encodeRUPString RUP.PatchEncodingUTF8 titleStr) }
      patch = RUP.createRUP (SourceFileContents source) (TargetFileContents target) info RUP.Ninja2Raw RUP.PatchEncodingUTF8
  in case RUP.parseRUP patch of
       Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
       Right parsed ->
         fmap (RUP.decodeRUPField RUP.PatchEncodingUTF8) (RUP.rupTitle (RUP.rupHeader parsed)) === Just titleStr

-- | Title whose UTF-8 encoding exceeds 256 bytes is silently truncated.
prop_rupFieldOverflow :: Property
prop_rupFieldOverflow = once $
  let longTitle = replicate 128 '\233' ++ "X"  -- 128 x 2-byte 'e' + 1 ASCII = 257 UTF-8 bytes > 256
      encodedTitle = RUP.encodeRUPString RUP.PatchEncodingUTF8 longTitle
      info = emptyRupInfo { RUP.rupTitle = Just encodedTitle }
      source = ByteString.pack [0]
      target = ByteString.pack [1]
      patch = RUP.createRUP (SourceFileContents source) (TargetFileContents target) info RUP.Ninja2Raw RUP.PatchEncodingUTF8
  in case RUP.parseRUP patch of
       Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
       Right parsed ->
         let titleBytes = fromMaybe ByteString.empty (RUP.rupTitle (RUP.rupHeader parsed))
         in counterexample ("title length: " ++ show (ByteString.length titleBytes)) $
            ByteString.length titleBytes <= 256 .&&.
            ByteString.isPrefixOf titleBytes encodedTitle .&&.
            isValidUtf8 titleBytes

prop_rupPatchEncByteUTF8 :: Property
prop_rupPatchEncByteUTF8 = forAll genPair $ \(source, target) ->
  let patch = RUP.createRUP (SourceFileContents source) (TargetFileContents target) emptyRupInfo RUP.Ninja2Raw RUP.PatchEncodingUTF8
  in case RUP.parseRUP patch of
       Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
       Right parsed -> RUP.rupPatchEncoding parsed === RUP.PatchEncodingUTF8

prop_rupPatchEncByteSystem :: Property
prop_rupPatchEncByteSystem = forAll genPair $ \(source, target) ->
  let patch = RUP.createRUP (SourceFileContents source) (TargetFileContents target) emptyRupInfo RUP.Ninja2Raw RUP.PatchEncodingSystem
  in case RUP.parseRUP patch of
       Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
       Right parsed -> RUP.rupPatchEncoding parsed === RUP.PatchEncodingSystem

prop_rupUTF8Decode :: Property
prop_rupUTF8Decode = forAll genPair $ \(source, target) ->
  let titleStr = "\1055\1072\1090\1095"  -- "Патч" (Cyrillic)
      info = emptyRupInfo { RUP.rupTitle = Just (RUP.encodeRUPString RUP.PatchEncodingUTF8 titleStr) }
      patch = RUP.createRUP (SourceFileContents source) (TargetFileContents target) info RUP.Ninja2Raw RUP.PatchEncodingUTF8
  in case RUP.parseRUP patch of
       Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
       Right parsed ->
         fmap (RUP.decodeRUPField RUP.PatchEncodingUTF8) (RUP.rupTitle (RUP.rupHeader parsed)) === Just titleStr

test_rupNonAsciiSystem :: IO ()
test_rupNonAsciiSystem = do
  let source = ByteString.pack [0]
      target = ByteString.pack [1]
      titleString = "Pok\xE9mon"
      info = emptyRupInfo { RUP.rupTitle = Just (RUP.encodeRUPString RUP.PatchEncodingSystem titleString) }
      patch = RUP.createRUP (SourceFileContents source) (TargetFileContents target) info RUP.Ninja2Raw RUP.PatchEncodingSystem
  case RUP.parseRUP patch of
    Left slapError -> assertFailure ("parse: " ++ renderSlapError slapError)
    Right parsed ->
      assertEqual "title round-trip" titleString
        (RUP.decodeRUPField RUP.PatchEncodingSystem
          (fromMaybe ByteString.empty (RUP.rupTitle (RUP.rupHeader parsed))))

-- | Opaque description bytes that happen to be valid UTF-8 → RUP PATCH_ENC=1.
test_utf8InferenceValid :: IO ()
test_utf8InferenceValid = do
  let source = ByteString.pack [0]
      target = ByteString.pack [1]
      contents = (emptyContents [])
        { contentsDescription = Just (encodeUtf8Field "Andr\xE9")
        }
  case createFromMemory (CreateDiff CreateRUP) (SourceFileContents source) (TargetFileContents target) defaultMeta (Just contents) of
    Left slapError -> assertFailure ("create: " ++ renderSlapError slapError)
    Right (CreateResult patchBytes _) ->
      case RUP.parseRUP patchBytes of
        Left slapError -> assertFailure ("parse: " ++ renderSlapError slapError)
        Right parsed ->
          assertEqual "valid UTF-8 description -> PatchEncodingUTF8"
            RUP.PatchEncodingUTF8 (RUP.rupPatchEncoding parsed)

-- | Opaque description bytes that are not valid UTF-8 → RUP PATCH_ENC=0.
test_utf8InferenceInvalid :: IO ()
test_utf8InferenceInvalid = do
  let source = ByteString.pack [0]
      target = ByteString.pack [1]
      contents = (emptyContents [])
        { contentsDescription = Just (ByteString.pack [0xC0, 0x41])
        }
  case createFromMemory (CreateDiff CreateRUP) (SourceFileContents source) (TargetFileContents target) defaultMeta (Just contents) of
    Left slapError -> assertFailure ("create: " ++ renderSlapError slapError)
    Right (CreateResult patchBytes _) ->
      case RUP.parseRUP patchBytes of
        Left slapError -> assertFailure ("parse: " ++ renderSlapError slapError)
        Right parsed ->
          assertEqual "invalid UTF-8 description -> PatchEncodingSystem"
            RUP.PatchEncodingSystem (RUP.rupPatchEncoding parsed)

----------------------------------------------------------------------------
-- Conversion metadata
----------------------------------------------------------------------------

-- | Conversion metadata round-trip: locale bytes through convertDirect to PPF3.
test_conversionMetadataRoundTrip :: IO ()
test_conversionMetadataRoundTrip = do
  let contents = (emptyContents [Hunk (Offset 0) (ByteString.pack [1])])
        { contentsDescription = Just (encodeLocaleField "Pok\xE9mon")
        }
  case convertDirect contents (CreateDirect CreatePPF3) defaultMeta of
    Left slapError -> assertFailure ("convert: " ++ renderSlapError slapError)
    Right (CreateResult patchBytes _) ->
      case PPF.parsePatch patchBytes of
        Left slapError -> assertFailure ("parse: " ++ renderSlapError slapError)
        Right parsed ->
          assertEqual "description round-trip through conversion"
            "Pok\xE9mon"
            (decodeLocaleField (trimNull (PPF.ppfDescription parsed)))
