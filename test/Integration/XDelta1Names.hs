{-# LANGUAGE OverloadedStrings #-}

-- | Behavioral tests for xdelta1's @from-name@ and @to-name@ header
-- fields: the create-side basename defaulting, the explicit-override
-- path, the empty-string honoring, the u16 length cap, the
-- convert-side inheritance / refusal matrix, and the type-level
-- invariant that the per-source-record name on the EDSIO source
-- list mirrors the header from-name.
--
-- These tests bypass the @slap@ binary and exercise the library
-- surfaces directly ('resolveXDelta1FileNames',
-- 'requireXDelta1FileNames', 'createXDelta1', 'parseXDelta1',
-- 'mergeRequestedMetadata') so the assertions land on the contract
-- the porcelain composes rather than on its string-rendered output.
module Integration.XDelta1Names (xdelta1NamesTests) where

import Integration.Skip (GroupPlan, MaybeTest(..), namedGroup)

import Slap.Convert
  ( RequestedPatchMetadata(..)
  , noMetadataRequested
  , mergeRequestedMetadata
  )
import Slap.Create (createXDelta1)
import Slap.Status (CreateResult(..), Parsed(..), SlapError(..), renderSlapError)
import Slap.FieldName (FieldName(..))
import Slap.FileContents (InputFileContents(..), OutputFileContents(..),
                          PatchFileContents(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.MetadataInclusion (VerificationInclusion(..))
import Slap.Text (EncodedText(..), EncodingName(..))
import Slap.XDelta1.Parse (parseXDelta1)
import Slap.XDelta1.Types (XDelta1Patch(..), XDelta1PatchCompression(..),
                           XDelta1FromName(..), XDelta1ToName(..),
                           ResolvedXDelta1FileNames,
                           resolveXDelta1FileNames,
                           requireXDelta1FileNames)

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.Text (Text)
import qualified Data.Text as Text
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (Assertion, testCase, assertEqual, assertFailure)

----------------------------------------------------------------------------
-- Shared fixtures
----------------------------------------------------------------------------

-- | Sample source and target bytes shared by every round-trip test.
-- Small enough to keep the suite snappy, large enough to ensure the
-- differ produces a non-trivial instruction stream.
sampleSource, sampleTarget :: ByteString
sampleSource = ByteString.replicate 1024 0x42
sampleTarget = ByteString.replicate 768  0x42 <> ByteString.replicate 256 0xFF

-- | u16 cap on each name's encoded byte length, as packed by
-- 'Slap.XDelta1.Create.encodeXDelta1'\'s @nameLengthsWord@. The
-- module-private constant in "Slap.XDelta1.Types" is the single
-- source of truth; this test-side mirror is a pin so that a future
-- change to the wire cap would force a deliberate update of both
-- numbers.
xdelta1NameByteCap :: Int
xdelta1NameByteCap = 0xFFFF

----------------------------------------------------------------------------
-- Test group
----------------------------------------------------------------------------

xdelta1NamesTests :: IO GroupPlan
xdelta1NamesTests = pure (namedGroup "xdelta1-names" (map WillRun trees))

trees :: [TestTree]
trees =
  [ testGroup "create"
      [ testCase "defaults: basename of source/target paths" defaultBasenamesCarry
      , testCase "explicit: --from-name TEXT and --to-name TEXT win"
          explicitNamesCarry
      , testCase "explicit empty: --from-name \"\" produces empty embedded bytes"
          explicitEmptyHonored
      , testCase "source-record name mirrors header from-name (xdelta1SourceName == xdelta1FromName)"
          sourceRecordNameMirrorsFromName
      ]
  , testGroup "length bounds"
      [ testCase "from-name exactly 65535 bytes: accepted" lengthAtBoundaryAccepted
      , testCase "both header names at 65535 bytes simultaneously: accepted"
          bothNamesAtBoundaryAccepted
      , testCase "from-name at cap also propagates to source-record name at cap"
          sourceRecordNameAtBoundary
      , testCase "from-name 65536 bytes: refused with FieldTooLong"
          lengthOneByteOverRefused
      , testCase "from-name ~1MB: refused with FieldTooLong"
          lengthFarOverRefused
      , testCase "to-name overflow: refused, identifies to-name field"
          toNameOverflowIdentified
      ]
  , testGroup "convert"
      [ testCase "from non-xdelta1 source, no flags: refused"
          convertFromBPSWithoutNamesRefused
      , testCase "from non-xdelta1 source, only --from-name: refused"
          convertFromBPSWithOnlyFromNameRefused
      , testCase "from non-xdelta1 source, both flags: accepted"
          convertFromBPSWithNamesAccepted
      , testCase "from xdelta1, no flags: inherited from source patch"
          convertXDeltaToXDeltaInherits
      , testCase "from xdelta1, --from-name only: CLI overrides from-name, to-name inherits"
          convertXDeltaToXDeltaPartialOverride
      ]
  ]

----------------------------------------------------------------------------
-- Wire-image probe shaped as a named record
----------------------------------------------------------------------------

-- | The three name fields slap emits on the xdelta1 wire: the two
-- header labels plus the per-source-record name inside the EDSIO
-- source list. Returned as a named record so call sites read the
-- field they mean (rather than 'fst'/'snd' on a tuple of three).
data ParsedXDelta1Names = ParsedXDelta1Names
  { parsedXDelta1FromName       :: !XDelta1FromName
  , parsedXDelta1ToName         :: !XDelta1ToName
  , parsedXDelta1SourceRecordName :: !XDelta1FromName
  } deriving (Eq, Show)

----------------------------------------------------------------------------
-- Helpers
----------------------------------------------------------------------------

-- | Wrap a 'Text' name as the locale-tagged 'EncodedText' the
-- resolvers now consume. Under stage 3b the resolvers take typed
-- text rather than raw bytes; CLI inputs and test fixtures both
-- arrive as 'String' \/ 'Text' from the user's perspective.
localeName :: Text -> EncodedText
localeName = EncodedText EncodingLocale

-- | Resolve a pair of explicit override names into a
-- 'ResolvedXDelta1FileNames'. Both 'Maybe' arguments are 'Just'
-- here; the filepath defaulting branch isn't relevant when the test
-- is feeding explicit values, so the placeholder paths are fine.
resolveExplicit
  :: Text -> Text
  -> Either SlapError ResolvedXDelta1FileNames
resolveExplicit fromText toText =
  resolveXDelta1FileNames (Just (localeName fromText)) (Just (localeName toText))
                          "ignored-source-path" "ignored-target-path"

-- | Build an xdelta1 patch from 'sampleSource' \/ 'sampleTarget' with
-- both name slots set to explicit text values. The resolver runs the
-- cap check; if it fails or 'createXDelta1' errors, the test fails
-- immediately.
createXDelta1WithNames
  :: Text -> Text -> IO ByteString
createXDelta1WithNames fromText toText = do
  resolved <- case resolveExplicit fromText toText of
    Right res -> pure res
    Left err  -> assertFailure ("resolveXDelta1FileNames: " ++ renderSlapError err)
  case createXDelta1 IncludeVerification CompressedPatch resolved
         (InputFileContents sampleSource) (OutputFileContents sampleTarget) of
    Left err -> assertFailure ("createXDelta1: " ++ renderSlapError err)
    Right (CreateResult (PatchFileContents wireBytes) _warnings) ->
      pure wireBytes

-- | Round-trip: build a patch with the supplied names, parse it
-- back, and hand the assertion the three name fields slap emitted
-- on the wire.
withRoundTrippedNames
  :: Text -> Text
  -> (ParsedXDelta1Names -> Assertion)
  -> Assertion
withRoundTrippedNames fromText toText check = do
  wireBytes <- createXDelta1WithNames fromText toText
  parsed <- parseAndExtractNames wireBytes
  check parsed

-- | Parse an xdelta1 wire image and pull out its three embedded name
-- fields.
parseAndExtractNames :: ByteString -> IO ParsedXDelta1Names
parseAndExtractNames wireBytes =
  case parseXDelta1 (PatchFileContents wireBytes) of
    Left err -> assertFailure ("parseXDelta1: " ++ renderSlapError err)
    Right (Parsed patch _warnings) -> pure ParsedXDelta1Names
      { parsedXDelta1FromName         = xdelta1FromName   patch
      , parsedXDelta1ToName           = xdelta1ToName     patch
      , parsedXDelta1SourceRecordName = xdelta1SourceName patch
      }

----------------------------------------------------------------------------
-- Create-side assertions
----------------------------------------------------------------------------

defaultBasenamesCarry :: Assertion
defaultBasenamesCarry = do
  resolved <- case resolveXDelta1FileNames Nothing Nothing
                     "/some/where/source.gba" "/elsewhere/target.gba" of
    Right res -> pure res
    Left err  -> assertFailure ("resolveXDelta1FileNames: " ++ renderSlapError err)
  case createXDelta1 IncludeVerification CompressedPatch resolved
         (InputFileContents sampleSource) (OutputFileContents sampleTarget) of
    Left err -> assertFailure ("createXDelta1: " ++ renderSlapError err)
    Right (CreateResult (PatchFileContents wireBytes) _warnings) -> do
      parsed <- parseAndExtractNames wireBytes
      assertEqual "from-name basename" (XDelta1FromName (localeName "source.gba"))
        (parsedXDelta1FromName parsed)
      assertEqual "to-name basename"   (XDelta1ToName (localeName "target.gba"))
        (parsedXDelta1ToName parsed)

explicitNamesCarry :: Assertion
explicitNamesCarry =
  withRoundTrippedNames "Dragon Quest" "Dragon Quest patched" $ \parsed -> do
    assertEqual "from-name embedded verbatim"
      (XDelta1FromName (localeName "Dragon Quest"))         (parsedXDelta1FromName parsed)
    assertEqual "to-name embedded verbatim"
      (XDelta1ToName   (localeName "Dragon Quest patched")) (parsedXDelta1ToName   parsed)

explicitEmptyHonored :: Assertion
explicitEmptyHonored = withRoundTrippedNames "" "target" $ \parsed -> do
  assertEqual "from-name: empty stays empty"
    (XDelta1FromName (localeName ""))       (parsedXDelta1FromName parsed)
  assertEqual "to-name: unchanged"
    (XDelta1ToName   (localeName "target")) (parsedXDelta1ToName parsed)

-- | xdelta1's EDSIO source list carries a per-source-record name on
-- the file-source record (separate from the header from-name).
-- Slap's create path resolves a single 'XDelta1FromName' and pipes
-- it into both wire fields: the header from-name 'xdelta1FromName'
-- and the source-record name 'xdelta1SourceName'. The type model
-- already reflects this (both fields are 'XDelta1FromName'); this
-- test pins the runtime equality so a divergence in
-- 'assemblePatch' would be caught.
sourceRecordNameMirrorsFromName :: Assertion
sourceRecordNameMirrorsFromName =
  withRoundTrippedNames "real-source.bin" "real-target.bin" $ \parsed -> do
    assertEqual "source-record name mirrors header from-name"
      (parsedXDelta1FromName parsed)
      (parsedXDelta1SourceRecordName parsed)
    assertEqual "source-record name is the real basename, not 'source'"
      (XDelta1FromName (localeName "real-source.bin"))
      (parsedXDelta1SourceRecordName parsed)

----------------------------------------------------------------------------
-- Length-bound assertions
----------------------------------------------------------------------------

-- | An ASCII 'Text' of the supplied codepoint count. Used for the
-- byte-cap tests: every codepoint encodes to one byte under any
-- ASCII-clean locale, so the codepoint count equals the encoded
-- byte count the resolver's cap-check sees.
asciiText :: Int -> Text
asciiText n = Text.replicate n (Text.singleton 'a')

lengthAtBoundaryAccepted :: Assertion
lengthAtBoundaryAccepted = do
  let huge = asciiText xdelta1NameByteCap  -- 'a' × 65535
  withRoundTrippedNames huge "target" $ \parsed ->
    assertEqual "boundary-length from-name round-trips"
      (XDelta1FromName (localeName huge)) (parsedXDelta1FromName parsed)

-- | Exercise the wire packing of both lengths into one Word32 (top
-- 16 bits = from-name length, bottom 16 = to-name length); a buggy
-- bit-shift could break specifically when both fields hit the cap
-- simultaneously.
bothNamesAtBoundaryAccepted :: Assertion
bothNamesAtBoundaryAccepted = do
  let huge = asciiText xdelta1NameByteCap
  withRoundTrippedNames huge huge $ \parsed -> do
    assertEqual "from-name at boundary"
      (XDelta1FromName (localeName huge)) (parsedXDelta1FromName parsed)
    assertEqual "to-name at boundary"
      (XDelta1ToName   (localeName huge)) (parsedXDelta1ToName parsed)

-- | The source-record name shares its bytes with the header
-- from-name. If from-name is at the cap, the source-record name is
-- too — and the wire encoder must accept it.
sourceRecordNameAtBoundary :: Assertion
sourceRecordNameAtBoundary = do
  let huge = asciiText xdelta1NameByteCap
  withRoundTrippedNames huge "target" $ \parsed -> do
    assertEqual "source-record name carries the same bytes"
      (XDelta1FromName (localeName huge)) (parsedXDelta1SourceRecordName parsed)

lengthOneByteOverRefused :: Assertion
lengthOneByteOverRefused = do
  let oversize = asciiText (xdelta1NameByteCap + 1)
  case resolveExplicit oversize "target" of
    Right _ -> assertFailure "expected FieldTooLong for 65536-byte from-name"
    Left (FieldTooLong LabelXDelta1 FieldXDelta1FromName _ _) -> pure ()
    Left other -> assertFailure
      ("expected FieldTooLong LabelXDelta1 FieldXDelta1FromName but got: " ++ show other)

lengthFarOverRefused :: Assertion
lengthFarOverRefused = do
  let oneMeg = asciiText (1024 * 1024)
  case resolveExplicit oneMeg "target" of
    Right _ -> assertFailure "expected FieldTooLong for 1 MB from-name"
    Left (FieldTooLong LabelXDelta1 FieldXDelta1FromName _ _) -> pure ()
    Left other -> assertFailure
      ("expected FieldTooLong LabelXDelta1 FieldXDelta1FromName but got: " ++ show other)

toNameOverflowIdentified :: Assertion
toNameOverflowIdentified = do
  let oversize = asciiText (xdelta1NameByteCap + 1)
  case resolveExplicit "source" oversize of
    Right _ -> assertFailure "expected FieldTooLong for 65536-byte to-name"
    Left (FieldTooLong LabelXDelta1 FieldXDelta1ToName _ _) -> pure ()
    Left other -> assertFailure
      ("expected FieldTooLong LabelXDelta1 FieldXDelta1ToName but got: " ++ show other)

----------------------------------------------------------------------------
-- Convert-side assertions
----------------------------------------------------------------------------

convertFromBPSWithoutNamesRefused :: Assertion
convertFromBPSWithoutNamesRefused =
  case requireXDelta1FileNames Nothing Nothing LabelBPS of
    Right _ -> assertFailure "expected XDelta1ConvertRequiresNames refusal"
    Left (XDelta1ConvertRequiresNames LabelBPS) -> pure ()
    Left other -> assertFailure
      ("expected XDelta1ConvertRequiresNames LabelBPS but got: " ++ show other)

convertFromBPSWithOnlyFromNameRefused :: Assertion
convertFromBPSWithOnlyFromNameRefused =
  case requireXDelta1FileNames (Just (localeName "user-from")) Nothing LabelBPS of
    Right _ -> assertFailure
      "expected refusal: --from-name set but --to-name absent"
    Left (XDelta1ConvertRequiresNames LabelBPS) -> pure ()
    Left other -> assertFailure
      ("expected XDelta1ConvertRequiresNames LabelBPS but got: " ++ show other)

convertFromBPSWithNamesAccepted :: Assertion
convertFromBPSWithNamesAccepted =
  case requireXDelta1FileNames (Just (localeName "user-from")) (Just (localeName "user-to")) LabelBPS of
    Right _ -> pure ()
    Left err -> assertFailure
      ("expected acceptance, got: " ++ renderSlapError err)

convertXDeltaToXDeltaInherits :: Assertion
convertXDeltaToXDeltaInherits = do
  wireBytes <- createXDelta1WithNames "old-from" "old-to"
  parsed <- parseAndExtractNames wireBytes
  let cliMeta    = noMetadataRequested
      sourceMeta = noMetadataRequested
        { requestedXDelta1FromName = Just (parsedXDelta1FromName parsed)
        , requestedXDelta1ToName   = Just (parsedXDelta1ToName   parsed)
        }
      merged = mergeRequestedMetadata cliMeta sourceMeta
  case requireXDelta1FileNames
         (fmap unXDelta1FromName (requestedXDelta1FromName merged))
         (fmap unXDelta1ToName   (requestedXDelta1ToName   merged))
         LabelXDelta1 of
    Right _ -> pure ()
    Left err -> assertFailure
      ("requireXDelta1FileNames refused inheritance: " ++ renderSlapError err)
  assertEqual "merge inherited from-name"
    (Just (XDelta1FromName (localeName "old-from"))) (requestedXDelta1FromName merged)
  assertEqual "merge inherited to-name"
    (Just (XDelta1ToName   (localeName "old-to")))   (requestedXDelta1ToName   merged)

convertXDeltaToXDeltaPartialOverride :: Assertion
convertXDeltaToXDeltaPartialOverride = do
  wireBytes <- createXDelta1WithNames "old-from" "old-to"
  parsed <- parseAndExtractNames wireBytes
  let cliMeta = noMetadataRequested
        { requestedXDelta1FromName = Just (XDelta1FromName (localeName "cli-from"))
        }
      sourceMeta = noMetadataRequested
        { requestedXDelta1FromName = Just (parsedXDelta1FromName parsed)
        , requestedXDelta1ToName   = Just (parsedXDelta1ToName   parsed)
        }
      merged = mergeRequestedMetadata cliMeta sourceMeta
  assertEqual "CLI from-name overrides"
    (Just (XDelta1FromName (localeName "cli-from"))) (requestedXDelta1FromName merged)
  assertEqual "to-name inherits from src"
    (Just (XDelta1ToName (localeName "old-to")))     (requestedXDelta1ToName   merged)
