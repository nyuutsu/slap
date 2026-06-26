{-# LANGUAGE OverloadedStrings #-}

module Integration.Metadata (metadataTests) where

import Integration.Helpers (assertFailureT)
import Integration.Helpers
  ( Tier
  , isHeavyPath
  , restrictToTier
  , repoDir
  , attemptConvert
  , parseCreateFormat
  , trim
  )
import Integration.Skip
  ( GroupPlan
  , MaybeTest(..)
  , namedGroup
  , requireFixture
  )
import Slap.Status (CreateResult(..), renderSlapError)
import Slap.Display.Analysis (renderAnalysisSummary)
import Slap.Display.EmbeddedContent (EmbeddedDepth(SizeOnly))
import Slap.Display.Info (renderPatchInfo)
import Slap.FileContents
  (InputFileContents(..), OutputFileContents(..), PatchFileContents(..))
import Slap.SomePatch (SomePatch(..), PatchKind(..), parseSome)
import Slap.Text (EncodingName(EncodingUtf8), EncodedText(..))
import Slap.Convert
  ( DirectCreate(..)
  , CreateFormat(..)
  , RequestedPatchMetadata(..)
  , FileIdDizRequest(..)
  , UndoInclusion(..)
  , VerificationInclusion(..)
  , contentsFileIdDiz
  , noMetadataRequested
  , noConstraintsRequested
  , noDialectsRequested
  )
import Slap.Create (createBPS, createPatch)
import Slap.BPS.Types (BPSMetadata(..))

import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Char8 as ByteString8
import Data.Char (isSpace, toLower)
import Data.List (isPrefixOf, find)
import System.FilePath ((</>))
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (testCase, assertFailure, assertEqual, assertBool)
import qualified Data.Text as Text

-- | The metadata group exercises field-by-field round-tripping
-- through self-convert: take a real patch, convert to its own format,
-- assert that the rendered info lines for each named field match.
-- Each row's patch path is the only fixture; absent patches contribute
-- one 'MissingFixture' skip per field-test that would have run.
metadataTests :: Tier -> IO GroupPlan
metadataTests tier = do
  repo <- repoDir
  let inTierCases = restrictToTier tier caseIsHeavy metadataCases
  caseMaybes      <- concat <$> mapM (planMetadataCase repo) inTierCases
  appHeaderMaybes <- planAppHeaderLiftCase repo
  let programmaticMaybes =
        map WillRun (testTreesFromGroup bpsMetadataGroup)
        ++ map WillRun (testTreesFromGroup ppfFileIdDizGroup)
  pure (namedGroup "metadata" (caseMaybes ++ appHeaderMaybes ++ programmaticMaybes))
  where
    caseIsHeavy (_format, relPath, _fields) = isHeavyPath relPath

-- | Decompose a 'testGroup' built locally back into its child trees so
-- the per-test count flowing into 'GroupPlan' matches reality. The
-- outer 'namedGroup' will rewrap.
testTreesFromGroup :: TestTree -> [TestTree]
testTreesFromGroup tree = [tree]  -- one node per group, by intent

-- | (format, patch_path_relative, fields_to_check)
metadataCases :: [(String, String, [String])]
metadataCases =
  [ ("ppf3",    "test/data/stadium2/fair-heavy/patch.ppf",       ["description", "undo data", "validation"])
  , ("aps-n64", "test/data/stadium2/fair-heavy/patch.aps",       ["dest size", "description"])
  ]

planMetadataCase :: FilePath -> (String, String, [String]) -> IO [MaybeTest]
planMetadataCase repo (formatString, relPath, fieldNames) =
  case parseCreateFormat formatString of
    Nothing     -> pure []  -- unknown @format@ in the static case list
    Just format ->
      let patchPath = repo </> relPath
      in requireFixture patchPath $ \_ ->
           pure [WillRun (testGroup formatString
                  (map (mkFieldTest patchPath format) fieldNames))]

mkFieldTest :: FilePath -> CreateFormat -> String -> TestTree
mkFieldTest patchPath format fieldName = testCase fieldName $ do
  patchBytes <- ByteString.readFile patchPath
  case parseSome noDialectsRequested EncodingUtf8 (PatchFileContents patchBytes) of
    Left slapError -> assertFailureT ("parseSome original failed: " <> renderSlapError slapError)
    Right original -> do
      -- Self-convert: convert to same format
      let meta = case format of
            CreateDirect CreatePPF3 -> noMetadataRequested
              { requestedUndoInclusion        = Just IncludeUndoData
              , requestedVerificationInclusion = Just IncludeVerification
              }
            _                       -> noMetadataRequested
      convResult <- attemptConvert original format Nothing meta
      case convResult of
        Left errorMessage -> assertFailure ("self-convert failed: " ++ errorMessage)
        Right (CreateResult convertedBytes _) -> case parseSome noDialectsRequested EncodingUtf8 convertedBytes of
          Left slapError -> assertFailureT ("parseSome converted failed: " <> renderSlapError slapError)
          Right converted -> do
            let originalInfo = Text.unpack (renderAnalysisSummary (patchInfo original) (patchAnalysis original) Nothing)
                convertedInfo = Text.unpack (renderAnalysisSummary (patchInfo converted) (patchAnalysis converted) Nothing)
                originalValue = extractField fieldName originalInfo
                convertedValue = extractField fieldName convertedInfo
            assertEqual ("field '" ++ fieldName ++ "' mismatch") originalValue convertedValue

-- | Extract a field value from info output.
-- Looks for a line starting with "  fieldName:" (case-insensitive prefix match)
-- and returns the trimmed value after the colon.
extractField :: String -> String -> String
extractField name info =
  case find (matchesField name) (lines info) of
    Just line -> trim (dropField name line)
    Nothing   -> "<not found>"
  where
    matchesField fieldName infoLine =
      let stripped = dropWhile isSpace infoLine
          lower = map toLower stripped
          target = map toLower fieldName ++ ":"
      in target `isPrefixOf` lower
    dropField _fieldName infoLine =
      let stripped = dropWhile isSpace infoLine
      in drop 1 (dropWhile (/= ':') stripped)

----------------------------------------------------------------------------
-- BPS metadata tests (programmatic, no committed test data)
----------------------------------------------------------------------------

bpsMetadataGroup :: TestTree
bpsMetadataGroup = testGroup "bps-metadata"
  [ testCase "round-trip via patchMetadata" $ do
      let source = ByteString.pack [0..63]
          target = ByteString.pack [64..127]
          meta   = ByteString8.pack "<patch><title>Test</title></patch>"
      patchBytes <- createBPSOrFail source target meta
      case parseSome noDialectsRequested EncodingUtf8 patchBytes of
        Left slapError -> assertFailureT ("parseSome failed: " <> renderSlapError slapError)
        Right parsed -> assertEqual "patchMetadata" (Just meta) (patchMetadata parsed)

  , testCase "empty metadata gives Nothing" $ do
      let source = ByteString.pack [0..15]
          target = ByteString.pack [16..31]
      patchBytes <- createBPSOrFail source target ByteString.empty
      case parseSome noDialectsRequested EncodingUtf8 patchBytes of
        Left slapError -> assertFailureT ("parseSome failed: " <> renderSlapError slapError)
        Right parsed -> assertEqual "patchMetadata" Nothing (patchMetadata parsed)

  , testCase "info shows the metadata size; explain shows the content" $ do
      let source = ByteString.pack [0..63]
          target = ByteString.pack [64..127]
          meta   = ByteString8.pack "hello-world-metadata"
      patchBytes <- createBPSOrFail source target meta
      case parseSome noDialectsRequested EncodingUtf8 patchBytes of
        Left slapError -> assertFailureT ("parseSome failed: " <> renderSlapError slapError)
        Right parsed -> do
          assertBool "info shows the byte count"
            ("20 bytes" `Text.isInfixOf` infoView parsed)
          assertBool "info withholds the content"
            (not ("hello-world-metadata" `Text.isInfixOf` infoView parsed))
          assertBool "explain shows the content"
            ("hello-world-metadata" `Text.isInfixOf` explainView parsed)

  , testCase "info shows (none) without metadata" $ do
      let source = ByteString.pack [0..63]
          target = ByteString.pack [64..127]
      patchBytes <- createBPSOrFail source target ByteString.empty
      case parseSome noDialectsRequested EncodingUtf8 patchBytes of
        Left slapError -> assertFailureT ("parseSome failed: " <> renderSlapError slapError)
        Right parsed ->
          assertBool "info shows (none)" ("(none)" `Text.isInfixOf` infoView parsed)
  ]

-- | Run 'createBPS' and unwrap. Test inputs are small and well-formed,
-- so a 'Left' indicates a test-infrastructure bug rather than an expected path.
createBPSOrFail :: ByteString.ByteString -> ByteString.ByteString -> ByteString.ByteString -> IO PatchFileContents
createBPSOrFail source target meta =
  case createBPS (InputFileContents source) (OutputFileContents target) (BPSMetadata meta) of
    Left slapError ->
      assertFailureT ("createBPS failed: " <> renderSlapError slapError)
    Right (CreateResult patchBytes _) -> pure patchBytes

-- | The lines @slap info@ prints — glances only.
infoView :: SomePatch -> Text.Text
infoView parsed = Text.unlines (renderPatchInfo SizeOnly (patchInfo parsed))

-- | The text @slap explain@ prints — glances opened to their content.
explainView :: SomePatch -> Text.Text
explainView parsed = renderAnalysisSummary (patchInfo parsed) (patchAnalysis parsed) Nothing

----------------------------------------------------------------------------
-- FILE_ID.DIZ (PPF2/PPF3): create, display, carry, drop, override, refuse
----------------------------------------------------------------------------

-- | PPF2's create path samples a 1024-byte validation block at source
-- offset 0x9320, so the source must reach 0x9720 bytes. Source and
-- target differ at offset 0 to force a single write record.
ppf2DizSource :: ByteString.ByteString
ppf2DizSource = ByteString.replicate 0x9720 0

ppf2DizTarget :: ByteString.ByteString
ppf2DizTarget = ByteString.cons 0xFF (ByteString.drop 1 ppf2DizSource)

ppfFileIdDizGroup :: TestTree
ppfFileIdDizGroup = testGroup "ppf-fileiddiz"
  [ testCase "PPF2 round-trips a FILE_ID.DIZ" $ do
      let fileIdDiz = EncodedText EncodingUtf8 (Text.pack "Cool Patch v1.0\nby tester")
          meta      = noMetadataRequested { requestedFileIdDiz = SetFileIdDiz fileIdDiz }
      patchBytes <- createPPF2OrFail ppf2DizSource ppf2DizTarget meta
      case parseSome noDialectsRequested EncodingUtf8 patchBytes of
        Left slapError -> assertFailureT ("parseSome failed: " <> renderSlapError slapError)
        Right parsed   -> assertEqual "FILE_ID.DIZ" (Just fileIdDiz) (parsedFileIdDiz parsed)

  , testCase "a PPF2 without a FILE_ID.DIZ carries none" $ do
      patchBytes <- createPPF2OrFail ppf2DizSource ppf2DizTarget noMetadataRequested
      case parseSome noDialectsRequested EncodingUtf8 patchBytes of
        Left slapError -> assertFailureT ("parseSome failed: " <> renderSlapError slapError)
        Right parsed   -> assertEqual "FILE_ID.DIZ" Nothing (parsedFileIdDiz parsed)

  , testCase "info shows the FILE_ID.DIZ size; explain shows the content" $ do
      let fileIdDiz = EncodedText EncodingUtf8 (Text.pack "ASCII-ART-HEADER-XYZZY")
          meta      = noMetadataRequested { requestedFileIdDiz = SetFileIdDiz fileIdDiz }
      patchBytes <- createPPF2OrFail ppf2DizSource ppf2DizTarget meta
      case parseSome noDialectsRequested EncodingUtf8 patchBytes of
        Left slapError -> assertFailureT ("parseSome failed: " <> renderSlapError slapError)
        Right parsed   -> do
          assertBool "info shows the character count"
            ("22 characters" `Text.isInfixOf` infoView parsed)
          assertBool "info withholds the content"
            (not ("XYZZY" `Text.isInfixOf` infoView parsed))
          assertBool "explain shows the content"
            ("XYZZY" `Text.isInfixOf` explainView parsed)

  , testCase "convert PPF2 -> PPF3 inherits the FILE_ID.DIZ" $ do
      let fileIdDiz = EncodedText EncodingUtf8 (Text.pack "carried-across-formats")
      result <- convertedPPF3FileIdDiz (SetFileIdDiz fileIdDiz) noMetadataRequested
      assertEqual "inherited FILE_ID.DIZ" (Right (Just fileIdDiz)) result

  , testCase "convert PPF2 -> PPF3 with a drop request drops the FILE_ID.DIZ" $ do
      let fileIdDiz = EncodedText EncodingUtf8 (Text.pack "to-be-dropped")
      result <- convertedPPF3FileIdDiz (SetFileIdDiz fileIdDiz)
                  (noMetadataRequested { requestedFileIdDiz = DropFileIdDiz })
      assertEqual "dropped FILE_ID.DIZ" (Right Nothing) result

  , testCase "convert PPF2 -> PPF3 with a set request overrides the FILE_ID.DIZ" $ do
      let sourceDiz   = EncodedText EncodingUtf8 (Text.pack "from-source")
          overrideDiz = EncodedText EncodingUtf8 (Text.pack "from-the-flag")
      result <- convertedPPF3FileIdDiz (SetFileIdDiz sourceDiz)
                  (noMetadataRequested { requestedFileIdDiz = SetFileIdDiz overrideDiz })
      assertEqual "overridden FILE_ID.DIZ" (Right (Just overrideDiz)) result

  , testCase "an over-long FILE_ID.DIZ is refused (PPF3 16-bit length)" $ do
      let overLongDiz = EncodedText EncodingUtf8 (Text.replicate 70000 (Text.pack "x"))
      result <- convertedPPF3FileIdDiz InheritFileIdDiz
                  (noMetadataRequested { requestedFileIdDiz = SetFileIdDiz overLongDiz })
      case result of
        Left _  -> pure ()
        Right _ -> assertFailure "expected an over-long FILE_ID.DIZ to be refused"
  ]

-- | The FILE_ID.DIZ a parsed PPF2/PPF3 carries in its 'PatchContents'.
parsedFileIdDiz :: SomePatch -> Maybe EncodedText
parsedFileIdDiz parsed = case patchKind parsed of
  Direct (Just contents) -> contentsFileIdDiz contents
  _                      -> Nothing

-- | Drive a PPF2 create with @sourceDiz@ baked in, parse it, convert to
-- PPF3 under @convertMeta@, and report the FILE_ID.DIZ the PPF3 carries
-- (or the convert's rendered refusal).
convertedPPF3FileIdDiz
  :: FileIdDizRequest
  -> RequestedPatchMetadata
  -> IO (Either String (Maybe EncodedText))
convertedPPF3FileIdDiz sourceDiz convertMeta = do
  ppf2Bytes <- createPPF2OrFail ppf2DizSource ppf2DizTarget
                 (noMetadataRequested { requestedFileIdDiz = sourceDiz })
  case parseSome noDialectsRequested EncodingUtf8 ppf2Bytes of
    Left slapError -> assertFailureT ("parseSome PPF2 failed: " <> renderSlapError slapError)
    Right ppf2 -> do
      converted <- attemptConvert ppf2 (CreateDirect CreatePPF3) Nothing convertMeta
      case converted of
        Left errorMessage -> pure (Left errorMessage)
        Right (CreateResult ppf3Bytes _) ->
          case parseSome noDialectsRequested EncodingUtf8 ppf3Bytes of
            Left slapError -> assertFailureT ("parseSome PPF3 failed: " <> renderSlapError slapError)
            Right ppf3     -> pure (Right (parsedFileIdDiz ppf3))

-- | Run a PPF2 'createPatch' and unwrap; a 'Left' on these small,
-- well-formed inputs is a test-infrastructure bug, not an expected path.
createPPF2OrFail
  :: ByteString.ByteString -> ByteString.ByteString -> RequestedPatchMetadata
  -> IO PatchFileContents
createPPF2OrFail source target meta =
  case createPatch (CreateDirect CreatePPF2) Nothing
                   (InputFileContents source) (OutputFileContents target)
                   meta Nothing noConstraintsRequested noDialectsRequested of
    Left slapError -> assertFailureT ("createPPF2 failed: " <> renderSlapError slapError)
    Right (CreateResult patchBytes _) -> pure patchBytes

----------------------------------------------------------------------------
-- xdelta3 application header lifts into the embedded-blob channel
----------------------------------------------------------------------------

-- | The xdelta3 application header must surface as 'patchMetadata' — the
-- lift that lets @info --extract-metadata@, convert carry, and
-- @--drop-metadata@ reach it, exactly as for the BPS blob. dm4y's vcdiff
-- is local-only, so the test is gated on its presence.
planAppHeaderLiftCase :: FilePath -> IO [MaybeTest]
planAppHeaderLiftCase repo =
  requireFixture (repo </> "test/data/dm4y/patch.vcdiff") $ \patchPath ->
    pure [WillRun (testCase "xdelta3 app header lifts into patchMetadata" (assertAppHeaderLift patchPath))]

assertAppHeaderLift :: FilePath -> IO ()
assertAppHeaderLift patchPath = do
  patchBytes <- ByteString.readFile patchPath
  case parseSome noDialectsRequested EncodingUtf8 (PatchFileContents patchBytes) of
    Left slapError -> assertFailureT ("parseSome failed: " <> renderSlapError slapError)
    Right parsed   -> assertEqual "patchMetadata"
      (Just (ByteString8.pack "dm4y-output.gbc//dm4y-input.gbc/"))
      (patchMetadata parsed)
