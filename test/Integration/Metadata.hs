module Integration.Metadata (metadataTests) where

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
import Slap.Error (CreateResult(..), renderSlapError)
import Slap.Explain (renderExplain, renderSummary)
import Slap.FileContents
  (SourceFileContents(..), TargetFileContents(..), PatchFileContents(..))
import Slap.SomePatch (SomePatch(..), parseSome)
import Slap.Convert
  ( DirectCreate(..)
  , CreateFormat(..)
  , RequestedPatchMetadata(..)
  , UndoInclusion(..)
  , ValidationInclusion(..)
  , noMetadataRequested
  )
import Slap.Create (createBPS)
import Slap.BPS.Types (BPSMetadata(..))

import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Char8 as ByteString8
import Data.Char (isSpace, toLower)
import Data.List (isPrefixOf, isInfixOf, find)
import System.FilePath ((</>))
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (testCase, assertFailure, assertEqual, assertBool)

-- | The metadata group exercises field-by-field round-tripping
-- through self-convert: take a real patch, convert to its own format,
-- assert that the rendered info lines for each named field match.
-- Each row's patch path is the only fixture; absent patches contribute
-- one 'MissingFixture' skip per field-test that would have run.
metadataTests :: Tier -> IO GroupPlan
metadataTests tier = do
  repo <- repoDir
  let inTierCases = restrictToTier tier caseIsHeavy metadataCases
  caseMaybes <- concat <$> mapM (planMetadataCase repo) inTierCases
  let bpsMaybes = map WillRun (testTreesFromGroup bpsMetadataGroup)
  pure (namedGroup "metadata" (caseMaybes ++ bpsMaybes))
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
  case parseSome (PatchFileContents patchBytes) of
    Left slapError -> assertFailure ("parseSome original failed: " ++ renderSlapError slapError)
    Right original -> do
      -- Self-convert: convert to same format
      let meta = case format of
            CreateDirect CreatePPF3 -> noMetadataRequested
              { requestedUndoInclusion       = Just IncludeUndoData
              , requestedValidationInclusion = Just IncludeValidationBlock
              }
            _                       -> noMetadataRequested
      convResult <- attemptConvert original format Nothing meta
      case convResult of
        Left errorMessage -> assertFailure ("self-convert failed: " ++ errorMessage)
        Right (CreateResult convertedBytes _) -> case parseSome convertedBytes of
          Left slapError -> assertFailure ("parseSome converted failed: " ++ renderSlapError slapError)
          Right converted -> do
            let originalInfo = renderSummary Nothing (patchExplain original)
                convertedInfo = renderSummary Nothing (patchExplain converted)
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
      case parseSome patchBytes of
        Left slapError -> assertFailure ("parseSome failed: " ++ renderSlapError slapError)
        Right parsed -> assertEqual "patchMetadata" (Just meta) (patchMetadata parsed)

  , testCase "empty metadata gives Nothing" $ do
      let source = ByteString.pack [0..15]
          target = ByteString.pack [16..31]
      patchBytes <- createBPSOrFail source target ByteString.empty
      case parseSome patchBytes of
        Left slapError -> assertFailure ("parseSome failed: " ++ renderSlapError slapError)
        Right parsed -> assertEqual "patchMetadata" Nothing (patchMetadata parsed)

  , testCase "info shows metadata preview" $ do
      let source = ByteString.pack [0..63]
          target = ByteString.pack [64..127]
          meta   = ByteString8.pack "hello-world-metadata"
      patchBytes <- createBPSOrFail source target meta
      case parseSome patchBytes of
        Left slapError -> assertFailure ("parseSome failed: " ++ renderSlapError slapError)
        Right parsed -> do
          let info = renderExplain Nothing (patchExplain parsed)
          assertBool "info mentions metadata content"
            ("hello-world-metadata" `isInfixOf` info)
          assertBool "info shows byte count"
            ("20 bytes" `isInfixOf` info)

  , testCase "info shows (none) without metadata" $ do
      let source = ByteString.pack [0..63]
          target = ByteString.pack [64..127]
      patchBytes <- createBPSOrFail source target ByteString.empty
      case parseSome patchBytes of
        Left slapError -> assertFailure ("parseSome failed: " ++ renderSlapError slapError)
        Right parsed ->
          assertBool "info shows (none)" ("(none)" `isInfixOf` renderExplain Nothing (patchExplain parsed))
  ]

-- | Run 'createBPS' and unwrap. Test inputs are small and well-formed,
-- so a 'Left' indicates a test-infrastructure bug rather than an expected path.
createBPSOrFail :: ByteString.ByteString -> ByteString.ByteString -> ByteString.ByteString -> IO PatchFileContents
createBPSOrFail source target meta =
  case createBPS (SourceFileContents source) (TargetFileContents target) (BPSMetadata meta) of
    Left slapError ->
      assertFailure ("createBPS failed: " ++ renderSlapError slapError)
    Right (CreateResult patchBytes _) -> pure patchBytes
