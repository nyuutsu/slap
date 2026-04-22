module Integration.Metadata (metadataTests) where

import Integration.Helpers
  (Tier, isHeavyPath, restrictToTier,
   repoDir, attemptConvert, parseCreateFormat, trim)
import Slap.Error (CreateResult(..), renderSlapError)
import Slap.Explain (renderExplain, renderSummary)
import Slap.FileContents (SourceFileContents(..), TargetFileContents(..), PatchFileContents(..))
import Slap.SomePatch (SomePatch(..), parseSome)
import Slap.Convert (DirectCreate(..), CreateFormat(..), CreateMeta(..), defaultMeta)
import qualified Slap.BPS.Create as BPS

import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Char8 as ByteString8
import Data.Char (isSpace, toLower)
import Data.List (isPrefixOf, isInfixOf, find)
import System.Directory (doesFileExist)
import System.FilePath ((</>))
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (testCase, assertFailure, assertEqual, assertBool)

metadataTests :: Tier -> IO TestTree
metadataTests tier = do
  repo <- repoDir
  groups <- mapM (makeMetadataGroup repo)
                 (restrictToTier tier caseIsHeavy metadataCases)
  pure (testGroup "metadata" (concat groups ++ [bpsMetadataGroup]))
  where
    caseIsHeavy (_format, relPath, _fields) = isHeavyPath relPath

-- | (format, patch_path_relative, fields_to_check)
metadataCases :: [(String, String, [String])]
metadataCases =
  [ ("ppf3",    "test/data/stadium2/heavy-diff/patch.ppf",       ["description", "undo data", "validation"])
  , ("ninja1",  "test/data/emerald/heavy-diff/patch.ninja1",     ["source CRC", "source MD5", "source SHA1"])
  , ("aps-n64", "test/data/stadium2/heavy-diff/patch.aps",   ["dest size", "description"])
  , ("ebp",     "test/data/emerald/heavy-diff/patch.ebp",    ["title", "author", "description"])
  ]

makeMetadataGroup :: FilePath -> (String, String, [String]) -> IO [TestTree]
makeMetadataGroup repo (formatString, relPath, fieldNames) = do
  let patchPath = repo </> relPath
  exists <- doesFileExist patchPath
  if not exists then pure [] else
    case parseCreateFormat formatString of
      Nothing -> pure []
      Just format -> pure [testGroup formatString (map (makeFieldTest patchPath format) fieldNames)]

makeFieldTest :: FilePath -> CreateFormat -> String -> TestTree
makeFieldTest patchPath format fieldName = testCase fieldName $ do
  patchBytes <- ByteString.readFile patchPath
  case parseSome (PatchFileContents patchBytes) of
    Left slapError -> assertFailure ("parseSome original failed: " ++ renderSlapError slapError)
    Right original -> do
      -- Self-convert: convert to same format
      let meta = case format of
            CreateDirect CreatePPF3 -> defaultMeta { metaUndo = Just True, metaValidate = Just True }
            _                       -> defaultMeta
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

-- | Run 'BPS.createBPS' and unwrap. Test inputs are small and well-formed,
-- so a 'Left' indicates a test-infrastructure bug rather than an expected path.
createBPSOrFail :: ByteString.ByteString -> ByteString.ByteString -> ByteString.ByteString -> IO PatchFileContents
createBPSOrFail source target meta =
  case BPS.createBPS (SourceFileContents source) (TargetFileContents target) meta of
    Left slapError ->
      assertFailure ("createBPS failed: " ++ renderSlapError slapError)
    Right (CreateResult patchBytes _) -> pure patchBytes
