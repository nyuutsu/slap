module Integration.Metadata (metadataTests) where

import Integration.Helpers (repoDir, attemptConvert, parseCreateFormat, RomCache)
import Patch.SomePatch (SomePatch(..), parseSome)
import Patch.Convert (CreateFormat(..), CreateMeta(..), defaultMeta)

import qualified Data.ByteString as BS
import Data.Char (isSpace)
import Data.List (isPrefixOf, find)
import System.Directory (doesFileExist)
import System.FilePath ((</>))
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (testCase, assertFailure, assertEqual)

metadataTests :: RomCache -> IO TestTree
metadataTests _romCache = do
  repo <- repoDir
  groups <- mapM (mkMetadataGroup repo) metadataCases
  pure (testGroup "metadata" (concat groups))

-- | (format, patch_path_relative, fields_to_check)
metadataCases :: [(String, String, [String])]
metadataCases =
  [ ("ppf3",    "test/data/stadium2/heavy-diff/patch.ppf",       ["description", "undo data", "validation"])
  , ("ninja1",  "test/data/emerald/heavy-diff/patch.ninja1",     ["source CRC", "source MD5", "source SHA1"])
  , ("aps-n64", "test/data/stadium2/heavy-diff/patch.aps.aps",   ["dest size", "description"])
  , ("ebp",     "test/data/emerald/heavy-diff/patch.ebp.ebp",    ["title", "author", "description"])
  ]

mkMetadataGroup :: FilePath -> (String, String, [String]) -> IO [TestTree]
mkMetadataGroup repo (fmtStr, relPath, fieldNames) = do
  let patchPath = repo </> relPath
  exists <- doesFileExist patchPath
  if not exists then pure [] else
    case parseCreateFormat fmtStr of
      Nothing -> pure []
      Just fmt -> pure [testGroup fmtStr (map (mkFieldTest patchPath fmt) fieldNames)]

mkFieldTest :: FilePath -> CreateFormat -> String -> TestTree
mkFieldTest patchPath fmt fieldName = testCase fieldName $ do
  patchBs <- BS.readFile patchPath
  case parseSome patchBs of
    Left err -> assertFailure ("parseSome original failed: " ++ err)
    Right sp1 -> do
      -- Self-convert: convert to same format
      let meta = case fmt of
            CfmtPPF3 -> defaultMeta { cmUndo = True, cmValidate = True }
            _        -> defaultMeta
      convResult <- attemptConvert sp1 fmt Nothing meta
      case convResult of
        Left err -> assertFailure ("self-convert failed: " ++ err)
        Right (convertedBs, _) -> case parseSome convertedBs of
          Left err -> assertFailure ("parseSome converted failed: " ++ err)
          Right sp2 -> do
            let info1 = spInfo sp1
                info2 = spInfo sp2
                val1 = extractField fieldName info1
                val2 = extractField fieldName info2
            assertEqual ("field '" ++ fieldName ++ "' mismatch") val1 val2

-- | Extract a field value from info output.
-- Looks for a line starting with "  fieldName:" (case-insensitive prefix match)
-- and returns the trimmed value after the colon.
extractField :: String -> String -> String
extractField name info =
  case find (matchesField name) (lines info) of
    Just l  -> trim' (dropField name l)
    Nothing -> "<not found>"
  where
    matchesField n line =
      let stripped = dropWhile isSpace line
          lower = map toLow stripped
          target = map toLow n ++ ":"
      in target `isPrefixOf` lower
    dropField _n line =
      let stripped = dropWhile isSpace line
      in drop 1 (dropWhile (/= ':') stripped)
    toLow c
      | c >= 'A' && c <= 'Z' = toEnum (fromEnum c + 32)
      | otherwise             = c

trim' :: String -> String
trim' = reverse . dropWhile isSpace . reverse . dropWhile isSpace
