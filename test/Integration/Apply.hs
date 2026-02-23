module Integration.Apply (applyTests) where

import Integration.Helpers
  (repoDir, parseSuiteFile, SuiteHeader(..), SuiteEntry(..),
   sha256Hex, applyPatch, RomCache, cachedReadFile)
import Patch.SomePatch (parseSome)

import qualified Data.ByteString as BS
import Data.List (sort)
import System.Directory (doesFileExist, listDirectory)
import System.FilePath ((</>), takeExtension)
import Test.Tasty (TestTree, testGroup, withResource)
import Test.Tasty.HUnit (testCase, assertFailure, assertEqual)

applyTests :: RomCache -> IO TestTree
applyTests romCache = do
  repo <- repoDir
  let suitesDir = repo </> "test" </> "suites"
  files <- sort . filter (\f -> takeExtension f == ".suite")
           <$> listDirectory suitesDir
  groups <- mapM (mkSuiteGroup romCache repo suitesDir) files
  pure (testGroup "apply" (concat groups))

mkSuiteGroup :: RomCache -> FilePath -> FilePath -> String -> IO [TestTree]
mkSuiteGroup romCache repo suitesDir name = do
  let path = suitesDir </> name
  (hdr, entries) <- parseSuiteFile path
  let basePath = repo </> shBase hdr
      expectedSha = shSha256 hdr
  baseExists <- doesFileExist basePath
  if not baseExists
    then pure []  -- skip suite if base ROM missing
    else do
      let validEntries = filter isTestable entries
          -- Share the base ROM read across all patch tests in this suite
          resource = withResource (cachedReadFile romCache basePath) (const (pure ()))
      pure [resource $ \getBase -> testGroup suiteName
              (map (mkPatchTest repo getBase expectedSha) validEntries)]
  where
    suiteName = take (length name - 6) name  -- strip .suite
    isTestable e = seConfidence e /= "broken"

mkPatchTest :: FilePath -> IO BS.ByteString -> String -> SuiteEntry -> TestTree
mkPatchTest repo getBase expectedSha entry =
  testCase (seFormat entry) $ do
    let patchPath = repo </> sePatch entry
    patchExists <- doesFileExist patchPath
    if not patchExists && seConfidence entry == "untested"
      then pure ()  -- silently skip untested entries with missing files
      else do
        baseBs <- getBase
        patchBs <- BS.readFile patchPath
        case parseSome patchBs of
          Left err -> assertFailure ("parseSome failed: " ++ err)
          Right sp -> do
            result <- applyPatch sp baseBs
            case result of
              Left err -> assertFailure ("apply failed: " ++ err)
              Right output -> assertEqual "SHA256 mismatch"
                expectedSha (sha256Hex output)
