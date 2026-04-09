module Integration.Apply (applyTests) where

import Integration.Helpers
  (repoDir, parseSuiteFile, SuiteHeader(..), SuiteEntry(..),
   sha1Hex, applyPatch, mmapRomFile)
import Slap.Error (renderSlapError)
import Slap.SomePatch (parseSome)

import qualified Data.ByteString as ByteString
import Data.List (sort)
import System.Directory (doesFileExist, listDirectory)
import System.FilePath ((</>), takeExtension)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (testCase, assertFailure, assertEqual)

applyTests :: IO TestTree
applyTests = do
  repo <- repoDir
  let suitesDir = repo </> "test" </> "suites"
  files <- sort . filter (\fileName -> takeExtension fileName == ".suite")
           <$> listDirectory suitesDir
  groups <- mapM (makeSuiteGroup repo suitesDir) files
  pure (testGroup "apply" (concat groups))

makeSuiteGroup :: FilePath -> FilePath -> String -> IO [TestTree]
makeSuiteGroup repo suitesDir name = do
  let path = suitesDir </> name
  (header, entries) <- parseSuiteFile path
  let basePath = repo </> suiteBase header
      expectedSha = suiteSha1 header
  baseExists <- doesFileExist basePath
  if not baseExists
    then pure []  -- skip suite if base ROM missing
    else do
      let validEntries = filter isTestable entries
      pure [testGroup suiteName
              (map (makePatchTest repo basePath expectedSha) validEntries)]
  where
    suiteName = take (length name - 6) name  -- strip .suite
    isTestable entry = entryConfidence entry /= "broken"

makePatchTest :: FilePath -> FilePath -> String -> SuiteEntry -> TestTree
makePatchTest repo basePath expectedSha entry =
  testCase (entryFormat entry) $ do
    let patchPath = repo </> entryPatch entry
    patchExists <- doesFileExist patchPath
    if not patchExists && entryConfidence entry == "untested"
      then pure ()  -- silently skip untested entries with missing files
      else do
        baseBytes <- mmapRomFile basePath
        patchBytes <- ByteString.readFile patchPath
        case parseSome patchBytes of
          Left slapError -> assertFailure ("parseSome failed: " ++ renderSlapError slapError)
          Right parsed -> do
            result <- applyPatch parsed baseBytes
            case result of
              Left slapError -> assertFailure ("apply failed: " ++ renderSlapError slapError)
              Right output -> assertEqual "SHA1 mismatch"
                expectedSha (sha1Hex output)
