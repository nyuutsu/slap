module Integration.Apply (applyTests) where

import Integration.Helpers
  (repoDir, parseSuiteFile, SuiteHeader(..), SuiteEntry(..),
   sha1Hex, applyPatch, RomCache, cachedReadFile)
import Patch.SomePatch (parseSome)

import qualified Data.ByteString as ByteString
import Data.List (sort)
import System.Directory (doesFileExist, listDirectory)
import System.FilePath ((</>), takeExtension)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (testCase, assertFailure, assertEqual)

applyTests :: RomCache -> IO TestTree
applyTests romCache = do
  repo <- repoDir
  let suitesDir = repo </> "test" </> "suites"
  files <- sort . filter (\fileName -> takeExtension fileName == ".suite")
           <$> listDirectory suitesDir
  groups <- mapM (makeSuiteGroup romCache repo suitesDir) files
  pure (testGroup "apply" (concat groups))

makeSuiteGroup :: RomCache -> FilePath -> FilePath -> String -> IO [TestTree]
makeSuiteGroup romCache repo suitesDir name = do
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
              (map (makePatchTest romCache repo basePath expectedSha) validEntries)]
  where
    suiteName = take (length name - 6) name  -- strip .suite
    isTestable entry = entryConfidence entry /= "broken"

makePatchTest :: RomCache -> FilePath -> FilePath -> String -> SuiteEntry -> TestTree
makePatchTest romCache repo basePath expectedSha entry =
  testCase (entryFormat entry) $ do
    let patchPath = repo </> entryPatch entry
    patchExists <- doesFileExist patchPath
    if not patchExists && entryConfidence entry == "untested"
      then pure ()  -- silently skip untested entries with missing files
      else do
        baseBytes <- cachedReadFile romCache basePath
        patchBytes <- ByteString.readFile patchPath
        case parseSome patchBytes of
          Left errorMessage -> assertFailure ("parseSome failed: " ++ errorMessage)
          Right parsed -> do
            result <- applyPatch parsed baseBytes
            case result of
              Left errorMessage -> assertFailure ("apply failed: " ++ errorMessage)
              Right output -> assertEqual "SHA1 mismatch"
                expectedSha (sha1Hex output)
