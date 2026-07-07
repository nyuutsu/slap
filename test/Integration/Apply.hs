{-# LANGUAGE OverloadedStrings #-}

module Integration.Apply (applyTests) where

import Integration.Helpers (assertFailureT)
import Integration.Helpers
  ( Tier
  , restrictToTier
  , repoDir
  , parseSuiteFile
  , SuiteHeader(..)
  , SuiteEntry(..)
  , sha1Hex
  , applyPatch
  , mmapRomFile
  )
import Integration.Skip
  ( GroupPlan
  , MaybeTest(..)
  , SkipReason(..)
  , namedGroup
  )
import Slap.Status (renderSlapError)
import Slap.FileContents
  (PatchFileContents(..), InputFileContents(..), OutputFileContents(..))
import Slap.SomePatch (parseSome)
import Slap.Text (EncodingName(EncodingUtf8))
import Slap.Convert (noDialectsRequested)

import qualified Data.ByteString as ByteString
import Data.List (sort)
import System.Directory (doesFileExist, listDirectory)
import System.FilePath ((</>), takeExtension)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (testCase, assertEqual)

-- | The apply group walks every @.suite@ file under @test/suites/@ and
-- registers one test per non-broken entry. A suite whose base ROM is
-- absent contributes one 'MissingFixture' skip per intended test
-- (preserving counts for the skip summary), keeping @apply@'s tree
-- shape unchanged when fixtures are present.
applyTests :: Tier -> IO GroupPlan
applyTests tier = do
  repo <- repoDir
  let suitesDir = repo </> "test" </> "suites"
  suiteFiles <- sort . filter (\fileName -> takeExtension fileName == ".suite")
                <$> listDirectory suitesDir
  perSuiteOutcomes <- mapM (planSuite repo suitesDir)
                           (restrictToTier tier suiteFiles)
  pure (namedGroup "apply" (concat perSuiteOutcomes))

-- | Plan a single suite. Returns either one 'WillRun' wrapping the
-- suite's own 'testGroup', or N 'WillSkip' (one per intended test) so
-- absent-fixture skip counts are accurate in the summary.
planSuite :: FilePath -> FilePath -> String -> IO [MaybeTest]
planSuite repo suitesDir suiteFileName = do
  let suitePath = suitesDir </> suiteFileName
  (header, entries) <- parseSuiteFile suitePath
  let basePath     = repo </> suiteBase header
      expectedSha  = suiteSha1 header
      runnableEntries = filter isRunnable entries
      suiteName    = take (length suiteFileName - 6) suiteFileName  -- strip .suite
  baseExists <- doesFileExist basePath
  if baseExists
    then pure
           [ WillRun
               (testGroup suiteName
                  (map (mkPatchTest repo basePath expectedSha) runnableEntries))
           ]
    else pure (replicate (length runnableEntries) (WillSkip (MissingFixture basePath)))
  where
    isRunnable entry = entryConfidence entry /= "broken"

mkPatchTest :: FilePath -> FilePath -> String -> SuiteEntry -> TestTree
mkPatchTest repo basePath expectedSha entry =
  testCase (entryFormat entry) $ do
    let patchPath = repo </> entryPatch entry
    patchExists <- doesFileExist patchPath
    if not patchExists && entryConfidence entry == "untested"
      then pure ()  -- the suite file flags this entry as not-yet-acquired patch data
      else do
        baseBytes  <- mmapRomFile basePath
        patchBytes <- ByteString.readFile patchPath
        case parseSome noDialectsRequested EncodingUtf8 (PatchFileContents patchBytes) of
          Left slapError ->
            assertFailureT ("parseSome failed: " <> renderSlapError slapError)
          Right parsed -> do
            result <- applyPatch parsed (InputFileContents baseBytes)
            case result of
              Left slapError ->
                assertFailureT ("apply failed: " <> renderSlapError slapError)
              Right (OutputFileContents output) ->
                assertEqual "SHA1 mismatch" expectedSha (sha1Hex output)
