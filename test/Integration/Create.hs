module Integration.Create (createTests) where

import Integration.Helpers
  (Tier, isHeavyPath, restrictToTier,
   repoDir, parseSpecFile, parseCreateFormat, sha1Hex, applyPatch,
   BootstrapTargets, lookupBootstrapTarget, mmapRomFile)
import Slap.Convert (CreateFormat, defaultMeta, createFromMemory)
import Slap.Error (CreateResult(..), renderSlapError)
import Slap.FileContents (SourceFileContents(..), TargetFileContents(..))
import Slap.SomePatch (parseSome)

import Data.ByteString (ByteString)
import System.Directory (doesFileExist)
import System.FilePath ((</>))
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (testCase, assertFailure, assertEqual)

createTests :: Tier -> BootstrapTargets -> IO TestTree
createTests tier bootstrapTargets = do
  repo <- repoDir
  allRows <- parseSpecFile (repo </> "test" </> "specs" </> "create.txt")
  tests <- mapM (makeCreateTest bootstrapTargets repo)
                (restrictToTier tier rowIsHeavy allRows)
  pure (testGroup "create" (concat tests))
  where
    rowIsHeavy row = case row of
      (_format : _scenario : basePath : _) -> isHeavyPath basePath
      _                                    -> False

makeCreateTest :: BootstrapTargets -> FilePath -> [String] -> IO [TestTree]
makeCreateTest bootstrapTargets repo fields = case fields of
  (formatString : scenario : basePath : bootstrapPath : targetSha : _) -> do
    case parseCreateFormat formatString of
      Nothing -> pure []
      Just format -> do
        let base = repo </> basePath
            boot = repo </> bootstrapPath
        baseExists <- doesFileExist base
        bootExists <- doesFileExist boot
        if not (baseExists && bootExists)
          then pure []
          else pure [testCase (formatString ++ "/" ++ scenario) $ do
            baseBytes <- mmapRomFile base
            let targetBytes = lookupBootstrapTarget bootstrapTargets base boot
            roundTrip format baseBytes targetBytes targetSha
          ]
  _ -> pure []

-- | Create a patch, parse it back, apply to base, verify SHA1.
roundTrip :: CreateFormat -> ByteString -> ByteString -> String -> IO ()
roundTrip format baseBytes targetBytes expectedSha = do
  case createFromMemory format baseBytes targetBytes defaultMeta Nothing of
    Left slapError -> assertFailure ("create failed: " ++ renderSlapError slapError)
    Right (CreateResult patchBytes _) -> case parseSome patchBytes of
      Left slapError -> assertFailure ("re-parse failed: " ++ renderSlapError slapError)
      Right parsed -> do
        result <- applyPatch parsed (SourceFileContents baseBytes)
        case result of
          Left slapError -> assertFailure ("re-apply failed: " ++ renderSlapError slapError)
          Right (TargetFileContents output) ->
            assertEqual "SHA1 mismatch" expectedSha (sha1Hex output)
