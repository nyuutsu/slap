module Integration.Undo (undoTests) where

import Integration.Helpers
  (Tier, isHeavyPath, restrictToTier,
   repoDir, parseSpecFile, sha1Hex, applyPatch, undoPatch, mmapRomFile)
import Slap.Error (renderSlapError)
import Slap.FileContents (SourceFileContents(..), TargetFileContents(..))
import Slap.SomePatch (parseSome)

import qualified Data.ByteString as ByteString
import System.Directory (doesFileExist)
import System.FilePath ((</>))
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (testCase, assertFailure, assertEqual)

undoTests :: Tier -> IO TestTree
undoTests tier = do
  repo <- repoDir
  allRows <- parseSpecFile (repo </> "test" </> "specs" </> "undo.txt")
  let tieredRows = restrictToTier tier rowIsHeavy allRows
  tests <- mapM (makeUndoTest repo) (zip [1::Int ..] tieredRows)
  pure (testGroup "undo" (concat tests))
  where
    rowIsHeavy row = case row of
      (_method : basePath : _) -> isHeavyPath basePath
      _                        -> False

makeUndoTest :: FilePath -> (Int, [String]) -> IO [TestTree]
makeUndoTest repo (_, fields) = case fields of
  (method : basePath : patchPath : baseSha : _) -> do
    let base  = repo </> basePath
        patch = repo </> patchPath
    baseExists  <- doesFileExist base
    patchExists <- doesFileExist patch
    if not (baseExists && patchExists)
      then pure []
      else pure [testCase label $ do
        baseBytes  <- mmapRomFile base
        patchBytes <- ByteString.readFile patch
        case parseSome patchBytes of
          Left slapError -> assertFailure ("parseSome failed: " ++ renderSlapError slapError)
          Right parsed -> do
            -- Apply
            applied <- applyPatch parsed (SourceFileContents baseBytes)
            case applied of
              Left slapError -> assertFailure ("apply failed: " ++ renderSlapError slapError)
              Right (TargetFileContents patchedBytes) -> do
                -- Undo
                undone <- undoPatch parsed patchedBytes
                case undone of
                  Left errorMessage -> assertFailure ("undo failed: " ++ errorMessage)
                  Right restoredBytes ->
                    assertEqual "SHA1 after undo" baseSha (sha1Hex restoredBytes)
      ]
    where
      label = method ++ "/" ++ patchPath
  _ -> pure []
