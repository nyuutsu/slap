module Integration.Undo (undoTests) where

import Integration.Helpers
  (repoDir, parseSpecFile, sha1Hex, applyPatch, undoPatch, mmapRomFile)
import Slap.Error (renderSlapError)
import Slap.SomePatch (parseSome)

import qualified Data.ByteString as ByteString
import System.Directory (doesFileExist)
import System.FilePath ((</>))
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (testCase, assertFailure, assertEqual)

undoTests :: IO TestTree
undoTests = do
  repo <- repoDir
  rows <- parseSpecFile (repo </> "test" </> "specs" </> "undo.txt")
  tests <- mapM (makeUndoTest repo) (zip [1::Int ..] rows)
  pure (testGroup "undo" (concat tests))

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
            applied <- applyPatch parsed baseBytes
            case applied of
              Left slapError -> assertFailure ("apply failed: " ++ renderSlapError slapError)
              Right patchedBytes -> do
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
