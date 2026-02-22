module Integration.Undo (undoTests) where

import Integration.Helpers
  (repoDir, parseSpecFile, sha256Hex, applyPatch, undoPatch)
import Patch.SomePatch (parseSome)

import qualified Data.ByteString as BS
import System.Directory (doesFileExist)
import System.FilePath ((</>))
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (testCase, assertFailure, assertEqual)

undoTests :: IO TestTree
undoTests = do
  repo <- repoDir
  rows <- parseSpecFile (repo </> "test" </> "specs" </> "undo.txt")
  tests <- mapM (mkUndoTest repo) (zip [1::Int ..] rows)
  pure (testGroup "undo" (concat tests))

mkUndoTest :: FilePath -> (Int, [String]) -> IO [TestTree]
mkUndoTest repo (_, fields) = case fields of
  (method : basePath : patchPath : baseSha : _) -> do
    let base  = repo </> basePath
        patch = repo </> patchPath
    baseExists  <- doesFileExist base
    patchExists <- doesFileExist patch
    if not (baseExists && patchExists)
      then pure []
      else pure [testCase label $ do
        baseBs  <- BS.readFile base
        patchBs <- BS.readFile patch
        case parseSome patchBs of
          Left err -> assertFailure ("parseSome failed: " ++ err)
          Right sp -> do
            -- Apply
            applied <- applyPatch sp baseBs
            case applied of
              Left err -> assertFailure ("apply failed: " ++ err)
              Right patchedBs -> do
                -- Undo
                undone <- undoPatch sp patchedBs
                case undone of
                  Left err -> assertFailure ("undo failed: " ++ err)
                  Right restoredBs ->
                    assertEqual "SHA256 after undo" baseSha (sha256Hex restoredBs)
      ]
    where
      label = method ++ "/" ++ patchPath
  _ -> pure []
