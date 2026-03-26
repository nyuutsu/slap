module Integration.Undo (undoTests) where

import Integration.Helpers
  (repoDir, parseSpecFile, sha1Hex, applyPatch, undoPatch,
   RomCache, cachedReadFile)
import Patch.SomePatch (parseSome)

import qualified Data.ByteString as BS
import System.Directory (doesFileExist)
import System.FilePath ((</>))
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (testCase, assertFailure, assertEqual)

undoTests :: RomCache -> IO TestTree
undoTests romCache = do
  repo <- repoDir
  rows <- parseSpecFile (repo </> "test" </> "specs" </> "undo.txt")
  tests <- mapM (mkUndoTest romCache repo) (zip [1::Int ..] rows)
  pure (testGroup "undo" (concat tests))

mkUndoTest :: RomCache -> FilePath -> (Int, [String]) -> IO [TestTree]
mkUndoTest romCache repo (_, fields) = case fields of
  (method : basePath : patchPath : baseSha : _) -> do
    let base  = repo </> basePath
        patch = repo </> patchPath
    baseExists  <- doesFileExist base
    patchExists <- doesFileExist patch
    if not (baseExists && patchExists)
      then pure []
      else pure [testCase label $ do
        baseBs  <- cachedReadFile romCache base
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
                    assertEqual "SHA1 after undo" baseSha (sha1Hex restoredBs)
      ]
    where
      label = method ++ "/" ++ patchPath
  _ -> pure []
