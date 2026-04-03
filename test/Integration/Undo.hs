module Integration.Undo (undoTests) where

import Integration.Helpers
  (repoDir, parseSpecFile, sha1Hex, applyPatch, undoPatch,
   RomCache, cachedReadFile)
import Slap.Error (renderSlapError)
import Slap.SomePatch (parseSome)

import qualified Data.ByteString as ByteString
import System.Directory (doesFileExist)
import System.FilePath ((</>))
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (testCase, assertFailure, assertEqual)

undoTests :: RomCache -> IO TestTree
undoTests romCache = do
  repo <- repoDir
  rows <- parseSpecFile (repo </> "test" </> "specs" </> "undo.txt")
  tests <- mapM (makeUndoTest romCache repo) (zip [1::Int ..] rows)
  pure (testGroup "undo" (concat tests))

makeUndoTest :: RomCache -> FilePath -> (Int, [String]) -> IO [TestTree]
makeUndoTest romCache repo (_, fields) = case fields of
  (method : basePath : patchPath : baseSha : _) -> do
    let base  = repo </> basePath
        patch = repo </> patchPath
    baseExists  <- doesFileExist base
    patchExists <- doesFileExist patch
    if not (baseExists && patchExists)
      then pure []
      else pure [testCase label $ do
        baseBytes  <- cachedReadFile romCache base
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
