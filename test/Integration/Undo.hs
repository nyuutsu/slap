{-# LANGUAGE OverloadedStrings #-}

module Integration.Undo (undoTests) where

import Integration.Helpers (assertFailureT)
import Integration.Helpers
  ( Tier
  , isHeavyPath
  , restrictToTier
  , repoDir
  , parseSpecFile
  , sha1Hex
  , applyPatch
  , undoPatch
  , mmapRomFile
  )
import Integration.Skip
  ( GroupPlan
  , MaybeTest(..)
  , namedGroup
  , requireFixture
  )
import Slap.Status (renderSlapError)
import Slap.FileContents (PatchFileContents(..), InputFileContents(..))
import Slap.SomePatch (parseSome)
import Slap.Convert (noDialectsRequested)

import qualified Data.ByteString as ByteString
import System.FilePath ((</>))
import Test.Tasty (TestTree)
import Test.Tasty.HUnit (testCase, assertFailure, assertEqual)

-- | Apply, then undo. For each row: parse the patch, apply to the
-- base, undo from the resulting target, and assert the source SHA1
-- matches what the spec recorded. Each row's two file prerequisites
-- (base + patch) become typed 'MissingFixture' skips when absent.
undoTests :: Tier -> IO GroupPlan
undoTests tier = do
  repo    <- repoDir
  allRows <- parseSpecFile (repo </> "test" </> "specs" </> "undo.txt")
  let inTierRows = restrictToTier tier rowIsHeavy allRows
  rowMaybes <- concat <$> mapM (planUndoRow repo) inTierRows
  pure (namedGroup "undo" rowMaybes)
  where
    rowIsHeavy row = case row of
      (_method : basePath : _) -> isHeavyPath basePath
      _                        -> False

planUndoRow :: FilePath -> [String] -> IO [MaybeTest]
planUndoRow repo fields = case fields of
  (method : basePath : patchPath : baseSha : _) ->
    let absoluteBase  = repo </> basePath
        absolutePatch = repo </> patchPath
        label         = method ++ "/" ++ patchPath
    in requireFixture absoluteBase $ \_ ->
       requireFixture absolutePatch $ \_ ->
         pure [WillRun (mkUndoTest absoluteBase absolutePatch baseSha label)]
  _ -> pure []  -- malformed spec row

mkUndoTest :: FilePath -> FilePath -> String -> String -> TestTree
mkUndoTest basePath patchPath expectedBaseSha label =
  testCase label $ do
    baseBytes  <- mmapRomFile basePath
    patchBytes <- ByteString.readFile patchPath
    case parseSome noDialectsRequested (PatchFileContents patchBytes) of
      Left slapError ->
        assertFailureT ("parseSome failed: " <> renderSlapError slapError)
      Right parsed -> do
        applied <- applyPatch parsed (InputFileContents baseBytes)
        case applied of
          Left slapError ->
            assertFailureT ("apply failed: " <> renderSlapError slapError)
          Right target -> do
            undone <- undoPatch parsed target
            case undone of
              Left errorMessage -> assertFailure ("undo failed: " ++ errorMessage)
              Right (InputFileContents restoredBytes) ->
                assertEqual "SHA1 after undo" expectedBaseSha (sha1Hex restoredBytes)
