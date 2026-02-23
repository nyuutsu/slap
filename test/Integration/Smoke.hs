module Integration.Smoke (smokeTests) where

import Integration.Helpers (repoDir, findPatchFiles)
import Patch.SomePatch (SomePatch(..), parseSome)
import Patch.Explain (renderExplain, renderSummary)

import Control.Exception (evaluate)
import qualified Data.ByteString as BS
import Data.List (sort, stripPrefix)
import System.FilePath ((</>))
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (testCase, assertFailure)

smokeTests :: IO TestTree
smokeTests = do
  repo <- repoDir
  let dataDir = repo </> "test" </> "data"
  files <- sort <$> findPatchFiles dataDir
  let tests = concatMap (mkTests dataDir) files
  pure (testGroup "smoke" tests)

mkTests :: FilePath -> FilePath -> [TestTree]
mkTests dataDir fp =
  let rel = maybe fp id (stripPrefix (dataDir ++ "/") fp)
  in [ testCase ("info/" ++ rel) (smokeInfo fp)
     , testCase ("explain/" ++ rel) (smokeExplain fp)
     ]

smokeInfo :: FilePath -> IO ()
smokeInfo fp = do
  bs <- BS.readFile fp
  case parseSome bs of
    Left err -> assertFailure ("parseSome failed: " ++ err)
    Right sp -> do
      let s = spInfo sp
      _ <- evaluate (length s)
      pure ()

smokeExplain :: FilePath -> IO ()
smokeExplain fp = do
  bs <- BS.readFile fp
  case parseSome bs of
    Left err -> assertFailure ("parseSome failed: " ++ err)
    Right sp -> do
      let s = renderExplain Nothing (spExplain sp)
      _ <- evaluate (length s)
      let s2 = renderSummary Nothing (spExplain sp)
      _ <- evaluate (length s2)
      pure ()
