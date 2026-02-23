module Integration.Smoke (smokeTests) where

import Integration.Helpers (repoDir, findPatchFiles, RomCache)
import Patch.SomePatch (SomePatch(..), parseSome)
import Patch.Explain (renderExplain, renderSummary)

import Control.Exception (evaluate)
import qualified Data.ByteString as BS
import Data.List (sort, stripPrefix)
import System.FilePath ((</>))
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (testCase, assertFailure)

smokeTests :: RomCache -> IO TestTree
smokeTests _romCache = do
  repo <- repoDir
  let dataDir = repo </> "test" </> "data"
  files <- sort <$> findPatchFiles dataDir
  let tests = map (mkTest dataDir) files
  pure (testGroup "smoke" tests)

mkTest :: FilePath -> FilePath -> TestTree
mkTest dataDir fp =
  let rel = maybe fp id (stripPrefix (dataDir ++ "/") fp)
  in testCase ("smoke/" ++ rel) $ do
    bs <- BS.readFile fp
    case parseSome bs of
      Left err -> assertFailure ("parseSome failed: " ++ err)
      Right sp -> do
        _ <- evaluate (length (spInfo sp))
        _ <- evaluate (length (take 10000 (renderExplain Nothing (spExplain sp))))
        _ <- evaluate (length (take 10000 (renderSummary Nothing (spExplain sp))))
        pure ()
