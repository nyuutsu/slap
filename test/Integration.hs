module Main (main) where

import Test.Tasty (defaultMain, testGroup)
import Integration.Apply (applyTests)
import Integration.Create (createTests)
import Integration.CrossVal (crossValTests)
import Integration.Convert (convertTests)
import Integration.Metadata (metadataTests)
import Integration.Undo (undoTests)
import Integration.Smoke (smokeTests)
import Integration.CLI (cliTests)

main :: IO ()
main = do
  trees <- sequence
    [applyTests, createTests, crossValTests, convertTests,
     metadataTests, undoTests, smokeTests, cliTests]
  defaultMain (testGroup "integration" trees)
