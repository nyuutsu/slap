module Main (main) where

import Test.Tasty (defaultMain, testGroup)
import Integration.Apply (applyTests)
import Integration.Create (createTests)
import Integration.CrossVal (crossValTests)
import Integration.Convert (convertTests)
import Integration.Metadata (metadataTests)
import Integration.Undo (undoTests)
import Integration.CLI (cliTests)
import Integration.FailureMode (failureModeTests)
import Integration.Helpers
  (repoDir, collectBootstrapPairs, buildBootstrapTargets)

import Control.Concurrent (newEmptyMVar, putMVar, takeMVar, forkIO)
import System.IO.Temp (withSystemTempDirectory)

parSequence :: [IO a] -> IO [a]
parSequence actions = do
  mvars <- mapM (\action -> do
    mvar <- newEmptyMVar
    _ <- forkIO (action >>= putMVar mvar)
    pure mvar) actions
  mapM takeMVar mvars

main :: IO ()
main = do
  repo  <- repoDir
  pairs <- collectBootstrapPairs repo
  withSystemTempDirectory "slap-integration-bootstrap" $ \tempDir -> do
    bootstrapTargets <- buildBootstrapTargets tempDir pairs
    trees <- parSequence
      [ applyTests
      , createTests bootstrapTargets
      , crossValTests bootstrapTargets
      , convertTests
      , metadataTests
      , undoTests
      , cliTests
      , failureModeTests bootstrapTargets
      ]
    defaultMain (testGroup "integration" trees)
