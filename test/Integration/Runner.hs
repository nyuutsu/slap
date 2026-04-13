-- | Shared entry point for the integration suite. The main file passes
-- a 'Tier' to 'runIntegrationSuite'; everything downstream is identical.
module Integration.Runner (runIntegrationSuite) where

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
  (Tier, repoDir, collectBootstrapPairs, buildBootstrapTargets)

import Control.Concurrent (newEmptyMVar, putMVar, takeMVar, forkIO)
import System.IO.Temp (withSystemTempDirectory)

-- | Bootstrap the shared targets, then run every integration test group and
-- hand the resulting tree to tasty's 'defaultMain'. The 'Tier' parameter is
-- a placeholder for future re-tiering; today it is always 'AllTests'.
runIntegrationSuite :: Tier -> IO ()
runIntegrationSuite tier = do
  repo  <- repoDir
  pairs <- collectBootstrapPairs tier repo
  withSystemTempDirectory "slap-integration-bootstrap" $ \tempDir -> do
    bootstrapTargets <- buildBootstrapTargets tempDir pairs
    trees <- parSequence
      [ applyTests tier
      , createTests tier bootstrapTargets
      , crossValTests tier bootstrapTargets
      , convertTests tier
      , metadataTests tier
      , undoTests tier
      , cliTests tier
      , failureModeTests tier bootstrapTargets
      ]
    defaultMain (testGroup "integration" trees)

parSequence :: [IO a] -> IO [a]
parSequence actions = do
  mvars <- mapM (\action -> do
    mvar <- newEmptyMVar
    _ <- forkIO (action >>= putMVar mvar)
    pure mvar) actions
  mapM takeMVar mvars
