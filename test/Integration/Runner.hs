-- | Shared entry-point machinery for the quick and full integration tiers.
-- Each tier-specific main file picks a 'Tier' and hands off to
-- 'runIntegrationSuite'; everything downstream is identical.
module Integration.Runner (runIntegrationSuite, topLevelGroupNames) where

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

-- | Bootstrap the shared targets for @tier@, then run every integration
-- test group at that tier and hand the resulting tree to tasty's
-- 'defaultMain'. The bootstrap pair set, the test groups themselves, and
-- the size of the temp directory all shrink automatically when @tier@ is
-- 'Integration.Helpers.Quick'.
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

-- | The canonical list of top-level test groups inside the
-- integration-full binary, in the order they're built by
-- 'runIntegrationSuite'. Adding a new top-level test group
-- requires updating this list AND the Makefile's
-- @TEST_GROUPS@ variable; the Makefile sanity-checks the
-- two stay in sync at the start of every @make test-full@
-- run via the @--list-groups@ flag exposed by the
-- integration-full binary's @Main@.
topLevelGroupNames :: [String]
topLevelGroupNames =
  [ "apply"
  , "create"
  , "crossval"
  , "convert"
  , "metadata"
  , "undo"
  , "cli"
  , "failure-mode"
  ]
