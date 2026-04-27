-- | Shared entry point for the integration suite. The main file passes
-- a 'Tier' to 'runIntegrationSuite'; everything downstream is identical.
--
-- Construction order matters here: each test group's 'IO GroupPlan'
-- runs filesystem surveys, so we collect plans first, then print the
-- skip summary, then check @SLAP_REQUIRE_TOOLS@ (which can abort
-- before tasty starts), and only then hand the assembled tree to
-- @defaultMain@. The bootstrap resource is wrapped around the tree
-- so its acquire / release brackets the tasty run; per-test
-- parallelism is whatever @-with-rtsopts=-N@ gave us.
module Integration.Runner (runIntegrationSuite) where

import Integration.Apply (applyTests)
import Integration.Bootstrap
  ( BootstrapAccess(..)
  , withBootstrapTargets
  )
import Integration.CLI (cliTests)
import Integration.Convert (convertTests)
import Integration.Create (createTests)
import Integration.CrossVal (crossValTests)
import Integration.CsvReporter (csvReporter)
import Integration.External (ExternalTool(..), resolveExternalTool)
import Integration.FailureMode (failureModeTests)
import Integration.Helpers (Tier, repoDir)
import Integration.Metadata (metadataTests)
import Integration.Skip
  ( GroupPlan(..)
  , checkRequiredTools
  , renderSkipSummary
  )
import Integration.Undo (undoTests)

import System.Environment (setEnv)
import System.IO (hPutStrLn, stderr)
import Test.Tasty (defaultMainWithIngredients, testGroup)
import Test.Tasty.Ingredients (composeReporters)
import Test.Tasty.Runners (consoleTestReporter, listingTests)

-- | Bootstrap shared targets, run every integration test group, and
-- hand the resulting tree to tasty's 'defaultMainWithIngredients'.
-- The 'Tier' parameter is a placeholder for future re-tiering; today
-- it is always 'AllTests'.
runIntegrationSuite :: Tier -> IO ()
runIntegrationSuite tier = do
  -- Pre-resolve the slap binary once so subsequent in-test
  -- 'runExternal SlapBinary' calls hit the @SLAP_BIN@ env-var fast
  -- path instead of paying a @cabal list-bin@ round-trip per call.
  -- The skip itself, if slap is missing, is recorded by
  -- 'requireSlapBinary' inside each group's plan.
  cacheSlapBinaryPath

  repo            <- repoDir
  bootstrapAccess <- withBootstrapTargets tier repo
  let getTargets = bootstrapAccessGet bootstrapAccess

  combinedPlan <- mconcat <$> sequence
    [ applyTests tier
    , createTests tier getTargets
    , crossValTests tier getTargets
    , convertTests tier
    , metadataTests tier
    , undoTests tier
    , cliTests tier
    , failureModeTests tier getTargets
    ]

  hPutStrLn stderr (renderSkipSummary (groupPlanSkips combinedPlan))
  checkRequiredTools (groupPlanSkips combinedPlan)

  let suiteTree   = testGroup "integration" (groupPlanTrees combinedPlan)
      wrappedTree = bootstrapAccessWrap bootstrapAccess suiteTree
      ingredients =
        [ listingTests
        , composeReporters consoleTestReporter csvReporter
        ]
  defaultMainWithIngredients ingredients wrappedTree

-- | Resolve the slap binary once and cache the result in @SLAP_BIN@ so
-- in-test @resolveExternalTool SlapBinary@ calls become a single
-- 'lookupEnv' instead of spawning @cabal -v0 list-bin slap@ per call.
-- If the binary cannot be resolved at all, we leave the env var alone
-- and let 'requireSlapBinary' record the skip during plan assembly.
cacheSlapBinaryPath :: IO ()
cacheSlapBinaryPath = do
  resolved <- resolveExternalTool SlapBinary
  case resolved of
    Just executablePath -> setEnv "SLAP_BIN" executablePath
    Nothing             -> pure ()
