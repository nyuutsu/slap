-- | Integration suite entry point. Runs every test group unconditionally.
-- The shared body lives in 'Integration.Runner'.
module Main (main) where

import Integration.Helpers (Tier(..))
import Integration.Runner (runIntegrationSuite)

main :: IO ()
main = runIntegrationSuite AllTests
