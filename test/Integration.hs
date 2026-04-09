-- | Quick-tier entry point. Runs every test group at 'Quick' tier so the
-- suite stays light enough to invoke on every save. The heavy tier lives
-- in @IntegrationFull.hs@ and is gated behind the @heavy-tests@ cabal flag.
-- The shared body lives in 'Integration.Runner'.
module Main (main) where

import Integration.Helpers (Tier(..))
import Integration.Runner (runIntegrationSuite)

main :: IO ()
main = runIntegrationSuite Quick
