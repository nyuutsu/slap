-- | Full-tier entry point. Runs every test group at 'Full' tier — the
-- quick tests plus the heavy ones (stadium2, cross-validation against
-- third-party tools, failure-mode subprocesses with multi-MB scratch
-- files). Built only when the @heavy-tests@ cabal flag is set, so
-- @cabal test@ never picks it up by accident. The shared body lives in
-- 'Integration.Runner'.
module Main (main) where

import Integration.Helpers (Tier(..))
import Integration.Runner (runIntegrationSuite)

main :: IO ()
main = runIntegrationSuite Full
