-- | Full-tier entry point. Runs every test group at 'Full' tier — the
-- quick tests plus the heavy ones (stadium2, cross-validation against
-- third-party tools, failure-mode subprocesses with multi-MB scratch
-- files). Built only when the @heavy-tests@ cabal flag is set, so
-- @cabal test@ never picks it up by accident. The shared body lives in
-- 'Integration.Runner'.
--
-- The @--list-groups@ flag is intercepted before tasty ever sees the
-- argv: it prints 'topLevelGroupNames' one per line and exits, giving
-- the Makefile something to diff its hardcoded @TEST_GROUPS@ list
-- against on every @make test@ run.
module Main (main) where

import Integration.Helpers (Tier(..))
import Integration.Runner (runIntegrationSuite, topLevelGroupNames)
import System.Environment (getArgs)

main :: IO ()
main = do
  args <- getArgs
  if "--list-groups" `elem` args
    then mapM_ putStrLn topLevelGroupNames
    else runIntegrationSuite Full
