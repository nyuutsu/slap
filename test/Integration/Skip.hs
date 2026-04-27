-- | Typed skips for the integration suite.
--
-- Every group's construction phase produces a 'GroupPlan': the trees
-- that will run, plus the recorded reasons for trees that won't. The
-- 'require'* family wraps each "do this only if the prerequisite is
-- present" pattern in a continuation that either runs and produces
-- runnable trees, or short-circuits to a 'WillSkip' carrying the
-- reason. The runner aggregates skips across groups, prints a
-- per-skip summary block, and (if @SLAP_REQUIRE_TOOLS@ is set) exits
-- before @defaultMain@ runs.
module Integration.Skip
  ( SkipReason(..)
  , MaybeTest(..)
  , GroupPlan(..)
  , partitionMaybeTests
  , namedGroup
  , renderSkipSummary
  , requireFixture
  , requireExternalTool
  , requireSlapBinary
  , checkRequiredTools
  ) where

import Data.List (intercalate, sort)
import System.Directory (doesFileExist)
import System.Environment (lookupEnv, setEnv)
import System.Exit (ExitCode(..), exitWith)
import System.IO (hPutStrLn, stderr)
import Test.Tasty (TestTree, testGroup)

import Integration.External
  ( ExternalTool(..)
  , externalToolName
  , parseExternalToolName
  , allExternalTools
  , resolveExternalTool
  )

----------------------------------------------------------------------------
-- The skip vocabulary
----------------------------------------------------------------------------

-- | Why a planned test will not run. Two variants — anything else is
-- either a programmer error or a sign the suite has grown a third
-- skip-shape that deserves its own constructor. The slap binary is
-- one tool among the others ('SlapBinary' :: 'ExternalTool'); a
-- missing slap is a 'MissingExternalTool', not its own variant.
data SkipReason
  = MissingFixture FilePath
  | MissingExternalTool ExternalTool
  deriving (Eq, Ord, Show)

-- | Construction-phase outcome for a single planned test: it either
-- becomes a 'TestTree' the runner will execute, or it becomes a
-- 'SkipReason' the runner aggregates.
data MaybeTest
  = WillRun TestTree
  | WillSkip SkipReason

-- | The output of a single test group's construction phase: trees that
-- will run, and the reasons trees that won't.
data GroupPlan = GroupPlan
  { groupPlanTrees :: ![TestTree]
  , groupPlanSkips :: ![SkipReason]
  }

instance Semigroup GroupPlan where
  GroupPlan trees1 skips1 <> GroupPlan trees2 skips2 =
    GroupPlan (trees1 <> trees2) (skips1 <> skips2)

instance Monoid GroupPlan where
  mempty = GroupPlan [] []

-- | Split a list of 'MaybeTest' into trees and skip reasons.
partitionMaybeTests :: [MaybeTest] -> GroupPlan
partitionMaybeTests = foldr step mempty
  where
    step (WillRun tree)   plan = plan { groupPlanTrees = tree   : groupPlanTrees plan }
    step (WillSkip reason) plan = plan { groupPlanSkips = reason : groupPlanSkips plan }

-- | Wrap the runnable trees of a 'partitionMaybeTests' result in a
-- named tasty group, leaving the skip reasons unwrapped so the runner
-- can aggregate them across groups. The standard last step of every
-- 'IO GroupPlan' function.
namedGroup :: String -> [MaybeTest] -> GroupPlan
namedGroup name maybeTests =
  let plan = partitionMaybeTests maybeTests
  in GroupPlan
       [testGroup name (groupPlanTrees plan)]
       (groupPlanSkips plan)

----------------------------------------------------------------------------
-- The require* family
----------------------------------------------------------------------------

-- | Run @action@ only if a fixture file exists; otherwise emit one
-- skip naming the missing path. The continuation receives the path so
-- it doesn't have to re-spell it.
requireFixture
  :: FilePath
  -> (FilePath -> IO [MaybeTest])
  -> IO [MaybeTest]
requireFixture fixturePath action = do
  exists <- doesFileExist fixturePath
  if exists
    then action fixturePath
    else pure [WillSkip (MissingFixture fixturePath)]

-- | Run @action@ only if an external tool is resolvable; otherwise
-- emit one skip naming the tool. The continuation receives the
-- resolved executable path; today no in-tree caller actually uses it
-- (subprocess invocations route through 'Integration.External.runExternal'
-- which re-resolves), but the path stays in the signature because
-- some future caller might want to assert against it directly.
requireExternalTool
  :: ExternalTool
  -> (FilePath -> IO [MaybeTest])
  -> IO [MaybeTest]
requireExternalTool tool action = do
  resolved <- resolveExternalTool tool
  case resolved of
    Just executablePath -> action executablePath
    Nothing             -> pure [WillSkip (MissingExternalTool tool)]

-- | Like 'requireExternalTool' 'SlapBinary', but with a side effect:
-- on success the resolved path is exported back into @SLAP_BIN@ so
-- that subsequent 'resolveExternalTool SlapBinary' calls (one per
-- 'runExternal SlapBinary' call site) hit the env-var fast path
-- instead of paying a @cabal list-bin@ round-trip per test body.
-- Kept as its own named gate so call sites read cleanly.
requireSlapBinary
  :: (FilePath -> IO [MaybeTest])
  -> IO [MaybeTest]
requireSlapBinary action = requireExternalTool SlapBinary $ \executablePath -> do
  setEnv "SLAP_BIN" executablePath
  action executablePath

----------------------------------------------------------------------------
-- Skip-summary rendering
----------------------------------------------------------------------------

-- | Multi-line summary listing every skipped test's reason: one
-- @missing fixture: PATH@ or @missing tool: NAME@ line per skip,
-- preserving full path / tool detail. Empty input returns a
-- placeholder so the runner can print unconditionally.
--
-- > renderSkipSummary [] == "(no skipped tests)"
-- > renderSkipSummary [MissingExternalTool Flips, MissingFixture "/x"]
-- >   == "SKIPPED:\n  missing tool: flips\n  missing fixture: /x"
renderSkipSummary :: [SkipReason] -> String
renderSkipSummary [] = "(no skipped tests)"
renderSkipSummary reasons =
  unlines (header : map ("  " ++) (map renderReason reasons))
  where
    header = "SKIPPED " ++ show (length reasons) ++ " tests:"
    renderReason (MissingFixture path)      = "missing fixture: " ++ path
    renderReason (MissingExternalTool tool) = "missing tool: " ++ externalToolName tool

----------------------------------------------------------------------------
-- $SLAP_REQUIRE_TOOLS pre-flight check
----------------------------------------------------------------------------

-- | Honour @SLAP_REQUIRE_TOOLS@. If set to a comma-separated list of
-- tool names ('externalToolName'), any required tool whose absence
-- would silently skip a test causes the suite to abort with a non-zero
-- exit code before @defaultMain@ runs.
--
-- Unset env var: no-op. Unknown name: abort with exit 2 naming the
-- name and the legal alphabet. Required-but-skipped: abort with exit
-- 2 listing the violated requirements.
checkRequiredTools :: [SkipReason] -> IO ()
checkRequiredTools skipReasons = do
  spec <- lookupEnv "SLAP_REQUIRE_TOOLS"
  case spec of
    Nothing       -> pure ()
    Just rawValue -> applyRequirements skipReasons (parseRequirementSpec rawValue)

-- | Split a @SLAP_REQUIRE_TOOLS@ value into trimmed, non-empty names.
parseRequirementSpec :: String -> [String]
parseRequirementSpec = filter (not . null) . map trim . splitOn ','
  where
    trim = let dropSides = reverse . dropWhile (`elem` (" \t" :: String)) . reverse
           in dropSides . dropWhile (`elem` (" \t" :: String))
    splitOn separator input = case break (== separator) input of
      (segment, [])             -> [segment]
      (segment, _separator:rest) -> segment : splitOn separator rest

-- | Validate the parsed requirement list against the actual skip set.
applyRequirements :: [SkipReason] -> [String] -> IO ()
applyRequirements skipReasons requestedNames = do
  let parsed = map (\name -> (name, parseExternalToolName name)) requestedNames
      unknownNames = [name | (name, Nothing) <- parsed]
      requiredTools = [tool | (_name, Just tool) <- parsed]
  case unknownNames of
    (badName:_) -> abortWith
      ( "SLAP_REQUIRE_TOOLS: unknown tool name "
        ++ show badName
        ++ " — known names: "
        ++ intercalate ", " (sort (map externalToolName allExternalTools))
      )
    [] -> case missingRequiredTools requiredTools skipReasons of
      []      -> pure ()
      missing -> abortWith
        ( "SLAP_REQUIRE_TOOLS violated: required tool(s) absent on this machine: "
          ++ intercalate ", " (map externalToolName missing)
          ++ " — clear the env var to allow silent skips, or install the missing tools."
        )
  where
    abortWith message = do
      hPutStrLn stderr message
      exitWith (ExitFailure 2)

-- | Return the subset of @requested@ for which the suite would skip at
-- least one test on this machine.
missingRequiredTools :: [ExternalTool] -> [SkipReason] -> [ExternalTool]
missingRequiredTools requestedTools skipReasons =
  [ tool | tool <- requestedTools, any (skipBlamesTool tool) skipReasons ]
  where
    skipBlamesTool tool (MissingExternalTool seenTool) = tool == seenTool
    skipBlamesTool _    (MissingFixture _)             = False
