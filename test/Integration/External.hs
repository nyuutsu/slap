-- | Every external program the integration suite shells out to, the
-- single way to launch one, and the per-tool resolution rules.
--
-- The point of this module is uniformity: there is exactly one
-- subprocess-launch site in the integration suite ('runExternal'), one
-- enum of tools ('ExternalTool'), and one resolver per tool
-- ('resolveExternalTool'). Test-side code never reaches for
-- 'readProcessWithExitCode' or 'findExecutable' directly.
module Integration.External
  ( ExternalTool(..)
  , externalToolName
  , parseExternalToolName
  , allExternalTools
  , resolveExternalTool
  , runExternal
  , ExternalRun(..)
  ) where

import Control.Exception (catch, IOException)
import Data.Time.Clock (NominalDiffTime)
import GHC.Clock (getMonotonicTime)
import System.Directory (doesFileExist, findExecutable, makeAbsolute)
import System.Environment (lookupEnv)
import System.Exit (ExitCode)
import System.FilePath ((</>))
import System.Process (proc, cwd, readCreateProcessWithExitCode, readProcess)

----------------------------------------------------------------------------
-- Tools
----------------------------------------------------------------------------

-- | Every external program the integration suite ever shells out to.
-- The 'Bounded'/'Enum' instances let @SLAP_REQUIRE_TOOLS@ parsing be
-- exhaustive and let the skip-summary renderer iterate cleanly.
data ExternalTool
  = SlapBinary
  | Flips
  | RomPatcher
  | BsPatch
  | Xdelta3
  | Zip
  | Unzip
  deriving (Eq, Ord, Show, Bounded, Enum)

-- | Wire name for a tool: lowercase, used in @SLAP_REQUIRE_TOOLS@,
-- skip-summary lines, and any user-facing diagnostic.
externalToolName :: ExternalTool -> String
externalToolName tool = case tool of
  SlapBinary -> "slap"
  Flips      -> "flips"
  RomPatcher -> "rompatcher"
  BsPatch    -> "bspatch"
  Xdelta3    -> "xdelta3"
  Zip        -> "zip"
  Unzip      -> "unzip"

-- | Inverse of 'externalToolName'. Returns 'Nothing' on an unknown
-- name; callers (notably @SLAP_REQUIRE_TOOLS@ parsing) decide how to
-- report that.
parseExternalToolName :: String -> Maybe ExternalTool
parseExternalToolName name =
  case [tool | tool <- allExternalTools, externalToolName tool == name] of
    (tool:_) -> Just tool
    []       -> Nothing

-- | Every value of 'ExternalTool' in declaration order.
allExternalTools :: [ExternalTool]
allExternalTools = [minBound .. maxBound]

----------------------------------------------------------------------------
-- Resolution
----------------------------------------------------------------------------

-- | Find the executable path for a tool. Each tool has its own resolution
-- rule (env var override, repo-vendored fallback, then @PATH@); they all
-- normalize to @IO (Maybe FilePath)@ so the gating layer ('requireExternalTool')
-- can treat them uniformly.
--
-- The slap binary's resolution short-circuits when @SLAP_BIN@ is set so
-- the test bodies don't pay a @cabal list-bin@ round-trip per call.
resolveExternalTool :: ExternalTool -> IO (Maybe FilePath)
resolveExternalTool tool = case tool of
  SlapBinary -> resolveSlapBinary
  Flips      -> resolveWithEnvOrFallback "FLIPS"      (vendoredFallback "flips/flips")
  RomPatcher -> resolveWithEnvOrFallback "ROMPATCHER" (vendoredFallback "rompatcher-js/index.js")
  BsPatch    -> resolveWithEnvOrFallback "BSPATCH"    (existingFile     "/usr/bin/bspatch")
  Xdelta3    -> resolveWithEnvOrFallback "XDELTA3"    (existingFile     "/usr/bin/xdelta3")
  Zip        -> findExecutable "zip"
  Unzip      -> findExecutable "unzip"

-- | The slap binary's lookup rule: @SLAP_BIN@ wins outright (it's the
-- cache the runner populates after the first cabal-list-bin call), then
-- @cabal -v0 list-bin slap@.
resolveSlapBinary :: IO (Maybe FilePath)
resolveSlapBinary = do
  envOverride <- lookupEnv "SLAP_BIN"
  case envOverride of
    Just executablePath -> pure (Just executablePath)
    Nothing -> do
      cabalResult <- (Just . trimRight <$> readProcess "cabal" ["-v0", "list-bin", "slap"] "")
                       `catch` (\(_ :: IOException) -> pure Nothing)
      case cabalResult of
        Just executablePath | not (null executablePath) -> pure (Just executablePath)
        _                                                -> pure Nothing
  where
    trimRight = reverse . dropWhile (`elem` (" \t\r\n" :: String)) . reverse

-- | A vendored-tool fallback at @<repo>/tools/<relative>@.
vendoredFallback :: FilePath -> IO (Maybe FilePath)
vendoredFallback relativePath = do
  repo <- repoRoot
  let candidate = repo </> "tools" </> relativePath
  exists <- doesFileExist candidate
  if exists
    then Just <$> makeAbsolute candidate
    else pure Nothing

-- | A fixed absolute path — used for system tools we want to pin (like
-- @\/usr\/bin\/bspatch@) rather than resolve via @PATH@.
existingFile :: FilePath -> IO (Maybe FilePath)
existingFile candidate = do
  exists <- doesFileExist candidate
  pure (if exists then Just candidate else Nothing)

-- | Standard env-var-then-fallback rule used by Flips/RomPatcher/BsPatch/Xdelta3.
-- The env var, when set, is taken at face value and only validated for
-- existence; if it points at nothing, resolution fails (rather than
-- silently degrading to the fallback) so user override mistakes surface.
resolveWithEnvOrFallback :: String -> IO (Maybe FilePath) -> IO (Maybe FilePath)
resolveWithEnvOrFallback envVarName fallback = do
  envOverride <- lookupEnv envVarName
  case envOverride of
    Just executablePath -> existingFile executablePath
    Nothing             -> fallback

-- | The repository root used to find @tools/@. Mirrors the 'repoDir'
-- helper in 'Integration.Helpers' but is kept local to avoid a
-- module-import cycle.
repoRoot :: IO FilePath
repoRoot = do
  envOverride <- lookupEnv "SLAP_REPO"
  pure (maybe "." id envOverride)

----------------------------------------------------------------------------
-- Subprocess launch
----------------------------------------------------------------------------

-- | The result of a single 'runExternal' call. Carries the duration so
-- that callers (or a future per-subprocess sidecar log) can reason about
-- timing without a second clock read; today the test bodies only inspect
-- exit code and streams.
data ExternalRun = ExternalRun
  { externalRunExitCode :: !ExitCode
  , externalRunStdout   :: !String
  , externalRunStderr   :: !String
  , externalRunDuration :: !NominalDiffTime
  }

-- | The single subprocess-launch site for the entire integration suite.
-- Resolves the tool's executable, builds a 'CreateProcess' with the
-- requested working directory, runs it, and times the call.
--
-- The 'RomPatcher' case wraps the resolved script path in a @node@
-- invocation; that's a property of the tool, not of the call site, so
-- it lives here.
--
-- A missing tool at this point is a programmer error: callers must gate
-- via 'Integration.Skip.requireExternalTool' (or 'requireSlapBinary')
-- before reaching 'runExternal'.
runExternal
  :: ExternalTool
  -> [String]              -- ^ arguments
  -> Maybe FilePath        -- ^ optional working directory
  -> String                -- ^ stdin
  -> IO ExternalRun
runExternal tool arguments workingDirectory stdinText = do
  resolved <- resolveExternalTool tool
  case resolved of
    Nothing -> error
      ("runExternal: tool " ++ externalToolName tool
       ++ " not resolved — call sites must gate via requireExternalTool.")
    Just toolPath -> do
      let (executable, executableArguments) = case tool of
            RomPatcher -> ("node", toolPath : arguments)
            _          -> (toolPath, arguments)
          processSpec = (proc executable executableArguments)
            { cwd = workingDirectory }
      before <- getMonotonicTime
      (exitCode, stdoutText, stderrText) <-
        readCreateProcessWithExitCode processSpec stdinText
      after <- getMonotonicTime
      pure ExternalRun
        { externalRunExitCode = exitCode
        , externalRunStdout   = stdoutText
        , externalRunStderr   = stderrText
        , externalRunDuration = realToFrac (after - before)
        }
