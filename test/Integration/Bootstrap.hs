-- | The shared bootstrap targets the integration suite consumes.
--
-- Several test groups (create, crossval, failure-mode round-trips)
-- need a /target ROM/ — the result of applying a known-good patch to a
-- known-good base — to compare against. Bootstrapping these targets
-- once and mmap-ing them back from disk costs a few seconds at startup
-- but turns a per-test cost into a per-suite cost.
--
-- This module owns the data structures, the bootstrap procedure, and
-- the tasty 'Resource' that brackets the temp directory's lifecycle
-- around @defaultMain@. The acquire timing is reported on stderr so
-- the bootstrap step is no longer invisible.
module Integration.Bootstrap
  ( BootstrapPair(..)
  , BootstrapTargets
  , collectBootstrapPairs
  , buildBootstrapTargets
  , lookupBootstrapTarget
  , BootstrapAccess(..)
  , withBootstrapTargets
  ) where

import Integration.Helpers
  ( Tier
  , isHeavyPath
  , restrictToTier
  , parseSpecFile
  , applyPatch
  , mmapRomFile
  )
import Slap.Status (renderSlapError)
import Slap.FileContents
  (PatchFileContents(..), InputFileContents(..), OutputFileContents(..))
import Slap.SomePatch (parseSome)
import Slap.Convert (noDialectsRequested)

import Control.Monad (filterM)
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.IORef (IORef, newIORef, readIORef, writeIORef)
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Maybe (mapMaybe)
import qualified Data.Set as Set
import GHC.Clock (getMonotonicTime)
import System.Directory (doesFileExist, removeDirectoryRecursive)
import System.FilePath ((</>))
import qualified System.IO.Temp as Temp
import System.IO (hPutStrLn, stderr)
import Test.Tasty (TestTree, withResource)
import Text.Printf (printf)

----------------------------------------------------------------------------
-- Bootstrap pairs and targets
----------------------------------------------------------------------------

-- | A pair of paths identifying a bootstrap operation: the base ROM
-- that downstream tests start from, and the patch that bootstraps it
-- into the target ROM they actually want to operate on. Stored as
-- absolute paths so two callers naming the same files always produce
-- the same map key.
data BootstrapPair = BootstrapPair
  { bootstrapBase  :: !FilePath
  , bootstrapPatch :: !FilePath
  } deriving (Eq, Ord, Show)

-- | Lookup table from 'BootstrapPair' to mmap'd target bytes. Built
-- once at the top of the test run and shared across every test that
-- compares against a bootstrapped target. Values cost (almost) no GHC
-- heap because they are mmap'd views into temp files.
newtype BootstrapTargets = BootstrapTargets
  { bootstrapTargetsByPair :: Map BootstrapPair ByteString }

-- | Walk the create and crossval spec files (plus the failure-mode
-- tests' hardcoded pairs) and return the deduplicated list of
-- bootstrap pairs the run will need. Pairs whose base or patch files
-- are missing on disk are silently dropped — the corresponding tests
-- already self-skip in that situation.
collectBootstrapPairs :: Tier -> FilePath -> IO [BootstrapPair]
collectBootstrapPairs tier repo = do
  createRows   <- parseSpecFile (repo </> "test" </> "specs" </> "create.txt")
  crossvalRows <- parseSpecFile (repo </> "test" </> "specs" </> "crossval.txt")
  let fromSpecRow row = case row of
        (_format : _scenario : baseRel : patchRel : _) ->
          Just (BootstrapPair (repo </> baseRel) (repo </> patchRel))
        _ -> Nothing
      specPairs = mapMaybe fromSpecRow (createRows ++ crossvalRows)
      failureModePairs =
        [ BootstrapPair
            (repo </> "test/data/dm4y/base.gbc")
            (repo </> "test/data/dm4y/patch.bps")
        , BootstrapPair
            (repo </> "test/data/stadium2/base.z64")
            (repo </> "test/data/stadium2/fair-heavy/patch.bps")
        ]
      allPairs = Set.toList (Set.fromList (specPairs ++ failureModePairs))
  filterM bothFilesExist (restrictToTier tier pairIsHeavy allPairs)
  where
    pairIsHeavy pair = isHeavyPath (bootstrapBase pair)
                    || isHeavyPath (bootstrapPatch pair)
    bothFilesExist pair = do
      baseExists  <- doesFileExist (bootstrapBase pair)
      patchExists <- doesFileExist (bootstrapPatch pair)
      pure (baseExists && patchExists)

-- | For each bootstrap pair: mmap the base, parse and apply the
-- bootstrap patch, write the resulting target bytes to a file inside
-- @tempDir@, and mmap that file back so the value stored in the map
-- costs (almost) no GHC heap. The transient peak during a single
-- bootstrap is one target's worth of bytes; once we re-mmap from
-- disk, that allocation is unreferenced and gets collected.
buildBootstrapTargets :: FilePath -> [BootstrapPair] -> IO BootstrapTargets
buildBootstrapTargets tempDir pairs = do
  entries <- mapM bootstrap (zip [0 :: Int ..] pairs)
  pure (BootstrapTargets (Map.fromList entries))
  where
    bootstrap (index, pair) = do
      baseBytes  <- mmapRomFile (bootstrapBase pair)
      patchBytes <- ByteString.readFile (bootstrapPatch pair)
      case parseSome noDialectsRequested (PatchFileContents patchBytes) of
        Left slapError ->
          error ("bootstrap parse failed for " ++ bootstrapPatch pair
                 ++ ": " ++ renderSlapError slapError)
        Right parsed -> do
          result <- applyPatch parsed (InputFileContents baseBytes)
          case result of
            Left slapError ->
              error ("bootstrap apply failed for " ++ bootstrapPatch pair
                     ++ ": " ++ renderSlapError slapError)
            Right (OutputFileContents targetBytes) -> do
              let targetFile = tempDir </> ("target-" ++ show index ++ ".bin")
              ByteString.writeFile targetFile targetBytes
              mmappedTarget <- mmapRomFile targetFile
              pure (pair, mmappedTarget)

-- | Look up a previously bootstrapped target by base ROM and
-- bootstrap patch path. Missing keys are programmer errors — the test
-- should not have been registered without a corresponding entry — so
-- this throws via 'error' rather than returning a 'Maybe'.
lookupBootstrapTarget :: BootstrapTargets -> FilePath -> FilePath -> ByteString
lookupBootstrapTarget targets basePath patchPath =
  case Map.lookup (BootstrapPair basePath patchPath) (bootstrapTargetsByPair targets) of
    Just targetBytes -> targetBytes
    Nothing -> error ("missing bootstrap target for base=" ++ show basePath
                      ++ " patch=" ++ show patchPath)

----------------------------------------------------------------------------
-- Tasty resource
----------------------------------------------------------------------------

-- | The two pieces a test-tree assembler needs: a deferred 'IO
-- BootstrapTargets' to embed in test bodies (called at run time, not
-- construction time), and a 'TestTree' wrapper that brackets the
-- bootstrap's lifecycle around any subtree that uses it.
--
-- The two-piece shape exists because each group's construction phase
-- runs in 'IO' (filesystem surveys), but tasty's 'withResource' offers
-- the resource only inside its pure continuation. We bridge by giving
-- tests a stable getter (an IORef read) and arranging acquire to fill
-- that IORef before any test in the wrapped subtree runs.
data BootstrapAccess = BootstrapAccess
  { bootstrapAccessGet  :: !(IO BootstrapTargets)
  , bootstrapAccessWrap :: !(TestTree -> TestTree)
  }

-- | Set up the shared bootstrap resource: collects pairs, prepares
-- acquire/release brackets backed by tasty's 'withResource', and
-- returns the access record the runner threads through every test
-- group that needs targets.
--
-- Acquire creates a temp directory, builds every target, prints
-- @bootstrap: built N targets in M.MMM seconds@ to stderr, and
-- populates the IORef so test bodies can read targets via the getter.
-- Release removes the temp directory.
withBootstrapTargets :: Tier -> FilePath -> IO BootstrapAccess
withBootstrapTargets tier repo = do
  pairs       <- collectBootstrapPairs tier repo
  targetsRef  <- newIORef bootstrapTargetsAccessedTooEarly
  let acquire = acquireBootstrap targetsRef pairs
      release = releaseBootstrap
      wrap subtree = withResource acquire release (\_ -> subtree)
  pure BootstrapAccess
    { bootstrapAccessGet  = readIORef targetsRef
    , bootstrapAccessWrap = wrap
    }
  where
    bootstrapTargetsAccessedTooEarly =
      error ( "BootstrapTargets accessed before withBootstrapTargets's "
            ++ "tasty resource was acquired — gate test bodies through "
            ++ "bootstrapAccessGet, do not force at construction time." )

-- | The state tasty holds onto between acquire and release: the temp
-- directory we made and the targets we built into it. Release just
-- needs the directory to remove; the targets are kept as the
-- resource value so they aren't GC'd while tests run.
data BootstrapResource = BootstrapResource
  { bootstrapResourceTempDir :: !FilePath
  , bootstrapResourceTargets :: !BootstrapTargets
  }

acquireBootstrap :: IORef BootstrapTargets -> [BootstrapPair] -> IO BootstrapResource
acquireBootstrap targetsRef pairs = do
  systemTempRoot <- Temp.getCanonicalTemporaryDirectory
  bootstrapDir   <- Temp.createTempDirectory systemTempRoot "slap-integration-bootstrap"
  startTime      <- getMonotonicTime
  targets        <- buildBootstrapTargets bootstrapDir pairs
  endTime        <- getMonotonicTime
  let elapsedSeconds = endTime - startTime
      builtCount     = Map.size (bootstrapTargetsByPair targets)
  -- The bootstrap line lands mid-run because tasty acquires
  -- 'withResource' lazily, right before the first test in the wrapped
  -- subtree. A leading newline keeps it visually separate from
  -- preceding test output. The structural fix (eager acquire, drop
  -- the IORef bridge) is a candidate once the perf work has revealed
  -- how bootstrap interacts with iteration.
  hPutStrLn stderr ""
  hPutStrLn stderr
    (printf "bootstrap: built %d targets in %.3f seconds" builtCount elapsedSeconds)
  writeIORef targetsRef targets
  pure BootstrapResource
    { bootstrapResourceTempDir = bootstrapDir
    , bootstrapResourceTargets = targets
    }

releaseBootstrap :: BootstrapResource -> IO ()
releaseBootstrap resource =
  removeDirectoryRecursive (bootstrapResourceTempDir resource)
