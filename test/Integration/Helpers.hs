module Integration.Helpers
  ( -- * Test tier
    Tier(..)
  , isHeavyPath
  , isHeavySuiteName
  , restrictToTier
  , onlyAtFull
    -- * ROM access (mmap-backed, kernel page cache only)
  , mmapRomFile
    -- * Shared bootstrap targets
  , BootstrapPair(..)
  , BootstrapTargets
  , collectBootstrapPairs
  , buildBootstrapTargets
  , lookupBootstrapTarget
    -- * Hashing
  , sha1Hex
    -- * Spec/suite parsing
  , parseSpecFile
  , SuiteHeader(..)
  , SuiteEntry(..)
  , parseSuiteFile
  , parseCreateFormat
    -- * Patch application
  , applyPatch
  , undoPatch
    -- * Conversion
  , attemptConvert
    -- * File discovery
  , repoDir
  , findSlapBinary
  , runSlap
    -- * Pattern matching
  , matchPattern
    -- * Subprocess assertions
  , expectFail
  , expectOk
  , expectOkWithWarning
    -- * Test data
  , writeGarbage
    -- * String helpers
  , trim
  , ciContains
    -- * File helpers
  , removeIfExists
    -- * Temp helpers
  , withTempFile
  , withTempDir
  ) where

import Slap.Binary (sha1)
import Slap.Checksum (SHA1Hash(..))
import Slap.Error (SlapError, CreateResult(..), renderSlapError)
import Slap.Format (padHex)
import Slap.FormatLabel (formatLabelName)
import Slap.SomePatch (SomePatch(..), ApplyStrategy(..), UndoStrategy(..), parseSome)
import Slap.Convert (DirectCreate(..), DiffCreate(..), CreateFormat(..), CreateMeta(..), convertDirect, createFromMemory)

import Control.Exception (catch, IOException)
import Control.Monad (filterM)
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.Char (toLower, isSpace)
import Data.Int (Int64)
import Data.List (isInfixOf, isPrefixOf)
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Maybe (mapMaybe)
import qualified Data.Set as Set
import System.Directory (doesFileExist, removeFile)
import System.Environment (lookupEnv)
import System.Exit (ExitCode(..))
import System.FilePath ((</>))
import System.IO.MMap (mmapFileByteString)
import Test.Tasty.HUnit (assertBool, assertFailure)
import System.IO (hClose)
import System.IO.Temp (withSystemTempFile, withSystemTempDirectory)
import System.Process (readProcessWithExitCode, readProcess)

----------------------------------------------------------------------------
-- Test tier
----------------------------------------------------------------------------

-- | Which tier of the integration suite a test belongs to. 'Quick' tests
-- run on every @cabal test@ invocation: they finish fast, touch only small
-- ROMs, and never shell out to a third-party tool. 'Full' covers everything
-- — both the quick tests and the heavy ones — and is gated behind the
-- @heavy-tests@ cabal flag so it only runs when explicitly invoked.
data Tier = Quick | Full deriving (Eq, Show)

-- | True if @path@ refers to one of the heavy ROMs the integration suite
-- knows about: stadium2 (64 MB N64) or paper-mario (40 MB N64). Used as
-- the row-/case-level filter for the 'Quick' tier across the spec-driven
-- test groups (create, convert, metadata, undo, bootstrap collection).
isHeavyPath :: FilePath -> Bool
isHeavyPath path = "stadium2" `isInfixOf` path || "paper-mario" `isInfixOf` path

-- | True if @suiteFileName@ is a @.suite@ file the 'Quick' apply tier
-- should skip. The two stadium2 suites are excluded wholesale because
-- they hash a 64 MB ROM per entry; @papermario-pmmq.suite@ is excluded
-- specifically because its single PMSR/Yay0 entry takes ~77 seconds.
-- Other paper-mario suites stay in 'Quick' since the apply path on a
-- 40 MB ROM is still fast.
isHeavySuiteName :: String -> Bool
isHeavySuiteName suiteFileName =
  "stadium2-" `isPrefixOf` suiteFileName
  || suiteFileName == "papermario-pmmq.suite"

-- | Drop entries the 'Quick' tier should skip; 'Full' keeps everything.
-- The predicate names "is this entry heavy" — i.e. true for the entries
-- 'Quick' excludes — so call sites read as
-- @restrictToTier tier rowIsHeavy rows@.
restrictToTier :: Tier -> (a -> Bool) -> [a] -> [a]
restrictToTier Quick entryIsHeavy  items = filter (not . entryIsHeavy) items
restrictToTier Full  _entryIsHeavy items = items

-- | Extras that contribute only when the tier is 'Full'. Used with
-- ordinary list concatenation, so the @(++)@ stays visible at the call
-- site and this helper just encodes the "include only if Full" gating:
--
-- > pure (quickSubprocess ++ onlyAtFull tier heavySubprocess)
onlyAtFull :: Tier -> [a] -> [a]
onlyAtFull Quick _heavyExtras = []
onlyAtFull Full  heavyExtras  = heavyExtras

----------------------------------------------------------------------------
-- ROM access
----------------------------------------------------------------------------

-- | Map a ROM file into memory and return a strict ByteString view onto the
-- mmap'd region. Bytes live in the kernel page cache, not the GHC heap, so
-- two calls on the same file are essentially free and large ROMs cost
-- (almost) nothing in residency. The returned ByteString is read-only.
mmapRomFile :: FilePath -> IO ByteString
mmapRomFile filePath = mmapFileByteString filePath Nothing

----------------------------------------------------------------------------
-- Bootstrap targets
----------------------------------------------------------------------------

-- | A pair of paths identifying a bootstrap operation: the base ROM that
-- downstream tests start from, and the patch that bootstraps it into the
-- target ROM they actually want to operate on. Stored as absolute paths so
-- two callers naming the same files always produce the same key.
data BootstrapPair = BootstrapPair
  { bootstrapBase  :: !FilePath
  , bootstrapPatch :: !FilePath
  } deriving (Eq, Ord, Show)

-- | Lookup table from 'BootstrapPair' to mmap'd target bytes. Built once at
-- the top of the test run and shared across every test tree that needs to
-- compare against a bootstrapped target. Values cost (almost) no GHC heap
-- because they are mmap'd views into temp files.
newtype BootstrapTargets = BootstrapTargets
  { bootstrapTargetsByPair :: Map BootstrapPair ByteString }

-- | Walk the create and crossval spec files (plus the failure-mode tests'
-- hardcoded pairs) and produce the deduplicated list of bootstrap pairs the
-- test run will need targets for. In the 'Quick' tier, pairs that touch a
-- heavy ROM (per 'isHeavyPath') are filtered out so the temp dir stays
-- small and bootstrap is fast. Pairs whose base or patch files are missing
-- on disk are silently dropped — the corresponding tests already self-skip
-- in that situation.
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
            (repo </> "test/data/stadium2/heavy-diff/patch.bps")
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

-- | For each bootstrap pair: mmap the base, parse and apply the bootstrap
-- patch, write the resulting target bytes to a file inside @tempDir@, and
-- mmap that file back so the value stored in the map costs (almost) no GHC
-- heap. The transient peak during a single bootstrap is one target's worth
-- of bytes; once we re-mmap from disk, that allocation is unreferenced and
-- gets collected.
buildBootstrapTargets :: FilePath -> [BootstrapPair] -> IO BootstrapTargets
buildBootstrapTargets tempDir pairs = do
  entries <- mapM bootstrap (zip [0 :: Int ..] pairs)
  pure (BootstrapTargets (Map.fromList entries))
  where
    bootstrap (index, pair) = do
      baseBytes  <- mmapRomFile (bootstrapBase pair)
      patchBytes <- ByteString.readFile (bootstrapPatch pair)
      case parseSome patchBytes of
        Left slapError ->
          error ("bootstrap parse failed for " ++ bootstrapPatch pair
                 ++ ": " ++ renderSlapError slapError)
        Right parsed -> do
          result <- applyPatch parsed baseBytes
          case result of
            Left slapError ->
              error ("bootstrap apply failed for " ++ bootstrapPatch pair
                     ++ ": " ++ renderSlapError slapError)
            Right targetBytes -> do
              let targetFile = tempDir </> ("target-" ++ show index ++ ".bin")
              ByteString.writeFile targetFile targetBytes
              mmappedTarget <- mmapRomFile targetFile
              pure (pair, mmappedTarget)

-- | Look up a previously bootstrapped target by base ROM and bootstrap patch
-- path. Missing keys are programmer errors (the test should not have been
-- registered without a corresponding entry in the shared map), so this
-- throws via 'error' rather than returning a 'Maybe'.
lookupBootstrapTarget :: BootstrapTargets -> FilePath -> FilePath -> ByteString
lookupBootstrapTarget targets basePath patchPath =
  case Map.lookup (BootstrapPair basePath patchPath) (bootstrapTargetsByPair targets) of
    Just targetBytes -> targetBytes
    Nothing -> error ("missing bootstrap target for base=" ++ show basePath
                      ++ " patch=" ++ show patchPath)

----------------------------------------------------------------------------
-- Hashing
----------------------------------------------------------------------------

sha1Hex :: ByteString -> String
sha1Hex inputBytes =
  let digest = sha1 inputBytes
  in concatMap (\byte -> padHex 2 (fromIntegral byte :: Int64)) (ByteString.unpack (unSHA1Hash digest))

----------------------------------------------------------------------------
-- Spec/suite parsing
----------------------------------------------------------------------------

-- | Read a spec file, strip comments and blanks, split on '|', trim fields.
parseSpecFile :: FilePath -> IO [[String]]
parseSpecFile path = do
  content <- readFile path
  let contentLines = filter (not . isComment) (lines content)
  pure (map splitFields contentLines)
  where
    isComment line = let stripped = dropWhile isSpace line in null stripped || "#" `isPrefixOf` stripped
    splitFields = map trim . splitOn '|'

trim :: String -> String
trim = reverse . dropWhile isSpace . reverse . dropWhile isSpace

splitOn :: Char -> String -> [String]
splitOn separator = splitLoop
  where
    splitLoop [] = [""]
    splitLoop (char:rest)
      | char == separator = "" : splitLoop rest
      | otherwise   = case splitLoop rest of
          (segment:segments) -> (char:segment) : segments
          []                 -> [""]

data SuiteHeader = SuiteHeader
  { suiteBase        :: FilePath
  , suiteSha1        :: String
  , suiteDescription :: String
  } deriving (Show)

data SuiteEntry = SuiteEntry
  { entryFormat     :: String
  , entryPatch      :: FilePath
  , entryConfidence :: String
  , _entryProvenance :: String
  } deriving (Show)

parseSuiteFile :: FilePath -> IO (SuiteHeader, [SuiteEntry])
parseSuiteFile path = do
  content <- readFile path
  let contentLines = lines content
      patchLines   = filter isPatchLine contentLines
      header       = parseHeader contentLines
      entries      = map parsePatchLine patchLines
  pure (header, entries)
  where
    isPatchLine line =
      let stripped = dropWhile isSpace line
      in '|' `elem` line && not ("#" `isPrefixOf` stripped) && not (null stripped)

    parseHeader headerLines = SuiteHeader
      { suiteBase        = extractField "base:" headerLines
      , suiteSha1        = extractField "sha1:" headerLines
      , suiteDescription = extractField "desc:" headerLines
      }

    extractField prefix fieldLines =
      case filter (\line -> prefix `isPrefixOf` dropWhile isSpace line) fieldLines of
        (line:_) -> trim (drop (length prefix) (dropWhile isSpace line))
        []       -> ""

    parsePatchLine line = case map trim (splitOn '|' line) of
      (formatString:patch:confidence:provenance:_) -> SuiteEntry formatString patch confidence provenance
      (formatString:patch:confidence:_)      -> SuiteEntry formatString patch confidence ""
      _                             -> SuiteEntry "" "" "" ""

-- | Parse a create format string (mirrors Main.hs parseCreateFormat).
parseCreateFormat :: String -> Maybe CreateFormat
parseCreateFormat formatString = case map toLower formatString of
  "bps"     -> Just (CreateDiff CreateBPS)
  "ips"     -> Just (CreateDirect CreateIPS)
  "ips32"   -> Just (CreateDirect CreateIPS32)
  "ebp"     -> Just (CreateDirect CreateEBP)
  "ups"     -> Just (CreateDiff CreateUPS)
  "ppf3"    -> Just (CreateDirect CreatePPF3)
  "ppf"     -> Just (CreateDirect CreatePPF3)
  "pmsr"    -> Just (CreateDirect CreatePMSR)
  "ninja1"  -> Just (CreateDirect CreateNINJA1)
  "dps"     -> Just (CreateDiff CreateDPS)
  "rup"     -> Just (CreateDiff CreateRUP)
  "ninja2"  -> Just (CreateDiff CreateRUP)
  "aps-n64" -> Just (CreateDirect CreateAPSN64)
  "apsn64"  -> Just (CreateDirect CreateAPSN64)
  "aps-gba" -> Just (CreateDiff CreateAPSGBA)
  "apsgba"  -> Just (CreateDiff CreateAPSGBA)
  "gdiff"   -> Just (CreateDiff CreateGDIFF)
  "pchtxt"  -> Just (CreateDirect CreatePCHTXT)
  _         -> Nothing

----------------------------------------------------------------------------
-- Patch application
----------------------------------------------------------------------------

-- | Apply a parsed patch to source bytes.
applyPatch :: SomePatch -> ByteString -> IO (Either SlapError ByteString)
applyPatch somePatch source = inMemoryApply (patchApply somePatch) source

-- | Undo a parsed patch.
undoPatch :: SomePatch -> ByteString -> IO (Either String ByteString)
undoPatch somePatch patched = case patchUndo somePatch of
  Nothing -> pure (Left "undo not supported")
  Just (UndoInMemory undoFunction) -> pure (Right (undoFunction patched))

removeIfExists :: FilePath -> IO ()
removeIfExists filePath = removeFile filePath `catch` (\(_ :: IOException) -> pure ())

----------------------------------------------------------------------------
-- Conversion
----------------------------------------------------------------------------

-- | Replicate the convert logic from Main.hs.
attemptConvert
  :: SomePatch
  -> CreateFormat
  -> Maybe ByteString    -- ^ base ROM (--with)
  -> CreateMeta          -- ^ metadata
  -> IO (Either String CreateResult)
attemptConvert somePatch targetFormat maybeBase meta = case maybeBase of
  Just baseBytes -> do
    targetResult <- applyPatch somePatch baseBytes
    case targetResult of
      Left slapError -> pure (Left (renderSlapError slapError))
      Right targetBytes ->
        case createFromMemory targetFormat baseBytes targetBytes meta (patchContents somePatch) of
          Left slapErr -> pure (Left (renderSlapError slapErr))
          Right result -> pure (Right result)
  Nothing -> case patchContents somePatch of
    Nothing -> pure (Left (needWithMsg somePatch))
    Just patchContent -> pure $ case convertDirect patchContent targetFormat meta of
      Left slapErr -> Left (renderSlapError slapErr)
      Right result -> Right result
  where
    needWithMsg thePatch =
      "converting from " ++ name ++ " requires the original ROM (--with SOURCE)\n"
      ++ name ++ " " ++ reason ++ " \8212 the original ROM is needed\n"
      ++ "to reconstruct the target file for re-encoding."
      where
        name = formatLabelName (patchFormat thePatch)
        reason
          | patchIsDifferential thePatch = "stores differential data, not raw bytes"
          | otherwise                    = "applies in-place to the target file"

----------------------------------------------------------------------------
-- File discovery
----------------------------------------------------------------------------

repoDir :: IO FilePath
repoDir = do
  maybeEnvironment <- lookupEnv "SLAP_REPO"
  pure (maybe "." id maybeEnvironment)

findSlapBinary :: IO (Maybe FilePath)
findSlapBinary = do
  maybeEnvironment <- lookupEnv "SLAP_BIN"
  case maybeEnvironment of
    Just executablePath -> pure (Just executablePath)
    Nothing -> do
      result <- (Just . trim <$> readProcess "cabal" ["-v0", "list-bin", "slap"] "")
                  `catch` (\(_ :: IOException) -> pure Nothing)
      case result of
        Just executablePath | not (null executablePath) -> pure (Just executablePath)
        _ -> pure Nothing

runSlap :: FilePath -> [String] -> IO (ExitCode, String, String)
runSlap executable arguments = readProcessWithExitCode executable arguments ""


----------------------------------------------------------------------------
-- Pattern matching
----------------------------------------------------------------------------

-- | Case-insensitive substring match with `.*` wildcard support.
-- matchPattern "dropping.*validation" "note: dropping PPF3 validation block" == True
matchPattern :: String -> String -> Bool
matchPattern pattern string =
  let patternLower = map toLower pattern
      stringLower = map toLower string
  in any (matchAt patternLower) (allTails stringLower)
  where
    allTails :: [a] -> [[a]]
    allTails [] = [[]]
    allTails whole@(_:remaining) = whole : allTails remaining

    matchAt :: String -> String -> Bool
    matchAt [] _  = True
    matchAt _  [] = False
    matchAt ('.' : '*' : patternRest) stringCharacters = any (matchAt patternRest) (allTails stringCharacters)
    matchAt (patternCharacter:patternRest) (stringCharacter:stringRest) = patternCharacter == stringCharacter && matchAt patternRest stringRest

----------------------------------------------------------------------------
-- Temp helpers
----------------------------------------------------------------------------

withTempFile :: String -> (FilePath -> IO a) -> IO a
withTempFile template action =
  withSystemTempFile template (\filePath handle -> hClose handle >> action filePath)

withTempDir :: String -> (FilePath -> IO a) -> IO a
withTempDir = withSystemTempDirectory

----------------------------------------------------------------------------
-- Subprocess assertions
----------------------------------------------------------------------------

-- | Run slap, expect failure, check stderr+stdout contains pattern (case-insensitive).
expectFail :: FilePath -> [String] -> String -> String -> IO ()
expectFail slap arguments label pattern = do
  (exitCode, stdoutText, stderrText) <- runSlap slap arguments
  let combined = stdoutText ++ stderrText
  case exitCode of
    ExitFailure _ ->
      assertBool (label ++ ": expected '" ++ pattern ++ "' in: " ++ combined)
        (map toLower pattern `isInfixOf` map toLower combined)
    ExitSuccess ->
      assertFailure (label ++ ": expected failure but got success: " ++ combined)

-- | Run slap, expect success, check stderr+stdout contains pattern (case-insensitive).
expectOk :: FilePath -> [String] -> String -> String -> IO ()
expectOk slap arguments label pattern = do
  (exitCode, stdoutText, stderrText) <- runSlap slap arguments
  let combined = stdoutText ++ stderrText
  case exitCode of
    ExitSuccess ->
      assertBool (label ++ ": expected '" ++ pattern ++ "' in: " ++ combined)
        (map toLower pattern `isInfixOf` map toLower combined)
    ExitFailure _ ->
      assertFailure (label ++ ": expected success but got failure: " ++ combined)

-- | Like expectOk, but also asserts that a warning was emitted.
expectOkWithWarning :: FilePath -> [String] -> String -> String -> IO ()
expectOkWithWarning slap arguments label pattern = do
  (exitCode, stdoutText, stderrText) <- runSlap slap arguments
  let combined = stdoutText ++ stderrText
  case exitCode of
    ExitSuccess -> do
      assertBool (label ++ ": expected '" ++ pattern ++ "' in: " ++ combined)
        (map toLower pattern `isInfixOf` map toLower combined)
      assertBool (label ++ ": expected warning in output: " ++ combined)
        ("warning" `isInfixOf` map toLower combined)
    ExitFailure _ ->
      assertFailure (label ++ ": expected success but got failure: " ++ combined)

----------------------------------------------------------------------------
-- Test data
----------------------------------------------------------------------------

-- | Write deterministic pseudo-random bytes to a file.
--
-- Generates the bytes directly into the destination ByteString via
-- 'ByteString.unfoldrN' so we never materialise an intermediate
-- @[Int]@ spine — at 4 MB that list would cost ~160 MB of throwaway
-- cons cells per call, and ~20 failure-mode tests call it.
writeGarbage :: FilePath -> Int -> IO ()
writeGarbage filePath count = ByteString.writeFile filePath bytes
  where
    bytes       = fst (ByteString.unfoldrN count step initialSeed)
    initialSeed = 42 :: Int
    multiplier  = 1103515245
    increment   = 12345
    modulus     = 256
    step seed =
      let nextSeed = (seed * multiplier + increment) `mod` modulus
      in Just (fromIntegral nextSeed, nextSeed)

----------------------------------------------------------------------------
-- String helpers
----------------------------------------------------------------------------

-- | Case-insensitive substring check.
ciContains :: String -> String -> Bool
ciContains needle haystack = map toLower needle `isInfixOf` map toLower haystack
