module Integration.Helpers
  ( -- * Test tier
    Tier(..)
  , isHeavyPath
  , isHeavySuiteName
  , restrictToTier
  , onlyAtFull
    -- * ROM access (mmap-backed, kernel page cache only)
  , mmapRomFile
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

import Integration.External (ExternalTool(..), ExternalRun(..), runExternal)

import Slap.Binary (sha1)
import Slap.Checksum (SHA1Hash(..))
import Slap.Status (SlapError, CreateResult(..), Outcome(..), renderSlapError)
import Slap.Display.Primitives (padHex)
import Slap.Display.Glyph (emDash)
import Slap.FormatLabel (formatLabelName)
import Slap.SomePatch (SomePatch(..), PatchKind(..), ApplyStrategy(..), UndoStrategy(..))
import Slap.FileContents (InputFileContents(..), OutputFileContents(..))
import Slap.Convert (DirectCreate(..), DifferentialCreate(..), CreateFormat(..), PatchContents, RequestedPatchMetadata(..), convertDirect, noConstraintsRequested, noDialectsRequested)
import Slap.Create (createPatch)

import Control.Exception (catch, IOException)
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.Char (toLower, isSpace)
import Data.Int (Int64)
import Data.List (isInfixOf, isPrefixOf)
import System.Directory (removeFile)
import System.Environment (lookupEnv)
import System.Exit (ExitCode(..))
import System.IO.MMap (mmapFileByteString)
import Test.Tasty.HUnit (assertBool, assertFailure)
import System.IO (hClose)
import System.IO.Temp (withSystemTempFile, withSystemTempDirectory)

----------------------------------------------------------------------------
-- Test tier
----------------------------------------------------------------------------

-- | Which tier of the integration suite to run. Currently a single-constructor
-- placeholder: every test runs unconditionally under 'AllTests'. The type is
-- preserved so that re-introducing a tier split later is a small, local change
-- (add a constructor, update 'restrictToTier' and 'onlyAtFull').
data Tier = AllTests deriving (Eq, Show)

-- | True if @path@ refers to one of the heavy ROMs the integration suite
-- knows about: stadium2 (64 MB N64) or paper-mario (40 MB N64). Used as
-- the row-/case-level filter for the 'Quick' tier across the spec-driven
-- test groups (create, convert, metadata, undo, bootstrap collection).
isHeavyPath :: FilePath -> Bool
isHeavyPath path = "stadium2" `isInfixOf` path || "paper-mario" `isInfixOf` path

isHeavySuiteName :: String -> Bool
isHeavySuiteName suiteFileName =
     suiteFileName == "stadium2-fair.suite"
  || suiteFileName == "stadium2-size.suite"
  || suiteFileName == "papermario-pmmq.suite"

-- | Filter entries by tier. With only 'AllTests' today, this is the identity
-- on the list — every entry is included. The signature and call sites are
-- preserved so that re-introducing a filtering tier is a one-line change here.
restrictToTier :: Tier -> (a -> Bool) -> [a] -> [a]
restrictToTier AllTests _entryIsHeavy items = items

-- | Extras that contribute only at the heaviest tier. With only 'AllTests'
-- today, this always includes everything. Call sites are preserved so that
-- re-introducing a light tier is a one-line change here.
onlyAtFull :: Tier -> [a] -> [a]
onlyAtFull AllTests extras = extras

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
  "bps"     -> Just (CreateDifferential CreateBPS)
  "ips"     -> Just (CreateDirect       CreateIPS)
  "ips32"   -> Just (CreateDirect       CreateIPS32)
  "ebp"     -> Just (CreateDirect       CreateEBP)
  "ups"     -> Just (CreateDifferential CreateUPS)
  "ppf3"    -> Just (CreateDirect       CreatePPF3)
  "ppf"     -> Just (CreateDirect       CreatePPF3)
  "pmsr"    -> Just (CreateDirect       CreatePMSR)
  "ninja1"  -> Just (CreateDirect       CreateNINJA1)
  "dps"     -> Just (CreateDifferential CreateDPS)
  "ninja2"  -> Just (CreateDifferential CreateNINJA2)
  "aps-n64" -> Just (CreateDirect       CreateAPSN64)
  "apsn64"  -> Just (CreateDirect       CreateAPSN64)
  "aps-gba" -> Just (CreateDifferential CreateAPSGBA)
  "apsgba"  -> Just (CreateDifferential CreateAPSGBA)
  "gdiff"   -> Just (CreateDifferential CreateGDIFF)
  "xdelta1" -> Just (CreateDifferential CreateXDelta1)
  "xdelta"  -> Just (CreateDifferential CreateXDelta1)
  _         -> Nothing

----------------------------------------------------------------------------
-- Patch application
----------------------------------------------------------------------------

-- | Apply a parsed patch to source bytes.
applyPatch :: SomePatch -> InputFileContents -> IO (Either SlapError OutputFileContents)
applyPatch somePatch source =
  fmap (fmap outcomeValue) (runApply (patchApply somePatch) source)

-- | Undo a parsed patch.
undoPatch :: SomePatch -> OutputFileContents -> IO (Either String InputFileContents)
undoPatch somePatch target = case patchUndo somePatch of
  Nothing -> pure (Left "undo not supported")
  Just undo -> case runUndo undo target of
    Left err -> pure (Left (renderSlapError err))
    Right outcome -> pure (Right (outcomeValue outcome))

removeIfExists :: FilePath -> IO ()
removeIfExists filePath = removeFile filePath `catch` (\(_ :: IOException) -> pure ())

----------------------------------------------------------------------------
-- Conversion
----------------------------------------------------------------------------

-- | Local helper for 'attemptConvert' — the cause/consequence pair
-- of why source-less convert fails for a given 'PatchKind'.
data SourceRequiredReason = SourceRequiredReason
  { sourceRequiredCause       :: String
  , sourceRequiredConsequence :: String
  }

-- | Peer copy of @Main.patchContentsOf@: project the optional
-- 'PatchContents' bag out of a 'SomePatch'.  'Differential' patches
-- never carry one; 'Direct' patches carry 'Just' when their data fits
-- the universal-bag representation ('Nothing' for PPF4 with Append
-- commands).  The peer copy keeps this test module independent of
-- @Main@'s internal helpers.
patchContentsOf :: SomePatch -> Maybe PatchContents
patchContentsOf somePatch = case patchKind somePatch of
  Direct optionalContents -> optionalContents
  Differential            -> Nothing

-- | Replicate the convert logic from Main.hs.
attemptConvert
  :: SomePatch
  -> CreateFormat
  -> Maybe ByteString    -- ^ base ROM (--with)
  -> RequestedPatchMetadata          -- ^ metadata
  -> IO (Either String CreateResult)
attemptConvert somePatch targetFormat maybeBase meta = case maybeBase of
  Just baseBytes -> do
    targetResult <- applyPatch somePatch (InputFileContents baseBytes)
    case targetResult of
      Left slapError -> pure (Left (renderSlapError slapError))
      Right target ->
        case createPatch targetFormat Nothing (InputFileContents baseBytes) target meta (patchContentsOf somePatch) noConstraintsRequested noDialectsRequested of
          Left slapErr -> pure (Left (renderSlapError slapErr))
          Right result -> pure (Right result)
  Nothing -> case patchKind somePatch of
    Direct (Just patchContent) -> pure $ case convertDirect patchContent targetFormat meta noConstraintsRequested noDialectsRequested of
      Left slapErr -> Left (renderSlapError slapErr)
      Right result -> Right result
    Direct Nothing             -> pure (Left (needWithMsg somePatch))
    Differential               -> pure (Left (needWithMsg somePatch))
  where
    needWithMsg thePatch =
      "converting from " ++ name ++ " requires the original ROM (--with INPUT)\n"
      ++ name ++ " " ++ sourceRequiredCause reason ++ ". "
      ++ sourceRequiredConsequence reason
      where
        name   = formatLabelName (patchFormat thePatch)
        reason = case patchKind thePatch of
          Differential -> SourceRequiredReason
            { sourceRequiredCause       = "tells us what to change in the source ROM, not what the result should be"
            , sourceRequiredConsequence = "To convert it, we'd apply the patch to the source first and convert the result " ++ [emDash] ++ " which is why we need the source."
            }
          Direct _ -> SourceRequiredReason
            { sourceRequiredCause       = "can't be converted directly into another patch format"
            , sourceRequiredConsequence = "To convert it, we'd apply the patch to the source first and convert the result " ++ [emDash] ++ " which is why we need the source."
            }

----------------------------------------------------------------------------
-- File discovery
----------------------------------------------------------------------------

repoDir :: IO FilePath
repoDir = do
  maybeEnvironment <- lookupEnv "SLAP_REPO"
  pure (maybe "." id maybeEnvironment)

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
--
-- The slap binary path is resolved via 'Integration.External.runExternal'
-- 'SlapBinary'; the 'Integration.Skip.requireSlapBinary' gate populates
-- @SLAP_BIN@ once at startup so this resolution is a fast env-var read.
expectFail :: [String] -> String -> String -> IO ()
expectFail arguments label pattern = do
  ExternalRun { externalRunExitCode = exitCode
              , externalRunStdout   = stdoutText
              , externalRunStderr   = stderrText } <-
    runExternal SlapBinary arguments Nothing ""
  let combined = stdoutText ++ stderrText
  case exitCode of
    ExitFailure _ ->
      assertBool (label ++ ": expected '" ++ pattern ++ "' in: " ++ combined)
        (map toLower pattern `isInfixOf` map toLower combined)
    ExitSuccess ->
      assertFailure (label ++ ": expected failure but got success: " ++ combined)

-- | Run slap, expect success, check stderr+stdout contains pattern (case-insensitive).
expectOk :: [String] -> String -> String -> IO ()
expectOk arguments label pattern = do
  ExternalRun { externalRunExitCode = exitCode
              , externalRunStdout   = stdoutText
              , externalRunStderr   = stderrText } <-
    runExternal SlapBinary arguments Nothing ""
  let combined = stdoutText ++ stderrText
  case exitCode of
    ExitSuccess ->
      assertBool (label ++ ": expected '" ++ pattern ++ "' in: " ++ combined)
        (map toLower pattern `isInfixOf` map toLower combined)
    ExitFailure _ ->
      assertFailure (label ++ ": expected success but got failure: " ++ combined)

-- | Like 'expectOk', but also asserts that a warning was emitted.
expectOkWithWarning :: [String] -> String -> String -> IO ()
expectOkWithWarning arguments label pattern = do
  ExternalRun { externalRunExitCode = exitCode
              , externalRunStdout   = stdoutText
              , externalRunStderr   = stderrText } <-
    runExternal SlapBinary arguments Nothing ""
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
