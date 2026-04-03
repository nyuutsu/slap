module Integration.Helpers
  ( -- * Caching
    RomCache
  , cachedReadFile
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
import Slap.Error (SlapError, renderSlapError, renderSlapWarning)
import Slap.Format (padHex)
import Slap.FormatLabel (formatLabelName)
import Slap.SomePatch (SomePatch(..), ApplyStrategy(..), UndoStrategy(..))
import Slap.Convert (DirectCreate(..), DiffCreate(..), CreateFormat(..), CreateMeta(..), convertDirect, createFromMemory)

import Control.Exception (catch, IOException)
import qualified Data.ByteString as ByteString
import Data.Char (toLower, isSpace)
import Data.Int (Int64)
import Data.IORef (IORef, readIORef, atomicModifyIORef')
import Data.List (isInfixOf, isPrefixOf)
import qualified Data.Map.Strict as Map
import System.Directory (removeFile)
import System.Environment (lookupEnv)
import System.Exit (ExitCode(..))
import Test.Tasty.HUnit (assertBool, assertFailure)
import System.IO (hClose)
import System.IO.Temp (withSystemTempFile, withSystemTempDirectory)
import System.Process (readProcessWithExitCode, readProcess)

----------------------------------------------------------------------------
-- Caching
----------------------------------------------------------------------------

type RomCache = IORef (Map.Map FilePath ByteString.ByteString)

cachedReadFile :: RomCache -> FilePath -> IO ByteString.ByteString
cachedReadFile reference filePath = do
  cache <- readIORef reference
  case Map.lookup filePath cache of
    Just fileBytes -> pure fileBytes
    Nothing -> do
      fileBytes <- ByteString.readFile filePath
      atomicModifyIORef' reference (\existing -> (Map.insert filePath fileBytes existing, ()))
      pure fileBytes

----------------------------------------------------------------------------
-- Hashing
----------------------------------------------------------------------------

sha1Hex :: ByteString.ByteString -> String
sha1Hex inputBytes =
  let digest = sha1 inputBytes
  in concatMap (\byte -> padHex 2 (fromIntegral byte :: Int64)) (ByteString.unpack digest)

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
applyPatch :: SomePatch -> ByteString.ByteString -> IO (Either SlapError ByteString.ByteString)
applyPatch somePatch source = inMemoryApply (patchApply somePatch) source

-- | Undo a parsed patch.
undoPatch :: SomePatch -> ByteString.ByteString -> IO (Either String ByteString.ByteString)
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
  -> Maybe ByteString.ByteString  -- ^ base ROM (--with)
  -> CreateMeta           -- ^ metadata
  -> IO (Either String (ByteString.ByteString, [String]))
attemptConvert somePatch targetFormat maybeBase meta = case maybeBase of
  Just baseBytes -> do
    targetResult <- applyPatch somePatch baseBytes
    case targetResult of
      Left slapError -> pure (Left (renderSlapError slapError))
      Right targetBytes ->
        case createFromMemory targetFormat baseBytes targetBytes meta (patchContents somePatch) of
          Left slapErr     -> pure (Left (renderSlapError slapErr))
          Right (result, warnings) -> pure (Right (result, map renderSlapWarning warnings))
  Nothing -> case patchContents somePatch of
    Nothing -> pure (Left (needWithMsg somePatch))
    Just patchContent -> pure $ case convertDirect patchContent targetFormat meta of
      Left slapErr              -> Left (renderSlapError slapErr)
      Right (result, warnings) -> Right (result, map renderSlapWarning warnings)
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
writeGarbage :: FilePath -> Int -> IO ()
writeGarbage filePath count = ByteString.writeFile filePath $ ByteString.pack $ take count $ map fromIntegral $
  iterate (\seed -> (seed * 1103515245 + 12345) `mod` 256) (42 :: Int)

----------------------------------------------------------------------------
-- String helpers
----------------------------------------------------------------------------

-- | Case-insensitive substring check.
ciContains :: String -> String -> Bool
ciContains needle haystack = map toLower needle `isInfixOf` map toLower haystack
