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
  , applyViaTemp
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

import Patch.Binary (sha1)
import Patch.Format (padHex)
import Patch.SomePatch (SomePatch(..), ApplyStrategy(..), UndoStrategy(..))
import Patch.Convert (CreateFormat(..), CreateMeta(..), convertDirect, createFromMemory)

import Control.Exception (catch, finally, IOException)
import qualified Data.ByteString as BS
import Data.Char (toLower, isSpace)
import Data.Int (Int64)
import Data.IORef (IORef, readIORef, atomicModifyIORef')
import Data.List (isInfixOf, isPrefixOf)
import qualified Data.Map.Strict as Map
import System.Directory (removeFile)
import System.Environment (lookupEnv)
import System.Exit (ExitCode(..))
import Test.Tasty.HUnit (assertBool, assertFailure)
import System.IO (hClose, openBinaryTempFile)
import System.IO.Temp (withSystemTempFile, withSystemTempDirectory)
import System.Process (readProcessWithExitCode, readProcess)

----------------------------------------------------------------------------
-- Caching
----------------------------------------------------------------------------

type RomCache = IORef (Map.Map FilePath BS.ByteString)

cachedReadFile :: RomCache -> FilePath -> IO BS.ByteString
cachedReadFile ref fp = do
  m <- readIORef ref
  case Map.lookup fp m of
    Just bs -> pure bs
    Nothing -> do
      bs <- BS.readFile fp
      atomicModifyIORef' ref (\m' -> (Map.insert fp bs m', ()))
      pure bs

----------------------------------------------------------------------------
-- Hashing
----------------------------------------------------------------------------

sha1Hex :: BS.ByteString -> String
sha1Hex bs =
  let digest = sha1 bs
  in concatMap (\b -> padHex 2 (fromIntegral b :: Int64)) (BS.unpack digest)

----------------------------------------------------------------------------
-- Spec/suite parsing
----------------------------------------------------------------------------

-- | Read a spec file, strip comments and blanks, split on '|', trim fields.
parseSpecFile :: FilePath -> IO [[String]]
parseSpecFile path = do
  content <- readFile path
  let ls = filter (not . isComment) (lines content)
  pure (map splitFields ls)
  where
    isComment l = let t = dropWhile isSpace l in null t || "#" `isPrefixOf` t
    splitFields = map trim . splitOn '|'

trim :: String -> String
trim = reverse . dropWhile isSpace . reverse . dropWhile isSpace

splitOn :: Char -> String -> [String]
splitOn sep = go
  where
    go [] = [""]
    go (c:cs)
      | c == sep  = "" : go cs
      | otherwise = case go cs of
          (x:xs) -> (c:x) : xs
          []     -> [""]

data SuiteHeader = SuiteHeader
  { shBase   :: FilePath
  , shSha1 :: String
  , shDesc   :: String
  } deriving (Show)

data SuiteEntry = SuiteEntry
  { seFormat     :: String
  , sePatch      :: FilePath
  , seConfidence :: String
  , _seProvenance :: String
  } deriving (Show)

parseSuiteFile :: FilePath -> IO (SuiteHeader, [SuiteEntry])
parseSuiteFile path = do
  content <- readFile path
  let ls = lines content
      patchLines  = filter isPatchLine ls
      hdr = parseHeader ls
      entries = map parsePatchLine patchLines
  pure (hdr, entries)
  where
    isPatchLine l =
      let t = dropWhile isSpace l
      in '|' `elem` l && not ("#" `isPrefixOf` t) && not (null t)

    parseHeader ls = SuiteHeader
      { shBase   = extractField "base:" ls
      , shSha1 = extractField "sha1:" ls
      , shDesc   = extractField "desc:" ls
      }

    extractField prefix ls =
      case filter (\l -> prefix `isPrefixOf` dropWhile isSpace l) ls of
        (l:_) -> trim (drop (length prefix) (dropWhile isSpace l))
        []    -> ""

    parsePatchLine l = case map trim (splitOn '|' l) of
      (fmt:patch:conf:prov:_) -> SuiteEntry fmt patch conf prov
      (fmt:patch:conf:_)      -> SuiteEntry fmt patch conf ""
      _                       -> SuiteEntry "" "" "" ""

-- | Parse a create format string (mirrors Main.hs parseCfmt).
parseCreateFormat :: String -> Maybe CreateFormat
parseCreateFormat s = case map toLower s of
  "bps"     -> Just CfmtBPS
  "ips"     -> Just CfmtIPS
  "ips32"   -> Just CfmtIPS32
  "ebp"     -> Just CfmtEBP
  "ups"     -> Just CfmtUPS
  "ppf3"    -> Just CfmtPPF3
  "ppf"     -> Just CfmtPPF3
  "pmsr"    -> Just CfmtPMSR
  "ninja1"  -> Just CfmtNINJA1
  "dps"     -> Just CfmtDPS
  "rup"     -> Just CfmtRUP
  "ninja2"  -> Just CfmtRUP
  "aps-n64" -> Just CfmtAPSN64
  "apsn64"  -> Just CfmtAPSN64
  "aps-gba" -> Just CfmtAPSGBA
  "apsgba"  -> Just CfmtAPSGBA
  "gdiff"   -> Just CfmtGDIFF
  "pchtxt"  -> Just CfmtPCHTXT
  _         -> Nothing

----------------------------------------------------------------------------
-- Patch application
----------------------------------------------------------------------------

-- | Apply a parsed patch to source bytes, handling both InMemory and InPlace.
applyPatch :: SomePatch -> BS.ByteString -> IO (Either String BS.ByteString)
applyPatch sp source = case spApply sp of
  InMemory { imApply = apply } -> apply source
  InPlace f -> Right <$> applyViaTemp source f

-- | Apply an InPlace action via a temp file.
applyViaTemp :: BS.ByteString -> (FilePath -> IO ()) -> IO BS.ByteString
applyViaTemp source action = do
  (tmp, h) <- openBinaryTempFile "/tmp" "slap-int"
  hClose h
  flip finally (removeIfExists tmp) $ do
    BS.writeFile tmp source
    action tmp
    BS.readFile tmp

-- | Undo a parsed patch.
undoPatch :: SomePatch -> BS.ByteString -> IO (Either String BS.ByteString)
undoPatch sp patched = case spUndo sp of
  Nothing -> pure (Left "undo not supported")
  Just (UndoInMemory f) -> pure (Right (f patched))
  Just (UndoInPlace f)  -> do
    (tmp, h) <- openBinaryTempFile "/tmp" "slap-undo"
    hClose h
    BS.writeFile tmp patched
    result <- f tmp
    case result of
      Left err -> removeIfExists tmp >> pure (Left err)
      Right _  -> do
        bs <- BS.readFile tmp
        removeIfExists tmp
        pure (Right bs)

removeIfExists :: FilePath -> IO ()
removeIfExists fp = removeFile fp `catch` (\(_ :: IOException) -> pure ())

----------------------------------------------------------------------------
-- Conversion
----------------------------------------------------------------------------

-- | Replicate the convert logic from Main.hs.
attemptConvert
  :: SomePatch
  -> CreateFormat
  -> Maybe BS.ByteString  -- ^ base ROM (--with)
  -> CreateMeta           -- ^ metadata
  -> IO (Either String (BS.ByteString, [String]))
attemptConvert sp tgtFmt mBase meta = case mBase of
  Just baseBs -> do
    targetResult <- applyPatch sp baseBs
    case targetResult of
      Left err -> pure (Left err)
      Right targetBs ->
        case createFromMemory tgtFmt baseBs targetBs meta of
          Left err     -> pure (Left err)
          Right result -> pure (Right (result, []))
  Nothing -> case spContents sp of
    Nothing -> pure (Left (needWithMsg sp))
    Just pc -> pure $ case convertDirect pc tgtFmt meta of
      Left err              -> Left err
      Right (result, notes) -> Right (result, notes)
  where
    needWithMsg sp' =
      "converting from " ++ name ++ " requires the original ROM (--with SOURCE)\n"
      ++ name ++ " " ++ reason ++ " \8212 the original ROM is needed\n"
      ++ "to reconstruct the target file for re-encoding."
      where
        name = spFormat sp'
        reason
          | spIsDifferential sp' = "stores differential data, not raw bytes"
          | otherwise            = "applies in-place to the target file"

----------------------------------------------------------------------------
-- File discovery
----------------------------------------------------------------------------

repoDir :: IO FilePath
repoDir = do
  menv <- lookupEnv "SLAP_REPO"
  pure (maybe "." id menv)

findSlapBinary :: IO (Maybe FilePath)
findSlapBinary = do
  menv <- lookupEnv "SLAP_BIN"
  case menv of
    Just p  -> pure (Just p)
    Nothing -> do
      result <- (Just . trim <$> readProcess "cabal" ["-v0", "list-bin", "slap"] "")
                  `catch` (\(_ :: IOException) -> pure Nothing)
      case result of
        Just p | not (null p) -> pure (Just p)
        _ -> pure Nothing

runSlap :: FilePath -> [String] -> IO (ExitCode, String, String)
runSlap bin args = readProcessWithExitCode bin args ""


----------------------------------------------------------------------------
-- Pattern matching
----------------------------------------------------------------------------

-- | Case-insensitive substring match with `.*` wildcard support.
-- matchPattern "dropping.*validation" "note: dropping PPF3 validation block" == True
matchPattern :: String -> String -> Bool
matchPattern pat str =
  let p = map toLower pat
      s = map toLower str
  in any (matchAt p) (allTails s)
  where
    allTails :: [a] -> [[a]]
    allTails [] = [[]]
    allTails xs@(_:xs') = xs : allTails xs'

    matchAt :: String -> String -> Bool
    matchAt [] _  = True
    matchAt _  [] = False
    matchAt ('.' : '*' : rest) s = any (matchAt rest) (allTails s)
    matchAt (a:as) (b:bs) = a == b && matchAt as bs

----------------------------------------------------------------------------
-- Temp helpers
----------------------------------------------------------------------------

withTempFile :: String -> (FilePath -> IO a) -> IO a
withTempFile template action =
  withSystemTempFile template (\fp h -> hClose h >> action fp)

withTempDir :: String -> (FilePath -> IO a) -> IO a
withTempDir = withSystemTempDirectory

----------------------------------------------------------------------------
-- Subprocess assertions
----------------------------------------------------------------------------

-- | Run slap, expect failure, check stderr+stdout contains pattern (case-insensitive).
expectFail :: FilePath -> [String] -> String -> String -> IO ()
expectFail slap args label pattern = do
  (ec, out, err) <- runSlap slap args
  let combined = out ++ err
  case ec of
    ExitFailure _ ->
      assertBool (label ++ ": expected '" ++ pattern ++ "' in: " ++ combined)
        (map toLower pattern `isInfixOf` map toLower combined)
    ExitSuccess ->
      assertFailure (label ++ ": expected failure but got success: " ++ combined)

-- | Run slap, expect success, check stderr+stdout contains pattern (case-insensitive).
expectOk :: FilePath -> [String] -> String -> String -> IO ()
expectOk slap args label pattern = do
  (ec, out, err) <- runSlap slap args
  let combined = out ++ err
  case ec of
    ExitSuccess ->
      assertBool (label ++ ": expected '" ++ pattern ++ "' in: " ++ combined)
        (map toLower pattern `isInfixOf` map toLower combined)
    ExitFailure _ ->
      assertFailure (label ++ ": expected success but got failure: " ++ combined)

----------------------------------------------------------------------------
-- Test data
----------------------------------------------------------------------------

-- | Write deterministic pseudo-random bytes to a file.
writeGarbage :: FilePath -> Int -> IO ()
writeGarbage fp n = BS.writeFile fp $ BS.pack $ take n $ map fromIntegral $
  iterate (\x -> (x * 1103515245 + 12345) `mod` 256) (42 :: Int)

----------------------------------------------------------------------------
-- String helpers
----------------------------------------------------------------------------

-- | Case-insensitive substring check.
ciContains :: String -> String -> Bool
ciContains needle haystack = map toLower needle `isInfixOf` map toLower haystack
