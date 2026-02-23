module Integration.Helpers
  ( -- * Hashing
    sha256Hex
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
  , findPatchFiles
    -- * Pattern matching
  , matchPattern
    -- * Temp helpers
  , withTempFile
  , withTempDir
  ) where

import Patch.Binary (sha256)
import Patch.Format (padHex)
import Patch.SomePatch (SomePatch(..), ApplyStrategy(..), UndoStrategy(..))
import Patch.Convert (CreateFormat(..), CreateMeta(..), convertDirect, createFromMemory)

import Control.Exception (catch, IOException)
import qualified Data.ByteString as BS
import Data.Char (toLower, isSpace)
import Data.Int (Int64)
import Data.List (isInfixOf, isPrefixOf)
import System.Directory (listDirectory, doesDirectoryExist, removeFile)
import System.Environment (lookupEnv)
import System.Exit (ExitCode)
import System.FilePath ((</>), takeExtension)
import System.IO (hClose, openBinaryTempFile)
import System.IO.Temp (withSystemTempFile, withSystemTempDirectory)
import System.Process (readProcessWithExitCode, readProcess)

----------------------------------------------------------------------------
-- Hashing
----------------------------------------------------------------------------

sha256Hex :: BS.ByteString -> String
sha256Hex bs =
  let digest = sha256 bs
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
  , shSha256 :: String
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
      , shSha256 = extractField "sha256:" ls
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
  BS.writeFile tmp source
  action tmp
  result <- BS.readFile tmp
  removeFileSafe tmp
  pure result

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
      Left err -> removeFileSafe tmp >> pure (Left err)
      Right _  -> do
        bs <- BS.readFile tmp
        removeFileSafe tmp
        pure (Right bs)

removeFileSafe :: FilePath -> IO ()
removeFileSafe fp = removeFile fp `catch` (\(_ :: IOException) -> pure ())

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

-- | Recursively find patch files by extension under a directory.
findPatchFiles :: FilePath -> IO [FilePath]
findPatchFiles dir = go dir
  where
    patchExts :: [String]
    patchExts = [".ips", ".ips32", ".bps", ".ups", ".vcdiff", ".bsdiff",
                 ".gdiff", ".xdelta1", ".mod", ".ppf", ".ebp", ".rup",
                 ".bdf", ".aps", ".ninja1", ".pchtxt", ".dps"]
    go :: FilePath -> IO [FilePath]
    go d = do
      entries <- listDirectory d
      concat <$> mapM (processEntry d) entries
    processEntry :: FilePath -> String -> IO [FilePath]
    processEntry parent name = do
      let full = parent </> name
      isDir <- doesDirectoryExist full
      if isDir
        then go full
        else pure [full | isPatchFile name]
    isPatchFile :: String -> Bool
    isPatchFile name =
      takeExtension name `elem` patchExts
      || ".ppf1" `isInfixOf` name
      || ".ppf2" `isInfixOf` name
      || ".ppf3" `isInfixOf` name
      || ".ebp." `isInfixOf` name
      || ".aps." `isInfixOf` name
      || ".rup." `isInfixOf` name

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
