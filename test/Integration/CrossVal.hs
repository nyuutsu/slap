module Integration.CrossVal (crossValTests) where

import Integration.Helpers
  (repoDir, parseSpecFile, parseCreateFormat, sha1Hex, applyPatch,
   withTempFile, withTempDir, RomCache, cachedReadFile)
import Slap.Convert (CreateFormat(..), defaultMeta, createFromMemory)
import Slap.Error (renderSlapError)
import Slap.SomePatch (parseSome)

import qualified Data.ByteString as ByteString
import qualified Data.Map.Strict as Map
import Data.IORef
import System.Directory (doesFileExist, listDirectory, copyFile, makeAbsolute)
import System.Environment (lookupEnv)
import System.Exit (ExitCode(..))
import System.FilePath ((</>), takeExtension)
import System.Process (readProcessWithExitCode, proc, cwd, readCreateProcessWithExitCode)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (testCase, assertFailure, assertEqual)

crossValTests :: RomCache -> IO TestTree
crossValTests romCache = do
  repo <- repoDir
  rows <- parseSpecFile (repo </> "test" </> "specs" </> "crossval.txt")
  cacheReference <- newIORef (Map.empty :: Map.Map (String, String) ByteString.ByteString)
  tests <- mapM (mkCrossValTest romCache repo cacheReference) rows
  pure (testGroup "crossval" (concat tests))

mkCrossValTest :: RomCache -> FilePath -> IORef (Map.Map (String, String) ByteString.ByteString)
               -> [String] -> IO [TestTree]
mkCrossValTest romCache repo cacheReference fields = case fields of
  (formatString : scenario : baseRelative : bootRelative : targetSha : toolName : _) -> do
    case parseCreateFormat formatString of
      Nothing -> pure []
      Just format -> do
        let basePath = repo </> baseRelative
            bootPath = repo </> bootRelative
        baseExists <- doesFileExist basePath
        bootExists <- doesFileExist bootPath
        if not (baseExists && bootExists)
          then pure []
          else do
            toolPath <- findTool toolName
            case toolPath of
              Nothing -> pure []
              Just tool -> pure [testCase (formatString ++ "/" ++ scenario) $ do
                baseBytes   <- cachedReadFile romCache basePath
                targetBytes <- getOrBootstrap cacheReference repo (baseRelative, bootRelative) baseBytes bootPath
                -- Create patch with slap
                case createFromMemory format baseBytes targetBytes defaultMeta Nothing of
                  Left slapError -> assertFailure ("create failed: " ++ renderSlapError slapError)
                  Right (patchBytes, _) ->
                    -- Apply with external tool, verify SHA1
                    withTempFile "slap-xv-patch" $ \patchFile ->
                    withTempFile "slap-xv-base" $ \baseFile ->
                    withTempFile "slap-xv-out" $ \outFile -> do
                      ByteString.writeFile patchFile patchBytes
                      ByteString.writeFile baseFile baseBytes
                      applyExternal tool toolName format baseFile patchFile outFile
                      resultBytes <- ByteString.readFile outFile
                      assertEqual "SHA1 mismatch" targetSha (sha1Hex resultBytes)
                ]
  _ -> pure []

getOrBootstrap :: IORef (Map.Map (String, String) ByteString.ByteString)
               -> FilePath -> (String, String) -> ByteString.ByteString -> FilePath
               -> IO ByteString.ByteString
getOrBootstrap cacheReference _repo key baseBytes bootPath = do
  cache <- readIORef cacheReference
  case Map.lookup key cache of
    Just targetBytes -> pure targetBytes
    Nothing -> do
      bootBytes <- ByteString.readFile bootPath
      case parseSome bootBytes of
        Left slapError -> error ("bootstrap parse failed: " ++ renderSlapError slapError)
        Right parsed -> do
          result <- applyPatch parsed baseBytes
          case result of
            Left slapError -> error ("bootstrap apply failed: " ++ renderSlapError slapError)
            Right targetBytes -> do
              atomicModifyIORef' cacheReference (\existing -> (Map.insert key targetBytes existing, ()))
              pure targetBytes

findTool :: String -> IO (Maybe FilePath)
findTool name = do
  repo <- repoDir
  let tools = repo </> "tools"
  case name of
    "flips"      -> lookupTool "FLIPS"      [tools </> "flips/flips"]
    "rompatcher" -> lookupTool "ROMPATCHER" [tools </> "rompatcher-js/index.js"]
    "bspatch"    -> lookupTool "BSPATCH"    ["/usr/bin/bspatch"]
    "xdelta3"    -> lookupTool "XDELTA3"    ["/usr/bin/xdelta3"]
    _            -> pure Nothing
  where
    lookupTool environmentVariable fallbacks = do
      maybeEnvironment <- lookupEnv environmentVariable
      case maybeEnvironment of
        Just executablePath -> do
          exists <- doesFileExist executablePath
          pure (if exists then Just executablePath else Nothing)
        Nothing -> findFirst fallbacks
    findFirst [] = pure Nothing
    findFirst (candidate:candidates) = do
      exists <- doesFileExist candidate
      if exists then Just <$> makeAbsolute candidate else findFirst candidates

applyExternal :: FilePath -> String -> CreateFormat -> FilePath -> FilePath -> FilePath -> IO ()
applyExternal tool toolName _format baseFile patchFile outFile = case toolName of
  "flips" -> do
    (exitCode, _, errorMessage) <- readProcessWithExitCode tool ["--apply", patchFile, baseFile, outFile] ""
    case exitCode of
      ExitSuccess -> pure ()
      _           -> assertFailure ("flips failed: " ++ errorMessage)

  "rompatcher" -> withTempDir "slap-rp" $ \temporaryDirectory -> do
    let extension = case takeExtension baseFile of
                "" -> ".bin"  -- RomPatcher.js needs an extension to name the output
                fileExtension -> fileExtension
        stem = "rom"
        romCopy = temporaryDirectory </> (stem ++ extension)
    copyFile baseFile romCopy
    -- RomPatcher.js outputs relative to CWD
    let processSpec = (proc "node" [tool, "patch", romCopy, patchFile]) { cwd = Just temporaryDirectory }
    (exitCode, stdoutText, stderrText) <- readCreateProcessWithExitCode processSpec ""
    case exitCode of
      ExitSuccess -> do
        files <- listDirectory temporaryDirectory
        let expected = stem ++ " (patched)" ++ extension
        case filter (== expected) files of
          (outputFile:_) -> do
            resultBytes <- ByteString.readFile (temporaryDirectory </> outputFile)
            ByteString.writeFile outFile resultBytes
          [] -> assertFailure ("RomPatcher.js output not found in " ++ show files)
      _ -> assertFailure ("RomPatcher.js failed: " ++ stderrText ++ stdoutText)

  "bspatch" -> do
    (exitCode, _, errorMessage) <- readProcessWithExitCode tool [baseFile, outFile, patchFile] ""
    case exitCode of
      ExitSuccess -> pure ()
      _           -> assertFailure ("bspatch failed: " ++ errorMessage)

  "xdelta3" -> do
    (exitCode, _, errorMessage) <- readProcessWithExitCode tool ["-d", "-s", baseFile, patchFile, outFile] ""
    case exitCode of
      ExitSuccess -> pure ()
      _           -> assertFailure ("xdelta3 failed: " ++ errorMessage)

  _ -> assertFailure ("unknown tool: " ++ toolName)
