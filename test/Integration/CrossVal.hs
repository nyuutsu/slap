module Integration.CrossVal (crossValTests) where

import Integration.Helpers
  (repoDir, parseSpecFile, parseCreateFormat, sha256Hex, applyPatch,
   withTempFile, withTempDir)
import Patch.Convert (CreateFormat(..), createFromMemory)
import Patch.SomePatch (parseSome)

import qualified Data.ByteString as BS
import qualified Data.Map.Strict as Map
import Data.IORef
import System.Directory (doesFileExist, listDirectory, copyFile)
import System.Environment (lookupEnv)
import System.Exit (ExitCode(..))
import System.FilePath ((</>), takeExtension)
import System.Process (readProcessWithExitCode)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (testCase, assertFailure, assertEqual)

crossValTests :: IO TestTree
crossValTests = do
  repo <- repoDir
  rows <- parseSpecFile (repo </> "test" </> "specs" </> "crossval.txt")
  cacheRef <- newIORef (Map.empty :: Map.Map (String, String) BS.ByteString)
  tests <- mapM (mkCrossValTest repo cacheRef) rows
  pure (testGroup "crossval" (concat tests))

mkCrossValTest :: FilePath -> IORef (Map.Map (String, String) BS.ByteString)
               -> [String] -> IO [TestTree]
mkCrossValTest repo cacheRef fields = case fields of
  (fmtStr : scenario : baseRel : bootRel : targetSha : toolName : _) -> do
    case parseCreateFormat fmtStr of
      Nothing -> pure []
      Just fmt -> do
        let basePath = repo </> baseRel
            bootPath = repo </> bootRel
        baseExists <- doesFileExist basePath
        bootExists <- doesFileExist bootPath
        if not (baseExists && bootExists)
          then pure []
          else do
            toolPath <- findTool toolName
            case toolPath of
              Nothing -> pure []
              Just tool -> pure [testCase (fmtStr ++ "/" ++ scenario) $ do
                baseBs   <- BS.readFile basePath
                targetBs <- getOrBootstrap cacheRef repo (baseRel, bootRel) baseBs bootPath
                -- Create patch with slap
                case createFromMemory fmt baseBs targetBs "" False False of
                  Left err -> assertFailure ("create failed: " ++ err)
                  Right patchBs ->
                    -- Apply with external tool, verify SHA256
                    withTempFile "slap-xv-patch" $ \patchFile ->
                    withTempFile "slap-xv-base" $ \baseFile ->
                    withTempFile "slap-xv-out" $ \outFile -> do
                      BS.writeFile patchFile patchBs
                      BS.writeFile baseFile baseBs
                      applyExternal tool toolName fmt baseFile patchFile outFile
                      resultBs <- BS.readFile outFile
                      assertEqual "SHA256 mismatch" targetSha (sha256Hex resultBs)
                ]
  _ -> pure []

getOrBootstrap :: IORef (Map.Map (String, String) BS.ByteString)
               -> FilePath -> (String, String) -> BS.ByteString -> FilePath
               -> IO BS.ByteString
getOrBootstrap cacheRef _repo key baseBs bootPath = do
  cache <- readIORef cacheRef
  case Map.lookup key cache of
    Just tgt -> pure tgt
    Nothing -> do
      bootBs <- BS.readFile bootPath
      case parseSome bootBs of
        Left err -> error ("bootstrap parse failed: " ++ err)
        Right sp -> do
          result <- applyPatch sp baseBs
          case result of
            Left err -> error ("bootstrap apply failed: " ++ err)
            Right tgt -> do
              modifyIORef' cacheRef (Map.insert key tgt)
              pure tgt

findTool :: String -> IO (Maybe FilePath)
findTool name = case name of
  "flips" -> lookupTool "FLIPS" [home </> "repos/Flips/flips"]
  "rompatcher" -> lookupTool "ROMPATCHER" [home </> "repos/RomPatcher.js/index.js"]
  "bspatch" -> lookupTool "BSPATCH" ["/usr/bin/bspatch"]
  "xdelta3" -> lookupTool "XDELTA3" ["/usr/bin/xdelta3"]
  _ -> pure Nothing
  where
    home = "/home/nyuu"
    lookupTool envVar fallbacks = do
      menv <- lookupEnv envVar
      case menv of
        Just p  -> do
          exists <- doesFileExist p
          pure (if exists then Just p else Nothing)
        Nothing -> findFirst fallbacks
    findFirst [] = pure Nothing
    findFirst (p:ps) = do
      exists <- doesFileExist p
      if exists then pure (Just p) else findFirst ps

applyExternal :: FilePath -> String -> CreateFormat -> FilePath -> FilePath -> FilePath -> IO ()
applyExternal tool toolName _fmt baseFile patchFile outFile = case toolName of
  "flips" -> do
    (ec, _, err) <- readProcessWithExitCode tool ["--apply", patchFile, baseFile, outFile] ""
    case ec of
      ExitSuccess -> pure ()
      _           -> assertFailure ("flips failed: " ++ err)

  "rompatcher" -> withTempDir "slap-rp" $ \tmpDir -> do
    let ext = takeExtension baseFile
        stem = "rom"
        romCopy = tmpDir </> (stem ++ ext)
    copyFile baseFile romCopy
    (ec, out, err) <- readProcessWithExitCode "node"
      [tool, "patch", romCopy, patchFile] ""
    case ec of
      ExitSuccess -> do
        -- RomPatcher.js outputs "rom (patched).ext"
        files <- listDirectory tmpDir
        let expected = stem ++ " (patched)" ++ ext
        case filter (== expected) files of
          (f:_) -> do
            resultBs <- BS.readFile (tmpDir </> f)
            BS.writeFile outFile resultBs
          [] -> assertFailure ("RomPatcher.js output not found in " ++ show files)
      _ -> assertFailure ("RomPatcher.js failed: " ++ err ++ out)

  "bspatch" -> do
    (ec, _, err) <- readProcessWithExitCode tool [baseFile, outFile, patchFile] ""
    case ec of
      ExitSuccess -> pure ()
      _           -> assertFailure ("bspatch failed: " ++ err)

  "xdelta3" -> do
    (ec, _, err) <- readProcessWithExitCode tool ["-d", "-s", baseFile, patchFile, outFile] ""
    case ec of
      ExitSuccess -> pure ()
      _           -> assertFailure ("xdelta3 failed: " ++ err)

  _ -> assertFailure ("unknown tool: " ++ toolName)
