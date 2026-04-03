module Integration.Create (createTests) where

import Integration.Helpers
  (repoDir, parseSpecFile, parseCreateFormat, sha1Hex, applyPatch,
   RomCache, cachedReadFile)
import Slap.Convert (CreateFormat, defaultMeta, createFromMemory)
import Slap.Error (renderSlapError)
import Slap.SomePatch (parseSome)

import qualified Data.ByteString as ByteString
import qualified Data.Map.Strict as Map
import Data.IORef
import System.Directory (doesFileExist)
import System.FilePath ((</>))
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (testCase, assertFailure, assertEqual)

createTests :: RomCache -> IO TestTree
createTests romCache = do
  repo <- repoDir
  rows <- parseSpecFile (repo </> "test" </> "specs" </> "create.txt")
  -- Cache bootstrapped targets by (base, bootstrap_patch)
  cacheReference <- newIORef (Map.empty :: Map.Map (String, String) ByteString.ByteString)
  tests <- mapM (makeCreateTest romCache repo cacheReference) rows
  pure (testGroup "create" (concat tests))

makeCreateTest :: RomCache -> FilePath -> IORef (Map.Map (String, String) ByteString.ByteString)
             -> [String] -> IO [TestTree]
makeCreateTest romCache repo cacheReference fields = case fields of
  (formatString : scenario : basePath : bootstrapPath : targetSha : _) -> do
    case parseCreateFormat formatString of
      Nothing -> pure []
      Just format -> do
        let base = repo </> basePath
            boot = repo </> bootstrapPath
        baseExists <- doesFileExist base
        bootExists <- doesFileExist boot
        if not (baseExists && bootExists)
          then pure []
          else pure [testCase (formatString ++ "/" ++ scenario) $ do
            baseBytes   <- cachedReadFile romCache base
            targetBytes <- getOrBootstrap cacheReference (basePath, bootstrapPath) baseBytes boot
            roundTrip format baseBytes targetBytes targetSha
          ]
  _ -> pure []

-- | Bootstrap: apply patch to base, cache result.
-- Uses atomicModifyIORef' to avoid redundant bootstrapping under parallelism.
getOrBootstrap :: IORef (Map.Map (String, String) ByteString.ByteString)
               -> (String, String) -> ByteString.ByteString -> FilePath
               -> IO ByteString.ByteString
getOrBootstrap cacheReference key baseBytes bootPath = do
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

-- | Create a patch, parse it back, apply to base, verify SHA1.
roundTrip :: CreateFormat -> ByteString.ByteString -> ByteString.ByteString -> String -> IO ()
roundTrip format baseBytes targetBytes expectedSha = do
  case createFromMemory format baseBytes targetBytes defaultMeta Nothing of
    Left slapError -> assertFailure ("create failed: " ++ renderSlapError slapError)
    Right (patchBytes, _) -> case parseSome patchBytes of
      Left slapError -> assertFailure ("re-parse failed: " ++ renderSlapError slapError)
      Right parsed -> do
        result <- applyPatch parsed baseBytes
        case result of
          Left slapError -> assertFailure ("re-apply failed: " ++ renderSlapError slapError)
          Right output ->
            assertEqual "SHA1 mismatch" expectedSha (sha1Hex output)
