module Integration.Create (createTests) where

import Integration.Helpers
  (repoDir, parseSpecFile, parseCreateFormat, sha1Hex, applyPatch,
   RomCache, cachedReadFile)
import Patch.Convert (CreateFormat, defaultMeta, createFromMemory)
import Patch.SomePatch (parseSome)

import qualified Data.ByteString as BS
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
  cacheRef <- newIORef (Map.empty :: Map.Map (String, String) BS.ByteString)
  tests <- mapM (mkCreateTest romCache repo cacheRef) rows
  pure (testGroup "create" (concat tests))

mkCreateTest :: RomCache -> FilePath -> IORef (Map.Map (String, String) BS.ByteString)
             -> [String] -> IO [TestTree]
mkCreateTest romCache repo cacheRef fields = case fields of
  (fmtStr : scenario : basePath : bootstrapPath : targetSha : _) -> do
    case parseCreateFormat fmtStr of
      Nothing -> pure []
      Just fmt -> do
        let base = repo </> basePath
            boot = repo </> bootstrapPath
        baseExists <- doesFileExist base
        bootExists <- doesFileExist boot
        if not (baseExists && bootExists)
          then pure []
          else pure [testCase (fmtStr ++ "/" ++ scenario) $ do
            baseBs   <- cachedReadFile romCache base
            targetBs <- getOrBootstrap cacheRef (basePath, bootstrapPath) baseBs boot
            roundTrip fmt baseBs targetBs targetSha
          ]
  _ -> pure []

-- | Bootstrap: apply patch to base, cache result.
-- Uses atomicModifyIORef' to avoid redundant bootstrapping under parallelism.
getOrBootstrap :: IORef (Map.Map (String, String) BS.ByteString)
               -> (String, String) -> BS.ByteString -> FilePath
               -> IO BS.ByteString
getOrBootstrap cacheRef key baseBs bootPath = do
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
              atomicModifyIORef' cacheRef (\m -> (Map.insert key tgt m, ()))
              pure tgt

-- | Create a patch, parse it back, apply to base, verify SHA1.
roundTrip :: CreateFormat -> BS.ByteString -> BS.ByteString -> String -> IO ()
roundTrip fmt baseBs targetBs expectedSha = do
  case createFromMemory fmt baseBs targetBs defaultMeta of
    Left err -> assertFailure ("create failed: " ++ err)
    Right patchBs -> case parseSome patchBs of
      Left err -> assertFailure ("re-parse failed: " ++ err)
      Right sp -> do
        result <- applyPatch sp baseBs
        case result of
          Left err -> assertFailure ("re-apply failed: " ++ err)
          Right output ->
            assertEqual "SHA1 mismatch" expectedSha (sha1Hex output)
