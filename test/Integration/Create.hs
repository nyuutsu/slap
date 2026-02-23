module Integration.Create (createTests) where

import Integration.Helpers
  (repoDir, parseSpecFile, parseCreateFormat, sha256Hex, applyPatch)
import Patch.Convert (CreateFormat, defaultMeta, createFromMemory)
import Patch.SomePatch (parseSome)

import qualified Data.ByteString as BS
import qualified Data.Map.Strict as Map
import Data.IORef
import System.Directory (doesFileExist)
import System.FilePath ((</>))
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (testCase, assertFailure, assertEqual)

createTests :: IO TestTree
createTests = do
  repo <- repoDir
  rows <- parseSpecFile (repo </> "test" </> "specs" </> "create.txt")
  -- Cache bootstrapped targets by (base, bootstrap_patch)
  cacheRef <- newIORef (Map.empty :: Map.Map (String, String) BS.ByteString)
  tests <- mapM (mkCreateTest repo cacheRef) rows
  pure (testGroup "create" (concat tests))

mkCreateTest :: FilePath -> IORef (Map.Map (String, String) BS.ByteString)
             -> [String] -> IO [TestTree]
mkCreateTest repo cacheRef fields = case fields of
  (fmtStr : _scenario : basePath : bootstrapPath : targetSha : _) -> do
    case parseCreateFormat fmtStr of
      Nothing -> pure []
      Just fmt -> do
        let base = repo </> basePath
            boot = repo </> bootstrapPath
        baseExists <- doesFileExist base
        bootExists <- doesFileExist boot
        if not (baseExists && bootExists)
          then pure []
          else pure [testCase (fmtStr ++ "/" ++ _scenario) $ do
            baseBs   <- BS.readFile base
            targetBs <- getOrBootstrap cacheRef (basePath, bootstrapPath) baseBs boot
            roundTrip fmt baseBs targetBs targetSha
          ]
  _ -> pure []

-- | Bootstrap: apply patch to base, cache result.
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
              modifyIORef' cacheRef (Map.insert key tgt)
              pure tgt

-- | Create a patch, parse it back, apply to base, verify SHA256.
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
            assertEqual "SHA256 mismatch" expectedSha (sha256Hex output)
