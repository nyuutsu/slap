module Integration.Convert (convertTests) where

import Integration.Helpers
  (repoDir, parseSpecFile, parseCreateFormat, sha256Hex,
   applyPatch, attemptConvert, matchPattern)
import Patch.SomePatch (parseSome)
import Patch.Convert (CreateFormat, CreateMeta(..), defaultMeta)

import Control.Monad (when)
import qualified Data.ByteString as BS
import Data.List (isPrefixOf)
import System.Directory (doesFileExist)
import System.FilePath ((</>))
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (testCase, assertFailure, assertBool, assertEqual)

convertTests :: IO TestTree
convertTests = do
  repo <- repoDir
  rows <- parseSpecFile (repo </> "test" </> "specs" </> "convert.txt")
  tests <- mapM (mkConvertTest repo) rows
  pure (testGroup "convert" (concat tests))

mkConvertTest :: FilePath -> [String] -> IO [TestTree]
mkConvertTest repo fields = case fields of
  (srcFmt : tgtFmt : patchRel : baseRel : targetSha : result : rest)
    | "skip:" `isPrefixOf` result -> pure []
    | otherwise -> do
        let warningsStr = case rest of (w:_) -> w; _ -> ""
            flagsStr    = case rest of (_:f:_) -> f; _ -> ""
            patchPath = repo </> patchRel
        patchExists <- doesFileExist patchPath
        if not patchExists then pure [] else
          case parseCreateFormat tgtFmt of
            Nothing -> pure []
            Just tgtCfmt -> do
              let label = srcFmt ++ " -> " ++ tgtFmt ++ " (" ++ patchRel ++ ")"
              pure [testCase label $
                runConvertTest repo patchPath baseRel targetSha result
                  warningsStr flagsStr tgtCfmt]
  _ -> pure []

runConvertTest :: FilePath -> FilePath -> String -> String -> String
               -> String -> String -> CreateFormat -> IO ()
runConvertTest repo patchPath baseRel targetSha result warningsStr flagsStr tgtCfmt = do
  patchBs <- BS.readFile patchPath
  case parseSome patchBs of
    Left err -> assertFailure ("parseSome failed: " ++ err)
    Right sp -> do
      let flags = words flagsStr
          useWith = "--with" `elem` flags
          includeUndo = "--no-undo" `notElem` flags
          includeValidate = "--no-validate" `notElem` flags

      mBase <- if useWith && not (null baseRel)
               then do
                 let basePath = repo </> baseRel
                 exists <- doesFileExist basePath
                 if exists
                   then Just <$> BS.readFile basePath
                   else pure Nothing
               else pure Nothing

      let meta = defaultMeta { cmUndo = includeUndo, cmValidate = includeValidate }
      convResult <- attemptConvert sp tgtCfmt mBase meta

      if "reject:" `isPrefixOf` result
        then do
          let expectedPattern = drop 7 result
          case convResult of
            Right _ -> assertFailure "expected rejection but conversion succeeded"
            Left err -> assertBool
              ("expected '" ++ expectedPattern ++ "' in error: " ++ err)
              (matchPattern expectedPattern err)
        else do
          case convResult of
            Left err -> assertFailure ("conversion failed: " ++ err)
            Right (convertedBs, notes) -> do
              checkWarnings warningsStr notes
              when (not (null targetSha) && not (null baseRel)) $ do
                let basePath = repo </> baseRel
                baseExists <- doesFileExist basePath
                when baseExists $ do
                  baseBs <- maybe (BS.readFile basePath) pure mBase
                  case parseSome convertedBs of
                    Left err -> assertFailure ("re-parse converted failed: " ++ err)
                    Right sp2 -> do
                      applied <- applyPatch sp2 baseBs
                      case applied of
                        Left err -> assertFailure ("apply converted failed: " ++ err)
                        Right output ->
                          assertEqual "SHA256 mismatch" targetSha (sha256Hex output)

-- | Check that each comma-separated expected pattern matches at least one note.
checkWarnings :: String -> [String] -> IO ()
checkWarnings "" _ = pure ()
checkWarnings warningsStr notes = do
  let patterns = map trim' (splitComma warningsStr)
  mapM_ (\pat ->
    when (not (null pat)) $
      assertBool
        ("expected warning pattern '" ++ pat ++ "' not found in notes: " ++ show notes)
        (any (matchPattern pat) notes)
    ) patterns

splitComma :: String -> [String]
splitComma [] = [""]
splitComma (',':cs) = "" : splitComma cs
splitComma (c:cs) = case splitComma cs of
  (x:xs) -> (c:x) : xs
  []     -> [[c]]

trim' :: String -> String
trim' = reverse . dropWhile (== ' ') . reverse . dropWhile (== ' ')
