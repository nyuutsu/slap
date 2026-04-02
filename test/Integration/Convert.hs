module Integration.Convert (convertTests) where

import Integration.Helpers
  (repoDir, parseSpecFile, parseCreateFormat, sha1Hex,
   applyPatch, attemptConvert, matchPattern, trim, RomCache, cachedReadFile)
import Slap.SomePatch (parseSome)
import Slap.Convert (CreateFormat, CreateMeta(..), defaultMeta)

import Control.Monad (when)
import qualified Data.ByteString as ByteString
import Data.List (isPrefixOf)
import System.Directory (doesFileExist)
import System.FilePath ((</>))
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (testCase, assertFailure, assertBool, assertEqual)

convertTests :: RomCache -> IO TestTree
convertTests romCache = do
  repo <- repoDir
  rows <- parseSpecFile (repo </> "test" </> "specs" </> "convert.txt")
  tests <- mapM (makeConvertTest romCache repo) rows
  pure (testGroup "convert" (concat tests))

makeConvertTest :: RomCache -> FilePath -> [String] -> IO [TestTree]
makeConvertTest romCache repo fields = case fields of
  (sourceFormat : targetFormat : patchRel : baseRel : targetSha : result : rest)
    | "skip:" `isPrefixOf` result -> pure []
    | otherwise -> do
        let warningsString = case rest of (warning:_) -> warning; _ -> ""
            flagsString    = case rest of (_:flagField:_) -> flagField; _ -> ""
            patchPath = repo </> patchRel
        patchExists <- doesFileExist patchPath
        if not patchExists then pure [] else
          case parseCreateFormat targetFormat of
            Nothing -> pure []
            Just targetCreateFormat -> do
              let label = sourceFormat ++ " -> " ++ targetFormat ++ " (" ++ patchRel ++ ")"
              pure [testCase label $
                runConvertTest romCache repo patchPath baseRel targetSha result
                  warningsString flagsString targetCreateFormat]
  _ -> pure []

runConvertTest :: RomCache -> FilePath -> FilePath -> String -> String -> String
               -> String -> String -> CreateFormat -> IO ()
runConvertTest romCache repo patchPath baseRel targetSha result warningsString flagsString targetCreateFormat = do
  patchBytes <- ByteString.readFile patchPath
  case parseSome patchBytes of
    Left errorMessage -> assertFailure ("parseSome failed: " ++ errorMessage)
    Right parsed -> do
      let flags = words flagsString
          useWith = "--with" `elem` flags
          includeUndo
            | "--undo" `elem` flags    = Just True
            | "--no-undo" `elem` flags = Just False
            | otherwise                = Nothing
          includeValidate
            | "--validate" `elem` flags    = Just True
            | "--no-validate" `elem` flags = Just False
            | otherwise                    = Nothing

      maybeBase <- if useWith && not (null baseRel)
               then do
                 let basePath = repo </> baseRel
                 exists <- doesFileExist basePath
                 if exists
                   then Just <$> cachedReadFile romCache basePath
                   else pure Nothing
               else pure Nothing

      let meta = defaultMeta { metaUndo = includeUndo, metaValidate = includeValidate }
      convResult <- attemptConvert parsed targetCreateFormat maybeBase meta

      if "reject:" `isPrefixOf` result
        then do
          let expectedPattern = drop 7 result
          case convResult of
            Right _ -> assertFailure "expected rejection but conversion succeeded"
            Left errorMessage -> assertBool
              ("expected '" ++ expectedPattern ++ "' in error: " ++ errorMessage)
              (matchPattern expectedPattern errorMessage)
        else do
          case convResult of
            Left errorMessage -> assertFailure ("conversion failed: " ++ errorMessage)
            Right (convertedBytes, notes) -> do
              checkWarnings warningsString notes
              when (not (null targetSha) && not (null baseRel)) $ do
                let basePath = repo </> baseRel
                baseExists <- doesFileExist basePath
                when baseExists $ do
                  baseBytes <- maybe (cachedReadFile romCache basePath) pure maybeBase
                  case parseSome convertedBytes of
                    Left errorMessage -> assertFailure ("re-parse converted failed: " ++ errorMessage)
                    Right convertedParsed -> do
                      applied <- applyPatch convertedParsed baseBytes
                      case applied of
                        Left errorMessage -> assertFailure ("apply converted failed: " ++ errorMessage)
                        Right output ->
                          assertEqual "SHA1 mismatch" targetSha (sha1Hex output)

-- | Check that each comma-separated expected pattern matches at least one note.
checkWarnings :: String -> [String] -> IO ()
checkWarnings "" _ = pure ()
checkWarnings warningsString notes = do
  let patterns = map trim (splitComma warningsString)
  mapM_ (\pattern ->
    when (not (null pattern)) $
      assertBool
        ("expected warning pattern '" ++ pattern ++ "' not found in notes: " ++ show notes)
        (any (matchPattern pattern) notes)
    ) patterns

splitComma :: String -> [String]
splitComma [] = [""]
splitComma (',':rest) = "" : splitComma rest
splitComma (char:rest) = case splitComma rest of
  (segment:segments) -> (char:segment) : segments
  []                 -> [[char]]

