module Integration.Convert (convertTests) where

import Integration.Helpers
  (Tier, isHeavyPath, restrictToTier,
   repoDir, parseSpecFile, parseCreateFormat, sha1Hex,
   applyPatch, attemptConvert, matchPattern, trim, mmapRomFile)
import Slap.Create (createFromMemory)
import Slap.Error (CreateResult(..), renderSlapError, renderSlapWarning)
import Slap.FileContents (PatchFileContents(..), SourceFileContents(..), TargetFileContents(..))
import Slap.SomePatch (SomePatch, parseSome)
import Slap.Convert (CreateFormat(..), CreateMeta(..), DirectCreate(..), defaultMeta)

import Control.Monad (when)
import qualified Data.ByteString as ByteString
import Data.List (isPrefixOf)
import System.Directory (doesFileExist)
import System.FilePath ((</>))
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (Assertion, testCase, assertFailure, assertBool, assertEqual)

convertTests :: Tier -> IO TestTree
convertTests tier = do
  repo <- repoDir
  allRows <- parseSpecFile (repo </> "test" </> "specs" </> "convert.txt")
  tests <- mapM (makeConvertTest repo)
                (restrictToTier tier (any isHeavyPath) allRows)
  pure (testGroup "convert" (concat tests ++ applyOutputRefusalTests))

makeConvertTest :: FilePath -> [String] -> IO [TestTree]
makeConvertTest repo fields = case fields of
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
                runConvertTest repo patchPath baseRel targetSha result
                  warningsString flagsString targetCreateFormat]
  _ -> pure []

runConvertTest :: FilePath -> FilePath -> String -> String -> String
               -> String -> String -> CreateFormat -> IO ()
runConvertTest repo patchPath baseRel targetSha result warningsString flagsString targetCreateFormat = do
  patchBytes <- ByteString.readFile patchPath
  case parseSome (PatchFileContents patchBytes) of
    Left slapError -> assertFailure ("parseSome failed: " ++ renderSlapError slapError)
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
                   then Just <$> mmapRomFile basePath
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
            Right (CreateResult convertedBytes warnings) -> do
              checkWarnings warningsString (map renderSlapWarning warnings)
              when (not (null targetSha) && not (null baseRel)) $ do
                let basePath = repo </> baseRel
                baseExists <- doesFileExist basePath
                when baseExists $ do
                  baseBytes <- maybe (mmapRomFile basePath) pure maybeBase
                  case parseSome convertedBytes of
                    Left slapError -> assertFailure ("re-parse converted failed: " ++ renderSlapError slapError)
                    Right convertedParsed -> do
                      applied <- applyPatch convertedParsed (SourceFileContents baseBytes)
                      case applied of
                        Left slapError -> assertFailure ("apply converted failed: " ++ renderSlapError slapError)
                        Right (TargetFileContents output) ->
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

----------------------------------------------------------------------------
-- Apply-output field refusal tests
----------------------------------------------------------------------------

-- | The conversion contract layer refuses to drop fields that affect
-- the output bytes of the apply operation (see
-- 'Slap.PatchField.affectsApplyOutput'). Today 'FTruncation' is the
-- only such field; these tests exercise the two targets that would
-- silently lose it — IPS32 and EBP — and confirm the refusal fires
-- with a message naming the field and the target format.
applyOutputRefusalTests :: [TestTree]
applyOutputRefusalTests =
  [ testCase "truncation: IPS with marker refuses conversion to EBP" $
      assertRefusesTruncation CreateEBP "EBP"
  , testCase "truncation: IPS with marker refuses conversion to IPS32" $
      assertRefusesTruncation CreateIPS32 "IPS32"
  ]

-- | Build a 'StandardIPS' patch whose Flips-style truncation marker
-- declares a target smaller than the source. Shared by both refusal
-- tests so the truncating-IPS construction lives in one place.
makeTruncatingIPSPatch :: IO SomePatch
makeTruncatingIPSPatch =
  let sourceBytes = ByteString.replicate 1024 0x00
      targetBytes = ByteString.replicate 512 0xFF
  in case createFromMemory (CreateDirect CreateIPS)
         (SourceFileContents sourceBytes) (TargetFileContents targetBytes)
         defaultMeta Nothing of
       Left slapError ->
         error ("setup: create truncating IPS failed: " ++ renderSlapError slapError)
       Right createResult -> case parseSome (resultBytes createResult) of
         Left slapError ->
           error ("setup: parse truncating IPS failed: " ++ renderSlapError slapError)
         Right parsed -> pure parsed

-- | Assert that converting a truncating IPS patch to @target@ is
-- refused, and that the rendered error names both the truncation
-- field and the target format. The @cannot convert to@ phrase is
-- unique to 'ApplyOutputFieldsWouldBeDropped' — it pins the refusal
-- to the contract layer rather than a downstream encoder check that
-- would emit different wording.
assertRefusesTruncation :: DirectCreate -> String -> Assertion
assertRefusesTruncation target targetName = do
  parsed <- makeTruncatingIPSPatch
  result <- attemptConvert parsed (CreateDirect target) Nothing defaultMeta
  case result of
    Right _ -> assertFailure
      ("expected refusal converting truncating IPS to " ++ targetName
       ++ " but conversion succeeded")
    Left errorMessage -> do
      assertBool ("expected contract-layer refusal phrase 'cannot convert to' in error: "
                  ++ errorMessage)
        (matchPattern "cannot convert to" errorMessage)
      assertBool ("expected 'truncation' in error: " ++ errorMessage)
        (matchPattern "truncation" errorMessage)
      assertBool ("expected '" ++ targetName ++ "' in error: " ++ errorMessage)
        (matchPattern targetName errorMessage)

