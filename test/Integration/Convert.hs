{-# LANGUAGE OverloadedStrings #-}

module Integration.Convert (convertTests) where

import Integration.HeavyTests (FixtureName(..), bpsCreateIsExpensive)
import Integration.Helpers (assertFailureT)
import Integration.Helpers
  ( Tier
  , isHeavyPath
  , restrictToTier
  , repoDir
  , parseSpecFile
  , lookupCreateFormatToken
  , sha1Hex
  , applyPatch
  , attemptConvert
  , matchPattern
  , trim
  , mmapRomFile
  )
import Integration.Skip
  ( GroupPlan
  , MaybeTest(..)
  , namedGroup
  , requireFixture
  )
import Slap.Create (createPatch)
import Slap.Status (CreateResult(..), renderSlapError, renderSlapAdvisory)
import Slap.FileContents
  (PatchFileContents(..), InputFileContents(..), OutputFileContents(..))
import Slap.SomePatch (SomePatch, parseSome)
import Slap.Text (EncodingName(EncodingUtf8))
import Slap.Convert
  ( CreateFormat(..)
  , DifferentialCreate(..)
  , RequestedPatchMetadata(..)
  , UndoInclusion(..)
  , VerificationInclusion(..)
  , DirectCreate(..)
  , noMetadataRequested
  , noConstraintsRequested
  , noDialectsRequested
  )

-- NB: the spec file uses CLI-style flag strings (`--no-undo`, `--omit-verification`)
-- but the flags get parsed here, not by 'requestedPatchMetadataInputsParser',
-- so the harness controls which flag strings are recognized.

import Control.Monad (when)
import qualified Data.ByteString as ByteString
import Data.List (isPrefixOf)
import System.Directory (doesFileExist)
import System.FilePath ((</>))
import Test.Tasty (TestTree)
import Test.Tasty.HUnit (Assertion, testCase, assertFailure, assertBool, assertEqual)
import qualified Data.Text as Text

-- | The convert group walks @test/specs/convert.txt@ and registers
-- one test per row. Rows whose @result@ field starts with @skip:@ are
-- intentional spec-side omissions (not fixture-driven skips), so they
-- contribute nothing to either the runnable trees or the skip
-- summary; rows whose patch file is absent contribute one
-- 'MissingFixture' skip.
convertTests :: Tier -> IO GroupPlan
convertTests tier = do
  repo <- repoDir
  allRows <- parseSpecFile (repo </> "test" </> "specs" </> "convert.txt")
  let inTierRows = restrictToTier tier (any isHeavyPath) allRows
  rowMaybes <- concat <$> mapM (planConvertRow repo) inTierRows
  let refusalMaybes = map WillRun applyOutputRefusalTests
  pure (namedGroup "convert" (rowMaybes ++ refusalMaybes))

planConvertRow :: FilePath -> [String] -> IO [MaybeTest]
planConvertRow repo fields = case fields of
  (sourceFormat : targetFormat : patchRel : baseRel : targetSha : verdict : rest)
    | "skip:" `isPrefixOf` verdict -> pure []  -- spec-side intentional omission
    | Just targetCreateFormat <- lookupCreateFormatToken targetFormat ->
        let warningsString = case rest of (warning:_)        -> warning; _ -> ""
            flagsString    = case rest of (_:flagField:_)    -> flagField; _ -> ""
            patchPath      = repo </> patchRel
            label          = sourceFormat ++ " -> " ++ targetFormat
                          ++ " (" ++ patchRel ++ ")"
            runnable       = mkConvertTest repo patchPath baseRel targetSha verdict
                               warningsString flagsString targetCreateFormat label
            constructor
              | targetCreateFormat == CreateDifferential CreateBPS
              , bpsCreateIsExpensive (FixtureName patchRel) = WillRunHeavy
              | otherwise                                   = WillRun
        in requireFixture patchPath $ \_ ->
             pure [constructor runnable]
    | otherwise -> pure []  -- unknown @--to FORMAT@ in the spec row
  _ -> pure []              -- malformed spec row

mkConvertTest
  :: FilePath        -- ^ repo root
  -> FilePath        -- ^ patch path
  -> FilePath        -- ^ relative base ROM path (used only when --with is asked)
  -> String          -- ^ expected target SHA1
  -> String          -- ^ verdict: empty/non-prefixed for accept, "reject:PATTERN" for refuse
  -> String          -- ^ comma-separated expected warning patterns
  -> String          -- ^ space-separated extra flags from the spec row
  -> CreateFormat    -- ^ target format
  -> String          -- ^ test label
  -> TestTree
mkConvertTest repo patchPath baseRel targetSha verdict
              warningsString flagsString targetCreateFormat label =
  testCase label $
    runConvertTest repo patchPath baseRel targetSha verdict
                   warningsString flagsString targetCreateFormat

runConvertTest
  :: FilePath -> FilePath -> String -> String -> String
  -> String -> String -> CreateFormat -> IO ()
runConvertTest repo patchPath baseRel targetSha verdict warningsString flagsString targetCreateFormat = do
  patchBytes <- ByteString.readFile patchPath
  case parseSome noDialectsRequested EncodingUtf8 (PatchFileContents patchBytes) of
    Left slapError -> assertFailureT ("parseSome failed: " <> renderSlapError slapError)
    Right parsed -> do
      let flags = words flagsString
          useWith = "--with" `elem` flags
          includeUndo
            | "--no-undo" `elem` flags = Just OmitUndoData
            | otherwise                = Nothing
          includeVerification
            | "--omit-verification" `elem` flags = Just OmitVerification
            | otherwise                  = Nothing

      maybeBase <- if useWith && not (null baseRel)
               then do
                 let basePath = repo </> baseRel
                 exists <- doesFileExist basePath
                 if exists
                   then Just <$> mmapRomFile basePath
                   else pure Nothing
               else pure Nothing

      let meta = noMetadataRequested
            { requestedUndoInclusion        = includeUndo
            , requestedVerificationInclusion = includeVerification
            }
      convResult <- attemptConvert parsed targetCreateFormat maybeBase meta

      if "reject:" `isPrefixOf` verdict
        then do
          let expectedPattern = drop 7 verdict
          case convResult of
            Right _ -> assertFailure "expected rejection but conversion succeeded"
            Left errorMessage -> assertBool
              ("expected '" ++ expectedPattern ++ "' in error: " ++ errorMessage)
              (matchPattern expectedPattern errorMessage)
        else
          case convResult of
            Left errorMessage -> assertFailure ("conversion failed: " ++ errorMessage)
            Right (CreateResult convertedBytes warnings) -> do
              checkWarnings warningsString (map (Text.unpack . renderSlapAdvisory) warnings)
              when (not (null targetSha) && not (null baseRel)) $ do
                let basePath = repo </> baseRel
                baseExists <- doesFileExist basePath
                when baseExists $ do
                  baseBytes <- maybe (mmapRomFile basePath) pure maybeBase
                  case parseSome noDialectsRequested EncodingUtf8 convertedBytes of
                    Left slapError ->
                      assertFailureT ("re-parse converted failed: " <> renderSlapError slapError)
                    Right convertedParsed -> do
                      applied <- applyPatch convertedParsed (InputFileContents baseBytes)
                      case applied of
                        Left slapError ->
                          assertFailureT ("apply converted failed: " <> renderSlapError slapError)
                        Right (OutputFileContents output) ->
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
-- 'Slap.PatchField.affectsApplyOutput'). Today 'FieldTruncation' is the
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

-- | Build a 'StandardIPS' patch whose post-EOF truncation marker
-- declares a target smaller than the source. Shared by both refusal
-- tests so the truncating-IPS construction lives in one place.
makeTruncatingIPSPatch :: IO SomePatch
makeTruncatingIPSPatch =
  let sourceBytes = ByteString.replicate 1024 0x00
      targetBytes = ByteString.replicate 512 0xFF
  in case createPatch (CreateDirect CreateIPS) Nothing
         (InputFileContents sourceBytes) (OutputFileContents targetBytes)
         noMetadataRequested Nothing noConstraintsRequested noDialectsRequested of
       Left slapError ->
         error ("setup: create truncating IPS failed: " ++ Text.unpack (renderSlapError slapError))
       Right createResult -> case parseSome noDialectsRequested EncodingUtf8 (resultBytes createResult) of
         Left slapError ->
           error ("setup: parse truncating IPS failed: " ++ Text.unpack (renderSlapError slapError))
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
  result <- attemptConvert parsed (CreateDirect target) Nothing noMetadataRequested
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
