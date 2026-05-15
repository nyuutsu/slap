module Integration.CrossVal (crossValTests) where

import Integration.Bootstrap (BootstrapTargets, lookupBootstrapTarget)
import Integration.External
  ( ExternalTool(..)
  , ExternalRun(..)
  , externalToolName
  , parseExternalToolName
  , runExternal
  )
import Integration.HeavyTests (FixtureName(..), bpsCreateIsExpensive)
import Integration.Helpers
  ( Tier(..)
  , repoDir
  , parseSpecFile
  , parseCreateFormat
  , sha1Hex
  , withTempFile
  , withTempDir
  , mmapRomFile
  )
import Integration.Skip
  ( GroupPlan
  , MaybeTest(..)
  , namedGroup
  , requireExternalTool
  , requireFixture
  )
import Slap.Convert
  (CreateFormat(..), DifferentialCreate(..), noMetadataRequested, noConstraintsRequested, noDialectsRequested)
import Slap.Create (createPatch)
import Slap.Error (CreateResult(..), renderSlapError)
import Slap.FileContents
  (InputFileContents(..), OutputFileContents(..), PatchFileContents(..))

import qualified Data.ByteString as ByteString
import System.Directory (copyFile, listDirectory)
import System.Exit (ExitCode(..))
import System.FilePath ((</>), takeExtension)
import Test.Tasty (TestTree)
import Test.Tasty.HUnit (testCase, assertFailure, assertEqual)

-- | The crossval group depends on third-party tools (Flips,
-- RomPatcher.js, bspatch, xdelta3) and ROM bytes flowing across a
-- subprocess boundary. Each row resolves to a runnable test only if
-- both fixtures are present and the row's tool resolves; otherwise
-- the row contributes a typed 'WillSkip' to the group plan.
crossValTests :: Tier -> IO BootstrapTargets -> IO GroupPlan
crossValTests AllTests getTargets = do
  repo <- repoDir
  rows <- parseSpecFile (repo </> "test" </> "specs" </> "crossval.txt")
  rowMaybes <- concat <$> mapM (planCrossValRow getTargets repo) rows
  pure (namedGroup "crossval" rowMaybes)

-- | Map a single crossval-spec row to its planned outcome: a runnable
-- test, or a typed skip. Malformed rows and rows whose @format@ field
-- doesn't parse contribute nothing — those are spec-file authoring
-- mistakes, not silent skips.
planCrossValRow :: IO BootstrapTargets -> FilePath -> [String] -> IO [MaybeTest]
planCrossValRow getTargets repo fields = case fields of
  (formatString : scenario : baseRelative : bootRelative : targetSha : toolName : _)
    | Just format <- parseCreateFormat formatString
    , Just tool   <- parseExternalToolName toolName ->
        let basePath = repo </> baseRelative
            bootPath = repo </> bootRelative
            label    = formatString ++ "/" ++ scenario
            runnable = mkCrossValTest getTargets label format tool
                         basePath bootPath targetSha
            constructor
              | format == CreateDifferential CreateBPS
              , bpsCreateIsExpensive (FixtureName scenario) = WillRunHeavy
              | otherwise                                   = WillRun
        in requireFixture basePath $ \_ ->
           requireFixture bootPath $ \_ ->
             requireExternalTool tool $ \_ ->
               pure [constructor runnable]
    | otherwise -> pure []  -- spec row references unknown format/tool wire name
  _ -> pure []              -- malformed spec row

mkCrossValTest
  :: IO BootstrapTargets
  -> String        -- ^ test label
  -> CreateFormat
  -> ExternalTool
  -> FilePath      -- ^ base ROM path
  -> FilePath      -- ^ bootstrap-patch path (key into the bootstrap map)
  -> String        -- ^ expected SHA1 of the target produced by the external tool
  -> TestTree
mkCrossValTest getTargets label format tool basePath bootPath expectedTargetSha =
  testCase label $ do
    bootstrapTargets <- getTargets
    baseBytes        <- mmapRomFile basePath
    let targetBytes = lookupBootstrapTarget bootstrapTargets basePath bootPath
    case createPatch format Nothing
           (InputFileContents baseBytes)
           (OutputFileContents targetBytes)
           noMetadataRequested Nothing noConstraintsRequested noDialectsRequested of
      Left slapError ->
        assertFailure ("create failed: " ++ renderSlapError slapError)
      Right (CreateResult patchBytes _) ->
        withTempFile "slap-xv-patch" $ \patchFile ->
        withTempFile "slap-xv-base"  $ \baseFile ->
        withTempFile "slap-xv-out"   $ \outFile -> do
          ByteString.writeFile patchFile (unPatchFileContents patchBytes)
          ByteString.writeFile baseFile  baseBytes
          applyExternal tool baseFile patchFile outFile
          resultBytes <- ByteString.readFile outFile
          assertEqual "SHA1 mismatch" expectedTargetSha (sha1Hex resultBytes)

-- | Apply a slap-produced patch with the external tool indicated by
-- the spec row, leaving the result at @outFile@. Each tool has its
-- own argument shape; the dispatch lives here, the subprocess launch
-- is funneled through 'runExternal'.
applyExternal
  :: ExternalTool
  -> FilePath  -- ^ base ROM file
  -> FilePath  -- ^ patch file
  -> FilePath  -- ^ output target file
  -> IO ()
applyExternal tool baseFile patchFile outFile = case tool of
  Flips -> do
    run <- runExternal Flips ["--apply", patchFile, baseFile, outFile] Nothing ""
    expectExternalSuccess "flips" run

  RomPatcher -> withTempDir "slap-rp" $ \workingDirectory -> do
    -- RomPatcher.js writes its output in CWD, named after the input ROM
    -- with a "(patched)" suffix; the in-test bookkeeping copies the ROM
    -- into a workspace, runs the script there, then copies the output
    -- bytes to the file the harness expects.
    let extension = case takeExtension baseFile of
                      ""            -> ".bin"
                      fileExtension -> fileExtension
        baseStem  = "rom"
        baseCopy  = workingDirectory </> (baseStem ++ extension)
    copyFile baseFile baseCopy
    run <- runExternal RomPatcher
            ["patch", baseCopy, patchFile]
            (Just workingDirectory) ""
    case externalRunExitCode run of
      ExitFailure _ ->
        assertFailure ("RomPatcher.js failed: "
                       ++ externalRunStderr run ++ externalRunStdout run)
      ExitSuccess -> do
        producedFiles <- listDirectory workingDirectory
        let expectedOutputName = baseStem ++ " (patched)" ++ extension
        case filter (== expectedOutputName) producedFiles of
          (outputFile:_) -> do
            outputBytes <- ByteString.readFile (workingDirectory </> outputFile)
            ByteString.writeFile outFile outputBytes
          [] ->
            assertFailure ("RomPatcher.js output not found in "
                           ++ show producedFiles)

  BsPatch -> do
    run <- runExternal BsPatch [baseFile, outFile, patchFile] Nothing ""
    expectExternalSuccess "bspatch" run

  Xdelta3 -> do
    run <- runExternal Xdelta3 ["-d", "-s", baseFile, patchFile, outFile] Nothing ""
    expectExternalSuccess "xdelta3" run

  -- The crossval spec only references the four tools above; any other
  -- variant slipping through 'parseExternalToolName' is an authoring
  -- error, surfaced loudly rather than silently skipped.
  unsupported ->
    assertFailure ("crossval row references unsupported tool: "
                   ++ externalToolName unsupported)

-- | Surface the tool's own stderr when it exits non-zero; the message
-- shape matches the pre-refactor failure assertions so test output
-- diff stays minimal during this restructure.
expectExternalSuccess :: String -> ExternalRun -> IO ()
expectExternalSuccess toolLabel run = case externalRunExitCode run of
  ExitSuccess   -> pure ()
  ExitFailure _ -> assertFailure (toolLabel ++ " failed: " ++ externalRunStderr run)
