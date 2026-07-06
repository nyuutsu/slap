{-# LANGUAGE OverloadedStrings #-}

module Integration.CrossVal (crossValTests) where

import Integration.Bootstrap (BootstrapTargets, lookupBootstrapTarget)
import Integration.External
  ( ExternalTool(..)
  , ExternalRun(..)
  , externalToolName
  , parseExternalToolName
  , runExternal
  )
import Integration.HeavyTests (FixtureName(..), differentialCreateIsExpensive)
import Integration.Helpers (assertFailureT)
import Integration.Helpers
  ( Tier(..)
  , repoDir
  , parseSpecFile
  , lookupCreateFormatToken
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
  (CreateFormat(..), DifferentialCreate(..), RequestedPatchMetadata(..),
   noMetadataRequested, noConstraintsRequested, noDialectsRequested)
import Slap.VCDIFF.SecondaryCompression (XDelta3SecondaryCompressor(..))
import Slap.VCDIFF.Types (xdelta3WindowSizeOfBytes)
import Slap.Create (createPatch)
import Slap.Status (CreateResult(..), renderSlapError)
import Slap.FileContents
  (InputFileContents(..), OutputFileContents(..), PatchFileContents(..))

import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Char8 as ByteString8
import Data.List (isInfixOf)
import System.Directory (copyFile, listDirectory)
import System.Exit (ExitCode(..))
import System.FilePath ((</>), takeExtension)
import Test.Tasty (TestTree)
import Test.Tasty.HUnit (testCase, assertFailure, assertBool, assertEqual)

-- | The crossval group depends on third-party tools (Flips,
-- RomPatcher.js, bspatch, xdelta3) and ROM bytes flowing across a
-- subprocess boundary. Each row resolves to a runnable test only if
-- both fixtures are present and the row's tool resolves; otherwise
-- the row contributes a typed 'WillSkip' to the group plan.
crossValTests :: Tier -> IO BootstrapTargets -> IO GroupPlan
crossValTests AllTests getTargets = do
  repo <- repoDir
  rows <- parseSpecFile (repo </> "test" </> "specs" </> "crossval.txt")
  rowMaybes    <- concat <$> mapM (planCrossValRow getTargets repo) rows
  djwRow       <- planDJWCompressedRow getTargets repo
  appHeaderRow <- planAppHeaderRow getTargets repo
  windowedRow  <- planWindowedRow getTargets repo
  pure (namedGroup "crossval" (rowMaybes ++ djwRow ++ appHeaderRow ++ windowedRow))

-- | Map a single crossval-spec row to its planned outcome: a runnable
-- test, or a typed skip. Malformed rows and rows whose @format@ field
-- doesn't parse contribute nothing — those are spec-file authoring
-- mistakes, not silent skips.
planCrossValRow :: IO BootstrapTargets -> FilePath -> [String] -> IO [MaybeTest]
planCrossValRow getTargets repo fields = case fields of
  (formatString : scenario : baseRelative : bootRelative : targetSha : toolName : _)
    | Just format <- lookupCreateFormatToken formatString
    , Just tool   <- parseExternalToolName toolName ->
        let basePath = repo </> baseRelative
            bootPath = repo </> bootRelative
            label    = formatString ++ "/" ++ scenario
            runnable = buildCrossValTest getTargets label format tool
                         basePath bootPath targetSha noMetadataRequested
            constructor
              | format == CreateDifferential CreateBPS
              , differentialCreateIsExpensive (FixtureName scenario) = WillRunHeavy
              | otherwise                                   = WillRun
        in requireFixture basePath $ \_ ->
           requireFixture bootPath $ \_ ->
             requireExternalTool tool $ \_ ->
               pure [constructor runnable]
    | otherwise -> pure []  -- spec row references unknown format/tool wire name
  _ -> pure []              -- malformed spec row

-- | The DJW-compressed xdelta3 row. The crossval spec's grammar has no flag column —
-- every spec row creates with default metadata — and this is the one row that needs a
-- requested field, so it is planned here by hand against the same kirby fixtures as the
-- spec's xdelta3 row: slap creates with the DJW secondary compressor selected, and the
-- installed xdelta3 must decode our DJW streams to the same target.
planDJWCompressedRow :: IO BootstrapTargets -> FilePath -> IO [MaybeTest]
planDJWCompressedRow getTargets repo =
  let basePath = repo </> "test/data/kirby-dl2/base.gb"
      bootPath = repo </> "test/data/kirby-dl2/kirby-dl2-dx.bps"
      djwMeta  = noMetadataRequested { requestedSecondaryCompressor = Just SecondaryDJW }
      runnable = buildCrossValTest getTargets "xdelta3/kirby-dl2-dx compress-with-djw"
                   (CreateDifferential CreateXDelta3) Xdelta3
                   basePath bootPath "a34fb26e1066e464e55b473f0a1f87e9c764a010" djwMeta
  in requireFixture basePath $ \_ ->
     requireFixture bootPath $ \_ ->
       requireExternalTool Xdelta3 $ \_ ->
         pure [WillRun runnable]

-- | The application-header row, planned by hand like the DJW row above:
-- slap creates with a header requested, and the installed xdelta3 must both show it under @printhdr@ and still decode to the same target.
planAppHeaderRow :: IO BootstrapTargets -> FilePath -> IO [MaybeTest]
planAppHeaderRow getTargets repo =
  let basePath = repo </> "test/data/kirby-dl2/base.gb"
      bootPath = repo </> "test/data/kirby-dl2/kirby-dl2-dx.bps"
  in requireFixture basePath $ \_ ->
     requireFixture bootPath $ \_ ->
       requireExternalTool Xdelta3 $ \_ ->
         pure [WillRun (appHeaderRowTest getTargets basePath bootPath)]

appHeaderRowTest :: IO BootstrapTargets -> FilePath -> FilePath -> TestTree
appHeaderRowTest getTargets basePath bootPath =
  testCase "xdelta3/kirby-dl2-dx application header" $ do
    bootstrapTargets <- getTargets
    baseBytes        <- mmapRomFile basePath
    let targetBytes = lookupBootstrapTarget bootstrapTargets basePath bootPath
        headerText  = "made with slap"
        headerMeta  = noMetadataRequested
          { requestedEmbeddedBlob = Just (ByteString8.pack headerText) }
    case createPatch (CreateDifferential CreateXDelta3) Nothing
           (InputFileContents baseBytes)
           (OutputFileContents targetBytes)
           headerMeta Nothing noConstraintsRequested noDialectsRequested of
      Left slapError ->
        assertFailureT ("create failed: " <> renderSlapError slapError)
      Right (CreateResult patchBytes _) ->
        withTempFile "slap-xv-patch" $ \patchFile ->
        withTempFile "slap-xv-base"  $ \baseFile ->
        withTempFile "slap-xv-out"   $ \outFile -> do
          ByteString.writeFile patchFile (unPatchFileContents patchBytes)
          ByteString.writeFile baseFile  baseBytes
          headerRun <- runExternal Xdelta3 ["printhdr", patchFile] Nothing ""
          case externalRunExitCode headerRun of
            ExitFailure _ ->
              assertFailure ("xdelta3 printhdr failed: " ++ externalRunStderr headerRun)
            ExitSuccess -> do
              assertBool "printhdr names VCD_APPHEADER"
                ("VCD_APPHEADER" `isInfixOf` externalRunStdout headerRun)
              assertBool "printhdr shows the header bytes"
                (headerText `isInfixOf` externalRunStdout headerRun)
          applyExternal Xdelta3 baseFile patchFile outFile
          resultBytes <- ByteString.readFile outFile
          assertEqual "SHA1 mismatch"
            "a34fb26e1066e464e55b473f0a1f87e9c764a010" (sha1Hex resultBytes)

-- | The multi-window row, planned by hand like the two above:
-- slap creates with windows far smaller than the target — a real multi-window emission, its LZMA streams
-- continuing across windows — and the installed xdelta3 must decode the whole run to the same target.
planWindowedRow :: IO BootstrapTargets -> FilePath -> IO [MaybeTest]
planWindowedRow getTargets repo =
  let basePath = repo </> "test/data/kirby-dl2/base.gb"
      bootPath = repo </> "test/data/kirby-dl2/kirby-dl2-dx.bps"
  in requireFixture basePath $ \_ ->
     requireFixture bootPath $ \_ ->
       requireExternalTool Xdelta3 $ \_ ->
         pure [WillRun (windowedRowTest getTargets basePath bootPath)]

windowedRowTest :: IO BootstrapTargets -> FilePath -> FilePath -> TestTree
windowedRowTest getTargets basePath bootPath =
  testCase "xdelta3/kirby-dl2-dx window-size 128k" $ do
    bootstrapTargets <- getTargets
    baseBytes        <- mmapRomFile basePath
    let targetBytes  = lookupBootstrapTarget bootstrapTargets basePath bootPath
        windowedMeta = noMetadataRequested
          { requestedWindowSize = xdelta3WindowSizeOfBytes (128 * 1024) }
    case createPatch (CreateDifferential CreateXDelta3) Nothing
           (InputFileContents baseBytes)
           (OutputFileContents targetBytes)
           windowedMeta Nothing noConstraintsRequested noDialectsRequested of
      Left slapError ->
        assertFailureT ("create failed: " <> renderSlapError slapError)
      Right (CreateResult patchBytes _) ->
        withTempFile "slap-xv-patch" $ \patchFile ->
        withTempFile "slap-xv-base"  $ \baseFile ->
        withTempFile "slap-xv-out"   $ \outFile -> do
          ByteString.writeFile patchFile (unPatchFileContents patchBytes)
          ByteString.writeFile baseFile  baseBytes
          applyExternal Xdelta3 baseFile patchFile outFile
          resultBytes <- ByteString.readFile outFile
          assertEqual "SHA1 mismatch"
            "a34fb26e1066e464e55b473f0a1f87e9c764a010" (sha1Hex resultBytes)

buildCrossValTest
  :: IO BootstrapTargets
  -> String        -- ^ test label
  -> CreateFormat
  -> ExternalTool
  -> FilePath      -- ^ base ROM path
  -> FilePath      -- ^ bootstrap-patch path (key into the bootstrap map)
  -> String        -- ^ expected SHA1 of the target produced by the external tool
  -> RequestedPatchMetadata
  -> TestTree
buildCrossValTest getTargets label format tool basePath bootPath expectedTargetSha meta =
  testCase label $ do
    bootstrapTargets <- getTargets
    baseBytes        <- mmapRomFile basePath
    let targetBytes = lookupBootstrapTarget bootstrapTargets basePath bootPath
    case createPatch format Nothing
           (InputFileContents baseBytes)
           (OutputFileContents targetBytes)
           meta Nothing noConstraintsRequested noDialectsRequested of
      Left slapError ->
        assertFailureT ("create failed: " <> renderSlapError slapError)
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
    -- -f because the harness pre-creates the output temp file, and xdelta3 (alone among these tools) refuses to overwrite without it.
    run <- runExternal Xdelta3 ["-d", "-f", "-s", baseFile, patchFile, outFile] Nothing ""
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
