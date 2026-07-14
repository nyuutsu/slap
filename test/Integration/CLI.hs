{-# LANGUAGE OverloadedStrings #-}

module Integration.CLI (cliTests) where

import Integration.External (ExternalRun(..), ExternalTool(..), runExternal)
import Integration.Helpers (assertFailureT)
import Integration.Helpers
  ( Tier(..)
  , onlyAtFull
  , repoDir
  , sha1Hex
  , withTempFile
  , withTempDir
  , expectFail
  , expectOk
  , writeGarbage
  , ciContains
  , removeIfExists
  )
import Integration.Skip
  ( GroupPlan
  , MaybeTest(..)
  , namedGroup
  , requireExternalTool
  , requireFixture
  , requireSlapBinary
  )
import Slap.Status (renderSlapError, renderSlapAdvisory)
import Slap.Display.Analysis (renderAnalysisSummary)
import Slap.FileContents (PatchFileContents(..))
import Slap.SomePatch (SomePatch(..), parseSome)
import Slap.Text (EncodingName(EncodingUtf8))
import Slap.Convert (noDialectsRequested)

import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Char8 as ByteString8
import Data.List (isInfixOf)
import System.Directory (doesFileExist)
import System.Exit (ExitCode(..))
import System.FilePath ((</>))
import Test.Tasty (TestTree)
import Test.Tasty.HUnit (testCase, assertFailure, assertBool, assertEqual)
import qualified Data.Text as Text

-- | The CLI group splits into: in-process parser tests (no fixtures,
-- no slap binary), single-shot subprocess tests (slap + dm4y base
-- ROM), and the archive sub-strand (slap + dm4y + zip on @PATH@).
-- Each strand gates independently, so a missing fixture in one
-- doesn't suppress the others.
cliTests :: Tier -> IO GroupPlan
cliTests tier = do
  repo <- repoDir
  let inProcessMaybes = map WillRun (corruptTests
                                  ++ warningTests repo)

  subprocessMaybes <- requireSlapBinary $ \_slap -> do
    let dm4yBase    = repo </> "test/data/dm4y/base.gbc"
        dm4yBps     = repo </> "test/data/dm4y/patch.bps"
        dm4yIps     = repo </> "test/data/dm4y/patch.ips"
        dm4yUps     = repo </> "test/data/dm4y/patch.ups"
        dm4yXdelta1 = repo </> "test/data/dm4y/patch.xdelta1"

    -- Most subprocess tests need the dm4y base ROM. Bundle them under
    -- one fixture gate so a missing ROM produces a single bucket of
    -- skips rather than scattering them.
    dm4yGated <- requireFixture dm4yBase $ \_ -> pure $ map WillRun $ concat
      [ collisionTests dm4yBase dm4yIps
      , verboseTests dm4yBase dm4yIps
      , undoErrorTests dm4yBase dm4yIps dm4yBps
      , compoundTests dm4yBase dm4yIps dm4yBps
      , createFlagTests dm4yBase dm4yBps
      , ipsTruncateTests dm4yBase
      , ninja1VerifyTests tier dm4yBase dm4yIps
      , descriptionTests dm4yBase dm4yBps
      , metadataRejectionTests dm4yBase dm4yBps
      , bpsConvertMetadataTests dm4yBase dm4yBps
      , metadataTextTests dm4yBase dm4yBps
      , dizExtractByteExactTests dm4yBase dm4yBps
      , dizTextTests dm4yBase dm4yBps
      , undoCliTests dm4yBase dm4yUps
      , xdelta1SourceLengthTests dm4yBase dm4yXdelta1
      , headerRescueTests dm4yBase dm4yBps
      , verificationReportTests dm4yBase dm4yBps dm4yIps
      , headerFlagTests dm4yBase dm4yIps dm4yBps
      , onlyAtFull tier (forceTests dm4yBase dm4yUps)
      , onlyAtFull tier (noverifyTests dm4yBase dm4yBps)
      ]

    -- Archive tests additionally need the @zip@ and @unzip@ executables.
    archiveGated <-
      requireFixture dm4yBase $ \_ ->
      requireExternalTool Zip $ \_ ->
      requireExternalTool Unzip $ \_ ->
        pure (map WillRun (archiveTests dm4yBase dm4yIps dm4yBps dm4yUps))

    -- Codetable, VCD_TARGET, and VCDIFF-flag tests are slap-only
    -- (committed or temp-file fixtures; no ROM gate).
    let codetableMaybes =
          map WillRun (customCodetableTests ++ vcdTargetTests ++ vcdiffCreateFlagTests)

    -- ROM-type normalization tests build their dumps from whole cloth
    -- (synthetic headered files in temp paths), so they need only slap.
    let normalizationMaybes = map WillRun normalizationTests

    -- Explain-mode tests use dm4y paths but degrade to "no --with"
    -- mode when the base ROM is missing. They register
    -- unconditionally — the test bodies themselves carry the fixture
    -- check (matching pre-refactor behavior).
    let explainMaybes = map WillRun
          (explainModeTests dm4yIps (Just (dm4yBase, dm4yUps, dm4yBps)))

    pure (dm4yGated ++ archiveGated ++ codetableMaybes ++ normalizationMaybes ++ explainMaybes)

  pure (namedGroup "cli" (inProcessMaybes ++ subprocessMaybes))

----------------------------------------------------------------------------
-- Test groups
----------------------------------------------------------------------------

corruptTests :: [TestTree]
corruptTests =
  [ testCase "corrupt/empty file" $
      case parseSome noDialectsRequested EncodingUtf8 (PatchFileContents ByteString.empty) of
        Left slapError -> assertBool "expected the unrecognized-format message" (ciContains "any patch format slap knows" (Text.unpack (renderSlapError slapError)))
        Right _ -> assertFailure "expected parse failure for empty file"

  , testCase "corrupt/random garbage" $ do
      let garbageBytes = ByteString.pack $ take 256 $ map fromIntegral $
                 iterate (\seed -> (seed * 1103515245 + 12345) `mod` 256) (42 :: Int)
      case parseSome noDialectsRequested EncodingUtf8 (PatchFileContents garbageBytes) of
        Left slapError -> assertBool "expected the unrecognized-format message" (ciContains "any patch format slap knows" (Text.unpack (renderSlapError slapError)))
        Right _ -> assertFailure "expected parse failure for random garbage"

  , testCase "corrupt/info truncated IPS (graceful)" $ do
      let truncatedIPS = ByteString.pack [0x50,0x41,0x54,0x43,0x48,0x01,0x02]
      case parseSome noDialectsRequested EncodingUtf8 (PatchFileContents truncatedIPS) of
        Left slapError -> assertFailureT ("parseSome rejected truncated IPS: " <> renderSlapError slapError)
        Right parsed -> assertBool "expected '0' in info" ("0" `Text.isInfixOf` renderAnalysisSummary (patchInfo parsed) (patchAnalysis parsed) Nothing)

  , testCase "corrupt/info truncated BPS" $ do
      let truncatedBPS = ByteString.pack [0x42,0x50,0x53,0x31]
      case parseSome noDialectsRequested EncodingUtf8 (PatchFileContents truncatedBPS) of
        Left _ -> pure ()
        Right _ -> assertFailure "expected parse failure for truncated BPS"
  ]

-- | The from-file length gate:
-- canonical xdelta refuses a wrong-length from file in both verification postures, so slap enforces the declared length as a 'RequiredSize'.
xdelta1SourceLengthTests :: FilePath -> FilePath -> [TestTree]
xdelta1SourceLengthTests base xdelta1 =
  [ testCase "xdelta1-length/refuses a wrong-length source" $
      withTempFile "slap-lengthened" $ \lengthened ->
      withTempFile "slap-out" $ \out -> do
        baseBytes <- ByteString.readFile base
        ByteString.writeFile lengthened (baseBytes <> ByteString.pack [0x00])
        removeIfExists out
        expectFail ["apply", xdelta1, lengthened, "-o", out]
          "xdelta1-length/refuses a wrong-length source" "file size mismatch"

  , testCase "xdelta1-length/--no-verify downgrades the gate to a warning" $
      withTempFile "slap-lengthened" $ \lengthened ->
      withTempFile "slap-out" $ \out -> do
        baseBytes <- ByteString.readFile base
        ByteString.writeFile lengthened (baseBytes <> ByteString.pack [0x00])
        removeIfExists out
        expectOk ["apply", xdelta1, lengthened, "-o", out, "--no-verify"]
          "xdelta1-length/--no-verify downgrades the gate" "applied"
  ]

-- | The header fix beside a source mismatch: one proven arrangement is carried out and narrated,
-- empty hands still refuse with the kinder line, and neither a typed directive nor @--no-verify@ is overridden.
headerRescueTests :: FilePath -> FilePath -> [TestTree]
headerRescueTests base bps =
  [ testCase "rescue/a headered input is applied with the header set aside" $
      withTempFile "slap-headered" $ \headered ->
      withTempFile "slap-fixed"    $ \fixedOut ->
      withTempFile "slap-direct"   $ \directOut -> do
        baseBytes <- ByteString.readFile base
        ByteString.writeFile headered (ByteString.replicate 512 0x00 <> baseBytes)
        run <- runExternal SlapBinary ["apply", bps, headered, "-o", fixedOut, "--force"] Nothing ""
        let combined = externalRunStdout run ++ externalRunStderr run
        case externalRunExitCode run of
          ExitSuccess   -> assertBool "the fix should narrate itself" (ciContains "set aside" combined)
          ExitFailure _ -> assertFailure ("the fix should proceed: " ++ combined)
        _ <- runExternal SlapBinary ["apply", bps, base, "-o", directOut, "--force"] Nothing ""
        fixedSha  <- sha1Hex <$> ByteString.readFile fixedOut
        directSha <- sha1Hex <$> ByteString.readFile directOut
        assertEqual "the fixed apply should equal applying to the bare rom" directSha fixedSha

  , testCase "rescue/an unrelated input is told the kinder truth" $
      withTempFile "slap-unrelated" $ \unrelated ->
      withTempFile "slap-out" $ \out -> do
        ByteString.writeFile unrelated (ByteString.replicate 4096 0xEE)
        removeIfExists out
        expectFail ["apply", bps, unrelated, "-o", out]
          "rescue/unrelated input" "most likely a different rom"

  , testCase "rescue/a typed directive is never second-guessed" $
      withTempFile "slap-headered" $ \headered ->
      withTempFile "slap-out" $ \out -> do
        baseBytes <- ByteString.readFile base
        ByteString.writeFile headered (ByteString.replicate 512 0x00 <> baseBytes)
        removeIfExists out
        run <- runExternal SlapBinary ["apply", bps, headered, "-o", out, "--remove-header", "snes"] Nothing ""
        let combined = externalRunStdout run ++ externalRunStderr run
        assertBool "the plain note should narrate the directive" (ciContains "removed the input's" combined)
        assertBool "the fix should not speak under a directive" (not (ciContains "set aside" combined))

  , testCase "rescue/--no-verify applies to the bytes as handed" $
      withTempFile "slap-headered" $ \headered ->
      withTempFile "slap-out" $ \out -> do
        baseBytes <- ByteString.readFile base
        ByteString.writeFile headered (ByteString.replicate 512 0x00 <> baseBytes)
        removeIfExists out
        run <- runExternal SlapBinary ["apply", bps, headered, "-o", out, "--no-verify"] Nothing ""
        let combined = externalRunStdout run ++ externalRunStderr run
        case externalRunExitCode run of
          ExitSuccess   -> assertBool "no fix on a run the user unfastened" (not (ciContains "set aside" combined))
          ExitFailure _ -> assertFailure ("--no-verify should proceed: " ++ combined)
  ]

-- | The happy-path verification report. The undo case is the load-bearing one:
-- a PPF3's only check is its source-side validation block, and undo weighs crosswise,
-- so the report must call the handed-in file uncheckable and the reverted file matched — a transposed wiring would say the opposite.
verificationReportTests :: FilePath -> FilePath -> FilePath -> [TestTree]
verificationReportTests base bps ips =
  [ testCase "report/a checksummed apply names what matched" $
      withTempFile "slap-out" $ \out -> do
        removeIfExists out
        expectOk ["apply", bps, base, "-o", out]
          "report/checksummed apply" "input matches the patch's declared size and crc"

  , testCase "report/a checkless apply says nothing was compared" $
      withTempFile "slap-out" $ \out -> do
        removeIfExists out
        expectOk ["apply", ips, base, "-o", out]
          "report/checkless apply" "carries no checks, so nothing was compared"

  , testCase "report/undo labels its crosswise sides truthfully" $
      withTempFile "slap-original" $ \original ->
      withTempFile "slap-modified" $ \modified ->
      withTempFile "slap-ppf" $ \ppf ->
      withTempFile "slap-patched" $ \patched ->
      withTempFile "slap-reverted" $ \reverted -> do
        baseBytes <- ByteString.readFile base
        -- 64 KiB reaches past the BIN validation block (1024 bytes at 0x9320), so the created PPF3 carries it;
        -- the changed byte sits outside that block.
        let originalBytes = ByteString.take 65536 baseBytes
            alteredByte   = if ByteString.index originalBytes 40000 == 0xAA then 0xAB else 0xAA
            modifiedBytes = ByteString.take 40000 originalBytes
                         <> ByteString.singleton alteredByte
                         <> ByteString.drop 40001 originalBytes
        ByteString.writeFile original originalBytes
        ByteString.writeFile modified modifiedBytes
        removeIfExists ppf
        removeIfExists patched
        removeIfExists reverted
        expectOk ["create", "--format", "ppf3", original, modified, ppf]
          "report/ppf3 create" "wrote"
        expectOk ["apply", ppf, original, "-o", patched]
          "report/ppf3 apply" "applied"
        expectOk ["undo", ppf, patched, "-o", reverted]
          "report/undo input side is the uncheckable one" "the patch carries no checks for the input"
  ]

-- | The --add-header and --remove-header flags: a console name aliases a byte quantity,
-- and slap puts that many zero bytes on the front of the input, or takes that many off, before applying.
headerFlagTests :: FilePath -> FilePath -> FilePath -> [TestTree]
headerFlagTests base ips bps =
  [ testCase "header/--remove-header applies a checksummed patch through a headered input" $
      withTempFile "slap-headered" $ \headered ->
      withTempFile "slap-out" $ \out ->
      withTempFile "slap-plain-out" $ \plainOut -> do
        baseBytes <- ByteString.readFile base
        ByteString.writeFile headered (ByteString.replicate 512 0x00 <> baseBytes)
        removeIfExists out
        removeIfExists plainOut
        expectOk ["apply", bps, headered, "-o", out, "--remove-header", "snes"]
          "header/--remove-header applies" "applied"
        expectOk ["apply", bps, base, "-o", plainOut]
          "header/plain apply for comparison" "applied"
        viaRemove <- sha1Hex <$> ByteString.readFile out
        viaPlain  <- sha1Hex <$> ByteString.readFile plainOut
        assertEqual "output should match a plain apply on the bare input" viaPlain viaRemove

  , testCase "header/--add-header matches applying to a zero-padded input" $
      withTempFile "slap-headered" $ \headered ->
      withTempFile "slap-padded-out" $ \paddedOut ->
      withTempFile "slap-added-out" $ \addedOut -> do
        baseBytes <- ByteString.readFile base
        ByteString.writeFile headered (ByteString.replicate 512 0x00 <> baseBytes)
        removeIfExists paddedOut
        removeIfExists addedOut
        expectOk ["apply", ips, headered, "-o", paddedOut]
          "header/apply to the padded input" "applied"
        expectOk ["apply", ips, base, "-o", addedOut, "--add-header", "snes"]
          "header/--add-header applies" "applied"
        viaPadded <- sha1Hex <$> ByteString.readFile paddedOut
        viaAdded  <- sha1Hex <$> ByteString.readFile addedOut
        assertEqual "output should match applying to the padded input" viaPadded viaAdded

  , testCase "header/--remove-header refuses an input shorter than the header" $
      withTempFile "slap-tiny" $ \tiny ->
      withTempFile "slap-out" $ \out -> do
        ByteString.writeFile tiny (ByteString.replicate 100 0x00)
        removeIfExists out
        expectFail ["apply", bps, tiny, "-o", out, "--remove-header", "snes"]
          "header/refuses a too-short input" "cannot remove"

  , testCase "header/unknown console names the roster" $
      withTempFile "slap-out" $ \out -> do
        removeIfExists out
        expectFail ["apply", ips, base, "-o", out, "--remove-header", "n64"]
          "header/unknown console" "unknown console"
  ]

forceTests :: FilePath -> FilePath -> [TestTree]
forceTests _base ups =
  [ testCase "force/--force does not bypass CRC" $
      withTempFile "slap-wrong" $ \wrong ->
      withTempFile "slap-out" $ \out -> do
        writeGarbage wrong (4096 * 1024)
        removeIfExists out
        expectFail ["apply", ups, wrong, "-o", out, "--force"]
          "force/--force does not bypass CRC" "CRC mismatch"
  ]

noverifyTests :: FilePath -> FilePath -> [TestTree]
noverifyTests _base bps =
  [ testCase "noverify/BPS wrong source fails and suggests flag" $
      withTempFile "slap-wrong" $ \wrong ->
      withTempFile "slap-out" $ \out -> do
        writeGarbage wrong (4096 * 1024)
        removeIfExists out
        run <- runExternal SlapBinary ["apply", bps, wrong, "-o", out] Nothing ""
        let combined = externalRunStdout run ++ externalRunStderr run
        case externalRunExitCode run of
          ExitFailure _ -> do
            assertBool "expected 'mismatch'" (ciContains "mismatch" combined)
            assertBool "expected '--no-verify'" ("--no-verify" `isInfixOf` combined)
          ExitSuccess ->
            assertFailure ("expected failure but got success: " ++ combined)

  , testCase "noverify/--no-verify bypasses CRC" $
      withTempFile "slap-wrong" $ \wrong ->
      withTempFile "slap-out" $ \out -> do
        writeGarbage wrong (4096 * 1024)
        removeIfExists out
        expectOk ["apply", bps, wrong, "-o", out, "--no-verify"]
          "noverify/--no-verify bypasses CRC" "applied"
  ]

collisionTests :: FilePath -> FilePath -> [TestTree]
collisionTests base ips =
  [ testCase "collision/overwrite refused" $
      withTempFile "slap-out" $ \out -> do
        ByteString.writeFile out (ByteString.pack [0])  -- existing file
        expectFail ["apply", ips, base, "-o", out]
          "collision/overwrite refused" "already exists"

  , testCase "collision/overwrite with --force" $
      withTempFile "slap-out" $ \out -> do
        ByteString.writeFile out (ByteString.pack [0])
        expectOk ["apply", ips, base, "-o", out, "--force"]
          "collision/overwrite with --force" "applied"
  ]

verboseTests :: FilePath -> FilePath -> [TestTree]
verboseTests base ips =
  [ testCase "verbose/prints records" $
      withTempFile "slap-out" $ \out -> do
        removeIfExists out
        run <- runExternal SlapBinary
          ["apply", ips, base, "-o", out, "--verbose", "--force"] Nothing ""
        let combined = externalRunStdout run ++ externalRunStderr run
        case externalRunExitCode run of
          ExitSuccess -> assertBool "expected 'Write' in verbose output"
            ("Write" `isInfixOf` combined)
          _ -> assertFailure ("verbose failed: " ++ combined)
  ]

undoErrorTests :: FilePath -> FilePath -> FilePath -> [TestTree]
undoErrorTests base ips _bps =
  [ testCase "undo/unsupported IPS" $
      expectFail ["undo", ips, base] "undo/unsupported IPS" "no undo for"
  ]

compoundTests :: FilePath -> FilePath -> FilePath -> [TestTree]
compoundTests base ips _bps =
  [ testCase "compound/explicit -o creates file" $
      withTempFile "slap-out" $ \out -> do
        removeIfExists out
        expectOk ["apply", ips, base, "-o", out] "compound/-o" "applied"
        exists <- doesFileExist out
        assertBool "output file not created" exists
  ]

createFlagTests :: FilePath -> FilePath -> [TestTree]
createFlagTests base bps =
  [ testCase "create/ppf3+desc" $
      withTempFile "slap-target" $ \target ->
      withTempFile "slap-patch" $ \patch -> do
        _ <- runExternal SlapBinary ["apply", bps, base, "-o", target, "--force"] Nothing ""
        expectOk ["create", "--format", "ppf3",
                  "--description", "test patch", base, target, patch, "--force"]
          "create/ppf3" "wrote"

  , testCase "create/ppf3 undo data present by default" $
      withTempFile "slap-target" $ \target ->
      withTempFile "slap-patch" $ \patch -> do
        _ <- runExternal SlapBinary ["apply", bps, base, "-o", target, "--force"] Nothing ""
        _ <- runExternal SlapBinary ["create", "--format", "ppf3",
                                     "--description", "test patch", base, target, patch, "--force"] Nothing ""
        expectOk ["info", patch] "create/ppf3 undo" "undo"
  ]

warningTests :: FilePath -> [TestTree]
warningTests repo =
  [ testCase "warnings/truncated IPS no EOF" $ do
      let truncatedIPS = ByteString.pack [0x50,0x41,0x54,0x43,0x48,0x01,0x02]
      case parseSome noDialectsRequested EncodingUtf8 (PatchFileContents truncatedIPS) of
        Left slapError -> assertFailureT ("parseSome failed: " <> renderSlapError slapError)
        Right parsed -> assertBool "expected 'no EOF marker' in warnings"
                     (any (ciContains "no EOF marker" . Text.unpack . renderSlapAdvisory) (patchAdvisories parsed))

  , testCase "warnings/truncated IPS empty" $ do
      let truncatedIPS = ByteString.pack [0x50,0x41,0x54,0x43,0x48,0x01,0x02]
      case parseSome noDialectsRequested EncodingUtf8 (PatchFileContents truncatedIPS) of
        Left slapError -> assertFailureT ("parseSome failed: " <> renderSlapError slapError)
        Right parsed -> assertBool "expected 'empty patch' in info"
                     (ciContains "empty patch" (Text.unpack (renderAnalysisSummary (patchInfo parsed) (patchAnalysis parsed) Nothing)))

  , testCase "warnings/empty IPS warns empty only" $ do
      let emptyIPS = ByteString.pack [0x50,0x41,0x54,0x43,0x48,0x45,0x4F,0x46]
      case parseSome noDialectsRequested EncodingUtf8 (PatchFileContents emptyIPS) of
        Left slapError -> assertFailureT ("parseSome failed: " <> renderSlapError slapError)
        Right parsed -> do
          let info = renderAnalysisSummary (patchInfo parsed) (patchAnalysis parsed) Nothing
          assertBool "should warn 'empty patch'" ("empty patch" `Text.isInfixOf` info)
          assertBool "should NOT warn 'no EOF'" (not ("no EOF" `Text.isInfixOf` info))

  , testCase "warnings/normal IPS no warnings" $ do
      let ipsPath = repo </> "test/data/dm4y/patch.ips"
      exists <- doesFileExist ipsPath
      if not exists
        then pure ()  -- in-process; no harness to skip via and not worth a fixture gate for one body
        else do
          patchBytes <- ByteString.readFile ipsPath
          case parseSome noDialectsRequested EncodingUtf8 (PatchFileContents patchBytes) of
            Left slapError -> assertFailureT ("parseSome failed: " <> renderSlapError slapError)
            Right parsed -> assertBool "unexpected warning" (null (patchAdvisories parsed))
  ]


-- | The archive tests assume @zip@ is on @PATH@; the @cliTests@
-- gating layer ensures that's true before any of these run, so the
-- subprocess invocations here can call 'runExternal' 'Zip' directly.
archiveTests :: FilePath -> FilePath -> FilePath -> FilePath -> [TestTree]
archiveTests base ips bps ups =
  [ testCase "archive/apply ZIP-wrapped patch" $
      withTempDir "slap-arc" $ \workingDirectory -> do
        let zipFile = workingDirectory </> "patch.zip"
            result  = workingDirectory </> "result"
            direct  = workingDirectory </> "direct"
        zipRun <- runExternal Zip ["-j", zipFile, ips] Nothing ""
        case externalRunExitCode zipRun of
          ExitFailure _ -> assertFailure "zip failed"
          ExitSuccess -> do
            expectOk ["apply", zipFile, base, "-o", result]
              "archive/apply" "applied"
            _ <- runExternal SlapBinary ["apply", ips, base, "-o", direct] Nothing ""
            zipSha    <- sha1Hex <$> ByteString.readFile result
            directSha <- sha1Hex <$> ByteString.readFile direct
            assertEqual "SHA1 mismatch" directSha zipSha

  , testCase "archive/undo ZIP-wrapped target" $
      withTempDir "slap-arc" $ \workingDirectory -> do
        let modifiedFile = workingDirectory </> "modified.bin"
            zipFile      = workingDirectory </> "modified.zip"
            revertedFile = workingDirectory </> "reverted.bin"
        _ <- runExternal SlapBinary ["apply", ups, base, "-o", modifiedFile] Nothing ""
        zipRun <- runExternal Zip ["-j", zipFile, modifiedFile] Nothing ""
        case externalRunExitCode zipRun of
          ExitFailure _ -> assertFailure "zip failed (zip not on PATH?)"
          ExitSuccess   -> do
            expectOk ["undo", ups, zipFile, "-o", revertedFile]
              "archive/undo ZIP-wrapped target" "reverted"
            baseSha     <- sha1Hex <$> ByteString.readFile base
            revertedSha <- sha1Hex <$> ByteString.readFile revertedFile
            assertEqual "reverted should match base" baseSha revertedSha

  , testCase "archive/info ZIP-wrapped" $
      withTempDir "slap-arc" $ \workingDirectory -> do
        let zipFile = workingDirectory </> "patch.zip"
        _ <- runExternal Zip ["-j", zipFile, ips] Nothing ""
        expectOk ["info", zipFile] "archive/info" "IPS"

  , testCase "archive/explain ZIP-wrapped" $
      withTempDir "slap-arc" $ \workingDirectory -> do
        let zipFile = workingDirectory </> "patch.zip"
        _ <- runExternal Zip ["-j", zipFile, ips] Nothing ""
        expectOk ["explain", zipFile] "archive/explain" "IPS"

  , testCase "archive/ZIP chaff filters readme" $
      withTempDir "slap-arc" $ \workingDirectory -> do
        let chaffZip = workingDirectory </> "chaff.zip"
            readme   = workingDirectory </> "readme.txt"
        ByteString.writeFile readme (ByteString.pack [0x52,0x45,0x41,0x44,0x4D,0x45])
        _ <- runExternal Zip ["-j", chaffZip, ips, readme] Nothing ""
        expectOk ["info", chaffZip] "archive/chaff" "IPS"

  , testCase "archive/multi-entry ZIP fails" $
      withTempDir "slap-arc" $ \workingDirectory -> do
        let multiZip = workingDirectory </> "multi.zip"
        _ <- runExternal Zip ["-j", multiZip, ips, bps] Nothing ""
        expectFail ["info", multiZip] "archive/multi" "candidate"
  ]

-- | CLI-surface tests for undo's asymmetric paths: the derived-filename default lane (unique to 'doUndo'),
-- and the three verification cases (fatal default, --no-verify downgrade, happy-path round-trip).
-- The lane plumbing literally shared with apply's 'writingLane' is covered by apply's own 'cliTests' and not duplicated here.
undoCliTests :: FilePath -> FilePath -> [TestTree]
undoCliTests base ups =
  [ testCase "undo/derived path leaves input untouched" $
      withTempDir "slap-undo" $ \workingDirectory -> do
        let modifiedFile = workingDirectory </> "patched.bin"
            derivedPath  = workingDirectory </> "patched [reverted].bin"
        _ <- runExternal SlapBinary ["apply", ups, base, "-o", modifiedFile] Nothing ""
        modifiedShaBefore <- sha1Hex <$> ByteString.readFile modifiedFile
        expectOk ["undo", ups, modifiedFile] "undo/derived path" "reverted"
        derivedExists <- doesFileExist derivedPath
        assertBool "derived output should exist at expected path" derivedExists
        modifiedShaAfter <- sha1Hex <$> ByteString.readFile modifiedFile
        assertEqual "input file should not be clobbered" modifiedShaBefore modifiedShaAfter
        baseSha    <- sha1Hex <$> ByteString.readFile base
        derivedSha <- sha1Hex <$> ByteString.readFile derivedPath
        assertEqual "derived output should match base bytes" baseSha derivedSha

  , testCase "undo/verification refuses mismatched modified file" $
      withTempDir "slap-undo" $ \workingDirectory -> do
        let wrongModified = workingDirectory </> "wrong.bin"
            outFile       = workingDirectory </> "out.bin"
        ByteString.readFile base >>= ByteString.writeFile wrongModified
        run <- runExternal SlapBinary
          ["undo", ups, wrongModified, "-o", outFile] Nothing ""
        case externalRunExitCode run of
          ExitFailure _ -> pure ()
          ExitSuccess   -> assertFailure
            "undo should refuse target with mismatched CRC under default policy"

  , testCase "undo/--no-verify proceeds with mismatched modified file" $
      withTempDir "slap-undo" $ \workingDirectory -> do
        let wrongModified = workingDirectory </> "wrong.bin"
            outFile       = workingDirectory </> "out.bin"
        ByteString.readFile base >>= ByteString.writeFile wrongModified
        run <- runExternal SlapBinary
          ["undo", "--no-verify", ups, wrongModified, "-o", outFile] Nothing ""
        case externalRunExitCode run of
          ExitSuccess   -> pure ()
          ExitFailure _ -> assertFailure
            "--no-verify should let undo proceed with mismatched modified file"

  , testCase "undo/happy path round-trips correct bytes" $
      withTempDir "slap-undo" $ \workingDirectory -> do
        let modifiedFile = workingDirectory </> "patched.bin"
            revertedFile = workingDirectory </> "reverted.bin"
        _ <- runExternal SlapBinary ["apply", ups, base, "-o", modifiedFile] Nothing ""
        expectOk ["undo", ups, modifiedFile, "-o", revertedFile]
          "undo/happy path" "reverted"
        baseSha     <- sha1Hex <$> ByteString.readFile base
        revertedSha <- sha1Hex <$> ByteString.readFile revertedFile
        assertEqual "reverted should match base bytes" baseSha revertedSha
  ]

ipsTruncateTests :: FilePath -> [TestTree]
ipsTruncateTests base =
  [ testCase "truncate/IPS truncation in info" $
      withTempFile "slap-small" $ \small ->
      withTempFile "slap-patch" $ \patch -> do
        baseBytes <- ByteString.readFile base
        ByteString.writeFile small (ByteString.take 65536 baseBytes)
        run <- runExternal SlapBinary ["create", "--format", "ips", base, small, patch, "--force"] Nothing ""
        case externalRunExitCode run of
          ExitSuccess -> expectOk ["info", patch] "truncate/info" "truncate"
          _ -> assertFailure "create failed"

  , testCase "truncate/IPS truncation apply correct" $
      withTempFile "slap-small" $ \small ->
      withTempFile "slap-patch" $ \patch ->
      withTempFile "slap-result" $ \result -> do
        baseBytes <- ByteString.readFile base
        let smallBytes = ByteString.take 65536 baseBytes
        ByteString.writeFile small smallBytes
        run <- runExternal SlapBinary ["create", "--format", "ips", base, small, patch, "--force"] Nothing ""
        case externalRunExitCode run of
          ExitSuccess -> do
            expectOk ["apply", patch, base, "-o", result, "--force"]
              "truncate/apply" "applied"
            smallSha  <- pure (sha1Hex smallBytes)
            resultSha <- sha1Hex <$> ByteString.readFile result
            assertEqual "SHA1 mismatch" smallSha resultSha
          _ -> assertFailure "create failed"
  ]

-- | VCDIFF custom-code-table coverage. No oracle can cross-validate these;
-- the expected outputs come from the fixtures' @generate.py@, which has the story.
customCodetableTests :: [TestTree]
customCodetableTests =
  [ testCase "custom-codetable/info names the custom table" $
      expectOk ["info", customTableFixture "fixtureA-identity.vcdiff"]
        "custom-codetable/info" "custom (RFC 3284"

  , testCase "custom-codetable/identity applies through the custom table" $
      withTempFile "slap-out" $ \out -> do
        removeIfExists out
        expectOk [ "apply", customTableFixture "fixtureA-identity.vcdiff"
                 , customTableFixture "sourceA.bin", "-o", out ]
          "custom-codetable/identity" "applied"
        decoded <- ByteString.readFile out
        assertEqual "decoded output" "HELLO" decoded

  , testCase "custom-codetable/nested table refused" $
      expectFail [ "apply", customTableFixture "fixtureB-nested.vcdiff"
                 , customTableFixture "sourceA.bin", "-o", "/dev/null" ]
        "custom-codetable/nested" "a place to start reading"

  , testCase "custom-codetable/invalid entry refused with context" $
      expectFail [ "apply", customTableFixture "fixtureC-invalid-entry.vcdiff"
                 , customTableFixture "sourceA.bin", "-o", "/dev/null" ]
        "custom-codetable/invalid-entry" "names an instruction that doesn't exist"

  , testCase "custom-codetable/do-nothing entry applies with a note" $
      withTempFile "slap-out" $ \out -> do
        removeIfExists out
        expectOk [ "apply", customTableFixture "fixtureD-noop-noop.vcdiff"
                 , customTableFixture "sourceD.bin", "-o", out ]
          "custom-codetable/noop-noop" "do-nothing"
        decoded <- ByteString.readFile out
        assertEqual "decoded output" "HELLO" decoded

  , testCase "custom-codetable/declared cache sizes steer decode" $
      withTempFile "slap-out" $ \out -> do
        removeIfExists out
        expectOk [ "apply", customTableFixture "fixtureE-larger-near-cache.vcdiff"
                 , customTableFixture "sourceE.bin", "-o", out ]
          "custom-codetable/larger-near-cache" "applied"
        decoded <- ByteString.readFile out
        assertEqual "decoded output" "3456" decoded

  , testCase "custom-codetable/mode past the declared caches refused" $
      expectFail [ "apply", customTableFixture "fixtureF-mode-out-of-range.vcdiff"
                 , customTableFixture "sourceA.bin", "-o", "/dev/null" ]
        "custom-codetable/mode-out-of-range" "modes 0 through 8"
  ]
  where
    customTableFixture name = "test/data/vcdiff-custom-table/" ++ name

-- | The VCDIFF create flags through real argv, on temp-file pairs so no fixture
-- gate applies. Each accepted flag round-trips through apply; the FGK case is
-- the flag surface of 'XDelta3CompressorEncodingUnsupported'.
vcdiffCreateFlagTests :: [TestTree]
vcdiffCreateFlagTests =
  [ testCase "vcdiff-flags/--window-size slices and applies back" $
      withGarbagePair $ \source target ->
      withTempFile "slap-patch" $ \patch ->
      withTempFile "slap-out" $ \out -> do
        expectOk [ "create", "--format", "rfc-vcdiff", "--window-size", "32k"
                 , source, target, patch, "--force" ]
          "vcdiff-flags/window-size" "wrote"
        removeIfExists out
        expectOk ["apply", patch, source, "-o", out]
          "vcdiff-flags/window-size-apply" "applied"
        assertRebuiltTarget target out

  , testCase "vcdiff-flags/--compress-with djw applies back" $
      withGarbagePair $ \source target ->
      withTempFile "slap-patch" $ \patch ->
      withTempFile "slap-out" $ \out -> do
        expectOk [ "create", "--format", "xdelta3", "--compress-with", "djw"
                 , source, target, patch, "--force" ]
          "vcdiff-flags/compress-with-djw" "wrote"
        removeIfExists out
        expectOk ["apply", patch, source, "-o", out]
          "vcdiff-flags/compress-with-djw-apply" "applied"
        assertRebuiltTarget target out

  , testCase "vcdiff-flags/--no-compress applies back" $
      withGarbagePair $ \source target ->
      withTempFile "slap-patch" $ \patch ->
      withTempFile "slap-out" $ \out -> do
        expectOk [ "create", "--format", "xdelta3", "--no-compress"
                 , source, target, patch, "--force" ]
          "vcdiff-flags/no-compress" "wrote"
        removeIfExists out
        expectOk ["apply", patch, source, "-o", out]
          "vcdiff-flags/no-compress-apply" "applied"
        assertRebuiltTarget target out

  , testCase "vcdiff-flags/--compress-with fgk is refused" $
      withGarbagePair $ \source target ->
      withTempFile "slap-patch" $ \patch ->
        expectFail [ "create", "--format", "xdelta3", "--compress-with", "fgk"
                   , source, target, patch, "--force" ]
          "vcdiff-flags/compress-with-fgk" "cannot yet write"
  ]
  where
    withGarbagePair body =
      withTempFile "slap-source" $ \source ->
      withTempFile "slap-target" $ \target -> do
        writeGarbage source (128 * 1024)
        writeGarbage target (128 * 1024)
        body source target
    assertRebuiltTarget target out = do
      targetSha <- sha1Hex <$> ByteString.readFile target
      outSha    <- sha1Hex <$> ByteString.readFile out
      assertEqual "apply output rebuilds the target" targetSha outSha

-- | VCD_TARGET apply coverage. No oracle can cross-validate these;
-- the expected outputs come from the fixtures' @generate.py@, which has the story.
vcdTargetTests :: [TestTree]
vcdTargetTests =
  [ testCase "vcd-target/window copies an earlier window's output" $
      withTempFile "slap-empty-source" $ \emptySource ->
      withTempFile "slap-out" $ \out -> do
        ByteString.writeFile emptySource ""
        removeIfExists out
        expectOk [ "apply", vcdTargetFixture "fixture1-cross-window.vcdiff"
                 , emptySource, "-o", out ]
          "vcd-target/cross-window" "applied"
        decoded <- ByteString.readFile out
        assertEqual "decoded output" "ABCDEFGHCDEF" decoded

  , testCase "vcd-target/info reads the RFC flavor" $
      expectOk ["info", vcdTargetFixture "fixture1-cross-window.vcdiff"]
        "vcd-target/info" "RFC 3284"

  , testCase "vcd-target/empty segment applies with a note" $
      withTempFile "slap-empty-source" $ \emptySource ->
      withTempFile "slap-out" $ \out -> do
        ByteString.writeFile emptySource ""
        removeIfExists out
        expectOk [ "apply", vcdTargetFixture "fixture2-empty-segment.vcdiff"
                 , emptySource, "-o", out ]
          "vcd-target/empty-segment" "empty source segment"
        decoded <- ByteString.readFile out
        assertEqual "decoded output" "" decoded

  , testCase "vcd-target/VCD_TARGET with a window Adler32 is neither dialect" $
      withTempFile "slap-empty-source" $ \emptySource ->
        expectFail [ "apply", vcdTargetFixture "fixture3-target-plus-adler.vcdiff"
                   , emptySource, "-o", "/dev/null" ]
          "vcd-target/neither-dialect" "mixes two different flavors"
  ]
  where
    vcdTargetFixture name = "test/data/vcdiff-vcd-target/" ++ name

-- | NINJA1 source-verification CLI coverage. The first two cases just
-- exercise the create+info+apply happy path on dm4y; the last two are
-- gated to 'Full' because they each materialise a 4 MB garbage source
-- file via 'writeGarbage'.
ninja1VerifyTests :: Tier -> FilePath -> FilePath -> [TestTree]
ninja1VerifyTests tier base ips = quickCases ++ onlyAtFull tier fullTierCases
  where
    quickCases =
      [ testCase "ninja1-verify/info shows source CRC" $
          withTempFile "slap-target" $ \target ->
          withTempFile "slap-patch" $ \patch -> do
            _ <- runExternal SlapBinary ["apply", ips, base, "-o", target, "--force"] Nothing ""
            _ <- runExternal SlapBinary ["create", "--format", "ninja1", base, target, patch, "--force"] Nothing ""
            expectOk ["info", patch] "ninja1/info" "source CRC"

      , testCase "ninja1-verify/correct source" $
          withTempFile "slap-target" $ \target ->
          withTempFile "slap-patch" $ \patch ->
          withTempFile "slap-out" $ \out -> do
            _ <- runExternal SlapBinary ["apply", ips, base, "-o", target, "--force"] Nothing ""
            _ <- runExternal SlapBinary ["create", "--format", "ninja1", base, target, patch, "--force"] Nothing ""
            removeIfExists out
            expectOk ["apply", patch, base, "-o", out] "ninja1/correct" "applied"
      ]

    fullTierCases =
      [ -- The 64 MiB stadium2 source exceeds NINJA1's 0x1e00000 sampling
        -- threshold, so verification runs the stored source hashes over the
        -- sampled input (first 20 MiB + last 10 MiB + decimal size) rather
        -- than the whole file. This is the only case that exercises that
        -- branch; a successful apply means the sampled hashes matched.
        testCase "ninja1-verify/large source samples (64 MiB)" $
          withTempFile "slap-out" $ \out -> do
            removeIfExists out
            expectOk [ "apply", "test/data/stadium2/fair-heavy/patch.ninja1"
                     , "test/data/stadium2/base.z64", "-o", out ]
                     "ninja1/large-sample" "applied"

      , testCase "ninja1-verify/wrong source rejected" $
          withTempFile "slap-target" $ \target ->
          withTempFile "slap-patch" $ \patch ->
          withTempFile "slap-wrong" $ \wrong ->
          withTempFile "slap-out" $ \out -> do
            _ <- runExternal SlapBinary ["apply", ips, base, "-o", target, "--force"] Nothing ""
            _ <- runExternal SlapBinary ["create", "--format", "ninja1", base, target, patch, "--force"] Nothing ""
            writeGarbage wrong (4096 * 1024)
            removeIfExists out
            expectFail ["apply", patch, wrong, "-o", out] "ninja1/wrong" "mismatch"

      , testCase "ninja1-verify/--no-verify bypasses" $
          withTempFile "slap-target" $ \target ->
          withTempFile "slap-patch" $ \patch ->
          withTempFile "slap-wrong" $ \wrong ->
          withTempFile "slap-out" $ \out -> do
            _ <- runExternal SlapBinary ["apply", ips, base, "-o", target, "--force"] Nothing ""
            _ <- runExternal SlapBinary ["create", "--format", "ninja1", base, target, patch, "--force"] Nothing ""
            writeGarbage wrong (4096 * 1024)
            removeIfExists out
            expectOk ["apply", patch, wrong, "-o", out, "--no-verify"]
              "ninja1/--no-verify" "applied"
      ]

-- | ROM-type normalization through the full CLI pipeline. The round trip is
-- the whole feature in one breath: create from headered dumps (both sides
-- canonicalized before the diff, hashes stored over the clean forms), apply
-- to the headered original (normalize, verify, patch, restore), and read the
-- headered modified back byte-for-byte. The retag rule rides along: convert
-- refuses a cross-platform @--rom-type@ against a patch that carries one.
normalizationTests :: [TestTree]
normalizationTests =
  [ testCase "normalize/ninja2 nes: headered pair round-trips through create and apply" $
      withTempFile "slap-original" $ \original ->
      withTempFile "slap-modified" $ \modified ->
      withTempFile "slap-patch" $ \patch ->
      withTempFile "slap-out" $ \out -> do
        let header      = "NES\x1A" <> ByteString.replicate 12 0xEE
            body        = ByteString.pack (take 0x400 (cycle [0 .. 255]))
            patchedBody = ByteString.take 0x100 body <> "patched!" <> ByteString.drop 0x108 body
        ByteString.writeFile original (header <> body)
        ByteString.writeFile modified (header <> patchedBody)
        _ <- runExternal SlapBinary
               ["create", "--format", "ninja2", "--rom-type", "nes", original, modified, patch, "--force"] Nothing ""
        removeIfExists out
        expectOk ["apply", patch, original, "-o", out] "normalize/ninja2-nes" "applied"
        outBytes      <- ByteString.readFile out
        expectedBytes <- ByteString.readFile modified
        assertEqual "restored output equals the modified dump" expectedBytes outBytes

  , testCase "normalize/convert refuses a cross-platform --rom-type retag" $
      withTempFile "slap-original" $ \original ->
      withTempFile "slap-modified" $ \modified ->
      withTempFile "slap-patch" $ \patch ->
      withTempFile "slap-out" $ \out -> do
        let header = "NES\x1A" <> ByteString.replicate 12 0xEE
            body   = ByteString.replicate 0x200 0x42
        ByteString.writeFile original (header <> body)
        ByteString.writeFile modified (header <> ByteString.replicate 0x200 0x24)
        _ <- runExternal SlapBinary
               ["create", "--format", "ninja2", "--rom-type", "nes", original, modified, patch, "--force"] Nothing ""
        removeIfExists out
        expectFail ["convert", patch, "--to", "ninja1", "--rom-type", "snes", "-o", out]
          "normalize/retag-refused" "does not retag"
  ]

descriptionTests :: FilePath -> FilePath -> [TestTree]
descriptionTests base bps =
  [ testCase "desc/aps-n64 create --description" $
      withTempFile "slap-target" $ \target ->
      withTempFile "slap-patch" $ \patch -> do
        _ <- runExternal SlapBinary ["apply", bps, base, "-o", target, "--force"] Nothing ""
        expectOk ["create", "--format", "aps-n64", "--description", "Test description",
                  base, target, patch, "--force"]
          "desc/aps-n64" "wrote"
        expectOk ["info", patch] "desc/aps-n64 info" "Test description"
  ]

-- | Slap rejects metadata flags that the target format won't carry.
-- The check runs against the user's CLI-supplied metadata only:
-- inherited-from-source metadata stays on the existing drop-with-warning
-- path. Rendered errors name the offending flag and the target format,
-- so the assertions look for both substrings.
metadataRejectionTests :: FilePath -> FilePath -> [TestTree]
metadataRejectionTests base bps =
  [ testCase "metadata-reject/ips refuses --title" $
      withTempFile "slap-target" $ \target ->
      withTempFile "slap-patch" $ \patch -> do
        _ <- runExternal SlapBinary ["apply", bps, base, "-o", target, "--force"] Nothing ""
        expectFailContains
          ["create", "--format", "ips", base, target, patch, "--title", "x"]
          ["--title", "IPS"]

  , testCase "metadata-reject/ips refuses --rom-type" $
      withTempFile "slap-target" $ \target ->
      withTempFile "slap-patch" $ \patch -> do
        _ <- runExternal SlapBinary ["apply", bps, base, "-o", target, "--force"] Nothing ""
        expectFailContains
          ["create", "--format", "ips", base, target, patch, "--rom-type", "snes"]
          ["--rom-type", "IPS"]

  , testCase "metadata-reject/ips refuses --unstable" $
      withTempFile "slap-target" $ \target ->
      withTempFile "slap-patch" $ \patch -> do
        _ <- runExternal SlapBinary ["apply", bps, base, "-o", target, "--force"] Nothing ""
        expectFailContains
          ["create", "--format", "ips", base, target, patch, "--unstable"]
          ["--unstable", "IPS"]

  , testCase "metadata-reject/bps refuses --rom-type" $
      withTempFile "slap-target" $ \target ->
      withTempFile "slap-patch" $ \patch -> do
        _ <- runExternal SlapBinary ["apply", bps, base, "-o", target, "--force"] Nothing ""
        expectFailContains
          ["create", "--format", "bps", base, target, patch, "--rom-type", "snes"]
          ["--rom-type", "BPS"]

  , testCase "metadata-reject/dps refuses --rom-type" $
      withTempFile "slap-target" $ \target ->
      withTempFile "slap-patch" $ \patch -> do
        _ <- runExternal SlapBinary ["apply", bps, base, "-o", target, "--force"] Nothing ""
        expectFailContains
          ["create", "--format", "dps", base, target, patch, "--rom-type", "snes"]
          ["--rom-type", "DPS"]

  , testCase "metadata-reject/ninja2 refuses --image-type" $
      withTempFile "slap-target" $ \target ->
      withTempFile "slap-patch" $ \patch -> do
        _ <- runExternal SlapBinary ["apply", bps, base, "-o", target, "--force"] Nothing ""
        expectFailContains
          ["create", "--format", "ninja2", base, target, patch, "--image-type", "gi"]
          ["--image-type", "NINJA2"]

  , testCase "metadata-accept/dps takes --title --unstable" $
      withTempFile "slap-target" $ \target ->
      withTempFile "slap-patch" $ \patch -> do
        _ <- runExternal SlapBinary ["apply", bps, base, "-o", target, "--force"] Nothing ""
        expectOk
          ["create", "--format", "dps", base, target, patch,
           "--title", "Test patch", "--unstable", "--force"]
          "metadata-accept/dps" "wrote"

  , testCase "metadata-accept/ninja2 takes title rom-type genre" $
      withTempFile "slap-target" $ \target ->
      withTempFile "slap-patch" $ \patch -> do
        _ <- runExternal SlapBinary ["apply", bps, base, "-o", target, "--force"] Nothing ""
        expectOk
          ["create", "--format", "ninja2", base, target, patch,
           "--title", "T", "--rom-type", "gbc", "--genre", "RPG", "--force"]
          "metadata-accept/ninja2" "wrote"

  , testCase "metadata-accept/bps takes --metadata FILE" $
      withTempFile "slap-target" $ \target ->
      withTempFile "slap-patch" $ \patch ->
      withTempFile "slap-blob" $ \blob -> do
        _ <- runExternal SlapBinary ["apply", bps, base, "-o", target, "--force"] Nothing ""
        ByteString.writeFile blob (ByteString8.pack "<blob/>")
        expectOk
          ["create", "--format", "bps", base, target, patch, "--metadata", blob, "--force"]
          "metadata-accept/bps" "wrote"

  , testCase "metadata-accept/ppf3 takes --no-undo --omit-verification --description" $
      withTempFile "slap-target" $ \target ->
      withTempFile "slap-patch" $ \patch -> do
        _ <- runExternal SlapBinary ["apply", bps, base, "-o", target, "--force"] Nothing ""
        expectOk
          ["create", "--format", "ppf3", base, target, patch,
           "--description", "x", "--no-undo", "--omit-verification", "--force"]
          "metadata-accept/ppf3" "wrote"

  , testCase "metadata-accept/convert inherits source metadata silently" $
      -- An EBP patch carries title/author/description in its trailing JSON.
      -- The parser surfaces those into the patch's extracted metadata; the
      -- convert path merges them into the metadata it hands to the encoder.
      -- No --title on the convert CLI means the rejection check (which sees
      -- only CLI-supplied metadata) doesn't fire, so the conversion to a
      -- title-less target succeeds. This is the convert-time semantics the
      -- prompt's framing emphasizes: source-inherited fields stay on the
      -- existing drop path; only user-expressed flags can be rejected.
      withTempFile "slap-target" $ \target ->
      withTempFile "slap-ebp"    $ \ebp ->
      withTempFile "slap-ips"    $ \ips -> do
        _ <- runExternal SlapBinary ["apply", bps, base, "-o", target, "--force"] Nothing ""
        _ <- runExternal SlapBinary ["create", "--format", "ebp", base, target, ebp,
                                     "--title", "Inherited", "--author", "n", "--description", "d", "--force"] Nothing ""
        expectOk ["convert", ebp, "--to", "ips", "-o", ips, "--force"]
          "metadata-accept/inherit" "converted"
  ]

-- | BPS\8594BPS convert preserves embedded metadata by default
-- ('CarryBlob'), lets the user replace it (@--metadata FILE@), or
-- discard it (@--drop-metadata@).  The three intents are mutually
-- exclusive — combining the two override flags is a parse error.
-- These tests build a BPS that carries a known blob, run convert, and
-- inspect the produced patch's metadata via @slap info
-- --extract-metadata@.
bpsConvertMetadataTests :: FilePath -> FilePath -> [TestTree]
bpsConvertMetadataTests base bps =
  [ testCase "bps-convert/inherits source metadata by default" $
      withSourceBps $ \sourceBps blobBytes ->
      withTempFile "slap-out" $ \out -> do
        -- BPS\8594BPS has to round-trip through the source ROM, so
        -- @--with@ is required regardless of metadata intent.
        expectOk ["convert", sourceBps, "--to", "bps",
                  "--with", base, "-o", out, "--force"]
          "bps-convert/inherit" "converted"
        extracted <- extractEmbeddedMetadata out
        assertEqual "expected source blob to carry through"
          (Just blobBytes) extracted

  , testCase "bps-convert/--metadata FILE overrides inherited blob" $
      withSourceBps $ \sourceBps _ ->
      withTempFile "slap-out" $ \out ->
      withTempFile "slap-newblob" $ \newBlob -> do
        let replacement = ByteString8.pack "<replacement-blob/>"
        ByteString.writeFile newBlob replacement
        expectOk ["convert", sourceBps, "--to", "bps",
                  "--with", base, "--metadata", newBlob, "-o", out, "--force"]
          "bps-convert/override" "converted"
        extracted <- extractEmbeddedMetadata out
        assertEqual "expected CLI blob to win over source blob"
          (Just replacement) extracted

  , testCase "bps-convert/--drop-metadata discards inherited blob" $
      withSourceBps $ \sourceBps _ ->
      withTempFile "slap-out" $ \out -> do
        expectOk ["convert", sourceBps, "--to", "bps",
                  "--with", base, "--drop-metadata", "-o", out, "--force"]
          "bps-convert/drop" "converted"
        extracted <- extractEmbeddedMetadata out
        assertEqual "expected output to carry no metadata"
          Nothing extracted

  , testCase "bps-convert/--metadata and --drop-metadata are mutually exclusive" $
      withSourceBps $ \sourceBps _ ->
      withTempFile "slap-out" $ \out ->
      withTempFile "slap-newblob" $ \newBlob -> do
        ByteString.writeFile newBlob (ByteString8.pack "x")
        expectFail
          ["convert", sourceBps, "--to", "bps",
           "--metadata", newBlob, "--drop-metadata", "-o", out]
          "bps-convert/mutex" "invalid"

  , testCase "bps-convert/--drop-metadata is refused when the target has no metadata channel" $
      -- A drop is still a request about the metadata field, and IPS has no such field —
      -- the wrong flag for the task gets an objection, exactly as --drop-diz does.
      withSourceBps $ \sourceBps _ ->
      withTempFile "slap-out" $ \out ->
        expectFail ["convert", sourceBps, "--to", "ips",
                    "--with", base, "--drop-metadata", "-o", out, "--force"]
          "bps-convert/drop-cross-format" "--drop-metadata is not accepted"

  , testCase "bps-convert/--drop-diz is refused under its own name when the target has no FILE_ID.DIZ" $
      withSourceBps $ \sourceBps _ ->
      withTempFile "slap-out" $ \out ->
        expectFail ["convert", sourceBps, "--to", "ips",
                    "--with", base, "--drop-diz", "-o", out, "--force"]
          "bps-convert/drop-diz-cross-format" "--drop-diz is not accepted"

  , testCase "gate-order/incoherent --diz outranks its missing file" $
      withTempFile "slap-out" $ \out ->
        expectFail ["convert", "no-such-patch.bps", "--to", "ips",
                    "--diz", "no-such-diz.txt", "-o", out]
          "gate-order/incoherent" "--diz is not accepted"

  , testCase "gate-order/coherent --diz still reports its missing file" $
      withTempFile "slap-out" $ \out ->
        expectFail ["convert", "no-such-patch.bps", "--to", "ppf3",
                    "--diz", "no-such-diz.txt", "-o", out]
          "gate-order/coherent" "cannot read"
  ]
  where
    -- Build a BPS that carries a known metadata blob, by patching a
    -- copy of the dm4y base with the dm4y BPS and then re-creating the
    -- patch with @--metadata@ pointing at the blob.  Yields the path to
    -- the newly-built BPS and the blob bytes the caller should expect
    -- to find inside it.
    withSourceBps :: (FilePath -> ByteString.ByteString -> IO a) -> IO a
    withSourceBps action =
      withTempFile "slap-target"   $ \target ->
      withTempFile "slap-srcbps"   $ \sourceBps ->
      withTempFile "slap-srcblob"  $ \blob -> do
        let blobBytes = ByteString8.pack "<source-metadata/>"
        _ <- runExternal SlapBinary ["apply", bps, base, "-o", target, "--force"] Nothing ""
        ByteString.writeFile blob blobBytes
        _ <- runExternal SlapBinary ["create", "--format", "bps",
                                     base, target, sourceBps, "--metadata", blob, "--force"] Nothing ""
        action sourceBps blobBytes

-- | Read back a patch's embedded metadata by asking @slap info@ to extract it.
-- Returns 'Nothing' when the patch carries no metadata (info exits nonzero with
-- "no embedded metadata to extract"), or 'Just bytes' when it wrote the extraction file.
extractEmbeddedMetadata :: FilePath -> IO (Maybe ByteString.ByteString)
extractEmbeddedMetadata patchPath =
  withTempFile "slap-meta" $ \metaPath -> do
    run <- runExternal SlapBinary
      ["info", patchPath, "--extract-metadata", metaPath, "--force"] Nothing ""
    case externalRunExitCode run of
      ExitSuccess -> Just <$> ByteString.readFile metaPath
      ExitFailure _
        | "no embedded metadata" `isInfixOf` externalRunStderr run -> pure Nothing
        | otherwise -> assertFailure
            ("info --extract-metadata failed: "
             ++ externalRunStdout run ++ externalRunStderr run)

-- | @--metadata-text TEXT@ is the typed-content lane beside @--metadata FILE@: the person writes content, not markup,
-- and each target embeds it per its own convention — BPS in the thin XML jacket its spec recommends,
-- xdelta3's application header as the text's own UTF-8 bytes.
metadataTextTests :: FilePath -> FilePath -> [TestTree]
metadataTextTests base bps =
  [ testCase "metadata-text/bps jackets typed text, markup characters escaped" $
      withPatchedTarget $ \target ->
      withTempFile "slap-patch" $ \patch -> do
        expectOk ["create", "--format", "bps", base, target, patch,
                  "--metadata-text", "a & b <c>", "--force"]
          "metadata-text/bps" "wrote"
        extracted <- extractEmbeddedMetadata patch
        assertEqual "expected the typed text inside the XML jacket"
          (Just (ByteString8.pack
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<patch>a &amp; b &lt;c&gt;</patch>"))
          extracted

  , testCase "metadata-text/xdelta3 takes the text plainly — its application header is a string field" $
      withPatchedTarget $ \target ->
      withTempFile "slap-patch" $ \patch -> do
        expectOk ["create", "--format", "xdelta3", base, target, patch,
                  "--metadata-text", "typed words", "--force"]
          "metadata-text/xdelta3" "wrote"
        extracted <- extractEmbeddedMetadata patch
        assertEqual "expected the typed text, no jacket"
          (Just (ByteString8.pack "typed words")) extracted

  , testCase "metadata-text/refused under its own name where the target has no metadata channel" $
      expectFail ["create", "--format", "ips", "no-such-base", "no-such-target", "out.ips",
                  "--metadata-text", "x"]
        "metadata-text/cross-format" "--metadata-text is not accepted"

  , testCase "metadata-text/--metadata and --metadata-text are mutually exclusive" $
      withTempFile "slap-blob" $ \blob -> do
        ByteString.writeFile blob (ByteString8.pack "x")
        expectFail ["create", "--format", "bps", "no-such-base", "no-such-target", "out.bps",
                    "--metadata", blob, "--metadata-text", "x"]
          "metadata-text/mutex" "invalid"

  , testCase "metadata-text/convert does not offer the flag (it is create-only by design)" $
      expectFail ["convert", "no-such-patch.bps", "--to", "bps", "--metadata-text", "x", "-o", "out.bps"]
        "metadata-text/convert-absent" "invalid"
  ]
  where
    withPatchedTarget :: (FilePath -> IO a) -> IO a
    withPatchedTarget action =
      withTempFile "slap-target" $ \target -> do
        _ <- runExternal SlapBinary ["apply", bps, base, "-o", target, "--force"] Nothing ""
        action target

-- | @info --extract-diz@ writes the FILE_ID.DIZ the patch carries, byte-for-byte.
-- This drives the whole projection — the parse's carried bytes, 'SomePatch.patchFileIdDiz', and the write path —
-- which the format-level props reach only as far as the parsed record.
dizExtractByteExactTests :: FilePath -> FilePath -> [TestTree]
dizExtractByteExactTests base bps =
  [ testCase "diz-extract/ppf3 --extract-diz returns the bytes the patch was created with" $
      withTempFile "slap-target" $ \target ->
      withTempFile "slap-patch"  $ \patch ->
      withTempFile "slap-dizin"  $ \dizIn ->
      withTempFile "slap-dizout" $ \dizOut -> do
        let dizBytes = ByteString8.pack "slap sample FILE_ID.DIZ\nsecond line\n"
        _ <- runExternal SlapBinary ["apply", bps, base, "-o", target, "--force"] Nothing ""
        ByteString.writeFile dizIn dizBytes
        expectOk ["create", "--format", "ppf3", base, target, patch, "--diz", dizIn, "--force"]
          "diz-extract/create" "wrote"
        _ <- runExternal SlapBinary ["info", patch, "--extract-diz", dizOut, "--force"] Nothing ""
        extracted <- ByteString.readFile dizOut
        assertEqual "extracted FILE_ID.DIZ matches the bytes create embedded" dizBytes extracted
  ]

-- | @--diz-text TEXT@ is the FILE_ID.DIZ counterpart to @--metadata-text@: typed at the flag, create-only,
-- mutually exclusive with @--diz FILE@; and non-ASCII content is noted, not refused.
dizTextTests :: FilePath -> FilePath -> [TestTree]
dizTextTests base bps =
  [ testCase "diz-text/ppf3 --diz-text embeds the typed text, byte-exact on extract" $
      withPatchedTarget $ \target ->
      withTempFile "slap-patch"  $ \patch ->
      withTempFile "slap-dizout" $ \dizOut -> do
        let dizText = "typed FILE_ID.DIZ\nsecond line\n"
        expectOk ["create", "--format", "ppf3", base, target, patch, "--diz-text", dizText, "--force"]
          "diz-text/create" "wrote"
        _ <- runExternal SlapBinary ["info", patch, "--extract-diz", dizOut, "--force"] Nothing ""
        extracted <- ByteString.readFile dizOut
        assertEqual "extracted FILE_ID.DIZ is the typed text as UTF-8"
          (ByteString8.pack dizText) extracted

  , testCase "diz-text/--diz and --diz-text are mutually exclusive" $
      withTempFile "slap-dizfile" $ \dizFile -> do
        ByteString.writeFile dizFile (ByteString8.pack "x")
        expectFail ["create", "--format", "ppf3", "no-base", "no-target", "out.ppf3",
                    "--diz", dizFile, "--diz-text", "y"]
          "diz-text/mutex" "invalid"

  , testCase "diz-text/convert does not offer the flag (create-only, like --metadata-text)" $
      expectFail ["convert", "no-such-patch.bps", "--to", "ppf3", "--diz-text", "x", "-o", "out.ppf3"]
        "diz-text/convert-absent" "invalid"

  , testCase "diz-text/refused under its own name where the target has no FILE_ID.DIZ channel" $
      expectFail ["create", "--format", "ips", "no-such-base", "no-such-target", "out.ips",
                  "--diz-text", "x"]
        "diz-text/cross-format" "--diz-text is not accepted"

  , testCase "diz/content outside 7-bit ASCII is noted, not refused" $
      withPatchedTarget $ \target ->
      withTempFile "slap-patch"  $ \patch ->
      withTempFile "slap-dizin"  $ \dizIn -> do
        -- "café" in UTF-8: the é is two bytes, both outside 7-bit ASCII.
        ByteString.writeFile dizIn (ByteString.pack [0x63, 0x61, 0x66, 0xC3, 0xA9])
        run <- runExternal SlapBinary
          ["create", "--format", "ppf3", base, target, patch, "--diz", dizIn, "--force"] Nothing ""
        assertEqual "create still succeeds" ExitSuccess (externalRunExitCode run)
        assertBool "the non-ASCII note fires"
          ("outside 7-bit ASCII" `isInfixOf` (externalRunStdout run ++ externalRunStderr run))
  ]
  where
    withPatchedTarget :: (FilePath -> IO a) -> IO a
    withPatchedTarget action =
      withTempFile "slap-target" $ \target -> do
        _ <- runExternal SlapBinary ["apply", bps, base, "-o", target, "--force"] Nothing ""
        action target

-- | Like 'expectFail', but checks for several substrings in one go.
-- The error message produced by 'MetadataFieldRejected' names both the
-- offending flag (e.g. @--title@) and the target format (e.g. @IPS@);
-- callers assert both fragments without rewriting the loop each time.
expectFailContains :: [String] -> [String] -> IO ()
expectFailContains arguments needles = do
  run <- runExternal SlapBinary arguments Nothing ""
  let combined = externalRunStdout run ++ externalRunStderr run
  case externalRunExitCode run of
    ExitFailure _ ->
      mapM_ (\needle ->
        assertBool ("expected '" ++ needle ++ "' in: " ++ combined)
          (needle `isInfixOf` combined)) needles
    ExitSuccess ->
      assertFailure ("expected failure but got success: " ++ combined)

explainModeTests :: FilePath -> Maybe (FilePath, FilePath, FilePath) -> [TestTree]
explainModeTests ips maybeSourceFiles =
  [ testCase "explain/default is summary" $ do
      run <- runExternal SlapBinary ["explain", ips] Nothing ""
      let combined = externalRunStdout run ++ externalRunStderr run
      case externalRunExitCode run of
        ExitSuccess -> do
          assertBool "expected 'records:' in summary"
            ("records:" `isInfixOf` combined)
          assertBool "expected 'range:' in summary"
            ("range:" `isInfixOf` combined)
        ExitFailure _ ->
          assertFailure ("explain failed: " ++ combined)

  , testCase "explain/--records is dump" $ do
      run <- runExternal SlapBinary ["explain", "--records", ips] Nothing ""
      let combined = externalRunStdout run ++ externalRunStderr run
      case externalRunExitCode run of
        ExitSuccess ->
          -- record dump has numbered entries like "   1  Write"
          assertBool "expected numbered record in dump"
            ("Write" `isInfixOf` combined)
        ExitFailure _ ->
          assertFailure ("explain --records failed: " ++ combined)

  , testCase "explain/empty patch summary" $
      withTempFile "slap-ips" $ \filePath -> do
        -- "PATCHEOF" — valid IPS with 0 records
        ByteString.writeFile filePath (ByteString.pack [0x50,0x41,0x54,0x43,0x48,0x45,0x4F,0x46])
        run <- runExternal SlapBinary ["explain", filePath] Nothing ""
        case externalRunExitCode run of
          ExitSuccess ->
            assertBool "expected 'records:' even for empty"
              ("records:" `isInfixOf` externalRunStdout run)
          ExitFailure _ ->
            assertFailure "explain of empty IPS failed"
  ] ++ case maybeSourceFiles of
    Nothing -> []
    Just (base, ups, bps) ->
      [ testCase "explain/--with resolves XOR" $ do
          run <- runExternal SlapBinary
            ["explain", "--records", "--with", base, ups] Nothing ""
          let combined = externalRunStdout run ++ externalRunStderr run
          case externalRunExitCode run of
            ExitSuccess ->
              assertBool "expected 'resolved:' in output"
                ("resolved:" `isInfixOf` combined)
            ExitFailure _ ->
              assertFailure ("explain --with UPS failed: " ++ combined)

      , testCase "explain/--with resolves copy" $ do
          run <- runExternal SlapBinary
            ["explain", "--records", "--with", base, bps] Nothing ""
          let combined = externalRunStdout run ++ externalRunStderr run
          case externalRunExitCode run of
            ExitSuccess ->
              assertBool "expected 'source data:' in output"
                ("source data:" `isInfixOf` combined)
            ExitFailure _ ->
              assertFailure ("explain --with BPS failed: " ++ combined)

      , testCase "explain/--with summary note" $ do
          run <- runExternal SlapBinary
            ["explain", "--with", base, bps] Nothing ""
          let combined = externalRunStdout run ++ externalRunStderr run
          case externalRunExitCode run of
            ExitSuccess ->
              assertBool "expected 'source file provided' in output"
                ("source file provided" `isInfixOf` combined)
            ExitFailure _ ->
              assertFailure ("explain --with summary failed: " ++ combined)

      , testCase "explain/--with direct format unchanged" $ do
          run <- runExternal SlapBinary
            ["explain", "--records", "--with", base, ips] Nothing ""
          let combined = externalRunStdout run ++ externalRunStderr run
          case externalRunExitCode run of
            ExitSuccess -> do
              assertBool "unexpected 'resolved:' for direct format"
                (not ("resolved:" `isInfixOf` combined))
              assertBool "unexpected 'source data:' for direct format"
                (not ("source data:" `isInfixOf` combined))
            ExitFailure _ ->
              assertFailure ("explain --with IPS failed: " ++ combined)
      ]
