module Integration.CLI (cliTests) where

import Integration.External (ExternalRun(..), ExternalTool(..), runExternal)
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
import Slap.FormatLabel (formatLabelName)
import Slap.FileContents (PatchFileContents(..))
import Slap.SomePatch (SomePatch(..), parseSome)
import Slap.Convert (noDialectsRequested)

import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Char8 as ByteString8
import Data.List (isInfixOf)
import System.Directory (doesFileExist)
import System.Exit (ExitCode(..))
import System.FilePath ((</>))
import Test.Tasty (TestTree)
import Test.Tasty.HUnit (testCase, assertFailure, assertBool, assertEqual)

-- | The CLI group splits into: in-process parser tests (no fixtures,
-- no slap binary), single-shot subprocess tests (slap + dm4y base
-- ROM), and the archive sub-strand (slap + dm4y + zip on @PATH@).
-- Each strand gates independently, so a missing fixture in one
-- doesn't suppress the others.
cliTests :: Tier -> IO GroupPlan
cliTests tier = do
  repo <- repoDir
  let inProcessMaybes = map WillRun (corruptTests
                                  ++ warningTests repo
                                  ++ pchtxtDetectTests)

  subprocessMaybes <- requireSlapBinary $ \_slap -> do
    let dm4yBase = repo </> "test/data/dm4y/base.gbc"
        dm4yBps  = repo </> "test/data/dm4y/patch.bps"
        dm4yIps  = repo </> "test/data/dm4y/patch.ips"
        dm4yUps  = repo </> "test/data/dm4y/patch.ups"

    -- Most subprocess tests need the dm4y base ROM. Bundle them under
    -- one fixture gate so a missing ROM produces a single bucket of
    -- skips rather than scattering them.
    dm4yGated <- requireFixture dm4yBase $ \_ -> pure $ map WillRun $ concat
      [ dryrunTests dm4yBase dm4yBps
      , inplaceTests dm4yBase dm4yIps
      , collisionTests dm4yBase dm4yIps
      , verboseTests dm4yBase dm4yIps
      , undoErrorTests dm4yBase dm4yIps dm4yBps
      , compoundTests dm4yBase dm4yIps dm4yBps
      , createFlagTests dm4yBase dm4yBps
      , ipsTruncateTests dm4yBase
      , ninja1VerifyTests tier dm4yBase dm4yIps
      , descriptionTests dm4yBase dm4yBps
      , metadataRejectionTests dm4yBase dm4yBps
      , bpsConvertMetadataTests dm4yBase dm4yBps
      , undoCliTests dm4yBase dm4yUps
      , onlyAtFull tier (forceTests dm4yBase dm4yUps)
      , onlyAtFull tier (noverifyTests dm4yBase dm4yBps)
      ]

    -- Archive tests additionally need the @zip@ and @unzip@ executables.
    archiveGated <-
      requireFixture dm4yBase $ \_ ->
      requireExternalTool Zip $ \_ ->
      requireExternalTool Unzip $ \_ ->
        pure (map WillRun (archiveTests dm4yBase dm4yIps dm4yBps dm4yUps))

    -- Codetable tests are slap-only (no dm4y dependency).
    let codetableMaybes = map WillRun customCodetableTests

    -- Explain-mode tests use dm4y paths but degrade to "no --with"
    -- mode when the base ROM is missing. They register
    -- unconditionally — the test bodies themselves carry the fixture
    -- check (matching pre-refactor behavior).
    let explainMaybes = map WillRun
          (explainModeTests dm4yIps (Just (dm4yBase, dm4yUps, dm4yBps)))

    pure (dm4yGated ++ archiveGated ++ codetableMaybes ++ explainMaybes)

  pure (namedGroup "cli" (inProcessMaybes ++ subprocessMaybes))

----------------------------------------------------------------------------
-- Test groups
----------------------------------------------------------------------------

corruptTests :: [TestTree]
corruptTests =
  [ testCase "corrupt/empty file" $
      case parseSome noDialectsRequested (PatchFileContents ByteString.empty) of
        Left slapError -> assertBool "expected 'unknown'" (ciContains "unknown" (renderSlapError slapError))
        Right _ -> assertFailure "expected parse failure for empty file"

  , testCase "corrupt/random garbage" $ do
      let garbageBytes = ByteString.pack $ take 256 $ map fromIntegral $
                 iterate (\seed -> (seed * 1103515245 + 12345) `mod` 256) (42 :: Int)
      case parseSome noDialectsRequested (PatchFileContents garbageBytes) of
        Left slapError -> assertBool "expected 'unknown'" (ciContains "unknown" (renderSlapError slapError))
        Right _ -> assertFailure "expected parse failure for random garbage"

  , testCase "corrupt/info truncated IPS (graceful)" $ do
      let truncatedIPS = ByteString.pack [0x50,0x41,0x54,0x43,0x48,0x01,0x02]
      case parseSome noDialectsRequested (PatchFileContents truncatedIPS) of
        Left slapError -> assertFailure ("parseSome rejected truncated IPS: " ++ renderSlapError slapError)
        Right parsed -> assertBool "expected '0' in info" ("0" `isInfixOf` renderAnalysisSummary (patchInfo parsed) (patchAnalysis parsed) Nothing)

  , testCase "corrupt/info truncated BPS" $ do
      let truncatedBPS = ByteString.pack [0x42,0x50,0x53,0x31]
      case parseSome noDialectsRequested (PatchFileContents truncatedBPS) of
        Left _ -> pure ()
        Right _ -> assertFailure "expected parse failure for truncated BPS"
  ]

dryrunTests :: FilePath -> FilePath -> [TestTree]
dryrunTests base bps =
  [ testCase "dryrun/reports action" $
      expectOk ["apply", bps, base, "--dry-run"]
        "dryrun/reports action" "would apply"

  , testCase "dryrun/shows CRC" $
      expectOk ["apply", bps, base, "--dry-run"]
        "dryrun/shows CRC" "input CRC"

  , testCase "dryrun/rejects conflicting --output" $
      expectFail ["apply", bps, base, "-o", "/tmp/slap-unreachable", "--dry-run"]
        "dryrun/rejects conflicting --output" "usage"

  , testCase "dryrun/rejects conflicting --in-place" $
      expectFail ["apply", bps, base, "--in-place", "--dry-run"]
        "dryrun/rejects conflicting --in-place" "usage"
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

inplaceTests :: FilePath -> FilePath -> [TestTree]
inplaceTests base ips =
  [ testCase "inplace/creates .bak" $
      withTempFile "slap-work" $ \work -> do
        ByteString.readFile base >>= ByteString.writeFile work
        _ <- runExternal SlapBinary ["apply", ips, work, "--in-place"] Nothing ""
        let backup = work ++ ".bak"
        exists <- doesFileExist backup
        assertBool "no .bak created" exists
        removeIfExists backup

  , testCase "inplace/--no-backup skips .bak" $
      withTempFile "slap-work" $ \work -> do
        ByteString.readFile base >>= ByteString.writeFile work
        _ <- runExternal SlapBinary ["apply", ips, work, "--in-place", "--no-backup"] Nothing ""
        let backup = work ++ ".bak"
        exists <- doesFileExist backup
        assertBool ".bak was created" (not exists)
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
      expectFail ["undo", ips, base] "undo/unsupported IPS" "undo not supported"
  ]

compoundTests :: FilePath -> FilePath -> FilePath -> [TestTree]
compoundTests base ips bps =
  [ testCase "compound/in-place+verbose+no-backup (IPS)" $
      withTempFile "slap-work" $ \work -> do
        ByteString.readFile base >>= ByteString.writeFile work
        expectOk ["apply", ips, work, "--in-place", "--verbose", "--no-backup"]
          "compound/IPS" "applied"

  , testCase "compound/dry-run+verbose shows both" $ do
      run <- runExternal SlapBinary
        ["apply", ips, base, "--dry-run", "--verbose"] Nothing ""
      let combined = externalRunStdout run ++ externalRunStderr run
      assertBool "missing 'would apply'" ("would apply" `isInfixOf` combined)
      assertBool "missing 'Write'" ("Write" `isInfixOf` combined)

  , testCase "compound/rejects --in-place with --dry-run" $
      expectFail ["apply", bps, base, "--in-place", "--dry-run"]
        "compound/rejects --in-place with --dry-run" "usage"

  , testCase "compound/rejects --force with --in-place" $
      expectFail ["apply", bps, base, "--in-place", "--force"]
        "compound/rejects --force with --in-place" "usage"

  , testCase "compound/rejects --force with --dry-run" $
      expectFail ["apply", bps, base, "--dry-run", "--force"]
        "compound/rejects --force with --dry-run" "usage"

  , testCase "compound/explicit -o creates file" $
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
        ByteString.readFile base >>= ByteString.writeFile target
        _ <- runExternal SlapBinary ["apply", bps, target, "--in-place", "--no-backup"] Nothing ""
        expectOk ["create", "--format", "ppf3",
                  "--description", "test patch", base, target, patch]
          "create/ppf3" "wrote"

  , testCase "create/ppf3 undo data present by default" $
      withTempFile "slap-target" $ \target ->
      withTempFile "slap-patch" $ \patch -> do
        ByteString.readFile base >>= ByteString.writeFile target
        _ <- runExternal SlapBinary ["apply", bps, target, "--in-place", "--no-backup"] Nothing ""
        _ <- runExternal SlapBinary ["create", "--format", "ppf3",
                                     "--description", "test patch", base, target, patch] Nothing ""
        expectOk ["info", patch] "create/ppf3 undo" "undo"
  ]

warningTests :: FilePath -> [TestTree]
warningTests repo =
  [ testCase "warnings/truncated IPS no EOF" $ do
      let truncatedIPS = ByteString.pack [0x50,0x41,0x54,0x43,0x48,0x01,0x02]
      case parseSome noDialectsRequested (PatchFileContents truncatedIPS) of
        Left slapError -> assertFailure ("parseSome failed: " ++ renderSlapError slapError)
        Right parsed -> assertBool "expected 'no EOF marker' in warnings"
                     (any (ciContains "no EOF marker" . renderSlapAdvisory) (patchAdvisories parsed))

  , testCase "warnings/truncated IPS empty" $ do
      let truncatedIPS = ByteString.pack [0x50,0x41,0x54,0x43,0x48,0x01,0x02]
      case parseSome noDialectsRequested (PatchFileContents truncatedIPS) of
        Left slapError -> assertFailure ("parseSome failed: " ++ renderSlapError slapError)
        Right parsed -> assertBool "expected 'empty patch' in info"
                     (ciContains "empty patch" (renderAnalysisSummary (patchInfo parsed) (patchAnalysis parsed) Nothing))

  , testCase "warnings/empty IPS warns empty only" $ do
      let emptyIPS = ByteString.pack [0x50,0x41,0x54,0x43,0x48,0x45,0x4F,0x46]
      case parseSome noDialectsRequested (PatchFileContents emptyIPS) of
        Left slapError -> assertFailure ("parseSome failed: " ++ renderSlapError slapError)
        Right parsed -> do
          let info = renderAnalysisSummary (patchInfo parsed) (patchAnalysis parsed) Nothing
          assertBool "should warn 'empty patch'" ("empty patch" `isInfixOf` info)
          assertBool "should NOT warn 'no EOF'" (not ("no EOF" `isInfixOf` info))

  , testCase "warnings/normal IPS no warnings" $ do
      let ipsPath = repo </> "test/data/dm4y/patch.ips"
      exists <- doesFileExist ipsPath
      if not exists
        then pure ()  -- in-process; no harness to skip via and not worth a fixture gate for one body
        else do
          patchBytes <- ByteString.readFile ipsPath
          case parseSome noDialectsRequested (PatchFileContents patchBytes) of
            Left slapError -> assertFailure ("parseSome failed: " ++ renderSlapError slapError)
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
            ByteString.readFile base >>= ByteString.writeFile result
            expectOk ["apply", zipFile, result, "--in-place", "--no-backup"]
              "archive/apply" "applied"
            ByteString.readFile base >>= ByteString.writeFile direct
            _ <- runExternal SlapBinary ["apply", ips, direct, "--in-place", "--no-backup"] Nothing ""
            zipSha    <- sha1Hex <$> ByteString.readFile result
            directSha <- sha1Hex <$> ByteString.readFile direct
            assertEqual "SHA1 mismatch" directSha zipSha

  , testCase "archive/undo ZIP-wrapped target" $
      withTempDir "slap-arc" $ \workingDirectory -> do
        let modifiedFile = workingDirectory </> "modified.bin"
            zipFile      = workingDirectory </> "modified.zip"
            revertedFile = workingDirectory </> "reverted.bin"
        ByteString.readFile base >>= ByteString.writeFile modifiedFile
        _ <- runExternal SlapBinary
          ["apply", ups, modifiedFile, "--in-place", "--no-backup"] Nothing ""
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

-- | CLI-surface tests for undo's asymmetric paths: the derived-filename
-- default lane and the dry-run branch (both unique to 'doUndo'),
-- and the three verification cases (fatal default, --no-verify
-- downgrade, happy-path round-trip).  The lane plumbing literally
-- shared with apply's 'writingLane' (plain @-o FILE@ success,
-- positional @OUTPUT@ alternative, @--force@ against an existing
-- target) is covered by apply's own 'cliTests' and not duplicated here.
undoCliTests :: FilePath -> FilePath -> [TestTree]
undoCliTests base ups =
  [ testCase "undo/derived path leaves input untouched" $
      withTempDir "slap-undo" $ \workingDirectory -> do
        let modifiedFile = workingDirectory </> "patched.bin"
            derivedPath  = workingDirectory </> "patched [reverted].bin"
        ByteString.readFile base >>= ByteString.writeFile modifiedFile
        _ <- runExternal SlapBinary
          ["apply", ups, modifiedFile, "--in-place", "--no-backup"] Nothing ""
        modifiedShaBefore <- sha1Hex <$> ByteString.readFile modifiedFile
        expectOk ["undo", ups, modifiedFile] "undo/derived path" "reverted"
        derivedExists <- doesFileExist derivedPath
        assertBool "derived output should exist at expected path" derivedExists
        modifiedShaAfter <- sha1Hex <$> ByteString.readFile modifiedFile
        assertEqual "input file should not be clobbered" modifiedShaBefore modifiedShaAfter
        baseSha    <- sha1Hex <$> ByteString.readFile base
        derivedSha <- sha1Hex <$> ByteString.readFile derivedPath
        assertEqual "derived output should match base bytes" baseSha derivedSha

  , testCase "undo/--dry-run prints would-revert and writes nothing" $
      withTempDir "slap-undo" $ \workingDirectory -> do
        let modifiedFile = workingDirectory </> "patched.bin"
            derivedPath  = workingDirectory </> "patched [reverted].bin"
        ByteString.readFile base >>= ByteString.writeFile modifiedFile
        _ <- runExternal SlapBinary
          ["apply", ups, modifiedFile, "--in-place", "--no-backup"] Nothing ""
        modifiedShaBefore <- sha1Hex <$> ByteString.readFile modifiedFile
        expectOk ["undo", "--dry-run", ups, modifiedFile]
          "undo/--dry-run" "would revert"
        modifiedShaAfter <- sha1Hex <$> ByteString.readFile modifiedFile
        assertEqual "dry-run should not modify input" modifiedShaBefore modifiedShaAfter
        derivedExists <- doesFileExist derivedPath
        assertBool "dry-run should not create derived output" (not derivedExists)

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
        ByteString.readFile base >>= ByteString.writeFile modifiedFile
        _ <- runExternal SlapBinary
          ["apply", ups, modifiedFile, "--in-place", "--no-backup"] Nothing ""
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
        run <- runExternal SlapBinary ["create", "--format", "ips", base, small, patch] Nothing ""
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
        run <- runExternal SlapBinary ["create", "--format", "ips", base, small, patch] Nothing ""
        case externalRunExitCode run of
          ExitSuccess -> do
            ByteString.writeFile result baseBytes
            expectOk ["apply", patch, result, "--in-place", "--no-backup"]
              "truncate/apply" "applied"
            smallSha  <- pure (sha1Hex smallBytes)
            resultSha <- sha1Hex <$> ByteString.readFile result
            assertEqual "SHA1 mismatch" smallSha resultSha
          _ -> assertFailure "create failed"
  ]

customCodetableTests :: [TestTree]
customCodetableTests =
  [ testCase "custom-codetable/info" $
      withTempFile "slap-vcdiff" $ \patch -> do
        ByteString.writeFile patch vcdiffCustom
        expectOk ["info", patch] "custom-codetable/info" "custom"

  , testCase "custom-codetable/apply" $
      withTempFile "slap-vcdiff" $ \patch ->
      withTempFile "slap-source" $ \source ->
      withTempFile "slap-result" $ \result -> do
        ByteString.writeFile patch vcdiffCustom
        -- "AABBCCDD"
        ByteString.writeFile source (ByteString.pack [0x41,0x41,0x42,0x42,0x43,0x43,0x44,0x44])
        removeIfExists result
        run <- runExternal SlapBinary ["apply", patch, source, "-o", result, "--force"] Nothing ""
        case externalRunExitCode run of
          ExitSuccess -> do
            got <- ByteString.readFile result
            -- Expected: "AABBCCDDEE"
            assertEqual "wrong output"
              (ByteString.pack [0x41,0x41,0x42,0x42,0x43,0x43,0x44,0x44,0x45,0x45]) got
          _ -> assertFailure ("apply failed: " ++ externalRunStderr run)
  ]
  where
    vcdiffCustom = ByteString.pack
      [ 0xd6,0xc3,0xc4,0x00,0x02,0x16,0x05,0x02
      , 0xd6,0xc3,0xc4,0x00,0x00,0x01,0x8c,0x00,0x00,0x0a
      , 0x8c,0x00,0x00,0x00,0x03,0x01,0x13,0x8c,0x00,0x00
      , 0x01,0x08,0x00,0x0a,0x0a,0x00,0x02,0x02,0x01,0x45,0x45,0x18,0x03,0x00
      ]

pchtxtDetectTests :: [TestTree]
pchtxtDetectTests =
  [ testCase "pchtxt-detect/single-slash before directive" $ do
      let pchtxtBytes = ByteString.pack (map (fromIntegral . fromEnum)
            "/ block comment\n/ another line\n@enabled\n00000000 FF\n")
      case parseSome noDialectsRequested (PatchFileContents pchtxtBytes) of
        Left slapError -> assertFailure ("parseSome failed: " ++ renderSlapError slapError)
        Right parsed -> assertBool "expected 'PCHTXT' in format"
                     ("PCHTXT" `isInfixOf` formatLabelName (patchFormat parsed))
  ]

-- | NINJA1 source-verification CLI coverage. The first two cases just
-- exercise the create+info+apply happy path on dm4y; the last two are
-- gated to 'Full' because they each materialise a 4 MB garbage source
-- file via 'writeGarbage'.
ninja1VerifyTests :: Tier -> FilePath -> FilePath -> [TestTree]
ninja1VerifyTests tier base ips = quickCases ++ onlyAtFull tier heavyCases
  where
    quickCases =
      [ testCase "ninja1-verify/info shows source CRC" $
          withTempFile "slap-target" $ \target ->
          withTempFile "slap-patch" $ \patch -> do
            ByteString.readFile base >>= ByteString.writeFile target
            _ <- runExternal SlapBinary ["apply", ips, target, "--in-place", "--no-backup"] Nothing ""
            _ <- runExternal SlapBinary ["create", "--format", "ninja1", base, target, patch] Nothing ""
            expectOk ["info", patch] "ninja1/info" "source CRC"

      , testCase "ninja1-verify/correct source" $
          withTempFile "slap-target" $ \target ->
          withTempFile "slap-patch" $ \patch ->
          withTempFile "slap-out" $ \out -> do
            ByteString.readFile base >>= ByteString.writeFile target
            _ <- runExternal SlapBinary ["apply", ips, target, "--in-place", "--no-backup"] Nothing ""
            _ <- runExternal SlapBinary ["create", "--format", "ninja1", base, target, patch] Nothing ""
            removeIfExists out
            expectOk ["apply", patch, base, "-o", out] "ninja1/correct" "applied"
      ]

    heavyCases =
      [ testCase "ninja1-verify/wrong source rejected" $
          withTempFile "slap-target" $ \target ->
          withTempFile "slap-patch" $ \patch ->
          withTempFile "slap-wrong" $ \wrong ->
          withTempFile "slap-out" $ \out -> do
            ByteString.readFile base >>= ByteString.writeFile target
            _ <- runExternal SlapBinary ["apply", ips, target, "--in-place", "--no-backup"] Nothing ""
            _ <- runExternal SlapBinary ["create", "--format", "ninja1", base, target, patch] Nothing ""
            writeGarbage wrong (4096 * 1024)
            removeIfExists out
            expectFail ["apply", patch, wrong, "-o", out] "ninja1/wrong" "mismatch"

      , testCase "ninja1-verify/--no-verify bypasses" $
          withTempFile "slap-target" $ \target ->
          withTempFile "slap-patch" $ \patch ->
          withTempFile "slap-wrong" $ \wrong ->
          withTempFile "slap-out" $ \out -> do
            ByteString.readFile base >>= ByteString.writeFile target
            _ <- runExternal SlapBinary ["apply", ips, target, "--in-place", "--no-backup"] Nothing ""
            _ <- runExternal SlapBinary ["create", "--format", "ninja1", base, target, patch] Nothing ""
            writeGarbage wrong (4096 * 1024)
            removeIfExists out
            expectOk ["apply", patch, wrong, "-o", out, "--no-verify"]
              "ninja1/--no-verify" "applied"
      ]

descriptionTests :: FilePath -> FilePath -> [TestTree]
descriptionTests base bps =
  [ testCase "desc/aps-n64 create --description" $
      withTempFile "slap-target" $ \target ->
      withTempFile "slap-patch" $ \patch -> do
        ByteString.readFile base >>= ByteString.writeFile target
        _ <- runExternal SlapBinary ["apply", bps, target, "--in-place", "--no-backup"] Nothing ""
        expectOk ["create", "--format", "aps-n64", "--description", "Test description",
                  base, target, patch]
          "desc/aps-n64" "wrote"
        expectOk ["info", patch] "desc/aps-n64 info" "Test description"

  , testCase "desc/pchtxt create --description hex nsobid" $
      withTempFile "slap-target" $ \target ->
      withTempFile "slap-patch" $ \patch -> do
        ByteString.readFile base >>= ByteString.writeFile target
        _ <- runExternal SlapBinary ["apply", bps, target, "--in-place", "--no-backup"] Nothing ""
        let hexId = "AABBCCDD00112233445566778899AABB"
        expectOk ["create", "--format", "pchtxt", "--description", hexId,
                  base, target, patch]
          "desc/pchtxt hex" "wrote"
        patchString <- ByteString8.unpack <$> ByteString.readFile patch
        assertBool "expected @nsobid" ("@nsobid" `isInfixOf` patchString)

  , testCase "desc/pchtxt create --description comment" $
      withTempFile "slap-target" $ \target ->
      withTempFile "slap-patch" $ \patch -> do
        ByteString.readFile base >>= ByteString.writeFile target
        _ <- runExternal SlapBinary ["apply", bps, target, "--in-place", "--no-backup"] Nothing ""
        expectOk ["create", "--format", "pchtxt", "--description", "My cool patch",
                  base, target, patch]
          "desc/pchtxt comment" "wrote"
        patchString <- ByteString8.unpack <$> ByteString.readFile patch
        assertBool "expected // comment" ("// My cool patch" `isInfixOf` patchString)

  , testCase "desc/pchtxt convert --description override" $
      withTempFile "slap-target" $ \target ->
      withTempFile "slap-patch1" $ \patch1 ->
      withTempFile "slap-patch2" $ \patch2 -> do
        ByteString.readFile base >>= ByteString.writeFile target
        _ <- runExternal SlapBinary ["apply", bps, target, "--in-place", "--no-backup"] Nothing ""
        _ <- runExternal SlapBinary ["create", "--format", "pchtxt", "--description", "original",
                                     base, target, patch1] Nothing ""
        expectOk ["convert", patch1, "--to", "pchtxt", "--description", "override",
                  "-o", patch2]
          "desc/pchtxt convert" "converted"
        patchString <- ByteString8.unpack <$> ByteString.readFile patch2
        assertBool "expected override comment" ("// override" `isInfixOf` patchString)
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
        ByteString.readFile base >>= ByteString.writeFile target
        _ <- runExternal SlapBinary ["apply", bps, target, "--in-place", "--no-backup"] Nothing ""
        expectFailContains
          ["create", "--format", "ips", base, target, patch, "--title", "x"]
          ["--title", "IPS"]

  , testCase "metadata-reject/ips refuses --rom-type" $
      withTempFile "slap-target" $ \target ->
      withTempFile "slap-patch" $ \patch -> do
        ByteString.readFile base >>= ByteString.writeFile target
        _ <- runExternal SlapBinary ["apply", bps, target, "--in-place", "--no-backup"] Nothing ""
        expectFailContains
          ["create", "--format", "ips", base, target, patch, "--rom-type", "snes"]
          ["--rom-type", "IPS"]

  , testCase "metadata-reject/ips refuses --unstable" $
      withTempFile "slap-target" $ \target ->
      withTempFile "slap-patch" $ \patch -> do
        ByteString.readFile base >>= ByteString.writeFile target
        _ <- runExternal SlapBinary ["apply", bps, target, "--in-place", "--no-backup"] Nothing ""
        expectFailContains
          ["create", "--format", "ips", base, target, patch, "--unstable"]
          ["--unstable", "IPS"]

  , testCase "metadata-reject/bps refuses --rom-type" $
      withTempFile "slap-target" $ \target ->
      withTempFile "slap-patch" $ \patch -> do
        ByteString.readFile base >>= ByteString.writeFile target
        _ <- runExternal SlapBinary ["apply", bps, target, "--in-place", "--no-backup"] Nothing ""
        expectFailContains
          ["create", "--format", "bps", base, target, patch, "--rom-type", "snes"]
          ["--rom-type", "BPS"]

  , testCase "metadata-reject/dps refuses --rom-type" $
      withTempFile "slap-target" $ \target ->
      withTempFile "slap-patch" $ \patch -> do
        ByteString.readFile base >>= ByteString.writeFile target
        _ <- runExternal SlapBinary ["apply", bps, target, "--in-place", "--no-backup"] Nothing ""
        expectFailContains
          ["create", "--format", "dps", base, target, patch, "--rom-type", "snes"]
          ["--rom-type", "DPS"]

  , testCase "metadata-reject/ninja2 refuses --image-type" $
      withTempFile "slap-target" $ \target ->
      withTempFile "slap-patch" $ \patch -> do
        ByteString.readFile base >>= ByteString.writeFile target
        _ <- runExternal SlapBinary ["apply", bps, target, "--in-place", "--no-backup"] Nothing ""
        expectFailContains
          ["create", "--format", "ninja2", base, target, patch, "--image-type", "gi"]
          ["--image-type", "NINJA2"]

  , testCase "metadata-accept/dps takes --title --unstable" $
      withTempFile "slap-target" $ \target ->
      withTempFile "slap-patch" $ \patch -> do
        ByteString.readFile base >>= ByteString.writeFile target
        _ <- runExternal SlapBinary ["apply", bps, target, "--in-place", "--no-backup"] Nothing ""
        expectOk
          ["create", "--format", "dps", base, target, patch,
           "--title", "Test patch", "--unstable"]
          "metadata-accept/dps" "wrote"

  , testCase "metadata-accept/ninja2 takes title rom-type genre" $
      withTempFile "slap-target" $ \target ->
      withTempFile "slap-patch" $ \patch -> do
        ByteString.readFile base >>= ByteString.writeFile target
        _ <- runExternal SlapBinary ["apply", bps, target, "--in-place", "--no-backup"] Nothing ""
        expectOk
          ["create", "--format", "ninja2", base, target, patch,
           "--title", "T", "--rom-type", "gbc", "--genre", "RPG"]
          "metadata-accept/ninja2" "wrote"

  , testCase "metadata-accept/bps takes --metadata FILE" $
      withTempFile "slap-target" $ \target ->
      withTempFile "slap-patch" $ \patch ->
      withTempFile "slap-blob" $ \blob -> do
        ByteString.readFile base >>= ByteString.writeFile target
        _ <- runExternal SlapBinary ["apply", bps, target, "--in-place", "--no-backup"] Nothing ""
        ByteString.writeFile blob (ByteString8.pack "<blob/>")
        expectOk
          ["create", "--format", "bps", base, target, patch, "--metadata", blob]
          "metadata-accept/bps" "wrote"

  , testCase "metadata-accept/ppf3 takes --no-undo --no-verify --description" $
      withTempFile "slap-target" $ \target ->
      withTempFile "slap-patch" $ \patch -> do
        ByteString.readFile base >>= ByteString.writeFile target
        _ <- runExternal SlapBinary ["apply", bps, target, "--in-place", "--no-backup"] Nothing ""
        expectOk
          ["create", "--format", "ppf3", base, target, patch,
           "--description", "x", "--no-undo", "--no-verify"]
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
        ByteString.readFile base >>= ByteString.writeFile target
        _ <- runExternal SlapBinary ["apply", bps, target, "--in-place", "--no-backup"] Nothing ""
        _ <- runExternal SlapBinary ["create", "--format", "ebp", base, target, ebp,
                                     "--title", "Inherited", "--author", "n", "--description", "d"] Nothing ""
        expectOk ["convert", ebp, "--to", "ips", "-o", ips]
          "metadata-accept/inherit" "converted"
  ]

-- | BPS\8594BPS convert preserves embedded metadata by default
-- ('CarryIfPresent'), lets the user replace it (@--metadata FILE@), or
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
                  "--with", base, "-o", out]
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
                  "--with", base, "--metadata", newBlob, "-o", out]
          "bps-convert/override" "converted"
        extracted <- extractEmbeddedMetadata out
        assertEqual "expected CLI blob to win over source blob"
          (Just replacement) extracted

  , testCase "bps-convert/--drop-metadata discards inherited blob" $
      withSourceBps $ \sourceBps _ ->
      withTempFile "slap-out" $ \out -> do
        expectOk ["convert", sourceBps, "--to", "bps",
                  "--with", base, "--drop-metadata", "-o", out]
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

  , testCase "bps-convert/--drop-metadata is accepted when target is not BPS" $
      -- Discarding metadata is a coherent request regardless of the
      -- target format.  The drop intent suppresses any source-metadata
      -- carry; the existing metadata-dropped warning still fires
      -- because BPS\8594IPS has no metadata channel either way.
      withSourceBps $ \sourceBps _ ->
      withTempFile "slap-out" $ \out ->
        expectOk ["convert", sourceBps, "--to", "ips",
                  "--with", base, "--drop-metadata", "-o", out]
          "bps-convert/drop-cross-format" "converted"
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
        ByteString.readFile base >>= ByteString.writeFile target
        _ <- runExternal SlapBinary ["apply", bps, target, "--in-place", "--no-backup"] Nothing ""
        ByteString.writeFile blob blobBytes
        _ <- runExternal SlapBinary ["create", "--format", "bps",
                                     base, target, sourceBps, "--metadata", blob] Nothing ""
        action sourceBps blobBytes

    -- Read back the embedded metadata of a BPS by asking @slap info@
    -- to extract it.  Returns 'Nothing' when the patch carries no
    -- metadata (info reports \"no metadata in this patch\" on stderr
    -- rather than writing the file), 'Just bytes' otherwise.
    extractEmbeddedMetadata :: FilePath -> IO (Maybe ByteString.ByteString)
    extractEmbeddedMetadata patchPath =
      withTempFile "slap-meta" $ \metaPath -> do
        run <- runExternal SlapBinary
          ["info", patchPath, "--extract-metadata", metaPath] Nothing ""
        case externalRunExitCode run of
          ExitFailure _ -> assertFailure
            ("info --extract-metadata failed: "
             ++ externalRunStdout run ++ externalRunStderr run)
          ExitSuccess
            | "no metadata in this patch" `isInfixOf` externalRunStderr run -> pure Nothing
            | otherwise -> Just <$> ByteString.readFile metaPath

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
