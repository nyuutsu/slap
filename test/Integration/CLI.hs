module Integration.CLI (cliTests) where

import Integration.Helpers
  (Tier(..), onlyAtFull,
   repoDir, findSlapBinary, runSlap, sha1Hex, withTempFile, withTempDir,
   expectFail, expectOk, writeGarbage, ciContains, removeIfExists)
import Slap.Error (renderSlapError, renderSlapWarning)
import Slap.Explain (renderSummary)
import Slap.FormatLabel (formatLabelName)
import Slap.FileContents (PatchFileContents(..))
import Slap.SomePatch (SomePatch(..), parseSome)

import Control.Monad (when)
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Char8 as ByteString8
import Data.List (isInfixOf)
import System.Directory (doesFileExist, findExecutable)
import System.Exit (ExitCode(..))
import System.FilePath ((</>))
import System.Process (readProcessWithExitCode)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (testCase, assertFailure, assertBool, assertEqual)

cliTests :: Tier -> IO TestTree
cliTests tier = do
  repo <- repoDir
  maybeSlap <- findSlapBinary
  let inProcess = concat
        [ corruptTests
        , warningTests repo
        , pchtxtDetectTests
        ]
  subprocessTests <- case maybeSlap of
    Nothing -> pure []
    Just slap -> do
      let dm4yBase = repo </> "test/data/dm4y/base.gbc"
          dm4yBps  = repo </> "test/data/dm4y/patch.bps"
          dm4yIps  = repo </> "test/data/dm4y/patch.ips"
          dm4yUps  = repo </> "test/data/dm4y/patch.ups"
      baseExists <- doesFileExist dm4yBase
      let quickSubprocess = concat
            [ if baseExists then dryrunTests slap dm4yBase dm4yBps else []
            , if baseExists then inplaceTests slap dm4yBase dm4yIps else []
            , if baseExists then collisionTests slap dm4yBase dm4yIps else []
            , if baseExists then verboseTests slap dm4yBase dm4yIps else []
            , if baseExists then undoErrorTests slap dm4yBase dm4yIps dm4yBps else []
            , if baseExists then compoundTests slap dm4yBase dm4yIps dm4yBps else []
            , if baseExists then createFlagTests slap dm4yBase dm4yBps else []
            , if baseExists then archiveTests slap dm4yBase dm4yIps dm4yBps else []
            , if baseExists then ipsTruncateTests slap dm4yBase else []
            , customCodetableTests slap
            , if baseExists then ninja1VerifyTests tier slap dm4yBase dm4yIps else []
            , if baseExists then descriptionTests slap dm4yBase dm4yBps else []
            , explainModeTests slap dm4yIps
                (if baseExists then Just (dm4yBase, dm4yUps, dm4yBps) else Nothing)
            ]
          heavySubprocess = concat
            [ if baseExists then forceTests slap dm4yBase dm4yUps else []
            , if baseExists then noverifyTests slap dm4yBase dm4yBps else []
            ]
      pure (quickSubprocess ++ onlyAtFull tier heavySubprocess)
  pure $ testGroup "cli" (inProcess ++ subprocessTests)

----------------------------------------------------------------------------
-- Test groups
----------------------------------------------------------------------------

corruptTests :: [TestTree]
corruptTests =
  [ testCase "corrupt/empty file" $
      case parseSome (PatchFileContents ByteString.empty) of
        Left slapError -> assertBool "expected 'unknown'" (ciContains "unknown" (renderSlapError slapError))
        Right _ -> assertFailure "expected parse failure for empty file"

  , testCase "corrupt/random garbage" $ do
      let garbageBytes = ByteString.pack $ take 256 $ map fromIntegral $
                 iterate (\seed -> (seed * 1103515245 + 12345) `mod` 256) (42 :: Int)
      case parseSome (PatchFileContents garbageBytes) of
        Left slapError -> assertBool "expected 'unknown'" (ciContains "unknown" (renderSlapError slapError))
        Right _ -> assertFailure "expected parse failure for random garbage"

  , testCase "corrupt/info truncated IPS (graceful)" $ do
      let truncatedIPS = ByteString.pack [0x50,0x41,0x54,0x43,0x48,0x01,0x02]
      case parseSome (PatchFileContents truncatedIPS) of
        Left slapError -> assertFailure ("parseSome rejected truncated IPS: " ++ renderSlapError slapError)
        Right parsed -> assertBool "expected '0' in info" ("0" `isInfixOf` renderSummary Nothing (patchExplain parsed))

  , testCase "corrupt/info truncated BPS" $ do
      let truncatedBPS = ByteString.pack [0x42,0x50,0x53,0x31]
      case parseSome (PatchFileContents truncatedBPS) of
        Left _ -> pure ()
        Right _ -> assertFailure "expected parse failure for truncated BPS"
  ]

dryrunTests :: FilePath -> FilePath -> FilePath -> [TestTree]
dryrunTests slap base bps =
  [ testCase "dryrun/reports action" $
      expectOk slap ["apply", bps, base, "--dry-run"]
        "dryrun/reports action" "would apply"

  , testCase "dryrun/shows CRC" $
      expectOk slap ["apply", bps, base, "--dry-run"]
        "dryrun/shows CRC" "source CRC"

  , testCase "dryrun/rejects conflicting --output" $
      expectFail slap ["apply", bps, base, "-o", "/tmp/slap-unreachable", "--dry-run"]
        "dryrun/rejects conflicting --output" "usage"

  , testCase "dryrun/rejects conflicting --in-place" $
      expectFail slap ["apply", bps, base, "--in-place", "--dry-run"]
        "dryrun/rejects conflicting --in-place" "usage"
  ]

forceTests :: FilePath -> FilePath -> FilePath -> [TestTree]
forceTests slap _base ups =
  [ testCase "force/--force does not bypass CRC" $
      withTempFile "slap-wrong" $ \wrong ->
      withTempFile "slap-out" $ \out -> do
        writeGarbage wrong (4096 * 1024)
        removeIfExists out
        expectFail slap ["apply", ups, wrong, "-o", out, "--force"]
          "force/--force does not bypass CRC" "CRC mismatch"
  ]

noverifyTests :: FilePath -> FilePath -> FilePath -> [TestTree]
noverifyTests slap _base bps =
  [ testCase "noverify/BPS wrong source fails and suggests flag" $
      withTempFile "slap-wrong" $ \wrong ->
      withTempFile "slap-out" $ \out -> do
        writeGarbage wrong (4096 * 1024)
        removeIfExists out
        (exitCode, stdoutText, stderrText) <- runSlap slap ["apply", bps, wrong, "-o", out]
        let combined = stdoutText ++ stderrText
        case exitCode of
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
        expectOk slap ["apply", bps, wrong, "-o", out, "--no-verify"]
          "noverify/--no-verify bypasses CRC" "applied"
  ]

inplaceTests :: FilePath -> FilePath -> FilePath -> [TestTree]
inplaceTests slap base ips =
  [ testCase "inplace/creates .bak" $
      withTempFile "slap-work" $ \work -> do
        ByteString.readFile base >>= ByteString.writeFile work
        _ <- runSlap slap ["apply", ips, work, "--in-place"]
        let backup = work ++ ".bak"
        exists <- doesFileExist backup
        assertBool "no .bak created" exists
        removeIfExists backup

  , testCase "inplace/--no-backup skips .bak" $
      withTempFile "slap-work" $ \work -> do
        ByteString.readFile base >>= ByteString.writeFile work
        _ <- runSlap slap ["apply", ips, work, "--in-place", "--no-backup"]
        let backup = work ++ ".bak"
        exists <- doesFileExist backup
        assertBool ".bak was created" (not exists)
  ]

collisionTests :: FilePath -> FilePath -> FilePath -> [TestTree]
collisionTests slap base ips =
  [ testCase "collision/overwrite refused" $
      withTempFile "slap-out" $ \out -> do
        ByteString.writeFile out (ByteString.pack [0])  -- existing file
        expectFail slap ["apply", ips, base, "-o", out]
          "collision/overwrite refused" "already exists"

  , testCase "collision/overwrite with --force" $
      withTempFile "slap-out" $ \out -> do
        ByteString.writeFile out (ByteString.pack [0])
        expectOk slap ["apply", ips, base, "-o", out, "--force"]
          "collision/overwrite with --force" "applied"
  ]

verboseTests :: FilePath -> FilePath -> FilePath -> [TestTree]
verboseTests slap base ips =
  [ testCase "verbose/prints records" $
      withTempFile "slap-out" $ \out -> do
        removeIfExists out
        (exitCode, stdoutText, stderrText) <- runSlap slap
          ["apply", ips, base, "-o", out, "--verbose", "--force"]
        let combined = stdoutText ++ stderrText
        case exitCode of
          ExitSuccess -> assertBool "expected 'Write' in verbose output"
            ("Write" `isInfixOf` combined)
          _ -> assertFailure ("verbose failed: " ++ combined)
  ]

undoErrorTests :: FilePath -> FilePath -> FilePath -> FilePath -> [TestTree]
undoErrorTests slap base ips _bps =
  [ testCase "undo/unsupported IPS" $
      expectFail slap ["undo", ips, base] "undo/unsupported IPS" "undo not supported"
  ]

compoundTests :: FilePath -> FilePath -> FilePath -> FilePath -> [TestTree]
compoundTests slap base ips bps =
  [ testCase "compound/in-place+force+verbose+no-backup (IPS)" $
      withTempFile "slap-work" $ \work -> do
        ByteString.readFile base >>= ByteString.writeFile work
        expectOk slap ["apply", ips, work, "--in-place", "--force", "--verbose", "--no-backup"]
          "compound/IPS" "applied"

  , testCase "compound/dry-run+verbose shows both" $
      do (_, stdoutText, stderrText) <- runSlap slap
           ["apply", ips, base, "--dry-run", "--verbose"]
         let combined = stdoutText ++ stderrText
         assertBool "missing 'would apply'" ("would apply" `isInfixOf` combined)
         assertBool "missing 'Write'" ("Write" `isInfixOf` combined)

  , testCase "compound/rejects --in-place with --dry-run" $
      expectFail slap ["apply", bps, base, "--in-place", "--dry-run", "--force"]
        "compound/rejects --in-place with --dry-run" "usage"

  , testCase "compound/explicit -o creates file" $
      withTempFile "slap-out" $ \out -> do
        removeIfExists out
        expectOk slap ["apply", ips, base, "-o", out] "compound/-o" "applied"
        exists <- doesFileExist out
        assertBool "output file not created" exists
  ]

createFlagTests :: FilePath -> FilePath -> FilePath -> [TestTree]
createFlagTests slap base bps =
  [ testCase "create/ppf3+desc" $
      withTempFile "slap-target" $ \target ->
      withTempFile "slap-patch" $ \patch -> do
        ByteString.readFile base >>= ByteString.writeFile target
        _ <- runSlap slap ["apply", bps, target, "--in-place", "--no-backup"]
        expectOk slap ["create", "--format", "ppf3",
                        "-d", "test patch", base, target, patch]
          "create/ppf3" "wrote"

  , testCase "create/ppf3 undo data present by default" $
      withTempFile "slap-target" $ \target ->
      withTempFile "slap-patch" $ \patch -> do
        ByteString.readFile base >>= ByteString.writeFile target
        _ <- runSlap slap ["apply", bps, target, "--in-place", "--no-backup"]
        _ <- runSlap slap ["create", "--format", "ppf3",
                           "-d", "test patch", base, target, patch]
        expectOk slap ["info", patch] "create/ppf3 undo" "undo"
  ]

warningTests :: FilePath -> [TestTree]
warningTests repo =
  [ testCase "warnings/truncated IPS no EOF" $ do
      let truncatedIPS = ByteString.pack [0x50,0x41,0x54,0x43,0x48,0x01,0x02]
      case parseSome (PatchFileContents truncatedIPS) of
        Left slapError -> assertFailure ("parseSome failed: " ++ renderSlapError slapError)
        Right parsed -> assertBool "expected 'no EOF marker' in warnings"
                     (any (ciContains "no EOF marker" . renderSlapWarning) (patchWarnings parsed))

  , testCase "warnings/truncated IPS empty" $ do
      let truncatedIPS = ByteString.pack [0x50,0x41,0x54,0x43,0x48,0x01,0x02]
      case parseSome (PatchFileContents truncatedIPS) of
        Left slapError -> assertFailure ("parseSome failed: " ++ renderSlapError slapError)
        Right parsed -> assertBool "expected 'empty patch' in info"
                     (ciContains "empty patch" (renderSummary Nothing (patchExplain parsed)))

  , testCase "warnings/empty IPS warns empty only" $ do
      let emptyIPS = ByteString.pack [0x50,0x41,0x54,0x43,0x48,0x45,0x4F,0x46]
      case parseSome (PatchFileContents emptyIPS) of
        Left slapError -> assertFailure ("parseSome failed: " ++ renderSlapError slapError)
        Right parsed -> do
          let info = renderSummary Nothing (patchExplain parsed)
          assertBool "should warn 'empty patch'" ("empty patch" `isInfixOf` info)
          assertBool "should NOT warn 'no EOF'" (not ("no EOF" `isInfixOf` info))

  , testCase "warnings/normal IPS no warnings" $ do
      let ipsPath = repo </> "test/data/dm4y/patch.ips"
      exists <- doesFileExist ipsPath
      when exists $ do
        patchBytes <- ByteString.readFile ipsPath
        case parseSome (PatchFileContents patchBytes) of
          Left slapError -> assertFailure ("parseSome failed: " ++ renderSlapError slapError)
          Right parsed -> assertBool "unexpected warning"
                       (null (patchWarnings parsed))
  ]


archiveTests :: FilePath -> FilePath -> FilePath -> FilePath -> [TestTree]
archiveTests slap base ips bps =
  [ testCase "archive/apply ZIP-wrapped patch" $
      withTempDir "slap-arc" $ \temporaryDirectory -> do
        hasZip <- findExecutable "zip"
        hasUnzip <- findExecutable "unzip"
        case (hasZip, hasUnzip) of
          (Just _, Just _) -> do
            let zipFile = temporaryDirectory </> "patch.zip"
                result  = temporaryDirectory </> "result"
                direct  = temporaryDirectory </> "direct"
            (exitCode, _, _) <- readProcessWithExitCode "zip"
              ["-j", zipFile, ips] ""
            case exitCode of
              ExitFailure _ -> assertFailure "zip failed"
              ExitSuccess -> do
                ByteString.readFile base >>= ByteString.writeFile result
                expectOk slap ["apply", zipFile, result, "--in-place", "--no-backup"]
                  "archive/apply" "applied"
                ByteString.readFile base >>= ByteString.writeFile direct
                _ <- runSlap slap ["apply", ips, direct, "--in-place", "--no-backup"]
                zipSha    <- sha1Hex <$> ByteString.readFile result
                directSha <- sha1Hex <$> ByteString.readFile direct
                assertEqual "SHA1 mismatch" directSha zipSha
          _ -> pure ()

  , testCase "archive/info ZIP-wrapped" $
      withTempDir "slap-arc" $ \temporaryDirectory -> do
        hasZip <- findExecutable "zip"
        hasUnzip <- findExecutable "unzip"
        case (hasZip, hasUnzip) of
          (Just _, Just _) -> do
            let zipFile = temporaryDirectory </> "patch.zip"
            _ <- readProcessWithExitCode "zip" ["-j", zipFile, ips] ""
            expectOk slap ["info", zipFile] "archive/info" "IPS"
          _ -> pure ()

  , testCase "archive/explain ZIP-wrapped" $
      withTempDir "slap-arc" $ \temporaryDirectory -> do
        hasZip <- findExecutable "zip"
        hasUnzip <- findExecutable "unzip"
        case (hasZip, hasUnzip) of
          (Just _, Just _) -> do
            let zipFile = temporaryDirectory </> "patch.zip"
            _ <- readProcessWithExitCode "zip" ["-j", zipFile, ips] ""
            expectOk slap ["explain", zipFile] "archive/explain" "IPS"
          _ -> pure ()

  , testCase "archive/ZIP chaff filters readme" $
      withTempDir "slap-arc" $ \temporaryDirectory -> do
        hasZip <- findExecutable "zip"
        hasUnzip <- findExecutable "unzip"
        case (hasZip, hasUnzip) of
          (Just _, Just _) -> do
            let chaffZip = temporaryDirectory </> "chaff.zip"
                readme   = temporaryDirectory </> "readme.txt"
            ByteString.writeFile readme (ByteString.pack [0x52,0x45,0x41,0x44,0x4D,0x45])
            _ <- readProcessWithExitCode "zip" ["-j", chaffZip, ips, readme] ""
            expectOk slap ["info", chaffZip] "archive/chaff" "IPS"
          _ -> pure ()

  , testCase "archive/multi-entry ZIP fails" $
      withTempDir "slap-arc" $ \temporaryDirectory -> do
        hasZip <- findExecutable "zip"
        hasUnzip <- findExecutable "unzip"
        case (hasZip, hasUnzip) of
          (Just _, Just _) -> do
            let multiZip = temporaryDirectory </> "multi.zip"
            _ <- readProcessWithExitCode "zip" ["-j", multiZip, ips, bps] ""
            expectFail slap ["info", multiZip] "archive/multi" "candidate"
          _ -> pure ()
  ]

ipsTruncateTests :: FilePath -> FilePath -> [TestTree]
ipsTruncateTests slap base =
  [ testCase "truncate/IPS truncation in info" $
      withTempFile "slap-small" $ \small ->
      withTempFile "slap-patch" $ \patch -> do
        baseBytes <- ByteString.readFile base
        ByteString.writeFile small (ByteString.take 65536 baseBytes)
        (exitCode, _, _) <- runSlap slap ["create", "--format", "ips", base, small, patch]
        case exitCode of
          ExitSuccess -> expectOk slap ["info", patch] "truncate/info" "truncate"
          _ -> assertFailure "create failed"

  , testCase "truncate/IPS truncation apply correct" $
      withTempFile "slap-small" $ \small ->
      withTempFile "slap-patch" $ \patch ->
      withTempFile "slap-result" $ \result -> do
        baseBytes <- ByteString.readFile base
        let smallBytes = ByteString.take 65536 baseBytes
        ByteString.writeFile small smallBytes
        (exitCode, _, _) <- runSlap slap ["create", "--format", "ips", base, small, patch]
        case exitCode of
          ExitSuccess -> do
            ByteString.writeFile result baseBytes
            expectOk slap ["apply", patch, result, "--in-place", "--no-backup", "--force"]
              "truncate/apply" "applied"
            smallSha  <- pure (sha1Hex smallBytes)
            resultSha <- sha1Hex <$> ByteString.readFile result
            assertEqual "SHA1 mismatch" smallSha resultSha
          _ -> assertFailure "create failed"
  ]

customCodetableTests :: FilePath -> [TestTree]
customCodetableTests slap =
  [ testCase "custom-codetable/info" $
      withTempFile "slap-vcdiff" $ \patch -> do
        ByteString.writeFile patch vcdiffCustom
        expectOk slap ["info", patch] "custom-codetable/info" "custom"

  , testCase "custom-codetable/apply" $
      withTempFile "slap-vcdiff" $ \patch ->
      withTempFile "slap-source" $ \source ->
      withTempFile "slap-result" $ \result -> do
        ByteString.writeFile patch vcdiffCustom
        -- "AABBCCDD"
        ByteString.writeFile source (ByteString.pack [0x41,0x41,0x42,0x42,0x43,0x43,0x44,0x44])
        removeIfExists result
        (exitCode, _, stderrText) <- runSlap slap ["apply", patch, source, "-o", result, "--force"]
        case exitCode of
          ExitSuccess -> do
            got <- ByteString.readFile result
            -- Expected: "AABBCCDDEE"
            assertEqual "wrong output"
              (ByteString.pack [0x41,0x41,0x42,0x42,0x43,0x43,0x44,0x44,0x45,0x45]) got
          _ -> assertFailure ("apply failed: " ++ stderrText)
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
      case parseSome (PatchFileContents pchtxtBytes) of
        Left slapError -> assertFailure ("parseSome failed: " ++ renderSlapError slapError)
        Right parsed -> assertBool "expected 'PCHTXT' in format"
                     ("PCHTXT" `isInfixOf` formatLabelName (patchFormat parsed))
  ]

-- | NINJA1 source-verification CLI coverage. The first two cases just
-- exercise the create+info+apply happy path on dm4y; the last two are
-- gated to 'Full' because they each materialise a 4 MB garbage source
-- file via 'writeGarbage'.
ninja1VerifyTests :: Tier -> FilePath -> FilePath -> FilePath -> [TestTree]
ninja1VerifyTests tier slap base ips = quickCases ++ onlyAtFull tier heavyCases
  where
    quickCases =
      [ testCase "ninja1-verify/info shows source CRC" $
          withTempFile "slap-target" $ \target ->
          withTempFile "slap-patch" $ \patch -> do
            ByteString.readFile base >>= ByteString.writeFile target
            _ <- runSlap slap ["apply", ips, target, "--in-place", "--no-backup"]
            _ <- runSlap slap ["create", "--format", "ninja1", base, target, patch]
            expectOk slap ["info", patch] "ninja1/info" "source CRC"

      , testCase "ninja1-verify/correct source" $
          withTempFile "slap-target" $ \target ->
          withTempFile "slap-patch" $ \patch ->
          withTempFile "slap-out" $ \out -> do
            ByteString.readFile base >>= ByteString.writeFile target
            _ <- runSlap slap ["apply", ips, target, "--in-place", "--no-backup"]
            _ <- runSlap slap ["create", "--format", "ninja1", base, target, patch]
            removeIfExists out
            expectOk slap ["apply", patch, base, "-o", out] "ninja1/correct" "applied"
      ]

    heavyCases =
      [ testCase "ninja1-verify/wrong source rejected" $
          withTempFile "slap-target" $ \target ->
          withTempFile "slap-patch" $ \patch ->
          withTempFile "slap-wrong" $ \wrong ->
          withTempFile "slap-out" $ \out -> do
            ByteString.readFile base >>= ByteString.writeFile target
            _ <- runSlap slap ["apply", ips, target, "--in-place", "--no-backup"]
            _ <- runSlap slap ["create", "--format", "ninja1", base, target, patch]
            writeGarbage wrong (4096 * 1024)
            removeIfExists out
            expectFail slap ["apply", patch, wrong, "-o", out] "ninja1/wrong" "mismatch"

      , testCase "ninja1-verify/--no-verify bypasses" $
          withTempFile "slap-target" $ \target ->
          withTempFile "slap-patch" $ \patch ->
          withTempFile "slap-wrong" $ \wrong ->
          withTempFile "slap-out" $ \out -> do
            ByteString.readFile base >>= ByteString.writeFile target
            _ <- runSlap slap ["apply", ips, target, "--in-place", "--no-backup"]
            _ <- runSlap slap ["create", "--format", "ninja1", base, target, patch]
            writeGarbage wrong (4096 * 1024)
            removeIfExists out
            expectOk slap ["apply", patch, wrong, "-o", out, "--no-verify"]
              "ninja1/--no-verify" "applied"
      ]

descriptionTests :: FilePath -> FilePath -> FilePath -> [TestTree]
descriptionTests slap base bps =
  [ testCase "desc/aps-n64 create -d" $
      withTempFile "slap-target" $ \target ->
      withTempFile "slap-patch" $ \patch -> do
        ByteString.readFile base >>= ByteString.writeFile target
        _ <- runSlap slap ["apply", bps, target, "--in-place", "--no-backup"]
        expectOk slap ["create", "--format", "aps-n64", "-d", "Test description",
                        base, target, patch]
          "desc/aps-n64" "wrote"
        expectOk slap ["info", patch] "desc/aps-n64 info" "Test description"

  , testCase "desc/pchtxt create -d hex nsobid" $
      withTempFile "slap-target" $ \target ->
      withTempFile "slap-patch" $ \patch -> do
        ByteString.readFile base >>= ByteString.writeFile target
        _ <- runSlap slap ["apply", bps, target, "--in-place", "--no-backup"]
        let hexId = "AABBCCDD00112233445566778899AABB"
        expectOk slap ["create", "--format", "pchtxt", "-d", hexId,
                        base, target, patch]
          "desc/pchtxt hex" "wrote"
        patchString <- ByteString8.unpack <$> ByteString.readFile patch
        assertBool "expected @nsobid" ("@nsobid" `isInfixOf` patchString)

  , testCase "desc/pchtxt create -d comment" $
      withTempFile "slap-target" $ \target ->
      withTempFile "slap-patch" $ \patch -> do
        ByteString.readFile base >>= ByteString.writeFile target
        _ <- runSlap slap ["apply", bps, target, "--in-place", "--no-backup"]
        expectOk slap ["create", "--format", "pchtxt", "-d", "My cool patch",
                        base, target, patch]
          "desc/pchtxt comment" "wrote"
        patchString <- ByteString8.unpack <$> ByteString.readFile patch
        assertBool "expected // comment" ("// My cool patch" `isInfixOf` patchString)

  , testCase "desc/pchtxt convert -d override" $
      withTempFile "slap-target" $ \target ->
      withTempFile "slap-patch1" $ \patch1 ->
      withTempFile "slap-patch2" $ \patch2 -> do
        ByteString.readFile base >>= ByteString.writeFile target
        _ <- runSlap slap ["apply", bps, target, "--in-place", "--no-backup"]
        _ <- runSlap slap ["create", "--format", "pchtxt", "-d", "original",
                           base, target, patch1]
        expectOk slap ["convert", patch1, "--to", "pchtxt", "-d", "override",
                        "-o", patch2]
          "desc/pchtxt convert" "converted"
        patchString <- ByteString8.unpack <$> ByteString.readFile patch2
        assertBool "expected override comment" ("// override" `isInfixOf` patchString)
  ]

explainModeTests :: FilePath -> FilePath -> Maybe (FilePath, FilePath, FilePath) -> [TestTree]
explainModeTests slap ips maybeSourceFiles =
  [ testCase "explain/default is summary" $ do
      (exitCode, stdoutText, stderrText) <- runSlap slap ["explain", ips]
      let combined = stdoutText ++ stderrText
      case exitCode of
        ExitSuccess -> do
          assertBool "expected 'records:' in summary"
            ("records:" `isInfixOf` combined)
          assertBool "expected 'range:' in summary"
            ("range:" `isInfixOf` combined)
        ExitFailure _ ->
          assertFailure ("explain failed: " ++ combined)

  , testCase "explain/--records is dump" $ do
      (exitCode, stdoutText, stderrText) <- runSlap slap ["explain", "--records", ips]
      let combined = stdoutText ++ stderrText
      case exitCode of
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
        (exitCode, stdoutText, _) <- runSlap slap ["explain", filePath]
        case exitCode of
          ExitSuccess ->
            assertBool "expected 'records:' even for empty"
              ("records:" `isInfixOf` stdoutText)
          ExitFailure _ ->
            assertFailure "explain of empty IPS failed"
  ] ++ case maybeSourceFiles of
    Nothing -> []
    Just (base, ups, bps) ->
      [ testCase "explain/--with resolves XOR" $ do
          (exitCode, stdoutText, stderrText) <- runSlap slap
            ["explain", "--records", "--with", base, ups]
          let combined = stdoutText ++ stderrText
          case exitCode of
            ExitSuccess ->
              assertBool "expected 'resolved:' in output"
                ("resolved:" `isInfixOf` combined)
            ExitFailure _ ->
              assertFailure ("explain --with UPS failed: " ++ combined)

      , testCase "explain/--with resolves copy" $ do
          (exitCode, stdoutText, stderrText) <- runSlap slap
            ["explain", "--records", "--with", base, bps]
          let combined = stdoutText ++ stderrText
          case exitCode of
            ExitSuccess ->
              assertBool "expected 'source data:' in output"
                ("source data:" `isInfixOf` combined)
            ExitFailure _ ->
              assertFailure ("explain --with BPS failed: " ++ combined)

      , testCase "explain/--with summary note" $ do
          (exitCode, stdoutText, stderrText) <- runSlap slap
            ["explain", "--with", base, bps]
          let combined = stdoutText ++ stderrText
          case exitCode of
            ExitSuccess ->
              assertBool "expected 'source file provided' in output"
                ("source file provided" `isInfixOf` combined)
            ExitFailure _ ->
              assertFailure ("explain --with summary failed: " ++ combined)

      , testCase "explain/--with direct format unchanged" $ do
          (exitCode, stdoutText, stderrText) <- runSlap slap
            ["explain", "--records", "--with", base, ips]
          let combined = stdoutText ++ stderrText
          case exitCode of
            ExitSuccess -> do
              assertBool "unexpected 'resolved:' for direct format"
                (not ("resolved:" `isInfixOf` combined))
              assertBool "unexpected 'source data:' for direct format"
                (not ("source data:" `isInfixOf` combined))
            ExitFailure _ ->
              assertFailure ("explain --with IPS failed: " ++ combined)
      ]
