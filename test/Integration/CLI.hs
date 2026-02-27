module Integration.CLI (cliTests) where

import Integration.Helpers
  (repoDir, findSlapBinary, runSlap, sha256Hex, withTempFile, withTempDir, RomCache,
   expectFail, expectOk, writeGarbage, ciContains, removeIfExists)
import Patch.SomePatch (SomePatch(..), parseSome)

import Control.Monad (when)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BS8
import Data.List (isInfixOf)
import System.Directory (doesFileExist, findExecutable)
import System.Exit (ExitCode(..))
import System.FilePath ((</>))
import System.Process (readProcessWithExitCode)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (testCase, assertFailure, assertBool, assertEqual)

cliTests :: RomCache -> IO TestTree
cliTests _romCache = do
  repo <- repoDir
  mSlap <- findSlapBinary
  let inProcess = concat
        [ corruptTests
        , warningTests repo
        , pchtxtDetectTests
        ]
  subprocessTests <- case mSlap of
    Nothing -> pure []
    Just slap -> do
      let dm4kBase = repo </> "test/data/dm4k/base.gbc"
          dm4kBps  = repo </> "test/data/dm4k/patch.bps"
          dm4kIps  = repo </> "test/data/dm4k/patch.ips"
          dm4kUps  = repo </> "test/data/dm4k/patch.ups"
      baseExists <- doesFileExist dm4kBase
      pure $ concat
        [ if baseExists then dryrunTests slap dm4kBase dm4kBps else []
        , if baseExists then forceTests slap dm4kBase dm4kUps else []
        , if baseExists then noverifyTests slap dm4kBase dm4kBps else []
        , if baseExists then inplaceTests slap dm4kBase dm4kIps else []
        , if baseExists then collisionTests slap dm4kBase dm4kIps else []
        , if baseExists then verboseTests slap dm4kBase dm4kIps else []
        , if baseExists then undoErrorTests slap dm4kBase dm4kIps dm4kBps else []
        , if baseExists then compoundTests slap dm4kBase dm4kIps dm4kBps else []
        , if baseExists then createFlagTests slap dm4kBase dm4kBps else []
        , if baseExists then aliasTests slap dm4kBase dm4kIps dm4kBps else []
        , if baseExists then archiveTests slap dm4kBase dm4kIps dm4kBps else []
        , if baseExists then ipsTruncateTests slap dm4kBase else []
        , customCodetableTests slap
        , if baseExists then ninja1VerifyTests slap dm4kBase dm4kIps else []
        , if baseExists then descriptionTests slap dm4kBase dm4kBps else []
        , explainModeTests slap dm4kIps
            (if baseExists then Just (dm4kBase, dm4kUps, dm4kBps) else Nothing)
        ]
  pure $ testGroup "cli" (inProcess ++ subprocessTests)

----------------------------------------------------------------------------
-- Test groups
----------------------------------------------------------------------------

corruptTests :: [TestTree]
corruptTests =
  [ testCase "corrupt/empty file" $
      case parseSome BS.empty of
        Left err -> assertBool "expected 'unknown'" (ciContains "unknown" err)
        Right _ -> assertFailure "expected parse failure for empty file"

  , testCase "corrupt/random garbage" $ do
      let bs = BS.pack $ take 256 $ map fromIntegral $
                 iterate (\x -> (x * 1103515245 + 12345) `mod` 256) (42 :: Int)
      case parseSome bs of
        Left err -> assertBool "expected 'unknown'" (ciContains "unknown" err)
        Right _ -> assertFailure "expected parse failure for random garbage"

  , testCase "corrupt/info truncated IPS (graceful)" $ do
      let bs = BS.pack [0x50,0x41,0x54,0x43,0x48,0x01,0x02]
      case parseSome bs of
        Left err -> assertFailure ("parseSome rejected truncated IPS: " ++ err)
        Right sp -> assertBool "expected '0' in info" ("0" `isInfixOf` spInfo sp)

  , testCase "corrupt/info truncated BPS" $ do
      let bs = BS.pack [0x42,0x50,0x53,0x31]
      case parseSome bs of
        Left _ -> pure ()
        Right _ -> assertFailure "expected parse failure for truncated BPS"
  ]

dryrunTests :: FilePath -> FilePath -> FilePath -> [TestTree]
dryrunTests slap base bps =
  [ testCase "dryrun/reports action" $
      withTempFile "slap-out" $ \out -> do
        removeIfExists out
        expectOk slap ["apply", bps, base, "-o", out, "--dry-run"]
          "dryrun/reports action" "would apply"

  , testCase "dryrun/no output file" $
      withTempFile "slap-out" $ \out -> do
        removeIfExists out
        _ <- runSlap slap ["apply", bps, base, "-o", out, "--dry-run"]
        exists <- doesFileExist out
        assertBool "output file should not be created" (not exists)

  , testCase "dryrun/shows CRC" $
      expectOk slap ["apply", bps, base, "--dry-run"]
        "dryrun/shows CRC" "source CRC"

  , testCase "dryrun/in-place leaves source untouched" $
      withTempFile "slap-work" $ \work -> do
        BS.readFile base >>= BS.writeFile work
        beforeSha <- sha256Hex <$> BS.readFile work
        _ <- runSlap slap ["apply", bps, work, "--in-place", "--no-backup", "--dry-run"]
        afterSha <- sha256Hex <$> BS.readFile work
        assertEqual "source modified" beforeSha afterSha
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
        (ec, sout, serr) <- runSlap slap ["apply", bps, wrong, "-o", out]
        let combined = sout ++ serr
        case ec of
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
        BS.readFile base >>= BS.writeFile work
        _ <- runSlap slap ["apply", ips, work, "--in-place"]
        let bak = work ++ ".bak"
        exists <- doesFileExist bak
        assertBool "no .bak created" exists
        removeIfExists bak

  , testCase "inplace/--no-backup skips .bak" $
      withTempFile "slap-work" $ \work -> do
        BS.readFile base >>= BS.writeFile work
        _ <- runSlap slap ["apply", ips, work, "--in-place", "--no-backup"]
        let bak = work ++ ".bak"
        exists <- doesFileExist bak
        assertBool ".bak was created" (not exists)
  ]

collisionTests :: FilePath -> FilePath -> FilePath -> [TestTree]
collisionTests slap base ips =
  [ testCase "collision/overwrite refused" $
      withTempFile "slap-out" $ \out -> do
        BS.writeFile out (BS.pack [0])  -- existing file
        expectFail slap ["apply", ips, base, "-o", out]
          "collision/overwrite refused" "already exists"

  , testCase "collision/overwrite with --force" $
      withTempFile "slap-out" $ \out -> do
        BS.writeFile out (BS.pack [0])
        expectOk slap ["apply", ips, base, "-o", out, "--force"]
          "collision/overwrite with --force" "applied"
  ]

verboseTests :: FilePath -> FilePath -> FilePath -> [TestTree]
verboseTests slap base ips =
  [ testCase "verbose/prints records" $
      withTempFile "slap-out" $ \out -> do
        removeIfExists out
        (ec, sout, serr) <- runSlap slap
          ["apply", ips, base, "-o", out, "--verbose", "--force"]
        let combined = sout ++ serr
        case ec of
          ExitSuccess -> assertBool "expected [1/ in output"
            ("[1/" `isInfixOf` combined)
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
        BS.readFile base >>= BS.writeFile work
        expectOk slap ["apply", ips, work, "--in-place", "--force", "--verbose", "--no-backup"]
          "compound/IPS" "applied"

  , testCase "compound/dry-run+verbose shows both" $
      do (_, sout, serr) <- runSlap slap
           ["apply", ips, base, "--dry-run", "--verbose"]
         let combined = sout ++ serr
         assertBool "missing 'would apply'" ("would apply" `isInfixOf` combined)
         assertBool "missing [1/" ("[1/" `isInfixOf` combined)

  , testCase "compound/dry-run+force doesn't modify" $
      withTempFile "slap-work" $ \work -> do
        BS.readFile base >>= BS.writeFile work
        beforeSha <- sha256Hex <$> BS.readFile work
        _ <- runSlap slap ["apply", bps, work, "--in-place", "--dry-run", "--force"]
        afterSha <- sha256Hex <$> BS.readFile work
        assertEqual "source modified" beforeSha afterSha

  , testCase "compound/explicit -o creates file" $
      withTempFile "slap-out" $ \out -> do
        removeIfExists out
        expectOk slap ["apply", ips, base, "-o", out] "compound/-o" "applied"
        exists <- doesFileExist out
        assertBool "output file not created" exists
  ]

createFlagTests :: FilePath -> FilePath -> FilePath -> [TestTree]
createFlagTests slap base bps =
  [ testCase "create/ppf3+undo+validate+desc" $
      withTempFile "slap-target" $ \target ->
      withTempFile "slap-patch" $ \patch -> do
        BS.readFile base >>= BS.writeFile target
        _ <- runSlap slap ["apply", bps, target, "--in-place", "--no-backup"]
        expectOk slap ["create", "--format", "ppf3", "--undo", "--validate",
                        "-d", "test patch", base, target, patch]
          "create/ppf3" "wrote"

  , testCase "create/ppf3 undo data present" $
      withTempFile "slap-target" $ \target ->
      withTempFile "slap-patch" $ \patch -> do
        BS.readFile base >>= BS.writeFile target
        _ <- runSlap slap ["apply", bps, target, "--in-place", "--no-backup"]
        _ <- runSlap slap ["create", "--format", "ppf3", "--undo", "--validate",
                           "-d", "test patch", base, target, patch]
        expectOk slap ["info", patch] "create/ppf3 undo" "undo"
  ]

aliasTests :: FilePath -> FilePath -> FilePath -> FilePath -> [TestTree]
aliasTests slap base ips bps =
  [ testCase "aliases/--yolo overwrites" $
      withTempFile "slap-out" $ \out -> do
        BS.writeFile out (BS.pack [0])
        expectOk slap ["apply", ips, base, "-o", out, "--yolo"]
          "aliases/--yolo overwrites" "applied"

  , testCase "aliases/--yolo bypasses CRC" $
      withTempFile "slap-wrong" $ \wrong ->
      withTempFile "slap-out" $ \out -> do
        writeGarbage wrong (4096 * 1024)
        removeIfExists out
        expectOk slap ["apply", bps, wrong, "-o", out, "--yolo"]
          "aliases/--yolo bypasses CRC" "applied"

  ]

warningTests :: FilePath -> [TestTree]
warningTests repo =
  [ testCase "warnings/truncated IPS no EOF" $ do
      let bs = BS.pack [0x50,0x41,0x54,0x43,0x48,0x01,0x02]
      case parseSome bs of
        Left err -> assertFailure ("parseSome failed: " ++ err)
        Right sp -> assertBool "expected 'no EOF marker' in warnings"
                     (any (ciContains "no EOF marker") (spWarnings sp))

  , testCase "warnings/truncated IPS empty" $ do
      let bs = BS.pack [0x50,0x41,0x54,0x43,0x48,0x01,0x02]
      case parseSome bs of
        Left err -> assertFailure ("parseSome failed: " ++ err)
        Right sp -> assertBool "expected 'empty patch' in info"
                     (ciContains "empty patch" (spInfo sp))

  , testCase "warnings/empty IPS warns empty only" $ do
      let bs = BS.pack [0x50,0x41,0x54,0x43,0x48,0x45,0x4F,0x46]
      case parseSome bs of
        Left err -> assertFailure ("parseSome failed: " ++ err)
        Right sp -> do
          let info = spInfo sp
          assertBool "should warn 'empty patch'" ("empty patch" `isInfixOf` info)
          assertBool "should NOT warn 'no EOF'" (not ("no EOF" `isInfixOf` info))

  , testCase "warnings/normal IPS no warnings" $ do
      let ipsPath = repo </> "test/data/dm4k/patch.ips"
      exists <- doesFileExist ipsPath
      when exists $ do
        bs <- BS.readFile ipsPath
        case parseSome bs of
          Left err -> assertFailure ("parseSome failed: " ++ err)
          Right sp -> assertBool "unexpected warning"
                       (not ("warning" `isInfixOf` spInfo sp))
  ]


archiveTests :: FilePath -> FilePath -> FilePath -> FilePath -> [TestTree]
archiveTests slap base ips bps =
  [ testCase "archive/apply ZIP-wrapped patch" $
      withTempDir "slap-arc" $ \tmpDir -> do
        hasZip <- findExecutable "zip"
        hasUnzip <- findExecutable "unzip"
        case (hasZip, hasUnzip) of
          (Just _, Just _) -> do
            let zipFile = tmpDir </> "patch.zip"
                result  = tmpDir </> "result"
                direct  = tmpDir </> "direct"
            (ec, _, _) <- readProcessWithExitCode "zip"
              ["-j", zipFile, ips] ""
            case ec of
              ExitFailure _ -> assertFailure "zip failed"
              ExitSuccess -> do
                BS.readFile base >>= BS.writeFile result
                expectOk slap ["apply", zipFile, result, "--in-place", "--no-backup"]
                  "archive/apply" "applied"
                BS.readFile base >>= BS.writeFile direct
                _ <- runSlap slap ["apply", ips, direct, "--in-place", "--no-backup"]
                zipSha    <- sha256Hex <$> BS.readFile result
                directSha <- sha256Hex <$> BS.readFile direct
                assertEqual "SHA256 mismatch" directSha zipSha
          _ -> pure ()

  , testCase "archive/info ZIP-wrapped" $
      withTempDir "slap-arc" $ \tmpDir -> do
        hasZip <- findExecutable "zip"
        hasUnzip <- findExecutable "unzip"
        case (hasZip, hasUnzip) of
          (Just _, Just _) -> do
            let zipFile = tmpDir </> "patch.zip"
            _ <- readProcessWithExitCode "zip" ["-j", zipFile, ips] ""
            expectOk slap ["info", zipFile] "archive/info" "IPS"
          _ -> pure ()

  , testCase "archive/explain ZIP-wrapped" $
      withTempDir "slap-arc" $ \tmpDir -> do
        hasZip <- findExecutable "zip"
        hasUnzip <- findExecutable "unzip"
        case (hasZip, hasUnzip) of
          (Just _, Just _) -> do
            let zipFile = tmpDir </> "patch.zip"
            _ <- readProcessWithExitCode "zip" ["-j", zipFile, ips] ""
            expectOk slap ["explain", zipFile] "archive/explain" "IPS"
          _ -> pure ()

  , testCase "archive/ZIP chaff filters readme" $
      withTempDir "slap-arc" $ \tmpDir -> do
        hasZip <- findExecutable "zip"
        hasUnzip <- findExecutable "unzip"
        case (hasZip, hasUnzip) of
          (Just _, Just _) -> do
            let chaffZip = tmpDir </> "chaff.zip"
                readme   = tmpDir </> "readme.txt"
            BS.writeFile readme (BS.pack [0x52,0x45,0x41,0x44,0x4D,0x45])
            _ <- readProcessWithExitCode "zip" ["-j", chaffZip, ips, readme] ""
            expectOk slap ["info", chaffZip] "archive/chaff" "IPS"
          _ -> pure ()

  , testCase "archive/multi-entry ZIP fails" $
      withTempDir "slap-arc" $ \tmpDir -> do
        hasZip <- findExecutable "zip"
        hasUnzip <- findExecutable "unzip"
        case (hasZip, hasUnzip) of
          (Just _, Just _) -> do
            let multiZip = tmpDir </> "multi.zip"
            _ <- readProcessWithExitCode "zip" ["-j", multiZip, ips, bps] ""
            expectFail slap ["info", multiZip] "archive/multi" "candidate"
          _ -> pure ()
  ]

ipsTruncateTests :: FilePath -> FilePath -> [TestTree]
ipsTruncateTests slap base =
  [ testCase "truncate/IPS truncation in info" $
      withTempFile "slap-small" $ \small ->
      withTempFile "slap-patch" $ \patch -> do
        baseBs <- BS.readFile base
        BS.writeFile small (BS.take 65536 baseBs)
        (ec, _, _) <- runSlap slap ["create", "--format", "ips", base, small, patch]
        case ec of
          ExitSuccess -> expectOk slap ["info", patch] "truncate/info" "truncate"
          _ -> assertFailure "create failed"

  , testCase "truncate/IPS truncation apply correct" $
      withTempFile "slap-small" $ \small ->
      withTempFile "slap-patch" $ \patch ->
      withTempFile "slap-result" $ \result -> do
        baseBs <- BS.readFile base
        let smallBs = BS.take 65536 baseBs
        BS.writeFile small smallBs
        (ec, _, _) <- runSlap slap ["create", "--format", "ips", base, small, patch]
        case ec of
          ExitSuccess -> do
            BS.writeFile result baseBs
            expectOk slap ["apply", patch, result, "--in-place", "--no-backup", "--force"]
              "truncate/apply" "applied"
            smallSha  <- pure (sha256Hex smallBs)
            resultSha <- sha256Hex <$> BS.readFile result
            assertEqual "SHA256 mismatch" smallSha resultSha
          _ -> assertFailure "create failed"
  ]

customCodetableTests :: FilePath -> [TestTree]
customCodetableTests slap =
  [ testCase "custom-codetable/info" $
      withTempFile "slap-vcdiff" $ \patch -> do
        BS.writeFile patch vcdiffCustom
        expectOk slap ["info", patch] "custom-codetable/info" "custom"

  , testCase "custom-codetable/apply" $
      withTempFile "slap-vcdiff" $ \patch ->
      withTempFile "slap-source" $ \source ->
      withTempFile "slap-result" $ \result -> do
        BS.writeFile patch vcdiffCustom
        -- "AABBCCDD"
        BS.writeFile source (BS.pack [0x41,0x41,0x42,0x42,0x43,0x43,0x44,0x44])
        removeIfExists result
        (ec, _, serr) <- runSlap slap ["apply", patch, source, "-o", result, "--force"]
        case ec of
          ExitSuccess -> do
            got <- BS.readFile result
            -- Expected: "AABBCCDDEE"
            assertEqual "wrong output"
              (BS.pack [0x41,0x41,0x42,0x42,0x43,0x43,0x44,0x44,0x45,0x45]) got
          _ -> assertFailure ("apply failed: " ++ serr)
  ]
  where
    vcdiffCustom = BS.pack
      [ 0xd6,0xc3,0xc4,0x00,0x02,0x16,0x05,0x02
      , 0xd6,0xc3,0xc4,0x00,0x00,0x01,0x8c,0x00,0x00,0x0a
      , 0x8c,0x00,0x00,0x00,0x03,0x01,0x13,0x8c,0x00,0x00
      , 0x01,0x08,0x00,0x0a,0x0a,0x00,0x02,0x02,0x01,0x45,0x45,0x18,0x03,0x00
      ]

pchtxtDetectTests :: [TestTree]
pchtxtDetectTests =
  [ testCase "pchtxt-detect/single-slash before directive" $ do
      let bs = BS.pack (map (fromIntegral . fromEnum)
            "/ block comment\n/ another line\n@enabled\n00000000 FF\n")
      case parseSome bs of
        Left err -> assertFailure ("parseSome failed: " ++ err)
        Right sp -> assertBool "expected 'PCHTXT' in format"
                     ("PCHTXT" `isInfixOf` spFormat sp)
  ]

ninja1VerifyTests :: FilePath -> FilePath -> FilePath -> [TestTree]
ninja1VerifyTests slap base ips =
  [ testCase "ninja1-verify/info shows source CRC" $
      withTempFile "slap-target" $ \target ->
      withTempFile "slap-patch" $ \patch -> do
        BS.readFile base >>= BS.writeFile target
        _ <- runSlap slap ["apply", ips, target, "--in-place", "--no-backup"]
        _ <- runSlap slap ["create", "--format", "ninja1", base, target, patch]
        expectOk slap ["info", patch] "ninja1/info" "source CRC"

  , testCase "ninja1-verify/correct source" $
      withTempFile "slap-target" $ \target ->
      withTempFile "slap-patch" $ \patch ->
      withTempFile "slap-out" $ \out -> do
        BS.readFile base >>= BS.writeFile target
        _ <- runSlap slap ["apply", ips, target, "--in-place", "--no-backup"]
        _ <- runSlap slap ["create", "--format", "ninja1", base, target, patch]
        removeIfExists out
        expectOk slap ["apply", patch, base, "-o", out] "ninja1/correct" "applied"

  , testCase "ninja1-verify/wrong source rejected" $
      withTempFile "slap-target" $ \target ->
      withTempFile "slap-patch" $ \patch ->
      withTempFile "slap-wrong" $ \wrong ->
      withTempFile "slap-out" $ \out -> do
        BS.readFile base >>= BS.writeFile target
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
        BS.readFile base >>= BS.writeFile target
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
        BS.readFile base >>= BS.writeFile target
        _ <- runSlap slap ["apply", bps, target, "--in-place", "--no-backup"]
        expectOk slap ["create", "--format", "aps-n64", "-d", "Test description",
                        base, target, patch]
          "desc/aps-n64" "wrote"
        expectOk slap ["info", patch] "desc/aps-n64 info" "Test description"

  , testCase "desc/pchtxt create -d hex nsobid" $
      withTempFile "slap-target" $ \target ->
      withTempFile "slap-patch" $ \patch -> do
        BS.readFile base >>= BS.writeFile target
        _ <- runSlap slap ["apply", bps, target, "--in-place", "--no-backup"]
        let hexId = "AABBCCDD00112233445566778899AABB"
        expectOk slap ["create", "--format", "pchtxt", "-d", hexId,
                        base, target, patch]
          "desc/pchtxt hex" "wrote"
        patchStr <- BS8.unpack <$> BS.readFile patch
        assertBool "expected @nsobid" ("@nsobid" `isInfixOf` patchStr)

  , testCase "desc/pchtxt create -d comment" $
      withTempFile "slap-target" $ \target ->
      withTempFile "slap-patch" $ \patch -> do
        BS.readFile base >>= BS.writeFile target
        _ <- runSlap slap ["apply", bps, target, "--in-place", "--no-backup"]
        expectOk slap ["create", "--format", "pchtxt", "-d", "My cool patch",
                        base, target, patch]
          "desc/pchtxt comment" "wrote"
        patchStr <- BS8.unpack <$> BS.readFile patch
        assertBool "expected // comment" ("// My cool patch" `isInfixOf` patchStr)

  , testCase "desc/pchtxt convert -d override" $
      withTempFile "slap-target" $ \target ->
      withTempFile "slap-patch1" $ \patch1 ->
      withTempFile "slap-patch2" $ \patch2 -> do
        BS.readFile base >>= BS.writeFile target
        _ <- runSlap slap ["apply", bps, target, "--in-place", "--no-backup"]
        _ <- runSlap slap ["create", "--format", "pchtxt", "-d", "original",
                           base, target, patch1]
        expectOk slap ["convert", patch1, "--to", "pchtxt", "-d", "override",
                        "-o", patch2]
          "desc/pchtxt convert" "converted"
        patchStr <- BS8.unpack <$> BS.readFile patch2
        assertBool "expected override comment" ("// override" `isInfixOf` patchStr)
  ]

explainModeTests :: FilePath -> FilePath -> Maybe (FilePath, FilePath, FilePath) -> [TestTree]
explainModeTests slap ips mSourceFiles =
  [ testCase "explain/default is summary" $ do
      (ec, sout, serr) <- runSlap slap ["explain", ips]
      let combined = sout ++ serr
      case ec of
        ExitSuccess -> do
          assertBool "expected 'records:' in summary"
            ("records:" `isInfixOf` combined)
          assertBool "expected 'range:' in summary"
            ("range:" `isInfixOf` combined)
        ExitFailure _ ->
          assertFailure ("explain failed: " ++ combined)

  , testCase "explain/--records is dump" $ do
      (ec, sout, serr) <- runSlap slap ["explain", "--records", ips]
      let combined = sout ++ serr
      case ec of
        ExitSuccess ->
          -- record dump has numbered entries like "   1  Write"
          assertBool "expected numbered record in dump"
            ("Write" `isInfixOf` combined)
        ExitFailure _ ->
          assertFailure ("explain --records failed: " ++ combined)

  , testCase "explain/empty patch summary" $
      withTempFile "slap-ips" $ \fp -> do
        -- "PATCHEOF" — valid IPS with 0 records
        BS.writeFile fp (BS.pack [0x50,0x41,0x54,0x43,0x48,0x45,0x4F,0x46])
        (ec, sout, _) <- runSlap slap ["explain", fp]
        case ec of
          ExitSuccess ->
            assertBool "expected 'records:' even for empty"
              ("records:" `isInfixOf` sout)
          ExitFailure _ ->
            assertFailure "explain of empty IPS failed"
  ] ++ case mSourceFiles of
    Nothing -> []
    Just (base, ups, bps) ->
      [ testCase "explain/--with resolves XOR" $ do
          (ec, sout, serr) <- runSlap slap
            ["explain", "--records", "--with", base, ups]
          let combined = sout ++ serr
          case ec of
            ExitSuccess ->
              assertBool "expected 'resolved:' in output"
                ("resolved:" `isInfixOf` combined)
            ExitFailure _ ->
              assertFailure ("explain --with UPS failed: " ++ combined)

      , testCase "explain/--with resolves copy" $ do
          (ec, sout, serr) <- runSlap slap
            ["explain", "--records", "--with", base, bps]
          let combined = sout ++ serr
          case ec of
            ExitSuccess ->
              assertBool "expected 'source data:' in output"
                ("source data:" `isInfixOf` combined)
            ExitFailure _ ->
              assertFailure ("explain --with BPS failed: " ++ combined)

      , testCase "explain/--with summary note" $ do
          (ec, sout, serr) <- runSlap slap
            ["explain", "--with", base, bps]
          let combined = sout ++ serr
          case ec of
            ExitSuccess ->
              assertBool "expected 'source file provided' in output"
                ("source file provided" `isInfixOf` combined)
            ExitFailure _ ->
              assertFailure ("explain --with summary failed: " ++ combined)

      , testCase "explain/--with direct format unchanged" $ do
          (ec, sout, serr) <- runSlap slap
            ["explain", "--records", "--with", base, ips]
          let combined = sout ++ serr
          case ec of
            ExitSuccess -> do
              assertBool "unexpected 'resolved:' for direct format"
                (not ("resolved:" `isInfixOf` combined))
              assertBool "unexpected 'source data:' for direct format"
                (not ("source data:" `isInfixOf` combined))
            ExitFailure _ ->
              assertFailure ("explain --with IPS failed: " ++ combined)
      ]
