module Integration.FailureMode (failureModeTests) where

import Integration.Helpers
  (repoDir, findSlapBinary, runSlap, sha1Hex, applyPatch,
   withTempFile, RomCache, cachedReadFile, parseCreateFormat,
   expectFail, expectOkWithWarning, writeGarbage, ciContains, removeIfExists)
import Slap.SomePatch (parseSome)
import Slap.Convert (CreateFormat, createFromMemory, defaultMeta)

import Data.Bits (xor)
import qualified Data.ByteString as ByteString
import System.Directory (doesFileExist)
import System.Exit (ExitCode(..))
import System.FilePath ((</>))
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (testCase, assertFailure, assertBool, assertEqual)

failureModeTests :: RomCache -> IO TestTree
failureModeTests romCache = do
  repo <- repoDir
  maybeSlap <- findSlapBinary
  let dm4yBase  = repo </> "test/data/dm4y/base.gbc"
      dm4yBps   = repo </> "test/data/dm4y/patch.bps"
      dm4yUps   = repo </> "test/data/dm4y/patch.ups"
      dm4yRup   = repo </> "test/data/dm4y/patch.rup"
      dm4yXdelta1   = repo </> "test/data/dm4y/patch.xdelta1"
      dm4yVcdiff = repo </> "test/data/dm4y/patch.vcdiff"
      fftaBase  = repo </> "test/data/ffta/base.gba"
      fftaAps   = repo </> "test/data/ffta/ffta-x.aps"
      stadium2Base = repo </> "test/data/stadium2/base.z64"
  dm4yExists   <- doesFileExist dm4yBase
  fftaExists   <- doesFileExist fftaBase
  stadium2Exists <- doesFileExist stadium2Base
  tests <- case maybeSlap of
    Nothing -> pure []
    Just slap -> pure $ concat
      [ if dm4yExists then wrongSourceTests slap dm4yBase
          dm4yBps dm4yUps dm4yRup dm4yXdelta1 dm4yVcdiff else []
      , if dm4yExists && fftaExists then wrongSourceApsGbaTests slap fftaBase fftaAps else []
      , if dm4yExists then corruptPatchCRCTests dm4yBps dm4yUps else []
      , if dm4yExists then wrongSizeSourceTests slap dm4yBase dm4yBps else []
      ]
  let inProcessTests = concat
        [ if dm4yExists then crossFormatRoundTripTests romCache dm4yBase dm4yBps else []
        , if dm4yExists && stadium2Exists
          then createRoundTripTests romCache
                 dm4yBase dm4yBps
                 stadium2Base (repo </> "test/data/stadium2/heavy-diff/patch.bps")
          else []
        ]
  pure $ testGroup "failure-mode" (tests ++ inProcessTests)

----------------------------------------------------------------------------
-- 1. Wrong source ROM (critical)
----------------------------------------------------------------------------

-- | For each format with source verification, apply to the wrong ROM.
-- Without --no-verify: fails with verification error.
-- With --no-verify: succeeds with a warning (test checks exit code,
-- output pattern, and that "warning" appears in the output).
wrongSourceTests :: FilePath -> FilePath -> FilePath -> FilePath
                 -> FilePath -> FilePath -> FilePath -> [TestTree]
wrongSourceTests slap base bps ups rup xdelta1 vcdiff =
  -- BPS: CRC32 source verification
  [ testCase "wrong-source/BPS rejects" $
      withTempFile "slap-wrong" $ \wrong ->
      withTempFile "slap-out" $ \out -> do
        writeGarbage wrong (4 * 1024 * 1024)  -- same size as dm4y
        removeIfExists out
        expectFail slap ["apply", bps, wrong, "-o", out]
          "wrong-source/BPS" "mismatch"

  , testCase "wrong-source/BPS --no-verify proceeds" $
      withTempFile "slap-wrong" $ \wrong ->
      withTempFile "slap-out" $ \out -> do
        writeGarbage wrong (4 * 1024 * 1024)
        removeIfExists out
        expectOkWithWarning slap ["apply", bps, wrong, "-o", out, "--no-verify"]
          "wrong-source/BPS --no-verify" "applied"

  -- UPS: CRC32 source verification
  , testCase "wrong-source/UPS rejects" $
      withTempFile "slap-wrong" $ \wrong ->
      withTempFile "slap-out" $ \out -> do
        writeGarbage wrong (4 * 1024 * 1024)
        removeIfExists out
        expectFail slap ["apply", ups, wrong, "-o", out]
          "wrong-source/UPS" "mismatch"

  , testCase "wrong-source/UPS --no-verify proceeds" $
      withTempFile "slap-wrong" $ \wrong ->
      withTempFile "slap-out" $ \out -> do
        writeGarbage wrong (4 * 1024 * 1024)
        removeIfExists out
        expectOkWithWarning slap ["apply", ups, wrong, "-o", out, "--no-verify"]
          "wrong-source/UPS --no-verify" "applied"

  -- RUP: CRC32 source verification
  , testCase "wrong-source/RUP rejects" $
      withTempFile "slap-wrong" $ \wrong ->
      withTempFile "slap-out" $ \out -> do
        writeGarbage wrong (4 * 1024 * 1024)
        removeIfExists out
        expectFail slap ["apply", rup, wrong, "-o", out]
          "wrong-source/RUP" "mismatch"

  , testCase "wrong-source/RUP --no-verify proceeds" $
      withTempFile "slap-wrong" $ \wrong ->
      withTempFile "slap-out" $ \out -> do
        writeGarbage wrong (4 * 1024 * 1024)
        removeIfExists out
        expectOkWithWarning slap ["apply", rup, wrong, "-o", out, "--no-verify"]
          "wrong-source/RUP --no-verify" "applied"

  -- xdelta1: CRC32 source verification
  , testCase "wrong-source/xdelta1 rejects" $
      withTempFile "slap-wrong" $ \wrong ->
      withTempFile "slap-out" $ \out -> do
        writeGarbage wrong (4 * 1024 * 1024)
        removeIfExists out
        expectFail slap ["apply", xdelta1, wrong, "-o", out]
          "wrong-source/xdelta1" "mismatch"

  , testCase "wrong-source/xdelta1 --no-verify proceeds" $
      withTempFile "slap-wrong" $ \wrong ->
      withTempFile "slap-out" $ \out -> do
        writeGarbage wrong (4 * 1024 * 1024)
        removeIfExists out
        expectOkWithWarning slap ["apply", xdelta1, wrong, "-o", out, "--no-verify"]
          "wrong-source/xdelta1 --no-verify" "applied"

  -- VCDIFF: Adler32 per-window verification
  , testCase "wrong-source/VCDIFF rejects" $
      withTempFile "slap-wrong" $ \wrong ->
      withTempFile "slap-out" $ \out -> do
        writeGarbage wrong (4 * 1024 * 1024)
        removeIfExists out
        expectFail slap ["apply", vcdiff, wrong, "-o", out]
          "wrong-source/VCDIFF" "mismatch"

  , testCase "wrong-source/VCDIFF --no-verify proceeds" $
      withTempFile "slap-wrong" $ \wrong ->
      withTempFile "slap-out" $ \out -> do
        writeGarbage wrong (4 * 1024 * 1024)
        removeIfExists out
        expectOkWithWarning slap ["apply", vcdiff, wrong, "-o", out, "--no-verify"]
          "wrong-source/VCDIFF --no-verify" "applied"

  -- Swapped ROM: apply dm4y BPS patch to dm4y base (which IS the right source)
  -- then try applying it to the PATCHED output — verification should fail
  , testCase "wrong-source/BPS patched-as-source rejects" $
      withTempFile "slap-work" $ \work ->
      withTempFile "slap-out" $ \out -> do
        ByteString.readFile base >>= ByteString.writeFile work
        _ <- runSlap slap ["apply", bps, work, "--in-place", "--no-backup"]
        -- work is now the patched output, not the original source
        removeIfExists out
        expectFail slap ["apply", bps, work, "-o", out]
          "wrong-source/BPS patched-as-source" "mismatch"
  ]

-- | APS-GBA: per-block CRC16 verification (advisory warning, not hard fail)
wrongSourceApsGbaTests :: FilePath -> FilePath -> FilePath -> [TestTree]
wrongSourceApsGbaTests slap _fftaBase apsGba =
  [ testCase "wrong-source/APS-GBA warns on wrong source" $
      withTempFile "slap-wrong" $ \wrong ->
      withTempFile "slap-out" $ \out -> do
        writeGarbage wrong (16 * 1024 * 1024)  -- 16 MB like GBA
        removeIfExists out
        -- APS-GBA block CRC16 is advisory (warning-only), so it proceeds
        -- but should print a warning about CRC16 mismatch
        (exitCode, stdoutText, stderrText) <- runSlap slap ["apply", apsGba, wrong, "-o", out]
        let combined = stdoutText ++ stderrText
        case exitCode of
          ExitSuccess ->
            assertBool "expected CRC16 mismatch warning"
              (ciContains "crc16 mismatch" combined)
          ExitFailure _ ->
            -- If it fails, at least it should mention a mismatch
            assertBool "expected mismatch in error"
              (ciContains "mismatch" combined)
  ]

----------------------------------------------------------------------------
-- 2. Corrupted patch CRC
----------------------------------------------------------------------------

-- | Flip a byte inside BPS/UPS patches, verify parser rejects.
corruptPatchCRCTests :: FilePath -> FilePath -> [TestTree]
corruptPatchCRCTests bps ups =
  [ testCase "corrupt-crc/BPS flipped byte" $ do
      patchBytes <- ByteString.readFile bps
      -- Flip byte 10 (somewhere in the body, well before the footer)
      let corrupted = flipByte 10 patchBytes
      case parseSome corrupted of
        Left errorMessage -> assertBool "expected 'patch CRC mismatch'"
          (ciContains "patch CRC mismatch" errorMessage)
        Right _ -> assertFailure "expected BPS parse failure for corrupted patch"

  , testCase "corrupt-crc/UPS flipped byte" $ do
      patchBytes <- ByteString.readFile ups
      let corrupted = flipByte 10 patchBytes
      case parseSome corrupted of
        Left errorMessage -> assertBool "expected 'patch CRC mismatch'"
          (ciContains "patch CRC mismatch" errorMessage)
        Right _ -> assertFailure "expected UPS parse failure for corrupted patch"

  , testCase "corrupt-crc/BPS last data byte" $ do
      patchBytes <- ByteString.readFile bps
      -- Flip a byte just before the 12-byte footer (srcCRC + tgtCRC + patchCRC)
      let position = ByteString.length patchBytes - 13
      let corrupted = flipByte position patchBytes
      case parseSome corrupted of
        Left errorMessage -> assertBool "expected 'patch CRC mismatch'"
          (ciContains "patch CRC mismatch" errorMessage)
        Right _ -> assertFailure "expected BPS parse failure for corrupted patch"
  ]
  where
    flipByte :: Int -> ByteString.ByteString -> ByteString.ByteString
    flipByte position inputBytes =
      let (before, remaining) = ByteString.splitAt position inputBytes
          (byte, after) = case ByteString.uncons remaining of
            Just (theByte, theRest) -> (theByte, theRest)
            Nothing -> error "flipByte: position out of range"
      in before <> ByteString.singleton (byte `xor` 0xFF) <> after

----------------------------------------------------------------------------
-- 3. Wrong-size source
----------------------------------------------------------------------------

-- | Apply BPS to a source of wrong size — graceful error, not crash.
wrongSizeSourceTests :: FilePath -> FilePath -> FilePath -> [TestTree]
wrongSizeSourceTests slap _base bps =
  [ testCase "wrong-size/BPS too small" $
      withTempFile "slap-small" $ \small ->
      withTempFile "slap-out" $ \out -> do
        -- dm4y is 4 MB, give it 1 KB
        writeGarbage small 1024
        removeIfExists out
        expectFail slap ["apply", bps, small, "-o", out]
          "wrong-size/BPS too small" "mismatch"

  , testCase "wrong-size/BPS too large" $
      withTempFile "slap-large" $ \large ->
      withTempFile "slap-out" $ \out -> do
        -- dm4y is 4 MB, give it 8 MB
        writeGarbage large (8 * 1024 * 1024)
        removeIfExists out
        expectFail slap ["apply", bps, large, "-o", out]
          "wrong-size/BPS too large" "mismatch"

  , testCase "wrong-size/BPS empty source" $
      withTempFile "slap-empty" $ \empty ->
      withTempFile "slap-out" $ \out -> do
        ByteString.writeFile empty ByteString.empty
        removeIfExists out
        expectFail slap ["apply", bps, empty, "-o", out]
          "wrong-size/BPS empty" "mismatch"

  -- With --no-verify, wrong size should still not crash
  , testCase "wrong-size/BPS too small --no-verify no crash" $
      withTempFile "slap-small" $ \small ->
      withTempFile "slap-out" $ \out -> do
        writeGarbage small 1024
        removeIfExists out
        -- May succeed or fail, but should not crash with an unhandled exception
        (exitCode, stdoutText, stderrText) <- runSlap slap ["apply", bps, small, "-o", out, "--no-verify"]
        let combined = stdoutText ++ stderrText
        case exitCode of
          ExitSuccess -> pure ()  -- ok, it applied (maybe garbage, but didn't crash)
          ExitFailure code ->
            -- Normal failure (non-crash) exit codes are fine
            assertBool ("unexpected crash: exit " ++ show code ++ ": " ++ combined)
              (code == 1 || ciContains "error" combined || ciContains "mismatch" combined
               || ciContains "short" combined || ciContains "range" combined)
  ]

----------------------------------------------------------------------------
-- 4. Cross-format record preservation
----------------------------------------------------------------------------

-- | Convert IPS -> EBP -> IPS, IPS -> PPF3 -> IPS, and BPS -> UPS -> BPS.
-- Apply round-tripped patch, verify same output as original.
crossFormatRoundTripTests :: RomCache -> FilePath -> FilePath -> [TestTree]
crossFormatRoundTripTests romCache base bps =
  [ testCase "round-trip/IPS -> EBP -> IPS" $ do
      baseBytes <- cachedReadFile romCache base
      bpsBytes <- ByteString.readFile bps
      case parseSome bpsBytes of
        Left errorMessage -> assertFailure ("parse BPS failed: " ++ errorMessage)
        Right bpsParsed -> do
          targetResult <- applyPatch bpsParsed baseBytes
          case targetResult of
            Left errorMessage -> assertFailure ("apply BPS failed: " ++ errorMessage)
            Right targetBytes -> roundTripVia baseBytes targetBytes "ips" "ebp" "ips"

  , testCase "round-trip/IPS -> PPF3 -> IPS" $ do
      baseBytes <- cachedReadFile romCache base
      bpsBytes <- ByteString.readFile bps
      case parseSome bpsBytes of
        Left errorMessage -> assertFailure ("parse BPS failed: " ++ errorMessage)
        Right bpsParsed -> do
          targetResult <- applyPatch bpsParsed baseBytes
          case targetResult of
            Left errorMessage -> assertFailure ("apply BPS failed: " ++ errorMessage)
            Right targetBytes -> roundTripVia baseBytes targetBytes "ips" "ppf3" "ips"

  , testCase "round-trip/BPS -> UPS -> BPS" $ do
      baseBytes <- cachedReadFile romCache base
      bpsBytes <- ByteString.readFile bps
      case parseSome bpsBytes of
        Left errorMessage -> assertFailure ("parse BPS failed: " ++ errorMessage)
        Right bpsParsed -> do
          targetResult <- applyPatch bpsParsed baseBytes
          case targetResult of
            Left errorMessage -> assertFailure ("apply BPS failed: " ++ errorMessage)
            Right targetBytes -> roundTripVia baseBytes targetBytes "bps" "ups" "bps"
  ]
  where
    roundTripVia :: ByteString.ByteString -> ByteString.ByteString -> String -> String -> String -> IO ()
    roundTripVia baseBytes targetBytes formatA formatB formatC = do
      let expectedSha = sha1Hex targetBytes
      -- Step 1: create in format A
      createFormatA <- parseFormat formatA
      case createFromMemory createFormatA baseBytes targetBytes defaultMeta of
        Left errorMessage -> assertFailure ("create " ++ formatA ++ " failed: " ++ errorMessage)
        Right patchA -> do
          -- Step 2: parse A, apply to get target, create in format B
          case parseSome patchA of
            Left errorMessage -> assertFailure ("re-parse " ++ formatA ++ " failed: " ++ errorMessage)
            Right parsedA -> do
              resultA <- applyPatch parsedA baseBytes
              case resultA of
                Left errorMessage -> assertFailure ("re-apply " ++ formatA ++ " failed: " ++ errorMessage)
                Right outputA -> do
                  assertEqual (formatA ++ " round-trip fidelity") expectedSha (sha1Hex outputA)
                  createFormatB <- parseFormat formatB
                  case createFromMemory createFormatB baseBytes outputA defaultMeta of
                    Left errorMessage -> assertFailure ("create " ++ formatB ++ " failed: " ++ errorMessage)
                    Right patchB -> do
                      -- Step 3: parse B, apply to get target, create in format C
                      case parseSome patchB of
                        Left errorMessage -> assertFailure ("re-parse " ++ formatB ++ " failed: " ++ errorMessage)
                        Right parsedB -> do
                          resultB <- applyPatch parsedB baseBytes
                          case resultB of
                            Left errorMessage -> assertFailure ("re-apply " ++ formatB ++ " failed: " ++ errorMessage)
                            Right outputB -> do
                              assertEqual (formatB ++ " round-trip fidelity") expectedSha (sha1Hex outputB)
                              createFormatC <- parseFormat formatC
                              case createFromMemory createFormatC baseBytes outputB defaultMeta of
                                Left errorMessage -> assertFailure ("create " ++ formatC ++ " failed: " ++ errorMessage)
                                Right patchC -> do
                                  case parseSome patchC of
                                    Left errorMessage -> assertFailure ("re-parse " ++ formatC ++ " failed: " ++ errorMessage)
                                    Right parsedC -> do
                                      resultC <- applyPatch parsedC baseBytes
                                      case resultC of
                                        Left errorMessage -> assertFailure ("re-apply " ++ formatC ++ " failed: " ++ errorMessage)
                                        Right outputC ->
                                          assertEqual (formatA ++ " -> " ++ formatB ++ " -> " ++ formatC ++ " output SHA1")
                                            expectedSha (sha1Hex outputC)

    parseFormat :: String -> IO CreateFormat
    parseFormat formatString = case parseCreateFormat formatString of
      Just format -> pure format
      Nothing -> assertFailure ("unknown format: " ++ formatString) >> error "unreachable"

----------------------------------------------------------------------------
-- 5. Create round-trip on real ROMs
----------------------------------------------------------------------------

-- | Create a patch from real ROM pairs, parse it back, apply, and verify
-- the output matches the original target. Exercises create+parse+apply at
-- realistic scale — something the QuickCheck property tests can't cover.
createRoundTripTests :: RomCache -> FilePath -> FilePath
                     -> FilePath -> FilePath -> [TestTree]
createRoundTripTests romCache dm4yBase dm4yBps
                     stadium2Base stadium2Bps =
  [ testCase "create-round-trip/dm4y BPS" $ do
      (baseBytes, targetBytes) <- bootstrapTarget romCache dm4yBase dm4yBps
      createAndVerify "bps" baseBytes targetBytes

  , testCase "create-round-trip/dm4y IPS" $ do
      (baseBytes, targetBytes) <- bootstrapTarget romCache dm4yBase dm4yBps
      createAndVerify "ips" baseBytes targetBytes

  , testCase "create-round-trip/dm4y UPS" $ do
      (baseBytes, targetBytes) <- bootstrapTarget romCache dm4yBase dm4yBps
      createAndVerify "ups" baseBytes targetBytes

  , testCase "create-round-trip/stadium2 BPS" $ do
      (baseBytes, targetBytes) <- bootstrapTarget romCache stadium2Base stadium2Bps
      createAndVerify "bps" baseBytes targetBytes

  , testCase "create-round-trip/stadium2 IPS32" $ do
      (baseBytes, targetBytes) <- bootstrapTarget romCache stadium2Base stadium2Bps
      createAndVerify "ips32" baseBytes targetBytes
  ]
  where
    bootstrapTarget :: RomCache -> FilePath -> FilePath -> IO (ByteString.ByteString, ByteString.ByteString)
    bootstrapTarget romCacheLocal basePath bootPath = do
      baseBytes <- cachedReadFile romCacheLocal basePath
      bootBytes <- ByteString.readFile bootPath
      case parseSome bootBytes of
        Left errorMessage -> error ("bootstrap parse failed: " ++ errorMessage)
        Right parsed -> do
          result <- applyPatch parsed baseBytes
          case result of
            Left errorMessage -> error ("bootstrap apply failed: " ++ errorMessage)
            Right targetBytes -> pure (baseBytes, targetBytes)

    createAndVerify :: String -> ByteString.ByteString -> ByteString.ByteString -> IO ()
    createAndVerify formatString baseBytes targetBytes = do
      createFormat <- case parseCreateFormat formatString of
        Just format -> pure format
        Nothing -> assertFailure ("unknown format: " ++ formatString) >> error "unreachable"
      case createFromMemory createFormat baseBytes targetBytes defaultMeta of
        Left errorMessage -> assertFailure ("create " ++ formatString ++ " failed: " ++ errorMessage)
        Right patchBytes ->
          case parseSome patchBytes of
            Left errorMessage -> assertFailure ("re-parse " ++ formatString ++ " failed: " ++ errorMessage)
            Right parsed -> do
              result <- applyPatch parsed baseBytes
              case result of
                Left errorMessage -> assertFailure ("re-apply " ++ formatString ++ " failed: " ++ errorMessage)
                Right output ->
                  assertEqual "round-trip SHA1" (sha1Hex targetBytes) (sha1Hex output)
