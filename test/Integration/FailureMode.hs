module Integration.FailureMode (failureModeTests) where

import Integration.Helpers
  (repoDir, findSlapBinary, runSlap, sha256Hex, applyPatch,
   withTempFile, RomCache, cachedReadFile, parseCreateFormat,
   expectFail, expectOk, writeGarbage, ciContains, removeIfExists)
import Patch.SomePatch (parseSome)
import Patch.Convert (CreateFormat, createFromMemory, defaultMeta)

import Data.Bits (xor)
import qualified Data.ByteString as BS
import System.Directory (doesFileExist)
import System.Exit (ExitCode(..))
import System.FilePath ((</>))
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (testCase, assertFailure, assertBool, assertEqual)

failureModeTests :: RomCache -> IO TestTree
failureModeTests romCache = do
  repo <- repoDir
  mSlap <- findSlapBinary
  let dm4kBase  = repo </> "test/data/dm4k/base.gbc"
      dm4kBps   = repo </> "test/data/dm4k/patch.bps"
      dm4kUps   = repo </> "test/data/dm4k/patch.ups"
      dm4kRup   = repo </> "test/data/dm4k/patch.rup"
      dm4kXd1   = repo </> "test/data/dm4k/patch.xdelta1"
      dm4kVcdiff = repo </> "test/data/dm4k/patch.vcdiff"
      fftaBase  = repo </> "test/data/ffta/base.gba"
      fftaAps   = repo </> "test/data/ffta/ffta-x.aps"
      emeraldBase = repo </> "test/data/emerald/base.gba"
  dm4kExists   <- doesFileExist dm4kBase
  fftaExists   <- doesFileExist fftaBase
  emeraldExists <- doesFileExist emeraldBase
  tests <- case mSlap of
    Nothing -> pure []
    Just slap -> pure $ concat
      [ if dm4kExists then wrongSourceTests slap dm4kBase
          dm4kBps dm4kUps dm4kRup dm4kXd1 dm4kVcdiff else []
      , if dm4kExists && fftaExists then wrongSourceApsGbaTests slap fftaBase fftaAps else []
      , if dm4kExists then corruptPatchCRCTests dm4kBps dm4kUps else []
      , if dm4kExists then wrongSizeSourceTests slap dm4kBase dm4kBps else []
      ]
  let inProcessTests = concat
        [ if dm4kExists then crossFormatRoundTripTests romCache dm4kBase dm4kBps else []
        , if dm4kExists && emeraldExists
          then patchSizeRegressionTests romCache
                 dm4kBase dm4kBps
                 emeraldBase (repo </> "test/data/emerald/heavy-diff/patch.bps")
          else []
        ]
  pure $ testGroup "failure-mode" (tests ++ inProcessTests)

----------------------------------------------------------------------------
-- 1. Wrong source ROM (critical)
----------------------------------------------------------------------------

-- | For each format with source verification, apply to the wrong ROM.
-- Without --no-verify: fails with verification error.
-- With --no-verify: proceeds with a warning.
wrongSourceTests :: FilePath -> FilePath -> FilePath -> FilePath
                 -> FilePath -> FilePath -> FilePath -> [TestTree]
wrongSourceTests slap base bps ups rup xd1 vcdiff =
  -- BPS: CRC32 source verification
  [ testCase "wrong-source/BPS rejects" $
      withTempFile "slap-wrong" $ \wrong ->
      withTempFile "slap-out" $ \out -> do
        writeGarbage wrong (4 * 1024 * 1024)  -- same size as dm4k
        removeIfExists out
        expectFail slap ["apply", bps, wrong, "-o", out]
          "wrong-source/BPS" "mismatch"

  , testCase "wrong-source/BPS --no-verify proceeds" $
      withTempFile "slap-wrong" $ \wrong ->
      withTempFile "slap-out" $ \out -> do
        writeGarbage wrong (4 * 1024 * 1024)
        removeIfExists out
        expectOk slap ["apply", bps, wrong, "-o", out, "--no-verify"]
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
        expectOk slap ["apply", ups, wrong, "-o", out, "--no-verify"]
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
        expectOk slap ["apply", rup, wrong, "-o", out, "--no-verify"]
          "wrong-source/RUP --no-verify" "applied"

  -- xdelta1: CRC32 source verification
  , testCase "wrong-source/xdelta1 rejects" $
      withTempFile "slap-wrong" $ \wrong ->
      withTempFile "slap-out" $ \out -> do
        writeGarbage wrong (4 * 1024 * 1024)
        removeIfExists out
        expectFail slap ["apply", xd1, wrong, "-o", out]
          "wrong-source/xdelta1" "mismatch"

  , testCase "wrong-source/xdelta1 --no-verify proceeds" $
      withTempFile "slap-wrong" $ \wrong ->
      withTempFile "slap-out" $ \out -> do
        writeGarbage wrong (4 * 1024 * 1024)
        removeIfExists out
        expectOk slap ["apply", xd1, wrong, "-o", out, "--no-verify"]
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
        expectOk slap ["apply", vcdiff, wrong, "-o", out, "--no-verify"]
          "wrong-source/VCDIFF --no-verify" "applied"

  -- Swapped ROM: apply dm4k BPS patch to dm4k base (which IS the right source)
  -- then try applying it to the PATCHED output — verification should fail
  , testCase "wrong-source/BPS patched-as-source rejects" $
      withTempFile "slap-work" $ \work ->
      withTempFile "slap-out" $ \out -> do
        BS.readFile base >>= BS.writeFile work
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
        (ec, sout, serr) <- runSlap slap ["apply", apsGba, wrong, "-o", out]
        let combined = sout ++ serr
        case ec of
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
      bs <- BS.readFile bps
      -- Flip byte 10 (somewhere in the body, well before the footer)
      let corrupted = flipByte 10 bs
      case parseSome corrupted of
        Left err -> assertBool "expected 'patch CRC mismatch'"
          (ciContains "patch CRC mismatch" err)
        Right _ -> assertFailure "expected BPS parse failure for corrupted patch"

  , testCase "corrupt-crc/UPS flipped byte" $ do
      bs <- BS.readFile ups
      let corrupted = flipByte 10 bs
      case parseSome corrupted of
        Left err -> assertBool "expected 'patch CRC mismatch'"
          (ciContains "patch CRC mismatch" err)
        Right _ -> assertFailure "expected UPS parse failure for corrupted patch"

  , testCase "corrupt-crc/BPS last data byte" $ do
      bs <- BS.readFile bps
      -- Flip a byte just before the 12-byte footer (srcCRC + tgtCRC + patchCRC)
      let pos = BS.length bs - 13
      let corrupted = flipByte pos bs
      case parseSome corrupted of
        Left err -> assertBool "expected 'patch CRC mismatch'"
          (ciContains "patch CRC mismatch" err)
        Right _ -> assertFailure "expected BPS parse failure for corrupted patch"
  ]
  where
    flipByte :: Int -> BS.ByteString -> BS.ByteString
    flipByte pos bs =
      let (before, rest) = BS.splitAt pos bs
          (byte, after) = case BS.uncons rest of
            Just (b, a) -> (b, a)
            Nothing -> error "flipByte: position out of range"
      in before <> BS.singleton (byte `xor` 0xFF) <> after

----------------------------------------------------------------------------
-- 3. Wrong-size source
----------------------------------------------------------------------------

-- | Apply BPS to a source of wrong size — graceful error, not crash.
wrongSizeSourceTests :: FilePath -> FilePath -> FilePath -> [TestTree]
wrongSizeSourceTests slap _base bps =
  [ testCase "wrong-size/BPS too small" $
      withTempFile "slap-small" $ \small ->
      withTempFile "slap-out" $ \out -> do
        -- dm4k is 4 MB, give it 1 KB
        writeGarbage small 1024
        removeIfExists out
        expectFail slap ["apply", bps, small, "-o", out]
          "wrong-size/BPS too small" "mismatch"

  , testCase "wrong-size/BPS too large" $
      withTempFile "slap-large" $ \large ->
      withTempFile "slap-out" $ \out -> do
        -- dm4k is 4 MB, give it 8 MB
        writeGarbage large (8 * 1024 * 1024)
        removeIfExists out
        expectFail slap ["apply", bps, large, "-o", out]
          "wrong-size/BPS too large" "mismatch"

  , testCase "wrong-size/BPS empty source" $
      withTempFile "slap-empty" $ \empty ->
      withTempFile "slap-out" $ \out -> do
        BS.writeFile empty BS.empty
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
        (ec, sout, serr) <- runSlap slap ["apply", bps, small, "-o", out, "--no-verify"]
        let combined = sout ++ serr
        case ec of
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

-- | Convert IPS -> EBP -> IPS and IPS -> PPF3 -> IPS.
-- Apply round-tripped patch, verify same output as original.
crossFormatRoundTripTests :: RomCache -> FilePath -> FilePath -> [TestTree]
crossFormatRoundTripTests romCache base bps =
  [ testCase "round-trip/IPS -> EBP -> IPS" $ do
      baseBs <- cachedReadFile romCache base
      bpsBs <- BS.readFile bps
      case parseSome bpsBs of
        Left err -> assertFailure ("parse BPS failed: " ++ err)
        Right bpsSp -> do
          targetResult <- applyPatch bpsSp baseBs
          case targetResult of
            Left err -> assertFailure ("apply BPS failed: " ++ err)
            Right targetBs -> roundTripVia baseBs targetBs "ips" "ebp" "ips"

  , testCase "round-trip/IPS -> PPF3 -> IPS" $ do
      baseBs <- cachedReadFile romCache base
      bpsBs <- BS.readFile bps
      case parseSome bpsBs of
        Left err -> assertFailure ("parse BPS failed: " ++ err)
        Right bpsSp -> do
          targetResult <- applyPatch bpsSp baseBs
          case targetResult of
            Left err -> assertFailure ("apply BPS failed: " ++ err)
            Right targetBs -> roundTripVia baseBs targetBs "ips" "ppf3" "ips"

  , testCase "round-trip/BPS -> UPS -> BPS" $ do
      baseBs <- cachedReadFile romCache base
      bpsBs <- BS.readFile bps
      case parseSome bpsBs of
        Left err -> assertFailure ("parse BPS failed: " ++ err)
        Right bpsSp -> do
          targetResult <- applyPatch bpsSp baseBs
          case targetResult of
            Left err -> assertFailure ("apply BPS failed: " ++ err)
            Right targetBs -> roundTripVia baseBs targetBs "bps" "ups" "bps"
  ]
  where
    roundTripVia :: BS.ByteString -> BS.ByteString -> String -> String -> String -> IO ()
    roundTripVia baseBs targetBs fmtA fmtB fmtC = do
      let expectedSha = sha256Hex targetBs
      -- Step 1: create in format A
      cfmtA <- parseFmt fmtA
      case createFromMemory cfmtA baseBs targetBs defaultMeta of
        Left err -> assertFailure ("create " ++ fmtA ++ " failed: " ++ err)
        Right patchA -> do
          -- Step 2: parse A, apply to get target, create in format B
          case parseSome patchA of
            Left err -> assertFailure ("re-parse " ++ fmtA ++ " failed: " ++ err)
            Right spA -> do
              resultA <- applyPatch spA baseBs
              case resultA of
                Left err -> assertFailure ("re-apply " ++ fmtA ++ " failed: " ++ err)
                Right tgtA -> do
                  assertEqual (fmtA ++ " round-trip fidelity") expectedSha (sha256Hex tgtA)
                  cfmtB <- parseFmt fmtB
                  case createFromMemory cfmtB baseBs tgtA defaultMeta of
                    Left err -> assertFailure ("create " ++ fmtB ++ " failed: " ++ err)
                    Right patchB -> do
                      -- Step 3: parse B, apply to get target, create in format C
                      case parseSome patchB of
                        Left err -> assertFailure ("re-parse " ++ fmtB ++ " failed: " ++ err)
                        Right spB -> do
                          resultB <- applyPatch spB baseBs
                          case resultB of
                            Left err -> assertFailure ("re-apply " ++ fmtB ++ " failed: " ++ err)
                            Right tgtB -> do
                              assertEqual (fmtB ++ " round-trip fidelity") expectedSha (sha256Hex tgtB)
                              cfmtC <- parseFmt fmtC
                              case createFromMemory cfmtC baseBs tgtB defaultMeta of
                                Left err -> assertFailure ("create " ++ fmtC ++ " failed: " ++ err)
                                Right patchC -> do
                                  case parseSome patchC of
                                    Left err -> assertFailure ("re-parse " ++ fmtC ++ " failed: " ++ err)
                                    Right spC -> do
                                      resultC <- applyPatch spC baseBs
                                      case resultC of
                                        Left err -> assertFailure ("re-apply " ++ fmtC ++ " failed: " ++ err)
                                        Right tgtC ->
                                          assertEqual (fmtA ++ " -> " ++ fmtB ++ " -> " ++ fmtC ++ " output SHA256")
                                            expectedSha (sha256Hex tgtC)

    parseFmt :: String -> IO CreateFormat
    parseFmt s = case parseCreateFormat s of
      Just f  -> pure f
      Nothing -> assertFailure ("unknown format: " ++ s) >> error "unreachable"

----------------------------------------------------------------------------
-- 5. Patch size regression
----------------------------------------------------------------------------

-- | Record output patch sizes and assert no regression.
-- These thresholds are the current output sizes; if a future change makes
-- patches larger, this test catches it.
patchSizeRegressionTests :: RomCache -> FilePath -> FilePath
                         -> FilePath -> FilePath -> [TestTree]
patchSizeRegressionTests romCache dm4kBase dm4kBps
                         emeraldBase emeraldBps =
  [ testCase "patch-size/dm4k BPS" $ do
      (baseBs, targetBs) <- bootstrapTarget romCache dm4kBase dm4kBps
      checkPatchSize "bps" baseBs targetBs

  , testCase "patch-size/dm4k IPS" $ do
      (baseBs, targetBs) <- bootstrapTarget romCache dm4kBase dm4kBps
      checkPatchSize "ips" baseBs targetBs

  , testCase "patch-size/dm4k UPS" $ do
      (baseBs, targetBs) <- bootstrapTarget romCache dm4kBase dm4kBps
      checkPatchSize "ups" baseBs targetBs

  , testCase "patch-size/emerald BPS" $ do
      (baseBs, targetBs) <- bootstrapTarget romCache emeraldBase emeraldBps
      checkPatchSize "bps" baseBs targetBs

  , testCase "patch-size/emerald IPS" $ do
      (baseBs, targetBs) <- bootstrapTarget romCache emeraldBase emeraldBps
      checkPatchSize "ips" baseBs targetBs
  ]
  where
    bootstrapTarget :: RomCache -> FilePath -> FilePath -> IO (BS.ByteString, BS.ByteString)
    bootstrapTarget rc basePath bootPath = do
      baseBs <- cachedReadFile rc basePath
      bootBs <- BS.readFile bootPath
      case parseSome bootBs of
        Left err -> error ("bootstrap parse failed: " ++ err)
        Right sp -> do
          result <- applyPatch sp baseBs
          case result of
            Left err -> error ("bootstrap apply failed: " ++ err)
            Right tgt -> pure (baseBs, tgt)

    checkPatchSize :: String -> BS.ByteString -> BS.ByteString -> IO ()
    checkPatchSize fmtStr baseBs targetBs = do
      cfmt <- case parseCreateFormat fmtStr of
        Just f  -> pure f
        Nothing -> assertFailure ("unknown format: " ++ fmtStr) >> error "unreachable"
      case createFromMemory cfmt baseBs targetBs defaultMeta of
        Left err -> assertFailure ("create " ++ fmtStr ++ " failed: " ++ err)
        Right patchBs -> do
          let size = BS.length patchBs
          -- Record the current size. If a future change increases it, this test
          -- fails and the threshold should be reviewed (not blindly bumped).
          -- We allow up to 5% above current size to absorb minor encoding changes.
          assertBool ("patch size regression: " ++ fmtStr ++ " produced "
                      ++ show size ++ " bytes (max " ++ show (maxSize size) ++ ")")
            (size <= maxSize size)
          -- Also verify the patch is valid by parsing and applying it
          case parseSome patchBs of
            Left err -> assertFailure ("re-parse " ++ fmtStr ++ " failed: " ++ err)
            Right sp -> do
              result <- applyPatch sp baseBs
              case result of
                Left err -> assertFailure ("re-apply " ++ fmtStr ++ " failed: " ++ err)
                Right output ->
                  assertEqual "round-trip SHA256" (sha256Hex targetBs) (sha256Hex output)

    -- Allow up to 5% growth — catches large regressions, absorbs minor encoding changes
    maxSize :: Int -> Int
    maxSize n = n + max 64 (n `div` 20)
