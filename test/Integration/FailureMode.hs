module Integration.FailureMode (failureModeTests) where

import Integration.Bootstrap (BootstrapTargets, lookupBootstrapTarget)
import Integration.External (ExternalRun(..), ExternalTool(..), runExternal)
import Integration.Helpers
  ( Tier
  , onlyAtFull
  , repoDir
  , sha1Hex
  , applyPatch
  , withTempFile
  , mmapRomFile
  , parseCreateFormat
  , expectFail
  , expectOkWithWarning
  , writeGarbage
  , ciContains
  , removeIfExists
  )
import Integration.Skip
  ( GroupPlan
  , MaybeTest(..)
  , namedGroup
  , requireFixture
  , requireSlapBinary
  )
import Slap.Error (CreateResult(..), SlapError(..), renderSlapError)
import Slap.FileContents
  (PatchFileContents(..), SourceFileContents(..), TargetFileContents(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.SomePatch (parseSome, patchContents)
import Slap.Convert
  ( DirectCreate(..)
  , DiffCreate(..)
  , CreateFormat(..)
  , RequestedConstraints(..)
  , noMetadataRequested
  , noConstraintsRequested
  , rejectIncompatibleConstraints
  , convertDirect
  )
import Slap.Constraint (Constraint(..))
import Slap.IPS.Types (SMCShapeRequirement(..))
import Slap.Create (createFromMemory)

import Data.Bits (xor)
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import System.Exit (ExitCode(..))
import System.FilePath ((</>))
import Test.Tasty (TestTree)
import Test.Tasty.HUnit (testCase, assertFailure, assertBool, assertEqual)

-- | Failure-mode tests come in three flavours: in-process parser
-- checks (no fixtures, no subprocesses), subprocess matrix tests
-- against the real slap binary, and in-process round-trip tests over
-- bootstrap targets. Each strand has its own gating shape, all
-- routed through 'requireFixture' / 'requireSlapBinary'.
failureModeTests :: Tier -> IO BootstrapTargets -> IO GroupPlan
failureModeTests tier getTargets = do
  repo <- repoDir
  let dm4yBase     = repo </> "test/data/dm4y/base.gbc"
      dm4yBps      = repo </> "test/data/dm4y/patch.bps"
      dm4yUps      = repo </> "test/data/dm4y/patch.ups"
      dm4yRup      = repo </> "test/data/dm4y/patch.rup"
      dm4yXdelta1  = repo </> "test/data/dm4y/patch.xdelta1"
      dm4yVcdiff   = repo </> "test/data/dm4y/patch.vcdiff"
      fftaBase     = repo </> "test/data/ffta/base.gba"
      fftaAps      = repo </> "test/data/ffta/ffta-x.aps"
      stadium2Base = repo </> "test/data/stadium2/base.z64"
      stadium2Bps  = repo </> "test/data/stadium2/fair-heavy/patch.bps"

  let smcMaybes = map WillRun smcShapeConstraintTests

  corruptCrcMaybes <- requireFixture dm4yBps $ \_ ->
                      requireFixture dm4yUps $ \_ ->
                        pure (map WillRun (corruptPatchCRCTests dm4yBps dm4yUps))

  -- The heavy strand needs the slap binary AND various ROM/patch
  -- fixtures. Each sub-group gates independently so a missing
  -- fixture only suppresses its own tests.
  heavyMaybes <- fmap (onlyAtFull tier . concat) $ sequence
    [ requireSlapBinary $ \_ ->
        requireFixture dm4yBase $ \_ ->
          pure (map WillRun
                  (wrongSourceTests dm4yBase dm4yBps dm4yUps
                                    dm4yRup dm4yXdelta1 dm4yVcdiff))
    , requireSlapBinary $ \_ ->
        requireFixture dm4yBase $ \_ ->
          requireFixture fftaBase $ \_ ->
            pure (map WillRun (wrongSourceApsGbaTests fftaBase fftaAps))
    , requireSlapBinary $ \_ ->
        requireFixture dm4yBase $ \_ ->
          pure (map WillRun (wrongSizeSourceTests dm4yBase dm4yBps))
    , requireFixture dm4yBase $ \_ ->
        pure (map WillRun (crossFormatRoundTripTests dm4yBase dm4yBps))
    , requireFixture dm4yBase $ \_ ->
        requireFixture stadium2Base $ \_ ->
          pure (map WillRun
                  (createRoundTripTests getTargets dm4yBase dm4yBps
                                        stadium2Base stadium2Bps))
    ]

  pure (namedGroup "failure-mode" (smcMaybes ++ corruptCrcMaybes ++ heavyMaybes))

----------------------------------------------------------------------------
-- 1. Wrong source ROM (critical)
----------------------------------------------------------------------------

-- | For each format with source verification, apply to the wrong ROM.
-- Without --no-verify: fails with verification error.
-- With --no-verify: succeeds with a warning (test checks exit code,
-- output pattern, and that "warning" appears in the output).
wrongSourceTests :: FilePath -> FilePath -> FilePath
                 -> FilePath -> FilePath -> FilePath -> [TestTree]
wrongSourceTests base bps ups rup xdelta1 vcdiff =
  -- BPS: CRC32 source verification
  [ testCase "wrong-source/BPS rejects" $
      withTempFile "slap-wrong" $ \wrong ->
      withTempFile "slap-out" $ \out -> do
        writeGarbage wrong (4 * 1024 * 1024)  -- same size as dm4y
        removeIfExists out
        expectFail ["apply", bps, wrong, "-o", out]
          "wrong-source/BPS" "mismatch"

  , testCase "wrong-source/BPS --no-verify proceeds" $
      withTempFile "slap-wrong" $ \wrong ->
      withTempFile "slap-out" $ \out -> do
        writeGarbage wrong (4 * 1024 * 1024)
        removeIfExists out
        expectOkWithWarning ["apply", bps, wrong, "-o", out, "--no-verify"]
          "wrong-source/BPS --no-verify" "applied"

  -- UPS: CRC32 source verification
  , testCase "wrong-source/UPS rejects" $
      withTempFile "slap-wrong" $ \wrong ->
      withTempFile "slap-out" $ \out -> do
        writeGarbage wrong (4 * 1024 * 1024)
        removeIfExists out
        expectFail ["apply", ups, wrong, "-o", out]
          "wrong-source/UPS" "mismatch"

  , testCase "wrong-source/UPS --no-verify proceeds" $
      withTempFile "slap-wrong" $ \wrong ->
      withTempFile "slap-out" $ \out -> do
        writeGarbage wrong (4 * 1024 * 1024)
        removeIfExists out
        expectOkWithWarning ["apply", ups, wrong, "-o", out, "--no-verify"]
          "wrong-source/UPS --no-verify" "applied"

  -- NINJA2: MD5 source verification
  , testCase "wrong-source/NINJA2 rejects" $
      withTempFile "slap-wrong" $ \wrong ->
      withTempFile "slap-out" $ \out -> do
        writeGarbage wrong (4 * 1024 * 1024)
        removeIfExists out
        expectFail ["apply", rup, wrong, "-o", out]
          "wrong-source/NINJA2" "mismatch"

  , testCase "wrong-source/NINJA2 --no-verify proceeds" $
      withTempFile "slap-wrong" $ \wrong ->
      withTempFile "slap-out" $ \out -> do
        writeGarbage wrong (4 * 1024 * 1024)
        removeIfExists out
        expectOkWithWarning ["apply", rup, wrong, "-o", out, "--no-verify"]
          "wrong-source/NINJA2 --no-verify" "applied"

  -- xdelta1: CRC32 source verification
  , testCase "wrong-source/xdelta1 rejects" $
      withTempFile "slap-wrong" $ \wrong ->
      withTempFile "slap-out" $ \out -> do
        writeGarbage wrong (4 * 1024 * 1024)
        removeIfExists out
        expectFail ["apply", xdelta1, wrong, "-o", out]
          "wrong-source/xdelta1" "mismatch"

  , testCase "wrong-source/xdelta1 --no-verify proceeds" $
      withTempFile "slap-wrong" $ \wrong ->
      withTempFile "slap-out" $ \out -> do
        writeGarbage wrong (4 * 1024 * 1024)
        removeIfExists out
        expectOkWithWarning ["apply", xdelta1, wrong, "-o", out, "--no-verify"]
          "wrong-source/xdelta1 --no-verify" "applied"

  -- VCDIFF: Adler32 per-window verification
  , testCase "wrong-source/VCDIFF rejects" $
      withTempFile "slap-wrong" $ \wrong ->
      withTempFile "slap-out" $ \out -> do
        writeGarbage wrong (4 * 1024 * 1024)
        removeIfExists out
        expectFail ["apply", vcdiff, wrong, "-o", out]
          "wrong-source/VCDIFF" "mismatch"

  , testCase "wrong-source/VCDIFF --no-verify proceeds" $
      withTempFile "slap-wrong" $ \wrong ->
      withTempFile "slap-out" $ \out -> do
        writeGarbage wrong (4 * 1024 * 1024)
        removeIfExists out
        expectOkWithWarning ["apply", vcdiff, wrong, "-o", out, "--no-verify"]
          "wrong-source/VCDIFF --no-verify" "applied"

  -- Swapped ROM: apply dm4y BPS patch to dm4y base (which IS the right source)
  -- then try applying it to the PATCHED output — verification should fail
  , testCase "wrong-source/BPS patched-as-source rejects" $
      withTempFile "slap-work" $ \work ->
      withTempFile "slap-out" $ \out -> do
        ByteString.readFile base >>= ByteString.writeFile work
        _ <- runExternal SlapBinary ["apply", bps, work, "--in-place", "--no-backup"] Nothing ""
        -- work is now the patched output, not the original source
        removeIfExists out
        expectFail ["apply", bps, work, "-o", out]
          "wrong-source/BPS patched-as-source" "mismatch"
  ]

-- | APS-GBA: per-block CRC16 verification (advisory warning, not hard fail)
wrongSourceApsGbaTests :: FilePath -> FilePath -> [TestTree]
wrongSourceApsGbaTests _fftaBase apsGba =
  [ testCase "wrong-source/APS-GBA warns on wrong source" $
      withTempFile "slap-wrong" $ \wrong ->
      withTempFile "slap-out" $ \out -> do
        writeGarbage wrong (16 * 1024 * 1024)  -- 16 MB like GBA
        removeIfExists out
        -- APS-GBA block CRC16 is advisory (warning-only), so it proceeds
        -- but should print a warning about CRC16 mismatch
        run <- runExternal SlapBinary ["apply", apsGba, wrong, "-o", out] Nothing ""
        let combined = externalRunStdout run ++ externalRunStderr run
        case externalRunExitCode run of
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
      case parseSome (PatchFileContents corrupted) of
        Left slapError -> assertBool "expected 'patch CRC mismatch'"
          (ciContains "patch CRC mismatch" (renderSlapError slapError))
        Right _ -> assertFailure "expected BPS parse failure for corrupted patch"

  , testCase "corrupt-crc/UPS flipped byte" $ do
      patchBytes <- ByteString.readFile ups
      let corrupted = flipByte 10 patchBytes
      case parseSome (PatchFileContents corrupted) of
        Left slapError -> assertBool "expected 'patch CRC mismatch'"
          (ciContains "patch CRC mismatch" (renderSlapError slapError))
        Right _ -> assertFailure "expected UPS parse failure for corrupted patch"

  , testCase "corrupt-crc/BPS last data byte" $ do
      patchBytes <- ByteString.readFile bps
      -- Flip a byte just before the 12-byte footer (srcCRC + tgtCRC + patchCRC)
      let position = ByteString.length patchBytes - 13
      let corrupted = flipByte position patchBytes
      case parseSome (PatchFileContents corrupted) of
        Left slapError -> assertBool "expected 'patch CRC mismatch'"
          (ciContains "patch CRC mismatch" (renderSlapError slapError))
        Right _ -> assertFailure "expected BPS parse failure for corrupted patch"
  ]
  where
    flipByte :: Int -> ByteString -> ByteString
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
wrongSizeSourceTests :: FilePath -> FilePath -> [TestTree]
wrongSizeSourceTests _base bps =
  [ testCase "wrong-size/BPS too small" $
      withTempFile "slap-small" $ \small ->
      withTempFile "slap-out" $ \out -> do
        -- dm4y is 4 MB, give it 1 KB
        writeGarbage small 1024
        removeIfExists out
        expectFail ["apply", bps, small, "-o", out]
          "wrong-size/BPS too small" "mismatch"

  , testCase "wrong-size/BPS too large" $
      withTempFile "slap-large" $ \large ->
      withTempFile "slap-out" $ \out -> do
        -- dm4y is 4 MB, give it 8 MB
        writeGarbage large (8 * 1024 * 1024)
        removeIfExists out
        expectFail ["apply", bps, large, "-o", out]
          "wrong-size/BPS too large" "mismatch"

  , testCase "wrong-size/BPS empty source" $
      withTempFile "slap-empty" $ \empty ->
      withTempFile "slap-out" $ \out -> do
        ByteString.writeFile empty ByteString.empty
        removeIfExists out
        expectFail ["apply", bps, empty, "-o", out]
          "wrong-size/BPS empty" "mismatch"

  -- With --no-verify, wrong size should still not crash
  , testCase "wrong-size/BPS too small --no-verify no crash" $
      withTempFile "slap-small" $ \small ->
      withTempFile "slap-out" $ \out -> do
        writeGarbage small 1024
        removeIfExists out
        -- May succeed or fail, but should not crash with an unhandled exception
        run <- runExternal SlapBinary ["apply", bps, small, "-o", out, "--no-verify"] Nothing ""
        let combined = externalRunStdout run ++ externalRunStderr run
        case externalRunExitCode run of
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
crossFormatRoundTripTests :: FilePath -> FilePath -> [TestTree]
crossFormatRoundTripTests base bps =
  [ testCase "round-trip/IPS -> EBP -> IPS" $ do
      baseBytes <- mmapRomFile base
      bpsBytes <- ByteString.readFile bps
      case parseSome (PatchFileContents bpsBytes) of
        Left slapError -> assertFailure ("parse BPS failed: " ++ renderSlapError slapError)
        Right bpsParsed -> do
          targetResult <- applyPatch bpsParsed (SourceFileContents baseBytes)
          case targetResult of
            Left slapError -> assertFailure ("apply BPS failed: " ++ renderSlapError slapError)
            Right (TargetFileContents targetBytes) -> roundTripVia baseBytes targetBytes "ips" "ebp" "ips"

  , testCase "round-trip/IPS -> PPF3 -> IPS" $ do
      baseBytes <- mmapRomFile base
      bpsBytes <- ByteString.readFile bps
      case parseSome (PatchFileContents bpsBytes) of
        Left slapError -> assertFailure ("parse BPS failed: " ++ renderSlapError slapError)
        Right bpsParsed -> do
          targetResult <- applyPatch bpsParsed (SourceFileContents baseBytes)
          case targetResult of
            Left slapError -> assertFailure ("apply BPS failed: " ++ renderSlapError slapError)
            Right (TargetFileContents targetBytes) -> roundTripVia baseBytes targetBytes "ips" "ppf3" "ips"

  , testCase "round-trip/BPS -> UPS -> BPS" $ do
      baseBytes <- mmapRomFile base
      bpsBytes <- ByteString.readFile bps
      case parseSome (PatchFileContents bpsBytes) of
        Left slapError -> assertFailure ("parse BPS failed: " ++ renderSlapError slapError)
        Right bpsParsed -> do
          targetResult <- applyPatch bpsParsed (SourceFileContents baseBytes)
          case targetResult of
            Left slapError -> assertFailure ("apply BPS failed: " ++ renderSlapError slapError)
            Right (TargetFileContents targetBytes) -> roundTripVia baseBytes targetBytes "bps" "ups" "bps"
  ]
  where
    roundTripVia :: ByteString -> ByteString -> String -> String -> String -> IO ()
    roundTripVia baseBytes targetBytes formatA formatB formatC = do
      let expectedSha = sha1Hex targetBytes
      -- Step 1: create in format A
      createFormatA <- parseFormat formatA
      case createFromMemory createFormatA (SourceFileContents baseBytes) (TargetFileContents targetBytes) noMetadataRequested Nothing noConstraintsRequested of
        Left slapError -> assertFailure ("create " ++ formatA ++ " failed: " ++ renderSlapError slapError)
        Right (CreateResult patchA _) -> do
          -- Step 2: parse A, apply to get target, create in format B
          case parseSome patchA of
            Left slapError -> assertFailure ("re-parse " ++ formatA ++ " failed: " ++ renderSlapError slapError)
            Right parsedA -> do
              resultA <- applyPatch parsedA (SourceFileContents baseBytes)
              case resultA of
                Left slapError -> assertFailure ("re-apply " ++ formatA ++ " failed: " ++ renderSlapError slapError)
                Right (TargetFileContents outputA) -> do
                  assertEqual (formatA ++ " round-trip fidelity") expectedSha (sha1Hex outputA)
                  createFormatB <- parseFormat formatB
                  case createFromMemory createFormatB (SourceFileContents baseBytes) (TargetFileContents outputA) noMetadataRequested Nothing noConstraintsRequested of
                    Left slapError -> assertFailure ("create " ++ formatB ++ " failed: " ++ renderSlapError slapError)
                    Right (CreateResult patchB _) -> do
                      -- Step 3: parse B, apply to get target, create in format C
                      case parseSome patchB of
                        Left slapError -> assertFailure ("re-parse " ++ formatB ++ " failed: " ++ renderSlapError slapError)
                        Right parsedB -> do
                          resultB <- applyPatch parsedB (SourceFileContents baseBytes)
                          case resultB of
                            Left slapError -> assertFailure ("re-apply " ++ formatB ++ " failed: " ++ renderSlapError slapError)
                            Right (TargetFileContents outputB) -> do
                              assertEqual (formatB ++ " round-trip fidelity") expectedSha (sha1Hex outputB)
                              createFormatC <- parseFormat formatC
                              case createFromMemory createFormatC (SourceFileContents baseBytes) (TargetFileContents outputB) noMetadataRequested Nothing noConstraintsRequested of
                                Left slapError -> assertFailure ("create " ++ formatC ++ " failed: " ++ renderSlapError slapError)
                                Right (CreateResult patchC _) -> do
                                  case parseSome patchC of
                                    Left slapError -> assertFailure ("re-parse " ++ formatC ++ " failed: " ++ renderSlapError slapError)
                                    Right parsedC -> do
                                      resultC <- applyPatch parsedC (SourceFileContents baseBytes)
                                      case resultC of
                                        Left slapError -> assertFailure ("re-apply " ++ formatC ++ " failed: " ++ renderSlapError slapError)
                                        Right (TargetFileContents outputC) ->
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
createRoundTripTests :: IO BootstrapTargets -> FilePath -> FilePath
                     -> FilePath -> FilePath -> [TestTree]
createRoundTripTests getTargets dm4yBase dm4yBps
                     stadium2Base stadium2Bps =
  [ testCase "create-round-trip/dm4y BPS" $ do
      (baseBytes, targetBytes) <- bootstrapTarget dm4yBase dm4yBps
      createAndVerify "bps" baseBytes targetBytes

  , testCase "create-round-trip/dm4y IPS" $ do
      (baseBytes, targetBytes) <- bootstrapTarget dm4yBase dm4yBps
      createAndVerify "ips" baseBytes targetBytes

  , testCase "create-round-trip/dm4y UPS" $ do
      (baseBytes, targetBytes) <- bootstrapTarget dm4yBase dm4yBps
      createAndVerify "ups" baseBytes targetBytes

  , testCase "create-round-trip/stadium2 BPS" $ do
      (baseBytes, targetBytes) <- bootstrapTarget stadium2Base stadium2Bps
      createAndVerify "bps" baseBytes targetBytes

  , testCase "create-round-trip/stadium2 IPS32" $ do
      (baseBytes, targetBytes) <- bootstrapTarget stadium2Base stadium2Bps
      createAndVerify "ips32" baseBytes targetBytes
  ]
  where
    bootstrapTarget :: FilePath -> FilePath -> IO (ByteString, ByteString)
    bootstrapTarget basePath patchPath = do
      baseBytes <- mmapRomFile basePath
      bootstrapTargets <- getTargets
      let targetBytes = lookupBootstrapTarget bootstrapTargets basePath patchPath
      pure (baseBytes, targetBytes)

    createAndVerify :: String -> ByteString -> ByteString -> IO ()
    createAndVerify formatString baseBytes targetBytes = do
      createFormat <- case parseCreateFormat formatString of
        Just format -> pure format
        Nothing -> assertFailure ("unknown format: " ++ formatString) >> error "unreachable"
      case createFromMemory createFormat (SourceFileContents baseBytes) (TargetFileContents targetBytes) noMetadataRequested Nothing noConstraintsRequested of
        Left slapError -> assertFailure ("create " ++ formatString ++ " failed: " ++ renderSlapError slapError)
        Right (CreateResult patchBytes _) ->
          case parseSome patchBytes of
            Left slapError -> assertFailure ("re-parse " ++ formatString ++ " failed: " ++ renderSlapError slapError)
            Right parsed -> do
              result <- applyPatch parsed (SourceFileContents baseBytes)
              case result of
                Left slapError -> assertFailure ("re-apply " ++ formatString ++ " failed: " ++ renderSlapError slapError)
                Right (TargetFileContents output) ->
                  assertEqual "round-trip SHA1" (sha1Hex targetBytes) (sha1Hex output)

----------------------------------------------------------------------------
-- 6. --require-smc-shaped-target-size constraint
----------------------------------------------------------------------------

-- | The SMC-shape constraint refuses to emit an IPS truncation marker
-- whose declared target size doesn't satisfy SNESTool's
-- @(size & 0xFFF) == 0x200@ shape filter. These cases exercise the
-- create-time and convert-time gates without subprocesses or
-- bootstrap fixtures: synthetic source\/target pairs of a few KiB
-- each suffice.
smcShapeConstraintTests :: [TestTree]
smcShapeConstraintTests =
  [ testCase "smc-shape/IPS smc-sized target succeeds with flag" $ do
      -- 0x1200 bytes target satisfies (size & 0xFFF) == 0x200.
      let source = ByteString.replicate 0x2000 0x00
          target = ByteString.replicate 0x1200 0xFF
      case createWithSMC source target of
        Left slapError -> assertFailure
          ("expected success, got: " ++ renderSlapError slapError)
        Right (CreateResult patchBytes _) ->
          case parseSome patchBytes of
            Left slapError -> assertFailure
              ("re-parse: " ++ renderSlapError slapError)
            Right _ -> pure ()

  , testCase "smc-shape/IPS non-smc-sized target rejected with flag" $ do
      -- 4000 bytes (0xFA0) is not SMC-shaped: 4000 .&. 0xFFF == 0xFA0.
      let source = ByteString.replicate 0x2000 0x00
          target = ByteString.replicate 4000 0xFF
      case createWithSMC source target of
        Left (TruncationViolatesSMCShape _) -> pure ()
        Left other -> assertFailure
          ("expected TruncationViolatesSMCShape, got: " ++ renderSlapError other)
        Right _ -> assertFailure
          "expected refusal, got successful create"

  , testCase "smc-shape/IPS target>=source: gate vacuous, succeeds" $ do
      -- No truncation marker would be emitted, so the SMC filter doesn't apply.
      let source = ByteString.replicate 0x1000 0x00
          target = ByteString.replicate 0x2000 0xFF
      case createWithSMC source target of
        Left slapError -> assertFailure
          ("expected success (no truncation), got: " ++ renderSlapError slapError)
        Right _ -> pure ()

  , testCase "smc-shape/BPS rejected at constraint-acceptance layer" $
      -- The create entry point ('doCreate' in @app/Main.hs@) runs
      -- 'rejectIncompatibleConstraints' before invoking
      -- 'createFromMemory'; the constraint never reaches the
      -- per-format encoder. Exercise that check directly.
      case rejectIncompatibleConstraints (CreateDiff CreateBPS) smcConstraints of
        Left (ConstraintNotSupported SMCShapeConstraint LabelBPS) -> pure ()
        Left other -> assertFailure
          ("expected ConstraintNotSupported, got: " ++ renderSlapError other)
        Right () -> assertFailure
          "expected refusal at create entry"

  , testCase "smc-shape/IPS non-smc-sized succeeds without flag" $ do
      -- Regression: without the flag, slap continues to emit the
      -- wire-valid truncation marker it always has.
      let source = ByteString.replicate 0x2000 0x00
          target = ByteString.replicate 4000 0xFF
      case createFromMemory (CreateDirect CreateIPS)
             (SourceFileContents source) (TargetFileContents target)
             noMetadataRequested Nothing noConstraintsRequested of
        Left slapError -> assertFailure
          ("expected success (no flag), got: " ++ renderSlapError slapError)
        Right _ -> pure ()

  , testCase "smc-shape/convert --to bps rejected at constraint layer" $
      -- The convert entry point ('doConvert' in @app/Main.hs@) runs
      -- 'rejectIncompatibleConstraints' before dispatching, so the
      -- user-facing rejection lands here long before any encoder
      -- runs. Exercise that check directly.
      case rejectIncompatibleConstraints (CreateDiff CreateBPS) smcConstraints of
        Left (ConstraintNotSupported SMCShapeConstraint LabelBPS) -> pure ()
        Left other -> assertFailure
          ("expected ConstraintNotSupported, got: " ++ renderSlapError other)
        Right () -> assertFailure
          "expected refusal at convert entry"

  , testCase "smc-shape/source-less convert IPS->IPS refuses bad marker" $ do
      ipsPatch <- buildNonSMCShapedIPS
      case patchContents ipsPatch of
        Nothing -> assertFailure "test fixture should expose PatchContents"
        Just contents ->
          case convertDirect contents (CreateDirect CreateIPS)
                 noMetadataRequested smcConstraints of
            Left (TruncationViolatesSMCShape _) -> pure ()
            Left other -> assertFailure
              ("expected TruncationViolatesSMCShape, got: " ++ renderSlapError other)
            Right _ -> assertFailure
              "expected refusal at encode gate"
  ]
  where
    smcConstraints = noConstraintsRequested
      { requestedSMCShape = RequireSMCShapedTruncation }

    createWithSMC source target =
      createFromMemory (CreateDirect CreateIPS)
        (SourceFileContents source) (TargetFileContents target)
        noMetadataRequested Nothing smcConstraints

    -- Build a parsed IPS patch whose Flips-style truncation marker
    -- declares a non-SMC-shaped target size. Constructed via the
    -- create path with constraints disabled so the produced patch
    -- carries the marker; then re-parsed so 'patchContents' is
    -- populated for the source-less convert path.
    buildNonSMCShapedIPS = do
      let source = ByteString.replicate 0x2000 0x00
          target = ByteString.replicate 4000 0xFF
      case createFromMemory (CreateDirect CreateIPS)
             (SourceFileContents source) (TargetFileContents target)
             noMetadataRequested Nothing noConstraintsRequested of
        Left slapError -> assertFailure
          ("setup: create failed: " ++ renderSlapError slapError)
          >> error "unreachable"
        Right (CreateResult patchBytes _) ->
          case parseSome patchBytes of
            Left slapError -> assertFailure
              ("setup: parse failed: " ++ renderSlapError slapError)
              >> error "unreachable"
            Right parsed -> pure parsed
