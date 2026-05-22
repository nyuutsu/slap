{-# LANGUAGE OverloadedStrings #-}

module Integration.FailureMode (failureModeTests) where

import Integration.Bootstrap (BootstrapTargets, lookupBootstrapTarget)
import Integration.External (ExternalRun(..), ExternalTool(..), runExternal)
import Integration.HeavyTests (FixtureName(..), bpsCreateIsExpensive)
import Integration.Helpers (assertFailureT)
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
import Slap.Status
  ( CreateResult(..), SlapError(..), SlapAdvisory(..), Parsed(..)
  , XDelta1GzipStreamInputs(..)
  , renderSlapError
  )
import Slap.FileContents
  (PatchFileContents(..), InputFileContents(..), OutputFileContents(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.SomePatch
  (parseSome, patchKind, patchFormat, patchAdvisories
  , patchVerification, verifySourceMD5, verifyTargetMD5, PatchKind(..))
import Slap.XDelta1.Parse
  ( parseControl
  , parseXDelta1
  , XDelta1ControlSegment(..), XDelta1DataSegment(..)
  , XDelta1NoVerifyFlag(..)
  )
import qualified Slap.XDelta1.Apply as XDelta1
import Slap.Text (EncodedText(..), EncodingName(..))
import qualified Data.Text as Text
import Slap.XDelta1.Types
  ( XDelta1Patch(..)
  , XDelta1FromName(..), XDelta1ToName(..)
  , XDelta1OffsetMode(..)
  , XDelta1VerificationPosture(..)
  , XDelta1PatchCompression(..)
  , XDelta1FileAtDeltaTime(..)
  , xdelta1Verification
  , xdelta1FromAtDeltaTime
  , xdelta1ToAtDeltaTime
  , xdelta1ControlTypeTag
  , xdelta1ControlAllocationBound
  , xdelta1EmptyInputMD5Sentinel
  )
import Slap.Checksum (MD5Hash(..))
import Slap.Binary (word32BEBytes)
import Slap.Measure (FileSize(..))
import Slap.Convert
  ( DirectCreate(..)
  , DifferentialCreate(..)
  , CreateFormat(..)
  , RequestedConstraints(..)
  , RequestedDialects(..)
  , noMetadataRequested
  , noConstraintsRequested
  , noDialectsRequested
  , acceptedDialects
  , rejectIncompatibleConstraints
  , rejectIncompatibleDialects
  , createFormatLabel
  , convertDirect
  )
import Slap.Constraint (Constraint(..))
import Slap.Dialect (Dialect(..))
import Slap.IPS.Types (SMCShapeRequirement(..))
import Slap.PPF1.Types (PPF1Origin(..))
import Slap.Create (createPatch)
import qualified Data.Set as Set

import Data.Bits (xor, (.|.))
import Data.Word (Word8)
import Data.List.NonEmpty (NonEmpty(..))
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
      stadium2Base       = repo </> "test/data/stadium2/base.z64"
      stadium2Bps        = repo </> "test/data/stadium2/fair-heavy/patch.bps"
      stadium2SizeChange = repo </> "test/data/stadium2/size-change/patch.xdelta1"

  let smcMaybes = map WillRun smcShapeConstraintTests
      xdelta1ShapeMaybes = map WillRun xdelta1ShapeRejectionTests
      dialectMaybes = map WillRun dialectAxisRejectionTests

  xdelta1NoVerifyMaybes <- requireFixture stadium2SizeChange $ \_ ->
                             pure (map WillRun (xdelta1NoVerifyTests stadium2SizeChange))

  xdelta1InputPreCompressionMaybes <-
    requireFixture stadium2SizeChange $ \_ ->
      pure (map WillRun (xdelta1InputPreCompressionTests stadium2SizeChange))

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
          pure (createRoundTripTests getTargets dm4yBase dm4yBps
                                     stadium2Base stadium2Bps)
    ]

  pure (namedGroup "failure-mode"
          (smcMaybes ++ xdelta1ShapeMaybes ++ dialectMaybes
            ++ xdelta1NoVerifyMaybes ++ xdelta1InputPreCompressionMaybes
            ++ corruptCrcMaybes ++ heavyMaybes))

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
      case parseSome noDialectsRequested (PatchFileContents corrupted) of
        Left slapError -> assertBool "expected 'patch CRC mismatch'"
          (ciContains "patch CRC mismatch" (Text.unpack (renderSlapError slapError)))
        Right _ -> assertFailure "expected BPS parse failure for corrupted patch"

  , testCase "corrupt-crc/UPS flipped byte" $ do
      patchBytes <- ByteString.readFile ups
      let corrupted = flipByte 10 patchBytes
      case parseSome noDialectsRequested (PatchFileContents corrupted) of
        Left slapError -> assertBool "expected 'patch CRC mismatch'"
          (ciContains "patch CRC mismatch" (Text.unpack (renderSlapError slapError)))
        Right _ -> assertFailure "expected UPS parse failure for corrupted patch"

  , testCase "corrupt-crc/BPS last data byte" $ do
      patchBytes <- ByteString.readFile bps
      -- Flip a byte just before the 12-byte footer (srcCRC + tgtCRC + patchCRC)
      let position = ByteString.length patchBytes - 13
      let corrupted = flipByte position patchBytes
      case parseSome noDialectsRequested (PatchFileContents corrupted) of
        Left slapError -> assertBool "expected 'patch CRC mismatch'"
          (ciContains "patch CRC mismatch" (Text.unpack (renderSlapError slapError)))
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
      case parseSome noDialectsRequested (PatchFileContents bpsBytes) of
        Left slapError -> assertFailureT ("parse BPS failed: " <> renderSlapError slapError)
        Right bpsParsed -> do
          targetResult <- applyPatch bpsParsed (InputFileContents baseBytes)
          case targetResult of
            Left slapError -> assertFailureT ("apply BPS failed: " <> renderSlapError slapError)
            Right (OutputFileContents targetBytes) -> roundTripVia baseBytes targetBytes "ips" "ebp" "ips"

  , testCase "round-trip/IPS -> PPF3 -> IPS" $ do
      baseBytes <- mmapRomFile base
      bpsBytes <- ByteString.readFile bps
      case parseSome noDialectsRequested (PatchFileContents bpsBytes) of
        Left slapError -> assertFailureT ("parse BPS failed: " <> renderSlapError slapError)
        Right bpsParsed -> do
          targetResult <- applyPatch bpsParsed (InputFileContents baseBytes)
          case targetResult of
            Left slapError -> assertFailureT ("apply BPS failed: " <> renderSlapError slapError)
            Right (OutputFileContents targetBytes) -> roundTripVia baseBytes targetBytes "ips" "ppf3" "ips"

  , testCase "round-trip/BPS -> UPS -> BPS" $ do
      baseBytes <- mmapRomFile base
      bpsBytes <- ByteString.readFile bps
      case parseSome noDialectsRequested (PatchFileContents bpsBytes) of
        Left slapError -> assertFailureT ("parse BPS failed: " <> renderSlapError slapError)
        Right bpsParsed -> do
          targetResult <- applyPatch bpsParsed (InputFileContents baseBytes)
          case targetResult of
            Left slapError -> assertFailureT ("apply BPS failed: " <> renderSlapError slapError)
            Right (OutputFileContents targetBytes) -> roundTripVia baseBytes targetBytes "bps" "ups" "bps"
  ]
  where
    roundTripVia :: ByteString -> ByteString -> String -> String -> String -> IO ()
    roundTripVia baseBytes targetBytes formatA formatB formatC = do
      let expectedSha = sha1Hex targetBytes
      -- Step 1: create in format A
      createFormatA <- parseFormat formatA
      case createPatch createFormatA Nothing (InputFileContents baseBytes) (OutputFileContents targetBytes) noMetadataRequested Nothing noConstraintsRequested noDialectsRequested of
        Left slapError -> assertFailureT ("create " <> Text.pack formatA <> " failed: " <> renderSlapError slapError)
        Right (CreateResult patchA _) -> do
          -- Step 2: parse A, apply to get target, create in format B
          case parseSome noDialectsRequested patchA of
            Left slapError -> assertFailureT ("re-parse " <> Text.pack formatA <> " failed: " <> renderSlapError slapError)
            Right parsedA -> do
              resultA <- applyPatch parsedA (InputFileContents baseBytes)
              case resultA of
                Left slapError -> assertFailureT ("re-apply " <> Text.pack formatA <> " failed: " <> renderSlapError slapError)
                Right (OutputFileContents outputA) -> do
                  assertEqual (formatA ++ " round-trip fidelity") expectedSha (sha1Hex outputA)
                  createFormatB <- parseFormat formatB
                  case createPatch createFormatB Nothing (InputFileContents baseBytes) (OutputFileContents outputA) noMetadataRequested Nothing noConstraintsRequested noDialectsRequested of
                    Left slapError -> assertFailureT ("create " <> Text.pack formatB <> " failed: " <> renderSlapError slapError)
                    Right (CreateResult patchB _) -> do
                      -- Step 3: parse B, apply to get target, create in format C
                      case parseSome noDialectsRequested patchB of
                        Left slapError -> assertFailureT ("re-parse " <> Text.pack formatB <> " failed: " <> renderSlapError slapError)
                        Right parsedB -> do
                          resultB <- applyPatch parsedB (InputFileContents baseBytes)
                          case resultB of
                            Left slapError -> assertFailureT ("re-apply " <> Text.pack formatB <> " failed: " <> renderSlapError slapError)
                            Right (OutputFileContents outputB) -> do
                              assertEqual (formatB ++ " round-trip fidelity") expectedSha (sha1Hex outputB)
                              createFormatC <- parseFormat formatC
                              case createPatch createFormatC Nothing (InputFileContents baseBytes) (OutputFileContents outputB) noMetadataRequested Nothing noConstraintsRequested noDialectsRequested of
                                Left slapError -> assertFailureT ("create " <> Text.pack formatC <> " failed: " <> renderSlapError slapError)
                                Right (CreateResult patchC _) -> do
                                  case parseSome noDialectsRequested patchC of
                                    Left slapError -> assertFailureT ("re-parse " <> Text.pack formatC <> " failed: " <> renderSlapError slapError)
                                    Right parsedC -> do
                                      resultC <- applyPatch parsedC (InputFileContents baseBytes)
                                      case resultC of
                                        Left slapError -> assertFailureT ("re-apply " <> Text.pack formatC <> " failed: " <> renderSlapError slapError)
                                        Right (OutputFileContents outputC) ->
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
--
-- The stadium2 BPS row is the long pole of the entire suite (~11 s
-- single-thread); 'planRoundTrip' consults
-- 'Integration.HeavyTests.bpsCreateIsExpensive' so it ends up in
-- the heavy bucket without this builder having to know about
-- scheduling concerns directly.
createRoundTripTests :: IO BootstrapTargets -> FilePath -> FilePath
                     -> FilePath -> FilePath -> [MaybeTest]
createRoundTripTests getTargets dm4yBase dm4yBps
                     stadium2Base stadium2Bps =
  map planRoundTrip
    [ RoundTripCase "dm4y BPS"      dm4yBase     dm4yBps     "bps"
    , RoundTripCase "dm4y IPS"      dm4yBase     dm4yBps     "ips"
    , RoundTripCase "dm4y UPS"      dm4yBase     dm4yBps     "ups"
    , RoundTripCase "stadium2 BPS"  stadium2Base stadium2Bps "bps"
    , RoundTripCase "stadium2 IPS32" stadium2Base stadium2Bps "ips32"
    ]
  where
    planRoundTrip :: RoundTripCase -> MaybeTest
    planRoundTrip roundTrip =
      let basePath     = roundTripCaseBase   roundTrip
          patchPath    = roundTripCasePatch  roundTrip
          formatString = roundTripCaseFormat roundTrip
          label        = "create-round-trip/" ++ roundTripCaseName roundTrip
          tree         = testCase label $ do
                           (baseBytes, targetBytes) <- bootstrapTarget basePath patchPath
                           createAndVerify formatString baseBytes targetBytes
          isHeavy      = formatString == "bps"
                      && bpsCreateIsExpensive (FixtureName basePath)
      in if isHeavy then WillRunHeavy tree else WillRun tree

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
      case createPatch createFormat Nothing (InputFileContents baseBytes) (OutputFileContents targetBytes) noMetadataRequested Nothing noConstraintsRequested noDialectsRequested of
        Left slapError -> assertFailureT ("create " <> Text.pack formatString <> " failed: " <> renderSlapError slapError)
        Right (CreateResult patchBytes _) ->
          case parseSome noDialectsRequested patchBytes of
            Left slapError -> assertFailureT ("re-parse " <> Text.pack formatString <> " failed: " <> renderSlapError slapError)
            Right parsed -> do
              result <- applyPatch parsed (InputFileContents baseBytes)
              case result of
                Left slapError -> assertFailureT ("re-apply " <> Text.pack formatString <> " failed: " <> renderSlapError slapError)
                Right (OutputFileContents output) ->
                  assertEqual "round-trip SHA1" (sha1Hex targetBytes) (sha1Hex output)

-- | One row in 'createRoundTripTests' — the source ROM, patch path
-- the 'BootstrapTargets' look-up keys on, target format string, and
-- a short label that becomes the second segment of the test name
-- (@create-round-trip\/\<caseName\>@).
data RoundTripCase = RoundTripCase
  { roundTripCaseName    :: !String
  , roundTripCaseBase    :: !FilePath
  , roundTripCasePatch   :: !FilePath
  , roundTripCaseFormat  :: !String
  }

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
          ("expected success, got: " ++ Text.unpack (renderSlapError slapError))
        Right (CreateResult patchBytes _) ->
          case parseSome noDialectsRequested patchBytes of
            Left slapError -> assertFailure
              ("re-parse: " ++ Text.unpack (renderSlapError slapError))
            Right _ -> pure ()

  , testCase "smc-shape/IPS non-smc-sized target rejected with flag" $ do
      -- 4000 bytes (0xFA0) is not SMC-shaped: 4000 .&. 0xFFF == 0xFA0.
      let source = ByteString.replicate 0x2000 0x00
          target = ByteString.replicate 4000 0xFF
      case createWithSMC source target of
        Left (TruncationViolatesSMCShape _) -> pure ()
        Left other -> assertFailure
          ("expected TruncationViolatesSMCShape, got: " ++ Text.unpack (renderSlapError other))
        Right _ -> assertFailure
          "expected refusal, got successful create"

  , testCase "smc-shape/IPS target>=source: gate vacuous, succeeds" $ do
      -- No truncation marker would be emitted, so the SMC filter doesn't apply.
      let source = ByteString.replicate 0x1000 0x00
          target = ByteString.replicate 0x2000 0xFF
      case createWithSMC source target of
        Left slapError -> assertFailure
          ("expected success (no truncation), got: " ++ Text.unpack (renderSlapError slapError))
        Right _ -> pure ()

  , testCase "smc-shape/BPS rejected at constraint-acceptance layer" $
      -- The create entry point ('doCreate' in @app/Main.hs@) runs
      -- 'rejectIncompatibleConstraints' before invoking
      -- 'createPatch'; the constraint never reaches the
      -- per-format encoder. Exercise that check directly.
      case rejectIncompatibleConstraints (CreateDifferential CreateBPS) smcConstraints of
        Left (ConstraintNotSupported (SMCShapeConstraint :| []) LabelBPS) -> pure ()
        Left other -> assertFailure
          ("expected ConstraintNotSupported, got: " ++ Text.unpack (renderSlapError other))
        Right () -> assertFailure
          "expected refusal at create entry"

  , testCase "smc-shape/IPS non-smc-sized succeeds without flag" $ do
      -- Regression: without the flag, slap continues to emit the
      -- wire-valid truncation marker it always has.
      let source = ByteString.replicate 0x2000 0x00
          target = ByteString.replicate 4000 0xFF
      case createPatch (CreateDirect CreateIPS) Nothing
             (InputFileContents source) (OutputFileContents target)
             noMetadataRequested Nothing noConstraintsRequested noDialectsRequested of
        Left slapError -> assertFailure
          ("expected success (no flag), got: " ++ Text.unpack (renderSlapError slapError))
        Right _ -> pure ()

  , testCase "smc-shape/convert --to bps rejected at constraint layer" $
      -- The convert entry point ('doConvert' in @app/Main.hs@) runs
      -- 'rejectIncompatibleConstraints' before dispatching, so the
      -- user-facing rejection lands here long before any encoder
      -- runs. Exercise that check directly.
      case rejectIncompatibleConstraints (CreateDifferential CreateBPS) smcConstraints of
        Left (ConstraintNotSupported (SMCShapeConstraint :| []) LabelBPS) -> pure ()
        Left other -> assertFailure
          ("expected ConstraintNotSupported, got: " ++ Text.unpack (renderSlapError other))
        Right () -> assertFailure
          "expected refusal at convert entry"

  , testCase "smc-shape/source-less convert IPS->IPS refuses bad marker" $ do
      ipsPatch <- buildNonSMCShapedIPS
      case patchKind ipsPatch of
        Direct (Just contents) ->
          case convertDirect contents (CreateDirect CreateIPS)
                 noMetadataRequested smcConstraints noDialectsRequested of
            Left (TruncationViolatesSMCShape _) -> pure ()
            Left other -> assertFailure
              ("expected TruncationViolatesSMCShape, got: " ++ Text.unpack (renderSlapError other))
            Right _ -> assertFailure
              "expected refusal at encode gate"
        _ -> assertFailure "test fixture should expose PatchContents"
  ]
  where
    smcConstraints = noConstraintsRequested
      { requestedSMCShape = RequireSMCShapedTruncation }

    createWithSMC source target =
      createPatch (CreateDirect CreateIPS) Nothing
        (InputFileContents source) (OutputFileContents target)
        noMetadataRequested Nothing smcConstraints noDialectsRequested

    -- Build a parsed IPS patch whose post-EOF truncation marker
    -- declares a non-SMC-shaped target size. Constructed via the
    -- create path with constraints disabled so the produced patch
    -- carries the marker; then re-parsed so the @'Direct' ('Just' _)@
    -- bag is populated for the source-less convert path.
    buildNonSMCShapedIPS = do
      let source = ByteString.replicate 0x2000 0x00
          target = ByteString.replicate 4000 0xFF
      case createPatch (CreateDirect CreateIPS) Nothing
             (InputFileContents source) (OutputFileContents target)
             noMetadataRequested Nothing noConstraintsRequested noDialectsRequested of
        Left slapError -> assertFailure
          ("setup: create failed: " ++ Text.unpack (renderSlapError slapError))
          >> error "unreachable"
        Right (CreateResult patchBytes _) ->
          case parseSome noDialectsRequested patchBytes of
            Left slapError -> assertFailure
              ("setup: parse failed: " ++ Text.unpack (renderSlapError slapError))
              >> error "unreachable"
            Right parsed -> pure parsed

----------------------------------------------------------------------------
-- xdelta1 source-shape rejection
--
-- The format-in-practice admits exactly one source-list shape:
-- @[data segment, file source]@ in that order, per canonical xdelta
-- ('xdelta-1.1.4/xdelta.c:241-251' adds the data source,
-- 'xdmain.c:1539-1542' adds the from-file source — both unconditional)
-- and the xdelta.1 manpage (MacDonald 2001). The wire format's
-- structural capacity for arbitrary-length source lists is EDSIO
-- serialization plumbing, not format intent. Slap rejects off-spec
-- shapes at parse time with 'UnsupportedXDelta1Shape' (count or
-- ordering) or 'XDelta1UnknownInstructionTarget' (instruction names
-- a source index outside @{0, 1}@).
----------------------------------------------------------------------------

xdelta1ShapeRejectionTests :: [TestTree]
xdelta1ShapeRejectionTests =
  [ testCase "xdelta1-shape/rejects three sources" $
      let controlBytes = buildXDelta1Control
            [TestDataKind, TestFileKind, TestFileKind]
            []
      in case parseControlBytes controlBytes of
        Right _ -> assertFailure "expected parse failure for three-source xdelta1 patch"
        Left rendered -> do
          assertBool ("expected 'source list is not canonical': " ++ rendered)
            (ciContains "source list is not canonical" rendered)
          assertBool ("expected '3 sources' in: " ++ rendered)
            (ciContains "3 sources" rendered)

  , testCase "xdelta1-shape/rejects [file, data] ordering" $
      let controlBytes = buildXDelta1Control [TestFileKind, TestDataKind] []
      in case parseControlBytes controlBytes of
        Right _ -> assertFailure "expected parse failure for [file, data] ordering"
        Left rendered -> do
          assertBool ("expected 'source list is not canonical': " ++ rendered)
            (ciContains "source list is not canonical" rendered)
          assertBool ("expected '[file, data]' in: " ++ rendered)
            (ciContains "[file, data]" rendered)

  , testCase "xdelta1-shape/rejects empty source list" $
      let controlBytes = buildXDelta1Control [] []
      in case parseControlBytes controlBytes of
        Right _ -> assertFailure "expected parse failure for empty source list"
        Left rendered ->
          assertBool ("expected '0 sources' in: " ++ rendered)
            (ciContains "0 sources" rendered)

  , testCase "xdelta1-shape/rejects single data source" $
      let controlBytes = buildXDelta1Control [TestDataKind] []
      in case parseControlBytes controlBytes of
        Right _ -> assertFailure "expected parse failure for single-data source list"
        Left rendered ->
          assertBool ("expected '1 source: data' in: " ++ rendered)
            (ciContains "1 source: data" rendered)

  , testCase "xdelta1-shape/rejects single file source" $
      let controlBytes = buildXDelta1Control [TestFileKind] []
      in case parseControlBytes controlBytes of
        Right _ -> assertFailure "expected parse failure for single-file source list"
        Left rendered ->
          assertBool ("expected '1 source: file' in: " ++ rendered)
            (ciContains "1 source: file" rendered)

  , testCase "xdelta1-shape/rejects instruction targeting unknown source index" $
      let controlBytes = buildXDelta1Control
            [TestDataKind, TestFileKind]   -- canonical shape
            [(2, 0, 0)]                    -- index 2 is unknown
      in case parseControlBytes controlBytes of
        Right _ -> assertFailure "expected parse failure for unknown instruction target"
        Left rendered -> do
          assertBool ("expected 'instruction references source index 2' in: " ++ rendered)
            (ciContains "instruction references source index 2" rendered)
          assertBool ("expected '0 (data segment) or 1 (file source)' in: " ++ rendered)
            (ciContains "0 (data segment) or 1 (file source)" rendered)
  ]
  where
    parseControlBytes controlBytes =
      case parseControl NoVerifyFlagClear UncompressedPatch
                        (XDelta1ControlSegment controlBytes)
                        (XDelta1DataSegment ByteString.empty)
                        (XDelta1FromName (EncodedText EncodingLocale Text.empty))
                        (XDelta1ToName   (EncodedText EncodingLocale Text.empty)) of
        Left slapError         -> Left (Text.unpack (renderSlapError slapError))
        Right (Parsed patch _) -> Right patch

----------------------------------------------------------------------------
-- xdelta1 FLAG_NO_VERIFY: parse-side posture honored
----------------------------------------------------------------------------

-- | Three tests covering the parse-time encoding of xdelta1's
-- @FLAG_NO_VERIFY@ (bit 0 of the header's flags word) as the
-- 'XDelta1VerificationPosture' sum:
--
--   1. With the bit flipped on in an in-memory copy of a real
--      patch, 'parseXDelta1' produces 'CreatorOptedOutOfVerification'
--      and emits 'VerificationOptedOutByCreator LabelXDelta1'.
--   2. With the bit flipped on, 'parseSome' wires both
--      'verifySourceMD5' and 'verifyTargetMD5' to 'Nothing' and
--      passes the warning through 'patchAdvisories'.
--   3. Regression: the unflipped fixture parses with
--      'VerifyAgainstStoredMD5s' posture, no opt-out warning fires.
xdelta1NoVerifyTests :: FilePath -> [TestTree]
xdelta1NoVerifyTests fixturePath =
  [ testCase "xdelta1/FLAG_NO_VERIFY honored at parse" $ do
      originalBytes <- ByteString.readFile fixturePath
      let flippedBytes = flipNoVerifyBit originalBytes
      case parseXDelta1 (PatchFileContents flippedBytes) of
        Left err -> assertFailureT ("expected successful parse, got: " <> renderSlapError err)
        Right (Parsed patch warnings) -> do
          assertEqual "posture is CreatorOptedOutOfVerification"
            CreatorOptedOutOfVerification (xdelta1Verification patch)
          assertBool "VerificationOptedOutByCreator LabelXDelta1 warning is present"
            (VerificationOptedOutByCreator LabelXDelta1 `elem` warnings)
          assertBool "XDelta1NoVerifyWithDivergentSentinel warning is present"
            (XDelta1NoVerifyWithDivergentSentinel `elem` warnings)

  , testCase "xdelta1/FLAG_NO_VERIFY zeroes SomePatch verification fields" $ do
      originalBytes <- ByteString.readFile fixturePath
      let flippedBytes = flipNoVerifyBit originalBytes
      case parseSome noDialectsRequested (PatchFileContents flippedBytes) of
        Left err -> assertFailureT ("expected successful parse, got: " <> renderSlapError err)
        Right somePatch -> do
          let verification = patchVerification somePatch
          assertEqual "verifySourceMD5 is Nothing" Nothing (verifySourceMD5 verification)
          assertEqual "verifyTargetMD5 is Nothing" Nothing (verifyTargetMD5 verification)
          assertBool "VerificationOptedOutByCreator LabelXDelta1 reaches patchAdvisories"
            (VerificationOptedOutByCreator LabelXDelta1 `elem` patchAdvisories somePatch)
          assertBool "XDelta1NoVerifyWithDivergentSentinel reaches patchAdvisories"
            (XDelta1NoVerifyWithDivergentSentinel `elem` patchAdvisories somePatch)

  , testCase "xdelta1/unflipped fixture parses with VerifyAgainstStoredMD5s" $ do
      originalBytes <- ByteString.readFile fixturePath
      case parseXDelta1 (PatchFileContents originalBytes) of
        Left err -> assertFailureT ("expected successful parse, got: " <> renderSlapError err)
        Right (Parsed patch warnings) -> do
          case xdelta1Verification patch of
            VerifyAgainstStoredMD5s _      -> pure ()
            CreatorOptedOutOfVerification ->
              assertFailure "expected VerifyAgainstStoredMD5s posture on unflipped fixture"
          assertBool "no VerificationOptedOutByCreator warning on unflipped fixture"
            (VerificationOptedOutByCreator LabelXDelta1 `notElem` warnings)
          assertBool "no XDelta1NoVerifyWithDivergentSentinel on unflipped fixture"
            (XDelta1NoVerifyWithDivergentSentinel `notElem` warnings)
  ]
  where
    -- | Set bit 0 of byte 11 (the LSB of the BE flags word at offset 8).
    flipNoVerifyBit :: ByteString -> ByteString
    flipNoVerifyBit bytes = ByteString.concat
      [ ByteString.take 11 bytes
      , ByteString.singleton (ByteString.index bytes 11 .|. 0x01)
      , ByteString.drop 12 bytes
      ]

----------------------------------------------------------------------------
-- xdelta1 FLAG_FROM_COMPRESSED / FLAG_TO_COMPRESSED: apply refuses
--
-- Bits 1 and 2 of the header's flags word record that canonical
-- xdelta-1.x detected gzip-magic on the from- or to-file at delta
-- time and transparently decompressed it before computing the delta.
-- Slap does not implement that apply-time transparency, so it
-- refuses to proceed against the user's literal source bytes when
-- either bit is set. These three cases (FROM only, TO only, both)
-- exhaust the non-trivial corners of 'XDelta1FileAtDeltaTime' ×
-- 'XDelta1FileAtDeltaTime'; the (raw, raw) case is the success path
-- covered by the existing apply round-trip tests.
----------------------------------------------------------------------------

xdelta1InputPreCompressionTests :: FilePath -> [TestTree]
xdelta1InputPreCompressionTests fixturePath =
  [ inputPreCompressionCase
      "xdelta1/FROM_COMPRESSED parses as gzip stream and refuses apply"
      0x02
      (FileWasGzipStream, FileWasRawBytes)
      OnlyFromFileWasGzipStream
  , inputPreCompressionCase
      "xdelta1/TO_COMPRESSED parses as gzip stream and refuses apply"
      0x04
      (FileWasRawBytes, FileWasGzipStream)
      OnlyToFileWasGzipStream
  , inputPreCompressionCase
      "xdelta1/FROM_COMPRESSED+TO_COMPRESSED parse as gzip streams and refuse apply"
      0x06
      (FileWasGzipStream, FileWasGzipStream)
      BothFilesWereGzipStreams

  -- The previous three cases exercise the gate via wire-byte
  -- fiddling on a real fixture. This fourth case pins a degenerate
  -- corner that wire fiddling can't reach cheaply: 'xdelta1TargetLength'
  -- lives inside the EDSIO control segment (past gzip decompression),
  -- so constructing a target_length=0 flagged patch from on-disk
  -- bytes would mean rebuilding the control segment by hand.
  -- Constructing the 'XDelta1Patch' value directly is the right tool
  -- — the question being asked is whether 'applyXDelta1''s gate fires
  -- before its target-length guards, which is independent of the
  -- parse pipeline.
  , testCase "xdelta1/empty target with FROM_COMPRESSED refuses apply" $ do
      let emptyName = EncodedText EncodingLocale Text.empty
          patch = XDelta1Patch
            { xdelta1FromName         = XDelta1FromName emptyName
            , xdelta1ToName           = XDelta1ToName   emptyName
            , xdelta1Verification     = CreatorOptedOutOfVerification
            , xdelta1PatchCompression = UncompressedPatch
            , xdelta1FromAtDeltaTime  = FileWasGzipStream
            , xdelta1ToAtDeltaTime    = FileWasRawBytes
            , xdelta1TargetLength     = FileSize 0
            , xdelta1SourceName       = XDelta1FromName emptyName
            , xdelta1SourceMD5        = Nothing
            , xdelta1SourceLength     = FileSize 0
            , xdelta1SourceOffsetMode = AbsoluteOffsets
            , xdelta1Instructions     = []
            , xdelta1DataSegment      = ByteString.empty
            }
      case XDelta1.applyXDelta1 patch (InputFileContents ByteString.empty) of
        Left (XDelta1InputPreCompressionUnsupported OnlyFromFileWasGzipStream) -> pure ()
        Left other -> assertFailure
          ("expected XDelta1InputPreCompressionUnsupported OnlyFromFileWasGzipStream, got: "
           ++ Text.unpack (renderSlapError other))
        Right _ -> assertFailure
          "expected apply refusal even at target_length=0; got successful apply"
  ]
  where
    inputPreCompressionCase label flagBits expectedFields expectedSides =
      testCase label $ do
        originalBytes <- ByteString.readFile fixturePath
        let flippedBytes = setFlagBits flagBits originalBytes
        case parseXDelta1 (PatchFileContents flippedBytes) of
          Left err -> assertFailureT ("expected successful parse, got: " <> renderSlapError err)
          Right (Parsed patch _) -> do
            assertEqual "(xdelta1FromAtDeltaTime, xdelta1ToAtDeltaTime) match the flipped bits"
              expectedFields
              (xdelta1FromAtDeltaTime patch, xdelta1ToAtDeltaTime patch)
            case XDelta1.applyXDelta1 patch (InputFileContents ByteString.empty) of
              Left (XDelta1InputPreCompressionUnsupported sides) ->
                assertEqual "apply refuses with the expected XDelta1GzipStreamInputs"
                  expectedSides sides
              Left other -> assertFailure
                ("expected XDelta1InputPreCompressionUnsupported, got: " ++ Text.unpack (renderSlapError other))
              Right _ -> assertFailure
                "expected apply refusal, got successful apply"

    -- | OR @bits@ into byte 11 of the patch (the LSB of the BE flags
    -- word at offset 8). Existing bits — @FLAG_NO_VERIFY@ /
    -- @FLAG_PATCH_COMPRESSED@ — are preserved.
    setFlagBits :: Word8 -> ByteString -> ByteString
    setFlagBits bits bytes = ByteString.concat
      [ ByteString.take 11 bytes
      , ByteString.singleton (ByteString.index bytes 11 .|. bits)
      , ByteString.drop 12 bytes
      ]

-- | Test-local source-kind vocabulary for 'buildXDelta1Control'.
-- The parser's wire-kind enum is intentionally not exported (it is
-- internal to 'Slap.XDelta1.Parse'); the hand-crafted-bytes tests
-- need /some/ representation of "what byte goes in this slot" so
-- they can build off-canonical control segments. Defined locally so
-- the parser-internal vocabulary stays unexported and the test
-- bodies read with kind names that match the wire ordering.
data TestSourceKind = TestDataKind | TestFileKind

-- | Build a hand-crafted xdelta1 control segment carrying the given
-- source-kind list and instruction list. Each source has empty name,
-- zero MD5, zero length, and absolute-offset mode; each instruction
-- carries (index, offset, length). The returned bytes are the
-- decompressed control segment (no gzip wrapper) suitable for
-- 'parseControl' directly.
--
-- Layout (all integers EDSIO varints unless noted):
--
-- > 4 bytes : ST_XdeltaControl type tag (BE)
-- > 4 bytes : allocation upper bound (BE; read and discarded by parser)
-- > 16 bytes: target MD5 (zeros)
-- > varint  : target length (0)
-- > 1 byte  : has_data flag (0, ignored)
-- > varint  : source count
-- > [per source]
-- >   varint    : name length (0)
-- >   16 bytes  : source MD5 (zeros)
-- >   varint    : source length (0)
-- >   1 byte    : kind (1 = data segment, 0 = file)
-- >   1 byte    : offset mode (0 = absolute)
-- > varint  : instruction count
-- > [per instruction] index, offset, length (varints)
buildXDelta1Control
  :: [TestSourceKind]
  -> [(Int, Int, Int)]      -- ^ (instruction index, offset, length) tuples
  -> ByteString
buildXDelta1Control sourceKinds instructions = ByteString.concat
  [ word32BEBytes xdelta1ControlTypeTag        -- ST_XdeltaControl
  , word32BEBytes xdelta1ControlAllocationBound -- parser scratch bound
  , ByteString.replicate 16 0x00          -- target MD5
  , edsioVarintByte 0                     -- target length
  , ByteString.singleton 0x00             -- has_data
  , edsioVarintByte (length sourceKinds)
  , ByteString.concat (map encodeSource sourceKinds)
  , edsioVarintByte (length instructions)
  , ByteString.concat (map encodeInstruction instructions)
  ]
  where
    encodeSource :: TestSourceKind -> ByteString
    encodeSource kind = ByteString.concat
      [ edsioVarintByte 0                 -- name length
      , sourceMD5ForKind                  -- source MD5
      , edsioVarintByte 0                 -- source length
      , ByteString.singleton (case kind of
          TestDataKind -> 0x01            -- nonzero = data segment
          TestFileKind -> 0x00)
      , ByteString.singleton 0x00         -- absolute offsets
      ]
      where
        -- The parser checks the data-record's MD5 against the actual
        -- data-segment bytes under the default verify posture
        -- (which 'parseControlBytes' uses); the test fixtures pass
        -- an empty data segment, whose MD5 is
        -- 'xdelta1EmptyInputMD5Sentinel'. Writing the sentinel here
        -- keeps the structural consistency invariant the parser
        -- expects so these source-shape tests can focus on the
        -- shape failure they're testing rather than tripping the
        -- MD5 check first. File-source records aren't checked
        -- against external bytes at parse time, so the byte value
        -- there is incidental.
        sourceMD5ForKind = case kind of
          TestDataKind -> unMD5Hash xdelta1EmptyInputMD5Sentinel
          TestFileKind -> ByteString.replicate 16 0x00

    encodeInstruction :: (Int, Int, Int) -> ByteString
    encodeInstruction (idx, off, len) = ByteString.concat
      [ edsioVarintByte idx
      , edsioVarintByte off
      , edsioVarintByte len
      ]

    -- | EDSIO varint encoding for non-negative values that fit in a
    -- single byte (i.e. < 128). All hand-crafted test values stay
    -- small; this helper does not need a multi-byte path.
    edsioVarintByte :: Int -> ByteString
    edsioVarintByte n
      | n < 0 || n >= 128 = error ("edsioVarintByte: out of single-byte range: " ++ show n)
      | otherwise         = ByteString.singleton (fromIntegral n)

----------------------------------------------------------------------------
-- 9. Dialect-axis rejection (in-process)
----------------------------------------------------------------------------

-- | The PPF1-origin dialect axis must be refused by formats that don't
-- have it (apply/undo/info/explain/create paths) and honored on the
-- convert path when /either/ side of the chain admits it.
dialectAxisRejectionTests :: [TestTree]
dialectAxisRejectionTests =
  [ testCase "dialects/--is-amiga-patch on BPS apply rejects" $
      -- Apply-side: 'rejectIncompatibleDialects' run against the
      -- parsed patch's 'patchFormat' must refuse, because BPS has no
      -- PPF1-origin axis. Exercise the check directly.
      case rejectIncompatibleDialects
             (acceptedDialects LabelBPS) LabelBPS amigaDialects of
        Left (DialectNotSupported (PPF1OriginAxis :| []) LabelBPS) -> pure ()
        Left other -> assertFailure
          ("expected DialectNotSupported, got: " ++ Text.unpack (renderSlapError other))
        Right () -> assertFailure
          "expected refusal at apply entry"

  , testCase "dialects/create --to bps rejects --is-amiga-patch" $
      -- Create-side: 'rejectIncompatibleDialects' is run with the
      -- target 'createFormatLabel' before any IO. BPS doesn't carry a
      -- PPF1-origin axis, so the flag is refused.
      case rejectIncompatibleDialects
             (acceptedDialects (createFormatLabel (CreateDifferential CreateBPS)))
             (createFormatLabel (CreateDifferential CreateBPS))
             amigaDialects of
        Left (DialectNotSupported (PPF1OriginAxis :| []) LabelBPS) -> pure ()
        Left other -> assertFailure
          ("expected DialectNotSupported, got: " ++ Text.unpack (renderSlapError other))
        Right () -> assertFailure
          "expected refusal at create entry"

  , testCase "dialects/convert PPF1->BPS honors --is-amiga-patch on input" $ do
      -- Convert-side union check: with PPF1 on the input and BPS on
      -- the output, the chain admits PPF1OriginAxis (PPF1 admits it,
      -- BPS doesn't, but the union covers it). Build an Amiga-origin
      -- PPF1 patch by encoding with PPF1OriginAmiga, then re-parse
      -- with the same origin and round-trip via apply.
      let source = ByteString.replicate 64 0x11
          target = ByteString.pack [if i == 10 then 0xAA else 0x11 | i <- [0..63 :: Int]]
      case createPatch (CreateDirect CreatePPF1) Nothing
             (InputFileContents source) (OutputFileContents target)
             noMetadataRequested Nothing noConstraintsRequested amigaDialects of
        Left slapError -> assertFailure
          ("amiga create failed: " ++ Text.unpack (renderSlapError slapError))
        Right (CreateResult patchBytes _) ->
          case parseSome amigaDialects patchBytes of
            Left slapError -> assertFailure
              ("amiga parse failed: " ++ Text.unpack (renderSlapError slapError))
            Right parsed ->
              case patchKind parsed of
                Direct (Just _) ->
                  -- Sanity-check the union check would accept.
                  case rejectIncompatibleDialects
                         (acceptedDialects (patchFormat parsed)
                            `Set.union`
                          acceptedDialects LabelBPS)
                         LabelBPS amigaDialects of
                    Right () -> pure ()
                    Left slapError -> assertFailure
                      ("union check rejected: " ++ Text.unpack (renderSlapError slapError))
                _ -> assertFailure "expected Direct (Just _) for PPF1 patch"
  ]
  where
    amigaDialects = noDialectsRequested
      { requestedPPF1Origin = PPF1OriginAmiga }
