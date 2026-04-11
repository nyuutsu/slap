-- | Format detection heuristics.
--
-- Most formats use magic bytes. DPS has no magic and must be detected
-- via a structural walk of its header + tentative record parse.
-- These tests exercise the DPS heuristic on both valid and adversarial
-- inputs.
module Props.Detection (detectionTests) where

import qualified Slap.DPS.Types as DPS
import qualified Slap.DPS.Parse as DPS

import qualified Data.ByteString as ByteString
import Test.Tasty
import Test.Tasty.HUnit

detectionTests :: TestTree
detectionTests = testGroup "DPS Detection"
  [ testCase "valid-dps-zero-records" test_isDPSValidZeroRecords
  , testCase "valid-header-invalid-record-mode" test_isDPSInvalidRecordMode
  , testCase "printable-ascii-not-dps" test_isDPSPrintableAsciiNotDPS
  ]

-- | Valid DPS with zero records: 198 bytes, correct version and stability.
test_isDPSValidZeroRecords :: IO ()
test_isDPSValidZeroRecords = do
  let metadata = ByteString.replicate DPS.dpsMetadataSize 0    -- 192 bytes of nulls
      stabilityByte = ByteString.singleton 0                    -- stable
      versionByte = ByteString.singleton 1                      -- DPSVersion1
      originalSize = ByteString.pack [0x00, 0x00, 0x00, 0x00]  -- 4 bytes LE
      input = metadata <> stabilityByte <> versionByte <> originalSize
  assertEqual "input length" DPS.dpsMinimumFileSize (ByteString.length input)
  assertBool "isDPS returns True" (DPS.isDPS input)

-- | Valid header but first record byte is an invalid mode (2).
test_isDPSInvalidRecordMode :: IO ()
test_isDPSInvalidRecordMode = do
  let metadata = ByteString.replicate DPS.dpsMetadataSize 0
      stabilityByte = ByteString.singleton 0
      versionByte = ByteString.singleton 1
      originalSize = ByteString.pack [0x00, 0x00, 0x00, 0x00]
      invalidMode = ByteString.singleton 2  -- not 0 or 1
      input = metadata <> stabilityByte <> versionByte <> originalSize <> invalidMode
  assertEqual "input length" (DPS.dpsMinimumFileSize + 1) (ByteString.length input)
  assertBool "isDPS returns False" (not (DPS.isDPS input))

-- | 198 bytes of 'A': version byte at dpsVersionOffset is 0x41, not 1.
test_isDPSPrintableAsciiNotDPS :: IO ()
test_isDPSPrintableAsciiNotDPS = do
  let input = ByteString.replicate DPS.dpsMinimumFileSize 0x41
  assertBool "isDPS returns False" (not (DPS.isDPS input))
