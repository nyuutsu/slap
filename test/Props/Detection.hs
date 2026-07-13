-- | Format detection heuristics.
--
-- Most formats use magic bytes. DPS has no magic and must be detected
-- via a structural walk of its header + tentative record parse.
-- These tests exercise the DPS heuristic on both valid and adversarial
-- inputs.
module Props.Detection (detectionTests) where

import qualified Slap.DPS.Types as DPS
import qualified Slap.DPS.Parse as DPS
import Slap.Status (SlapError(..), ByteParserError(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.Text (EncodingName(EncodingUtf8))
import Slap.FileContents (PatchFileContents(..))
import Slap.Binary (replicateLength)
import Slap.Measure (Length(..), byteLength)

import qualified Data.ByteString as ByteString
import Test.Tasty
import Test.Tasty.HUnit

detectionTests :: TestTree
detectionTests = testGroup "DPS Detection"
  [ testCase "valid-dps-zero-records" test_isDPSValidZeroRecords
  , testCase "valid-header-invalid-record-mode" test_isDPSInvalidRecordMode
  , testCase "printable-ascii-not-dps" test_isDPSPrintableAsciiNotDPS
  , testCase "parse-rejects-trailing-fragment" test_parseDPSRejectsTrailingFragment
  ]

-- | Valid DPS with zero records: 198 bytes, correct version and stability.
test_isDPSValidZeroRecords :: IO ()
test_isDPSValidZeroRecords = do
  let metadata = replicateLength DPS.dpsMetadataSize 0    -- 192 bytes of nulls
      stabilityByte = ByteString.singleton 0                    -- stable
      versionByte = ByteString.singleton 1                      -- DPSVersion1
      originalSize = ByteString.pack [0x00, 0x00, 0x00, 0x00]  -- 4 bytes LE
      input = metadata <> stabilityByte <> versionByte <> originalSize
  assertEqual "input length" DPS.dpsMinimumFileSize (byteLength input)
  assertBool "isDPS returns True" (DPS.isDPS input)

-- | Valid header but first record byte is an invalid mode (2).
test_isDPSInvalidRecordMode :: IO ()
test_isDPSInvalidRecordMode = do
  let metadata = replicateLength DPS.dpsMetadataSize 0
      stabilityByte = ByteString.singleton 0
      versionByte = ByteString.singleton 1
      originalSize = ByteString.pack [0x00, 0x00, 0x00, 0x00]
      invalidMode = ByteString.singleton 2  -- not 0 or 1
      input = metadata <> stabilityByte <> versionByte <> originalSize <> invalidMode
  assertEqual "input length" (DPS.dpsMinimumFileSize <> Length 1) (byteLength input)
  assertBool "isDPS returns False" (not (DPS.isDPS input))

-- | 198 bytes of 'A': version byte at dpsVersionOffset is 0x41, not 1.
test_isDPSPrintableAsciiNotDPS :: IO ()
test_isDPSPrintableAsciiNotDPS = do
  let input = replicateLength DPS.dpsMinimumFileSize 0x41
  assertBool "isDPS returns False" (not (DPS.isDPS input))

-- | The parse-side complement of 'test_isDPSInvalidRecordMode': a valid
-- header followed by a single trailing byte — too few to begin a record.
-- DPS records run to EOF with nothing after the last, so detection
-- rejects this (records do not consume the file exactly) and the parser
-- must agree, refusing with a truncated-record error rather than
-- silently dropping the tail as a zero-record patch.
test_parseDPSRejectsTrailingFragment :: IO ()
test_parseDPSRejectsTrailingFragment = do
  let metadata = replicateLength DPS.dpsMetadataSize 0
      input = metadata
              <> ByteString.singleton 0            -- stability flag: stable
              <> ByteString.singleton 1            -- format version: 1
              <> ByteString.pack [0, 0, 0, 0]      -- original size
              <> ByteString.singleton 0x02         -- one trailing byte
  case DPS.parseDPS EncodingUtf8 (PatchFileContents input) of
    Left (ParseError LabelDPS (ByteParserTruncatedRecord{})) -> pure ()
    Left _  -> assertFailure "expected a DPS truncated-record rejection, got a different parse error"
    Right _ -> assertFailure "expected parse to reject the trailing fragment, but it succeeded"
