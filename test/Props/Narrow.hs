-- | Negative coverage for the narrowing layer: each direct format
-- with a per-record offset bound rejects offsets one byte past its
-- maximum, surfacing a typed 'OffsetExceedsBound' tagged with the
-- format's 'FormatLabel'. These are the structural counterparts to
-- the round-trip tests (which only exercise in-bounds inputs).
module Props.Narrow (narrowTests) where

import qualified Data.ByteString as ByteString

import Slap.APSN64.Types  (apsN64Limits)
import Slap.PCHTXT.Types  (pchtxtLimits)
import Slap.PMSR.Types    (pmsrLimits)
import Slap.FormatLabel   (FormatLabel(..))
import Slap.Measure       (Offset(..), Hunk(..), MaxOffset(..))
import Slap.Narrow        (NarrowingFailure(..), narrowHunk)

import Test.Tasty
import Test.Tasty.HUnit

narrowTests :: TestTree
narrowTests = testGroup "Slap.Narrow rejection cases"
  [ testCase "APSN64 rejects offset 2^32"  apsN64RejectsOverflow
  , testCase "PCHTXT rejects offset 2^32"  pchtxtRejectsOverflow
  , testCase "PMSR rejects offset 2^32"    pmsrRejectsOverflow
  ]

apsN64RejectsOverflow :: Assertion
apsN64RejectsOverflow =
  case narrowHunk apsN64Limits (Hunk (Offset 0x100000000) (ByteString.singleton 0xFF)) of
    Left (OffsetExceedsBound LabelAPSN64 _ (MaxOffset (Offset 0xFFFFFFFF))) -> pure ()
    other -> assertFailure ("expected APSN64 OffsetExceedsBound, got " ++ show other)

pchtxtRejectsOverflow :: Assertion
pchtxtRejectsOverflow =
  case narrowHunk pchtxtLimits (Hunk (Offset 0x100000000) (ByteString.singleton 0xFF)) of
    Left (OffsetExceedsBound LabelPCHTXT _ (MaxOffset (Offset 0xFFFFFFFF))) -> pure ()
    other -> assertFailure ("expected PCHTXT OffsetExceedsBound, got " ++ show other)

pmsrRejectsOverflow :: Assertion
pmsrRejectsOverflow =
  case narrowHunk pmsrLimits (Hunk (Offset 0x100000000) (ByteString.singleton 0xFF)) of
    Left (OffsetExceedsBound LabelPMSR _ (MaxOffset (Offset 0xFFFFFFFF))) -> pure ()
    other -> assertFailure ("expected PMSR OffsetExceedsBound, got " ++ show other)
