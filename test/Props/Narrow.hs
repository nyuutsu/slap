-- | Negative coverage for the narrowing layer: each direct format
-- with a per-record offset bound rejects offsets one byte past its
-- maximum, surfacing a typed 'OffsetExceedsBound' tagged with the
-- format's 'FormatLabel'. These are the structural counterparts to
-- the round-trip tests (which only exercise in-bounds inputs).
--
-- Also: targeted coverage for 'splitUndoHunks' (the create-time
-- producer for 'SplitUndoHunk'), exercising the zero-padding path
-- when a piece extends past the source ROM's end.
module Props.Narrow (narrowTests) where

import qualified Data.ByteString as ByteString

import Slap.APSN64.Types  (apsN64Limits)
import Slap.PCHTXT.Types  (pchtxtLimits)
import Slap.PMSR.Types    (pmsrLimits)
import Slap.PPF3.Types    (ppf3MaxRecordPayload)
import Slap.FormatLabel   (FormatLabel(..))
import Slap.Measure       (Offset(..), Hunk(..), MaxOffset(..),
                           splitHunksUnbounded, splitUndoHunks,
                           splitUndoOffset, splitUndoPayload,
                           splitUndoOriginal)
import Slap.Narrow        (NarrowingFailure(..), narrowHunks)

import Test.Tasty
import Test.Tasty.HUnit

narrowTests :: TestTree
narrowTests = testGroup "Slap.Narrow rejection cases"
  [ testCase "APSN64 rejects offset 2^32"  apsN64RejectsOverflow
  , testCase "PCHTXT rejects offset 2^32"  pchtxtRejectsOverflow
  , testCase "PMSR rejects offset 2^32"    pmsrRejectsOverflow
  , testCase "splitUndoHunks slices and zero-pads past source end"
             splitUndoHunksSlicesAndPads
  ]

overflowingHunk :: [Hunk]
overflowingHunk = [Hunk (Offset 0x100000000) (ByteString.singleton 0xFF)]

apsN64RejectsOverflow :: Assertion
apsN64RejectsOverflow =
  case narrowHunks apsN64Limits (splitHunksUnbounded overflowingHunk) of
    Left (OffsetExceedsBound LabelAPSN64 _ (MaxOffset (Offset 0xFFFFFFFF))) -> pure ()
    other -> assertFailure ("expected APSN64 OffsetExceedsBound, got " ++ show other)

pchtxtRejectsOverflow :: Assertion
pchtxtRejectsOverflow =
  case narrowHunks pchtxtLimits (splitHunksUnbounded overflowingHunk) of
    Left (OffsetExceedsBound LabelPCHTXT _ (MaxOffset (Offset 0xFFFFFFFF))) -> pure ()
    other -> assertFailure ("expected PCHTXT OffsetExceedsBound, got " ++ show other)

pmsrRejectsOverflow :: Assertion
pmsrRejectsOverflow =
  case narrowHunks pmsrLimits (splitHunksUnbounded overflowingHunk) of
    Left (OffsetExceedsBound LabelPMSR _ (MaxOffset (Offset 0xFFFFFFFF))) -> pure ()
    other -> assertFailure ("expected PMSR OffsetExceedsBound, got " ++ show other)

-- | A 600-byte payload at offset 100 against a 500-byte source ROM
-- splits into ⌈600 / 255⌉ = 3 pieces with offsets 100, 355, 610.
-- Original-bytes are pulled from source[100..354] (fully in source),
-- source[355..499] followed by 110 zero bytes (partial overflow), and
-- 90 zero bytes (entirely past source).
splitUndoHunksSlicesAndPads :: Assertion
splitUndoHunksSlicesAndPads = do
  let source  = ByteString.pack [fromIntegral (i `mod` 256) | i <- [0 .. 499 :: Int]]
      payload = ByteString.replicate 600 0xAB
      pieces  = splitUndoHunks ppf3MaxRecordPayload source
                  [Hunk (Offset 100) payload]
  case pieces of
    [piece1, piece2, piece3] -> do
      assertEqual "piece1 offset"  (Offset 100) (splitUndoOffset piece1)
      assertEqual "piece2 offset"  (Offset 355) (splitUndoOffset piece2)
      assertEqual "piece3 offset"  (Offset 610) (splitUndoOffset piece3)
      assertEqual "piece1 payload" 255 (ByteString.length (splitUndoPayload piece1))
      assertEqual "piece2 payload" 255 (ByteString.length (splitUndoPayload piece2))
      assertEqual "piece3 payload"  90 (ByteString.length (splitUndoPayload piece3))
      assertEqual "piece1 original (in-bounds slice)"
        (ByteString.take 255 (ByteString.drop 100 source))
        (splitUndoOriginal piece1)
      assertEqual "piece2 original (partial overflow + zero pad)"
        (ByteString.drop 355 source <> ByteString.replicate 110 0)
        (splitUndoOriginal piece2)
      assertEqual "piece3 original (all zero past source)"
        (ByteString.replicate 90 0)
        (splitUndoOriginal piece3)
    other -> assertFailure ("expected 3 pieces, got " ++ show (length other))
