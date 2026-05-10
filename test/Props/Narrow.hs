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
import Slap.IPS.Types     (ipsLimits, ips32Limits)
import Slap.PCHTXT.Types  (pchtxtLimits)
import Slap.PMSR.Types    (pmsrLimits)
import Slap.PPF1.Types    (ppf1Limits)
import Slap.PPF2.Types    (ppf2Limits)
import Slap.PPF3.Types    (ppf3MaxRecordPayload)
import Slap.FormatLabel   (FormatLabel(..))
import Slap.Measure       (Offset(..), Length(..), Hunk(..),
                           ActualOffset(..), MaxOffset(..),
                           splitHunks, splitHunksUnbounded, splitOffset,
                           splitPayload, splitUndoHunks, splitUndoOffset,
                           splitUndoPayload, splitUndoOriginal)
import Slap.Narrow        (NarrowingFailure(..), narrowHunks)

import Test.Tasty
import Test.Tasty.HUnit

narrowTests :: TestTree
narrowTests = testGroup "Slap.Narrow rejection cases"
  [ testCase "APSN64 rejects offset 2^32"   apsN64RejectsOverflow
  , testCase "PCHTXT rejects offset 2^32"   pchtxtRejectsOverflow
  , testCase "PMSR rejects offset 2^32"     pmsrRejectsOverflow
  , testCase "PPF1 rejects offset 2^32"     ppf1RejectsOverflow
  , testCase "PPF2 rejects offset 2^32"     ppf2RejectsOverflow
  , testCase "IPS rejects offset 2^24"      ipsRejectsOverflow
  , testCase "IPS32 rejects offset 2^32"    ips32RejectsOverflow
  , testCase "splitHunks slices payloads at the per-format cap"
             splitHunksAtCap
  , testCase "splitUndoHunks slices and zero-pads past source end"
             splitUndoHunksSlicesAndPads
  ]

overflowingHunk :: [Hunk]
overflowingHunk = [Hunk (Offset 0x100000000) (ByteString.singleton 0xFF)]

apsN64RejectsOverflow :: Assertion
apsN64RejectsOverflow =
  case narrowHunks apsN64Limits (splitHunksUnbounded overflowingHunk) of
    Left (OffsetExceedsBound LabelAPSN64
            (ActualOffset (Offset 0x100000000))
            (MaxOffset    (Offset 0xFFFFFFFF))) -> pure ()
    other -> assertFailure ("expected APSN64 OffsetExceedsBound, got " ++ show other)

pchtxtRejectsOverflow :: Assertion
pchtxtRejectsOverflow =
  case narrowHunks pchtxtLimits (splitHunksUnbounded overflowingHunk) of
    Left (OffsetExceedsBound LabelPCHTXT
            (ActualOffset (Offset 0x100000000))
            (MaxOffset    (Offset 0xFFFFFFFF))) -> pure ()
    other -> assertFailure ("expected PCHTXT OffsetExceedsBound, got " ++ show other)

pmsrRejectsOverflow :: Assertion
pmsrRejectsOverflow =
  case narrowHunks pmsrLimits (splitHunksUnbounded overflowingHunk) of
    Left (OffsetExceedsBound LabelPMSR
            (ActualOffset (Offset 0x100000000))
            (MaxOffset    (Offset 0xFFFFFFFF))) -> pure ()
    other -> assertFailure ("expected PMSR OffsetExceedsBound, got " ++ show other)

ppf1RejectsOverflow :: Assertion
ppf1RejectsOverflow =
  case narrowHunks ppf1Limits (splitHunksUnbounded overflowingHunk) of
    Left (OffsetExceedsBound LabelPPF1
            (ActualOffset (Offset 0x100000000))
            (MaxOffset    (Offset 0xFFFFFFFF))) -> pure ()
    other -> assertFailure ("expected PPF1 OffsetExceedsBound, got " ++ show other)

ppf2RejectsOverflow :: Assertion
ppf2RejectsOverflow =
  case narrowHunks ppf2Limits (splitHunksUnbounded overflowingHunk) of
    Left (OffsetExceedsBound LabelPPF2
            (ActualOffset (Offset 0x100000000))
            (MaxOffset    (Offset 0xFFFFFFFF))) -> pure ()
    other -> assertFailure ("expected PPF2 OffsetExceedsBound, got " ++ show other)

-- | IPS's 24-bit offset cap is two orders of magnitude tighter than
-- the 32-bit caps the other rejection cases share, so this test
-- builds its own one-byte-over-the-line hunk rather than reusing
-- 'overflowingHunk'.
ipsRejectsOverflow :: Assertion
ipsRejectsOverflow =
  let oneByteOver = [Hunk (Offset 0x1000000) (ByteString.singleton 0xFF)]
  in case narrowHunks ipsLimits (splitHunksUnbounded oneByteOver) of
    Left (OffsetExceedsBound LabelIPS
            (ActualOffset (Offset 0x1000000))
            (MaxOffset    (Offset 0xFFFFFF))) -> pure ()
    other -> assertFailure ("expected IPS OffsetExceedsBound, got " ++ show other)

ips32RejectsOverflow :: Assertion
ips32RejectsOverflow =
  case narrowHunks ips32Limits (splitHunksUnbounded overflowingHunk) of
    Left (OffsetExceedsBound LabelIPS32
            (ActualOffset (Offset 0x100000000))
            (MaxOffset    (Offset 0xFFFFFFFF))) -> pure ()
    other -> assertFailure ("expected IPS32 OffsetExceedsBound, got " ++ show other)

-- | A 600-byte payload at offset 100 split at a cap of 255 produces
-- three pieces with payloads of 255 + 255 + 90 bytes at offsets 100,
-- 355, 610. Parallels 'splitUndoHunksSlicesAndPads' but for the
-- regular write-record splitter; pins the cap-respecting behavior
-- every direct-format encoder relies on for its 'Word8'/'Word32'
-- length-field truncation safety.
splitHunksAtCap :: Assertion
splitHunksAtCap =
  let payload = ByteString.pack [fromIntegral (i `mod` 256) | i <- [0 .. 599 :: Int]]
      pieces  = splitHunks (Length 255) [Hunk (Offset 100) payload]
  in case pieces of
    [piece1, piece2, piece3] -> do
      assertEqual "piece1 offset"  (Offset 100) (splitOffset piece1)
      assertEqual "piece2 offset"  (Offset 355) (splitOffset piece2)
      assertEqual "piece3 offset"  (Offset 610) (splitOffset piece3)
      assertEqual "piece1 payload" (ByteString.take 255 payload)
                                    (splitPayload piece1)
      assertEqual "piece2 payload" (ByteString.take 255 (ByteString.drop 255 payload))
                                    (splitPayload piece2)
      assertEqual "piece3 payload" (ByteString.drop 510 payload)
                                    (splitPayload piece3)
    other -> assertFailure ("expected 3 pieces, got " ++ show (length other))

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
