-- | Properties for 'Slap.VCDIFF.Apply.resolveCopyAddress' — the pure
-- resolver that turns a COPY's decoded superstring address into the
-- physical read apply executes: a bulk read from the source file, a
-- bulk in-buffer copy of settled output, or an overrunning run-length
-- expansion. Inputs are generated within the parse-side core
-- invariants (no read at or past the write head, no read crossing the
-- segment boundary), matching the resolver's documented contract.
module Props.ResolveCopyAddress (resolveCopyAddressTests) where

import Slap.VCDIFF.Apply
  ( CopyRead(..), TargetExpansion(..), WindowWriteContext(..)
  , resolveCopyAddress )
import Slap.VCDIFF.Types (SourceSegment(..), SegmentOrigin(..))
import Slap.Measure (Offset(..), Length(..), ReadOffset(..), WritePosition(..))

import Test.Tasty
import Test.Tasty.HUnit
import Test.Tasty.QuickCheck

resolveCopyAddressTests :: TestTree
resolveCopyAddressTests = testGroup "resolveCopyAddress"
  [ testGroup "segment-backed reads"
      [ testCase "source-file segment, address inside: bulk source read"
          unit_sourceFileSegmentRead
      , testCase "target-backed segment, address inside: bulk in-buffer copy"
          unit_targetBackedSegmentRead
      ]
  , testGroup "own-output reads"
      [ testCase "no segment: the address is window-relative against T alone"
          unit_noSegmentReadsOwnOutput
      , testCase "address past the segment, read settled: bulk in-buffer copy"
          unit_settledSelfRead
      , testCase "read one byte behind the head: byte-run expansion"
          unit_byteRunExpansion
      , testCase "read further behind but overrunning: forward expansion"
          unit_forwardExpansion
      , testCase "zero-length read at the head is a settled no-op"
          unit_zeroLengthAtHead
      ]
  , testGroup "properties"
      [ testProperty "own-output arms partition on the overrun test"
          prop_ownOutputPartition
      , testProperty "the resolved read is placed absolutely"
          prop_ownOutputPlacement
      ]
  ]

-- | A window whose output begins at 100 with 10 bytes produced: the
-- write head sits at 110. Nonzero base on purpose, so a resolver that
-- forgot to place reads absolutely cannot pass.
midWindowContext :: WindowWriteContext
midWindowContext = WindowWriteContext
  { windowOutputBase    = WritePosition (Offset 100)
  , windowProducedSoFar = Length 10
  }

-- | A 40-byte segment cut from position 7 of its origin.
segmentOfOrigin :: SegmentOrigin -> SourceSegment
segmentOfOrigin origin = SourceSegment origin (Offset 7) (Length 40)

unit_sourceFileSegmentRead :: Assertion
unit_sourceFileSegmentRead =
  resolveCopyAddress (Just (segmentOfOrigin FromSourceFile))
                     midWindowContext (Length 5) (Offset 12)
    @?= CopyFromSource (ReadOffset (Offset 19)) (Length 5)
        -- segment position 7 + address 12

unit_targetBackedSegmentRead :: Assertion
unit_targetBackedSegmentRead =
  resolveCopyAddress (Just (segmentOfOrigin FromProducedTarget))
                     midWindowContext (Length 5) (Offset 12)
    @?= CopyFromTarget (ReadOffset (Offset 19)) (Length 5)

unit_noSegmentReadsOwnOutput :: Assertion
unit_noSegmentReadsOwnOutput =
  resolveCopyAddress Nothing midWindowContext (Length 4) (Offset 2)
    @?= CopyFromTarget (ReadOffset (Offset 102)) (Length 4)
        -- window base 100 + address 2; read ends at 106, head at 110

unit_settledSelfRead :: Assertion
unit_settledSelfRead =
  resolveCopyAddress (Just (segmentOfOrigin FromSourceFile))
                     midWindowContext (Length 4) (Offset 42)
    @?= CopyFromTarget (ReadOffset (Offset 102)) (Length 4)
        -- past the 40-byte segment: window base 100 + (42 - 40)

unit_byteRunExpansion :: Assertion
unit_byteRunExpansion =
  resolveCopyAddress Nothing midWindowContext (Length 25) (Offset 9)
    @?= ExpandFromTarget (ReadOffset (Offset 109)) (Length 25) ExpandByteRun
        -- read starts one byte behind the head at 110

unit_forwardExpansion :: Assertion
unit_forwardExpansion =
  resolveCopyAddress Nothing midWindowContext (Length 25) (Offset 7)
    @?= ExpandFromTarget (ReadOffset (Offset 107)) (Length 25) ExpandForward
        -- read starts three bytes behind the head and overruns it

unit_zeroLengthAtHead :: Assertion
unit_zeroLengthAtHead =
  resolveCopyAddress Nothing midWindowContext (Length 0) (Offset 10)
    @?= CopyFromTarget (ReadOffset (Offset 110)) (Length 0)
        -- read start == head, zero bytes: settled vacuously

-- | Generator for own-output reads within the core invariants: some
-- output exists, the address points strictly before the head, and the
-- length is unconstrained (an overrun is what the expansion arms are
-- for).
genOwnOutputRead :: Gen (WindowWriteContext, Length, Offset)
genOwnOutputRead = do
  windowBase <- chooseInt (0, 5000)
  produced   <- chooseInt (1, 5000)
  address    <- chooseInt (0, produced - 1)
  copyLength <- chooseInt (0, 5000)
  pure ( WindowWriteContext (WritePosition (Offset (fromIntegral windowBase))) (Length (fromIntegral produced))
       , Length (fromIntegral copyLength)
       , Offset (fromIntegral address) )

-- | With no segment, the three own-output verdicts partition exactly
-- on the overrun test: settled when the read ends at or before the
-- head, byte-run when it overruns from one byte behind, forward
-- otherwise.
prop_ownOutputPartition :: Property
prop_ownOutputPartition =
  forAll genOwnOutputRead $ \(writeContext, copyLength, copyAddress) ->
    let windowBase = unOffset (unWritePosition (windowOutputBase writeContext))
        writeHead  = windowBase + unLength (windowProducedSoFar writeContext)
        readStart  = windowBase + unOffset copyAddress
        readEnd    = readStart + unLength copyLength
        expected
          | readEnd <= writeHead          = CopyFromTarget   (ReadOffset (Offset readStart)) copyLength
          | writeHead - readStart == 1    = ExpandFromTarget (ReadOffset (Offset readStart)) copyLength ExpandByteRun
          | otherwise                     = ExpandFromTarget (ReadOffset (Offset readStart)) copyLength ExpandForward
    in resolveCopyAddress Nothing writeContext copyLength copyAddress === expected

-- | Every own-output read is placed absolutely: window base plus the
-- window-relative address, whatever the verdict.
prop_ownOutputPlacement :: Property
prop_ownOutputPlacement =
  forAll genOwnOutputRead $ \(writeContext, copyLength, copyAddress) ->
    let windowBase = unOffset (unWritePosition (windowOutputBase writeContext))
        expectedRead = ReadOffset (Offset (windowBase + unOffset copyAddress))
        resolvedRead = case resolveCopyAddress Nothing writeContext copyLength copyAddress of
          CopyFromSource   readOffset _   -> readOffset
          CopyFromTarget   readOffset _   -> readOffset
          ExpandFromTarget readOffset _ _ -> readOffset
    in resolvedRead === expectedRead
