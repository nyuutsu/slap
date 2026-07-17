{-# LANGUAGE OverloadedStrings #-}

-- | Properties for the shared bounds arithmetic in 'Slap.Measure' that
-- every format's apply path leans on: 'fitsWithin' (does a region land
-- inside the space it addresses?) and 'boundedWriteEnd' (where does a
-- write end, and can that end even be represented?).
--
-- The contract under test for both is totality. slap carries every size
-- and offset as a signed 'Int64', and several
-- formats decode wire fields wide enough to seat a near-'maxBound'
-- value (a 63-bit PPF3 offset, a byuu or VCDIFF varint, a bsdiff
-- sign-magnitude length). A plain @start + length@ then overflows the
-- carrier and wraps to a negative sum — for 'fitsWithin' that falsely
-- reports "fits", the door an out-of-bounds access walks through; for a
-- buffer-sizing fold it would be laundered by 'max' into a too-small
-- allocation. These pin the honest behaviour: 'fitsWithin' answers from
-- 'Integer'-faithful comparisons, 'boundedWriteEnd' answers 'Nothing'
-- when the end overflows, and PPF3 apply turns that 'Nothing' into a
-- typed addressable-range refusal rather than a wrong buffer.
module Props.Measure (measureTests) where

import Slap.Measure (Offset(..), Length(..), FileSize(..),
                     fitsWithin, boundedWriteEnd,
                     narrowToAddressable, maxAddressableByteCount,
                     AddressableByteCount(unAddressableByteCount),
                     AddressableNarrowFailure(..))
import Slap.PPF3.Types (PPF3Patch(..), PPF3Record(..), PPF3ImageType(..))
import Slap.PPF3.Apply (applyPPF3)
import Slap.Text (EncodedText(..), EncodingName(EncodingUtf8))
import Slap.FileContents (InputFileContents(..))
import Slap.Status (SlapError(..), ApplyError(..), renderSlapError, addressableByteCount)
import Slap.FormatLabel (FormatLabel(..))

import Props.Helpers (assertFailureT)

import qualified Data.ByteString as ByteString
import Data.Int (Int64)

import Test.Tasty
import Test.Tasty.HUnit
import Test.Tasty.QuickCheck

measureTests :: TestTree
measureTests = testGroup "Measure"
  [ fitsWithinTests
  , boundedWriteEndTests
  , narrowToAddressableTests
  ]

----------------------------------------------------------------------------
-- narrowToAddressable
----------------------------------------------------------------------------

-- | The over-ceiling refusal fires only where 'Int' is narrower than the 'Int64' a 'FileSize' carries —
-- wasm32 — so on a 64-bit host no 'FileSize' reaches it and only the reachable arms run here. What is
-- pinned on any host is that the ceiling is 'maxBound' :: 'Int'.
narrowToAddressableTests :: TestTree
narrowToAddressableTests = testGroup "narrowToAddressable"
  [ testCase "the ceiling is maxBound::Int, whatever the host's word size" $
      maxAddressableByteCount @?= FileSize (fromIntegral (maxBound :: Int))
  , testCase "a negative size is refused as negative" $
      narrowToAddressable (FileSize (-1)) @?= Left SizeIsNegative
  , testCase "zero narrows to a zero byte count" $
      fmap unAddressableByteCount (narrowToAddressable (FileSize 0)) @?= Right 0
  , testCase "an ordinary size narrows to its Int" $
      fmap unAddressableByteCount (narrowToAddressable (FileSize 4096)) @?= Right 4096
  , testCase "a size at the ceiling narrows, it does not overrun it" $
      fmap unAddressableByteCount (narrowToAddressable maxAddressableByteCount)
        @?= Right (fromIntegral (unFileSize maxAddressableByteCount))
  , testCase "addressableByteCount labels a negative size as NegativeTargetSize" $
      case addressableByteCount LabelBPS (FileSize (-1)) of
        Left (NegativeTargetSize LabelBPS _) -> pure ()
        other -> assertFailureT ("expected a NegativeTargetSize refusal, got: "
                                   <> either renderSlapError (const "a Right") other)
  , testCase "addressableByteCount passes an addressable size through" $
      fmap unAddressableByteCount (addressableByteCount LabelBPS (FileSize 4096))
        @?= Right 4096
  ]

----------------------------------------------------------------------------
-- fitsWithin
----------------------------------------------------------------------------

fitsWithinTests :: TestTree
fitsWithinTests = testGroup "fitsWithin"
  [ testGroup "ordinary bounds"
      [ testCase "a region inside the total fits" $
          fitsWithin (Offset 0) (Length 5) (FileSize 10) @?= True
      , testCase "a region past the total does not fit" $
          fitsWithin (Offset 8) (Length 5) (FileSize 10) @?= False
      , testCase "a region ending exactly at the total fits" $
          fitsWithin (Offset 5) (Length 5) (FileSize 10) @?= True
      , testCase "a zero-length region at the very end fits" $
          fitsWithin (Offset 10) (Length 0) (FileSize 10) @?= True
      ]
  , testGroup "the carrier must not wrap into a false fit"
      [ testCase "a maxBound start plus one byte does not fit" $
          fitsWithin (Offset maxBound) (Length 1) (FileSize 10) @?= False
      , testCase "one byte at a maxBound-long region does not fit" $
          fitsWithin (Offset 1) (Length maxBound) (FileSize 10) @?= False
      , testCase "two half-range operands do not sum into a fit" $
          fitsWithin (Offset halfRange) (Length halfRange) (FileSize 10) @?= False
      ]
  , testGroup "a negative operand never fits"
      [ testCase "a negative start" $
          fitsWithin (Offset (-1)) (Length 0) (FileSize 10) @?= False
      , testCase "a negative length" $
          fitsWithin (Offset 0) (Length (-1)) (FileSize 10) @?= False
      ]
  , testProperty "agrees with unbounded (Integer) arithmetic"
      prop_fitsWithin_matchesIntegerArithmetic
  ]

-- | The honest answer, computed in 'Integer' where no overflow is
-- possible: a region fits when its start and length are both
-- non-negative and @start + length@ stays within the total.
-- 'fitsWithin' must agree with this for every 'Int64'-range input,
-- including the near-'maxBound' and negative ones the carrier cannot
-- sum without wrapping.
prop_fitsWithin_matchesIntegerArithmetic :: Property
prop_fitsWithin_matchesIntegerArithmetic =
  forAll genCarrierEdge $ \regionStart ->
  forAll genCarrierEdge $ \regionLength ->
  forAll genCarrierEdge $ \totalSize ->
    let actual   = fitsWithin (Offset regionStart) (Length regionLength)
                              (FileSize totalSize)
        expected = regionStart  >= 0
                   && regionLength >= 0
                   && toInteger regionStart + toInteger regionLength
                        <= toInteger totalSize
    in counterexample ("regionStart=" ++ show regionStart
                        ++ " regionLength=" ++ show regionLength
                        ++ " totalSize=" ++ show totalSize) $
       actual === expected

----------------------------------------------------------------------------
-- boundedWriteEnd
----------------------------------------------------------------------------

boundedWriteEndTests :: TestTree
boundedWriteEndTests = testGroup "boundedWriteEnd"
  [ testGroup "ordinary ends"
      [ testCase "the end is start plus length" $
          boundedWriteEnd (Offset 4) (Length 6) @?= Just (Offset 10)
      , testCase "a zero-length write ends where it starts" $
          boundedWriteEnd (Offset 7) (Length 0) @?= Just (Offset 7)
      ]
  , testGroup "an end past the carrier is unrepresentable"
      [ testCase "maxBound start plus one byte overflows to Nothing" $
          boundedWriteEnd (Offset maxBound) (Length 1) @?= Nothing
      , testCase "two half-range operands overflow to Nothing" $
          boundedWriteEnd (Offset halfRange) (Length halfRange) @?= Nothing
      ]
  , testCase "a negative start is not an overflow — left for the apply walk" $
      boundedWriteEnd (Offset (-3)) (Length 1) @?= Just (Offset (-2))
  , testProperty "agrees with unbounded (Integer) arithmetic"
      prop_boundedWriteEnd_matchesIntegerArithmetic
  , testGroup "the apply-side refusal it drives"
      [ testCase "PPF3 declines an output whose end exceeds the addressable range"
          ppf3UnaddressableOutputIsRefused
      ]
  ]

-- | The plain-arithmetic end, computed in 'Integer': @start + length@ is
-- representable exactly when it does not pass 'maxBound' :: 'Int64'.
-- 'boundedWriteEnd' is only ever handed a non-negative length (a
-- 'Slap.Measure.byteLength'), so the overflow can only be upward; a
-- negative start is left to land wherever it lands, since it cannot
-- carry a non-negative length out of range.
prop_boundedWriteEnd_matchesIntegerArithmetic :: Property
prop_boundedWriteEnd_matchesIntegerArithmetic =
  forAll genCarrierEdge $ \regionStart ->
  forAll genNonNegativeCarrierEdge $ \regionLength ->
    let actual = boundedWriteEnd (Offset regionStart) (Length regionLength)
        expected
          | toInteger regionStart + toInteger regionLength > toInteger (maxBound :: Int64) = Nothing
          | otherwise = Just (Offset (regionStart + regionLength))
    in counterexample ("regionStart=" ++ show regionStart
                        ++ " regionLength=" ++ show regionLength) $
       actual === expected

-- | A PPF3 patch with a single record at the largest representable
-- offset and a one-byte payload: its write ends one past 'maxBound',
-- an output no 'Int64' can address. Apply must refuse with
-- 'ApplyOutputExceedsAddressableRange', naming the record, rather than
-- let the extent fold wrap into a too-small buffer. (Only the
-- 'ppf3Records' field reaches the apply path; the rest carry trivial
-- values.)
ppf3UnaddressableOutputIsRefused :: Assertion
ppf3UnaddressableOutputIsRefused =
  case applyPPF3 patch (InputFileContents (ByteString.pack [0, 1, 2, 3])) of
    Left (ApplyFailed LabelPPF3 (ApplyOutputExceedsAddressableRange _ _ _)) -> pure ()
    Left other -> assertFailureT
      ("expected an addressable-range refusal, got: " <> renderSlapError other)
    Right _ -> assertFailure
      "expected apply to refuse the unaddressable output, but it succeeded"
  where
    patch = PPF3Patch
      { ppf3Description     = EncodedText EncodingUtf8 ""
      , ppf3ImageType       = BIN
      , ppf3HasUndo         = False
      , ppf3ValidationBlock = Nothing
      , ppf3Records         = [PPF3Record (Offset maxBound) (ByteString.singleton 0xAB) Nothing]
      , ppf3FileId          = Nothing
      }

----------------------------------------------------------------------------
-- Generators
----------------------------------------------------------------------------

-- | Two of these sum to maxBound + 1, i.e. they overflow the carrier.
halfRange :: Int64
halfRange = maxBound `div` 2 + 1

-- | Carrier values drawn to land on the edges as often as in the
-- comfortable middle, so a property actually exercises the wrap and
-- negative cases instead of the small-number band QuickCheck samples
-- by default.
genCarrierEdge :: Gen Int64
genCarrierEdge = frequency
  [ (3, arbitrary)
  , (2, choose (0, 1000))
  , (1, elements [ 0, 1, -1, maxBound, minBound, maxBound - 1
                 , maxBound `div` 2, maxBound `div` 2 + 1
                 , negate (maxBound `div` 2) ])
  ]

-- | As 'genCarrierEdge' but non-negative — the shape a real length takes.
genNonNegativeCarrierEdge :: Gen Int64
genNonNegativeCarrierEdge = frequency
  [ (3, choose (0, 1000))
  , (2, choose (0, maxBound))
  , (1, elements [ 0, 1, maxBound, maxBound - 1
                 , maxBound `div` 2, maxBound `div` 2 + 1 ])
  ]
