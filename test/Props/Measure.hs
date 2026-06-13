-- | Properties for 'Slap.Measure.fitsWithin' — the shared bounds
-- primitive every format's apply path leans on to decide whether a
-- read or write lands inside the buffer it addresses.
--
-- The contract under test is totality: for any 'Int'-range start,
-- length, and total, 'fitsWithin' returns the honest answer, never a
-- wrong one manufactured by the carrier wrapping. slap carries every
-- size and offset as a signed 'Int' (= Int64 on a 64-bit host), so a
-- near-'maxBound' start plus a length overflows the carrier; an
-- unguarded @start + length <= total@ then wraps to a negative sum and
-- falsely reports "fits", which is the door an out-of-bounds access
-- walks through. Two operand shapes reach this: a genuinely wide value
-- (a 63-bit wire field), and a negative value (a malformed offset that
-- should never have been treated as a position at all). These cases
-- pin both shapes so neither can return.
module Props.Measure (measureTests) where

import Slap.Measure (Offset(..), Length(..), FileSize(..), fitsWithin)

import Test.Tasty
import Test.Tasty.HUnit
import Test.Tasty.QuickCheck

measureTests :: TestTree
measureTests = testGroup "Measure.fitsWithin"
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
  where
    -- Two of these sum to maxBound + 1, i.e. they overflow the carrier.
    halfRange = maxBound `div` 2 + 1

-- | The honest answer, computed in 'Integer' where no overflow is
-- possible: a region fits when its start and length are both
-- non-negative and @start + length@ stays within the total.
-- 'fitsWithin' must agree with this for every 'Int'-range input,
-- including the near-'maxBound' and negative ones the carrier cannot
-- sum without wrapping.
prop_fitsWithin_matchesIntegerArithmetic :: Property
prop_fitsWithin_matchesIntegerArithmetic =
  forAll genEdgeInt $ \regionStart ->
  forAll genEdgeInt $ \regionLength ->
  forAll genEdgeInt $ \totalSize ->
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

-- | 'Int's drawn to land on the carrier's edges as often as in its
-- comfortable middle, so the property actually exercises the wrap and
-- negative cases instead of the small-number band QuickCheck samples
-- by default.
genEdgeInt :: Gen Int
genEdgeInt = frequency
  [ (3, arbitrary)
  , (2, choose (0, 1000))
  , (1, elements [ 0, 1, -1, maxBound, minBound, maxBound - 1
                 , maxBound `div` 2, maxBound `div` 2 + 1
                 , negate (maxBound `div` 2) ])
  ]
