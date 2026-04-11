-- | Properties for 'Slap.BPS.Apply.classifyTargetCopy' — the pure
-- function that decides how a BPS TargetCopy action should be executed
-- (non-overlapping memmove, single-byte run-length, or byte-by-byte
-- self-referencing loop).
module Props.ClassifyTargetCopy (classifyTargetCopyTests) where

import Slap.BPS.Apply (TargetCopyStrategy(..), classifyTargetCopy)
import Slap.Measure (Offset(..), Length(..))

import Test.Tasty
import Test.Tasty.QuickCheck

classifyTargetCopyTests :: TestTree
classifyTargetCopyTests = testGroup "classifyTargetCopy"
  [ testProperty "classification-is-total"
      prop_classifyTargetCopy_total
  , testProperty "non-overlapping-iff-readEnd-le-writePos"
      prop_classifyTargetCopy_nonOverlapping
  , testProperty "single-byte-run-iff-back-one-and-overlapping"
      prop_classifyTargetCopy_singleByteRun
  , testProperty "general-overlap-is-residual"
      prop_classifyTargetCopy_generalOverlap
  , testProperty "length-zero-is-non-overlapping"
      prop_classifyTargetCopy_lengthZero
  , testProperty "agrees-with-reference"
      prop_classifyTargetCopy_referenceAgreement
  ]

-- | Generator for valid (readStart, writePos, copyLength) triples.
-- Preconditions: writePos >= 1, 0 <= readStart < writePos, copyLength >= 0.
genValidClassifierInput :: Gen (Offset, Offset, Length)
genValidClassifierInput = do
  writePos   <- Offset <$> chooseInt (1, 10000)
  readStart  <- Offset <$> chooseInt (0, unOffset writePos - 1)
  copyLength <- Length <$> chooseInt (0, 10000)
  pure (readStart, writePos, copyLength)

-- | Naive reference classifier, kept separate from the production code
-- so that a refactor of classifyTargetCopy doesn't silently change both.
referenceClassify :: Offset -> Offset -> Length -> TargetCopyStrategy
referenceClassify readStart writePos copyLength
  | readEnd <= writePos                         = TargetCopyNonOverlapping
  | unOffset readStart == unOffset writePos - 1 = TargetCopySingleByteRun
  | otherwise                                   = TargetCopyGeneralOverlap
  where
    readEnd = Offset (unOffset readStart + unLength copyLength)

-- | Classification is total: every valid input produces one of the
-- three constructors.
prop_classifyTargetCopy_total :: Property
prop_classifyTargetCopy_total =
  forAll genValidClassifierInput $ \(readStart, writePos, copyLength) ->
    case classifyTargetCopy readStart writePos copyLength of
      TargetCopyNonOverlapping -> True
      TargetCopySingleByteRun  -> True
      TargetCopyGeneralOverlap -> True

-- | NonOverlapping if and only if readStart + copyLength <= writePos.
prop_classifyTargetCopy_nonOverlapping :: Property
prop_classifyTargetCopy_nonOverlapping =
  forAll genValidClassifierInput $ \(readStart, writePos, copyLength) ->
    let readEnd    = unOffset readStart + unLength copyLength
        result     = classifyTargetCopy readStart writePos copyLength
        isNonOverlap = result == TargetCopyNonOverlapping
    in counterexample ("readEnd=" ++ show readEnd
                        ++ " writePos=" ++ show (unOffset writePos)) $
       isNonOverlap === (readEnd <= unOffset writePos)

-- | SingleByteRun if and only if readStart == writePos - 1 AND the
-- copy overlaps (readEnd > writePos). A one-byte copy from writePos-1
-- classifies as NonOverlapping because readEnd == writePos.
prop_classifyTargetCopy_singleByteRun :: Property
prop_classifyTargetCopy_singleByteRun =
  forAll genValidClassifierInput $ \(readStart, writePos, copyLength) ->
    let readEnd    = unOffset readStart + unLength copyLength
        result     = classifyTargetCopy readStart writePos copyLength
        isSingleByte = result == TargetCopySingleByteRun
        expected     = unOffset readStart == unOffset writePos - 1
                       && readEnd > unOffset writePos
    in counterexample ("readStart=" ++ show (unOffset readStart)
                        ++ " writePos=" ++ show (unOffset writePos)
                        ++ " readEnd=" ++ show readEnd) $
       isSingleByte === expected

-- | GeneralOverlap is the residual: neither NonOverlapping nor SingleByteRun.
prop_classifyTargetCopy_generalOverlap :: Property
prop_classifyTargetCopy_generalOverlap =
  forAll genValidClassifierInput $ \(readStart, writePos, copyLength) ->
    let readEnd    = unOffset readStart + unLength copyLength
        result     = classifyTargetCopy readStart writePos copyLength
        isGeneral  = result == TargetCopyGeneralOverlap
        isNonOverlap = readEnd <= unOffset writePos
        isSingleByte = unOffset readStart == unOffset writePos - 1
                       && readEnd > unOffset writePos
    in counterexample ("readStart=" ++ show (unOffset readStart)
                        ++ " writePos=" ++ show (unOffset writePos)
                        ++ " readEnd=" ++ show readEnd) $
       isGeneral === (not isNonOverlap && not isSingleByte)

-- | Length-zero always classifies as NonOverlapping because
-- readEnd = readStart <= writePos (given the precondition readStart < writePos).
prop_classifyTargetCopy_lengthZero :: Property
prop_classifyTargetCopy_lengthZero =
  forAll (do writePos  <- Offset <$> chooseInt (1, 10000)
             readStart <- Offset <$> chooseInt (0, unOffset writePos - 1)
             pure (readStart, writePos)) $ \(readStart, writePos) ->
    classifyTargetCopy readStart writePos (Length 0)
      === TargetCopyNonOverlapping

-- | The production classifier agrees with a reference implementation
-- on all valid inputs. Guards against drift during future refactors.
prop_classifyTargetCopy_referenceAgreement :: Property
prop_classifyTargetCopy_referenceAgreement =
  forAll genValidClassifierInput $ \(readStart, writePos, copyLength) ->
    classifyTargetCopy readStart writePos copyLength
      === referenceClassify readStart writePos copyLength
