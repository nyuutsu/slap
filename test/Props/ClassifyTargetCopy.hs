-- | Properties for 'Slap.BPS.Apply.classifyTargetCopy' — the pure
-- function that decides how a BPS TargetCopy action should be executed
-- (non-overlapping memmove, single-byte run-length, or byte-by-byte
-- self-referencing loop).
module Props.ClassifyTargetCopy (classifyTargetCopyTests) where

import Slap.BPS.Apply (TargetCopyStrategy(..), classifyTargetCopy)
import Slap.Measure (Offset(..), Length(..),
                     ReadOffset(..), WritePosition(..))

import Test.Tasty
import Test.Tasty.QuickCheck

classifyTargetCopyTests :: TestTree
classifyTargetCopyTests = testGroup "classifyTargetCopy"
  [ testProperty "non-overlapping-iff-readEnd-le-writePos"
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
genValidClassifierInput :: Gen (ReadOffset, WritePosition, Length)
genValidClassifierInput = do
  writePosInt   <- chooseInt (1, 10000)
  readStartInt  <- chooseInt (0, writePosInt - 1)
  copyLengthInt <- chooseInt (0, 10000)
  pure ( ReadOffset (Offset (fromIntegral readStartInt))
       , WritePosition (Offset (fromIntegral writePosInt))
       , Length (fromIntegral copyLengthInt) )

-- | Naive reference classifier, kept separate from the production code
-- so that a refactor of classifyTargetCopy doesn't silently change both.
referenceClassify :: ReadOffset -> WritePosition -> Length -> TargetCopyStrategy
referenceClassify readStart writePos copyLength
  | readEndInt <= writePosInt                = TargetCopyNonOverlapping
  | readStartInt == writePosInt - 1          = TargetCopySingleByteRun
  | otherwise                                = TargetCopyGeneralOverlap
  where
    readStartInt = unOffset (unReadOffset readStart)
    writePosInt  = unOffset (unWritePosition writePos)
    readEndInt   = readStartInt + unLength copyLength

-- | NonOverlapping if and only if readStart + copyLength <= writePos.
prop_classifyTargetCopy_nonOverlapping :: Property
prop_classifyTargetCopy_nonOverlapping =
  forAll genValidClassifierInput $ \(readStart, writePos, copyLength) ->
    let readStartInt = unOffset (unReadOffset readStart)
        writePosInt  = unOffset (unWritePosition writePos)
        readEnd      = readStartInt + unLength copyLength
        result       = classifyTargetCopy readStart writePos copyLength
        isNonOverlap = result == TargetCopyNonOverlapping
    in counterexample ("readEnd=" ++ show readEnd
                        ++ " writePos=" ++ show writePosInt) $
       isNonOverlap === (readEnd <= writePosInt)

-- | SingleByteRun if and only if readStart == writePos - 1 AND the
-- copy overlaps (readEnd > writePos). A one-byte copy from writePos-1
-- classifies as NonOverlapping because readEnd == writePos.
prop_classifyTargetCopy_singleByteRun :: Property
prop_classifyTargetCopy_singleByteRun =
  forAll genValidClassifierInput $ \(readStart, writePos, copyLength) ->
    let readStartInt = unOffset (unReadOffset readStart)
        writePosInt  = unOffset (unWritePosition writePos)
        readEnd      = readStartInt + unLength copyLength
        result       = classifyTargetCopy readStart writePos copyLength
        isSingleByte = result == TargetCopySingleByteRun
        expected     = readStartInt == writePosInt - 1
                       && readEnd > writePosInt
    in counterexample ("readStart=" ++ show readStartInt
                        ++ " writePos=" ++ show writePosInt
                        ++ " readEnd=" ++ show readEnd) $
       isSingleByte === expected

-- | GeneralOverlap is the residual: neither NonOverlapping nor SingleByteRun.
prop_classifyTargetCopy_generalOverlap :: Property
prop_classifyTargetCopy_generalOverlap =
  forAll genValidClassifierInput $ \(readStart, writePos, copyLength) ->
    let readStartInt = unOffset (unReadOffset readStart)
        writePosInt  = unOffset (unWritePosition writePos)
        readEnd      = readStartInt + unLength copyLength
        result       = classifyTargetCopy readStart writePos copyLength
        isGeneral    = result == TargetCopyGeneralOverlap
        isNonOverlap = readEnd <= writePosInt
        isSingleByte = readStartInt == writePosInt - 1
                       && readEnd > writePosInt
    in counterexample ("readStart=" ++ show readStartInt
                        ++ " writePos=" ++ show writePosInt
                        ++ " readEnd=" ++ show readEnd) $
       isGeneral === (not isNonOverlap && not isSingleByte)

-- | Length-zero always classifies as NonOverlapping because
-- readEnd = readStart <= writePos (given the precondition readStart < writePos).
prop_classifyTargetCopy_lengthZero :: Property
prop_classifyTargetCopy_lengthZero =
  forAll (do writePosInt  <- chooseInt (1, 10000)
             readStartInt <- chooseInt (0, writePosInt - 1)
             pure ( ReadOffset (Offset (fromIntegral readStartInt))
                  , WritePosition (Offset (fromIntegral writePosInt)) )) $ \(readStart, writePos) ->
    classifyTargetCopy readStart writePos (Length 0)
      === TargetCopyNonOverlapping

-- | The production classifier agrees with a reference implementation
-- on all valid inputs. Guards against drift during future refactors.
prop_classifyTargetCopy_referenceAgreement :: Property
prop_classifyTargetCopy_referenceAgreement =
  forAll genValidClassifierInput $ \(readStart, writePos, copyLength) ->
    classifyTargetCopy readStart writePos copyLength
      === referenceClassify readStart writePos copyLength
