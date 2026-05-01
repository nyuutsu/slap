-- | Properties for the IPS truncation-marker honour-only-when-shrinking
-- policy. Three groups: pure tests for 'decideMarkerDisposition'
-- (totality, per-case correctness, reference agreement), apply-side
-- unit tests for buffer sizing per disposition, apply-side unit
-- tests for record clipping when 'MarkerHonoured' fires.
module Props.IPSMarkerPolicy (ipsMarkerPolicyTests) where

import qualified Slap.IPS.Apply as IPS
import Slap.IPS.Types (IPSPatch(..), IPSRecord(..), IPSVariant(..),
                       MarkerDisposition(..), decideMarkerDisposition)
import Slap.Error (Outcome(..), SlapWarning(..),
                   ClippedRecordCount(..), MarkerOvershootBytes(..),
                   renderSlapError)
import Slap.FormatLabel (FormatLabel(..))
import Slap.Measure (Offset(..), Length(..), FileSize(..),
                     ActionIndex(..),
                     DeclaredTargetSize(..), NaturalTargetSize(..))
import Slap.FileContents (SourceFileContents(..), TargetFileContents(..))

import qualified Data.ByteString as ByteString
import qualified Data.Vector as Vector
import Data.Word (Word8)

import Test.Tasty
import Test.Tasty.HUnit (Assertion, assertEqual, assertFailure, testCase)
import Test.Tasty.QuickCheck

ipsMarkerPolicyTests :: TestTree
ipsMarkerPolicyTests = testGroup "IPSMarkerPolicy"
  [ testGroup "decideMarkerDisposition"
      [ testProperty "totality"             prop_dispositionTotal
      , testProperty "absent-iff-nothing"   prop_dispositionAbsentIffNothing
      , testProperty "honoured-iff-shrinks" prop_dispositionHonouredIffShrinks
      , testProperty "noop-iff-equal"       prop_dispositionNoOpIffEqual
      , testProperty "ignored-iff-grows"    prop_dispositionIgnoredIffGrows
      , testProperty "agrees-with-reference" prop_dispositionReferenceAgreement
      ]
  , testGroup "apply-effective-size"
      [ testCase "absent: natural"          test_applyAbsentSizesNatural
      , testCase "honoured: declared"       test_applyHonouredSizesDeclared
      , testCase "noop: declared"           test_applyNoOpSizesDeclared
      , testCase "ignored: natural"         test_applyIgnoredSizesNatural
      ]
  , testGroup "apply-clipping"
      [ testCase "honoured-no-cross-no-clip"    test_honouredNoCrossNoClip
      , testCase "honoured-records-cross-clip"  test_honouredRecordsCrossClip
      , testCase "honoured-record-straddles"    test_honouredRecordStraddles
      ]
  ]

----------------------------------------------------------------------------
-- decideMarkerDisposition: properties
----------------------------------------------------------------------------

-- | Generator for non-negative 'FileSize' values within a tractable
-- range. The disposition logic is monotone in the comparison, so a
-- small range exercises every branch without producing
-- unrepresentable buffer sizes.
genFileSize :: Gen FileSize
genFileSize = FileSize <$> chooseInt (0, 10000)

-- | Generator for a (declared, natural) pair plus an optional
-- declared marker. The 'Maybe' wrapping mirrors the apply-side
-- argument: 'Nothing' means the patch carried no marker, 'Just'
-- carries a 'DeclaredTargetSize'.
genDispositionInput :: Gen (Maybe DeclaredTargetSize, NaturalTargetSize)
genDispositionInput = do
  natural <- NaturalTargetSize <$> genFileSize
  marker  <- frequency
    [ (1, pure Nothing)
    , (3, Just . DeclaredTargetSize <$> genFileSize)
    ]
  pure (marker, natural)

-- | Naive reference disposition decider, kept separate from the
-- production code so a refactor of 'decideMarkerDisposition' does
-- not silently change both. Phrased in terms of the underlying
-- 'FileSize' values rather than the role newtypes — different code
-- path from production.
referenceDisposition
  :: Maybe DeclaredTargetSize -> NaturalTargetSize -> MarkerDisposition
referenceDisposition Nothing natural = MarkerAbsent natural
referenceDisposition (Just declared) natural =
  let declaredValue = unFileSize (unDeclaredTargetSize declared)
      naturalValue  = unFileSize (unNaturalTargetSize  natural)
  in case compare declaredValue naturalValue of
       LT -> MarkerHonoured declared natural
       EQ -> MarkerNoOp     declared
       GT -> MarkerIgnored  declared natural

-- | Disposition is total: every valid input produces one of the
-- four constructors.
prop_dispositionTotal :: Property
prop_dispositionTotal =
  forAll genDispositionInput $ \(marker, natural) ->
    case decideMarkerDisposition marker natural of
      MarkerAbsent   _   -> True
      MarkerHonoured _ _ -> True
      MarkerNoOp     _   -> True
      MarkerIgnored  _ _ -> True

-- | 'MarkerAbsent' is produced if and only if the input marker was
-- 'Nothing'.
prop_dispositionAbsentIffNothing :: Property
prop_dispositionAbsentIffNothing =
  forAll genDispositionInput $ \(marker, natural) ->
    let isAbsent = case decideMarkerDisposition marker natural of
                     MarkerAbsent _ -> True
                     _              -> False
    in isAbsent === isNothing marker
  where
    isNothing Nothing  = True
    isNothing (Just _) = False

-- | 'MarkerHonoured' is produced if and only if the marker is
-- present and strictly less than the natural size.
prop_dispositionHonouredIffShrinks :: Property
prop_dispositionHonouredIffShrinks =
  forAll genDispositionInput $ \(marker, natural) ->
    let isHonoured = case decideMarkerDisposition marker natural of
                       MarkerHonoured _ _ -> True
                       _                  -> False
        shouldHonour = case marker of
          Just declared ->
            unDeclaredTargetSize declared < unNaturalTargetSize natural
          Nothing -> False
    in isHonoured === shouldHonour

-- | 'MarkerNoOp' is produced if and only if the marker is present
-- and exactly equal to the natural size.
prop_dispositionNoOpIffEqual :: Property
prop_dispositionNoOpIffEqual =
  forAll genDispositionInput $ \(marker, natural) ->
    let isNoOp = case decideMarkerDisposition marker natural of
                   MarkerNoOp _ -> True
                   _            -> False
        shouldBeNoOp = case marker of
          Just declared ->
            unDeclaredTargetSize declared == unNaturalTargetSize natural
          Nothing -> False
    in isNoOp === shouldBeNoOp

-- | 'MarkerIgnored' is produced if and only if the marker is
-- present and strictly greater than the natural size.
prop_dispositionIgnoredIffGrows :: Property
prop_dispositionIgnoredIffGrows =
  forAll genDispositionInput $ \(marker, natural) ->
    let isIgnored = case decideMarkerDisposition marker natural of
                      MarkerIgnored _ _ -> True
                      _                 -> False
        shouldIgnore = case marker of
          Just declared ->
            unDeclaredTargetSize declared > unNaturalTargetSize natural
          Nothing -> False
    in isIgnored === shouldIgnore

-- | The production decider agrees with the reference decider on
-- every input.
prop_dispositionReferenceAgreement :: Property
prop_dispositionReferenceAgreement =
  forAll genDispositionInput $ \(marker, natural) ->
    decideMarkerDisposition marker natural
      === referenceDisposition marker natural

----------------------------------------------------------------------------
-- Apply-side unit tests
----------------------------------------------------------------------------

-- | A 'StandardIPS' patch with the given record vector and optional
-- truncation marker. Used by every unit test below.
makePatch :: Maybe FileSize -> [IPSRecord] -> IPSPatch
makePatch maybeTruncation records = IPSPatch
  { ipsVariant             = StandardIPS
  , ipsRecords             = Vector.fromList records
  , ipsTruncatedTargetSize = maybeTruncation
  }

-- | A copy record at the given offset, payload of @count@ copies of
-- @fillByte@. Avoids hand-rolling a payload at every call site.
copyRecordOf :: Int -> Int -> Word8 -> IPSRecord
copyRecordOf recordOffset recordLength fillByte = IPSRecordCopy
  { ipsCopyOffset  = Offset recordOffset
  , ipsCopyPayload = ByteString.replicate recordLength fillByte
  }

-- | A source ByteString of the given length, all bytes 0xFF. The
-- exact byte value is irrelevant to every test below — only the
-- length matters for sizing decisions.
makeSource :: Int -> SourceFileContents
makeSource sourceLength =
  SourceFileContents (ByteString.replicate sourceLength 0xFF)

-- | Run apply and return the unwrapped 'Outcome', failing the test
-- with a rendered 'SlapError' on failure.
runApplyOrFail
  :: SourceFileContents -> IPSPatch -> IO (Outcome TargetFileContents)
runApplyOrFail source patch =
  case IPS.applyIPS source patch of
    Left slapError -> assertFailure ("apply: " ++ renderSlapError slapError)
    Right outcome  -> pure outcome

-- | Assert that an apply produced a target of the given size and
-- exactly the expected warning list.
assertApplyResult
  :: String                -- ^ test description for failure messages
  -> Int                   -- ^ expected target byte length
  -> [SlapWarning]         -- ^ expected warning list (in order)
  -> Outcome TargetFileContents
  -> Assertion
assertApplyResult description expectedLength expectedWarnings outcome = do
  let TargetFileContents targetBytes = outcomeValue outcome
  assertEqual (description ++ ": target length")
    expectedLength (ByteString.length targetBytes)
  assertEqual (description ++ ": warnings")
    expectedWarnings (outcomeWarnings outcome)

-- absent: source 100, one record at offset 30 length 5. Expected:
-- 100-byte output, no warnings.
test_applyAbsentSizesNatural :: Assertion
test_applyAbsentSizesNatural = do
  let patch  = makePatch Nothing [copyRecordOf 30 5 0xAA]
      source = makeSource 100
  outcome <- runApplyOrFail source patch
  assertApplyResult "MarkerAbsent" 100 [] outcome

-- honoured: source 100, one record at offset 30 length 5 (reaches
-- 35), declared 80. Expected: 80-byte output, single
-- IPSTruncationMarkerHonoured warning, no clip warning.
test_applyHonouredSizesDeclared :: Assertion
test_applyHonouredSizesDeclared = do
  let patch  = makePatch (Just (FileSize 80)) [copyRecordOf 30 5 0xAA]
      source = makeSource 100
      expectedWarning =
        IPSTruncationMarkerHonoured LabelIPS
          (DeclaredTargetSize (FileSize 80))
          (NaturalTargetSize  (FileSize 100))
  outcome <- runApplyOrFail source patch
  assertApplyResult "MarkerHonoured" 80 [expectedWarning] outcome

-- noop: source 100, one record at offset 30 length 5, declared 100.
-- Expected: 100-byte output, no warnings.
test_applyNoOpSizesDeclared :: Assertion
test_applyNoOpSizesDeclared = do
  let patch  = makePatch (Just (FileSize 100)) [copyRecordOf 30 5 0xAA]
      source = makeSource 100
  outcome <- runApplyOrFail source patch
  assertApplyResult "MarkerNoOp" 100 [] outcome

-- ignored: source 50, one record at offset 0 length 10 (reaches 10),
-- declared 100. Expected: 50-byte output, single
-- IPSTruncationMarkerIgnored warning.
test_applyIgnoredSizesNatural :: Assertion
test_applyIgnoredSizesNatural = do
  let patch  = makePatch (Just (FileSize 100)) [copyRecordOf 0 10 0xAA]
      source = makeSource 50
      expectedWarning =
        IPSTruncationMarkerIgnored LabelIPS
          (DeclaredTargetSize (FileSize 100))
          (NaturalTargetSize  (FileSize 50))
  outcome <- runApplyOrFail source patch
  assertApplyResult "MarkerIgnored" 50 [expectedWarning] outcome

-- honoured-no-cross-no-clip: same as honoured: declared, asserts no
-- IPSRecordsClippedByMarker warning is appended.
test_honouredNoCrossNoClip :: Assertion
test_honouredNoCrossNoClip = do
  let patch  = makePatch (Just (FileSize 80)) [copyRecordOf 30 5 0xAA]
      source = makeSource 100
      expectedWarning =
        IPSTruncationMarkerHonoured LabelIPS
          (DeclaredTargetSize (FileSize 80))
          (NaturalTargetSize  (FileSize 100))
  outcome <- runApplyOrFail source patch
  assertApplyResult "MarkerHonoured no-cross" 80 [expectedWarning] outcome

-- honoured-records-cross-clip: source 100, one record at offset 80
-- length 30 (reaches 110), declared 90. Expected: 90-byte output,
-- two warnings (Honoured + Clipped with count 1, first at index 0,
-- overshoot 20 bytes — record sits entirely past effective end).
test_honouredRecordsCrossClip :: Assertion
test_honouredRecordsCrossClip = do
  let patch  = makePatch (Just (FileSize 90)) [copyRecordOf 80 30 0xAA]
      source = makeSource 100
      honouredWarning =
        IPSTruncationMarkerHonoured LabelIPS
          (DeclaredTargetSize (FileSize 90))
          (NaturalTargetSize  (FileSize 110))
      clippedWarning =
        IPSRecordsClippedByMarker LabelIPS
          (ClippedRecordCount 1) (ActionIndex 0) (MarkerOvershootBytes (Length 20))
  outcome <- runApplyOrFail source patch
  assertApplyResult "MarkerHonoured records-cross"
    90 [honouredWarning, clippedWarning] outcome

-- honoured-record-straddles: source 100, one record at offset 70
-- length 30 (reaches 100), declared 80. Expected: 80-byte output,
-- two warnings (Honoured + Clipped with count 1, first at index 0,
-- overshoot 20 bytes — record straddles, prefix written).
test_honouredRecordStraddles :: Assertion
test_honouredRecordStraddles = do
  let patch  = makePatch (Just (FileSize 80)) [copyRecordOf 70 30 0xAA]
      source = makeSource 100
      honouredWarning =
        IPSTruncationMarkerHonoured LabelIPS
          (DeclaredTargetSize (FileSize 80))
          (NaturalTargetSize  (FileSize 100))
      clippedWarning =
        IPSRecordsClippedByMarker LabelIPS
          (ClippedRecordCount 1) (ActionIndex 0) (MarkerOvershootBytes (Length 20))
  outcome <- runApplyOrFail source patch
  assertApplyResult "MarkerHonoured straddles"
    80 [honouredWarning, clippedWarning] outcome
