-- | Properties for the IPS truncation-marker honor-only-when-shrinking
-- policy. Three groups: pure tests for 'decideMarkerDisposition'
-- (totality, per-case correctness, reference agreement), apply-side
-- unit tests for buffer sizing per disposition, apply-side unit
-- tests for record clipping when 'MarkerHonored' fires.
module Props.IPSMarkerPolicy (ipsMarkerPolicyTests) where

import qualified Slap.IPS.Apply as IPS
import Slap.IPS.Types (IPSPatch(..), IPSRecord(..), IPSVariant(..),
                       MarkerDisposition(..), decideMarkerDisposition)
import Slap.Error (Outcome(..), SlapWarning(..),
                   ClippedRecordCount(..), MarkerOvershootBytes(..),
                   renderSlapError)
import Slap.FormatLabel (FormatLabel(..))
import Slap.Measure (Offset(..), Length(..), FileSize(..),
                     actionAtPosition,
                     DeclaredTargetSize(..), NaturalTargetSize(..))
import Slap.FileContents (InputFileContents(..), OutputFileContents(..))

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
      , testProperty "honored-iff-shrinks" prop_dispositionHonoredIffShrinks
      , testProperty "noop-iff-equal"       prop_dispositionNoOpIffEqual
      , testProperty "ignored-iff-grows"    prop_dispositionIgnoredIffGrows
      , testProperty "agrees-with-reference" prop_dispositionReferenceAgreement
      ]
  , testGroup "apply-effective-size"
      [ testCase "absent: natural"          test_applyAbsentSizesNatural
      , testCase "honored: declared"       test_applyHonoredSizesDeclared
      , testCase "noop: declared"           test_applyNoOpSizesDeclared
      , testCase "ignored: natural"         test_applyIgnoredSizesNatural
      ]
  , testGroup "apply-clipping"
      [ testCase "honored-no-cross-no-clip"    test_honoredNoCrossNoClip
      , testCase "honored-records-cross-clip"  test_honoredRecordsCrossClip
      , testCase "honored-record-straddles"    test_honoredRecordStraddles
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
       LT -> MarkerHonored declared natural
       EQ -> MarkerNoOp     declared
       GT -> MarkerIgnored  declared natural

-- | Disposition is total: every valid input produces one of the
-- four constructors.
prop_dispositionTotal :: Property
prop_dispositionTotal =
  forAll genDispositionInput $ \(marker, natural) ->
    case decideMarkerDisposition marker natural of
      MarkerAbsent   _   -> True
      MarkerHonored _ _ -> True
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

-- | 'MarkerHonored' is produced if and only if the marker is
-- present and strictly less than the natural size.
prop_dispositionHonoredIffShrinks :: Property
prop_dispositionHonoredIffShrinks =
  forAll genDispositionInput $ \(marker, natural) ->
    let isHonored = case decideMarkerDisposition marker natural of
                       MarkerHonored _ _ -> True
                       _                  -> False
        shouldHonor = case marker of
          Just declared ->
            unDeclaredTargetSize declared < unNaturalTargetSize natural
          Nothing -> False
    in isHonored === shouldHonor

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
makeSource :: Int -> InputFileContents
makeSource sourceLength =
  InputFileContents (ByteString.replicate sourceLength 0xFF)

-- | Run apply and return the unwrapped 'Outcome', failing the test
-- with a rendered 'SlapError' on failure.
runApplyOrFail
  :: InputFileContents -> IPSPatch -> IO (Outcome OutputFileContents)
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
  -> Outcome OutputFileContents
  -> Assertion
assertApplyResult description expectedLength expectedWarnings outcome = do
  let OutputFileContents targetBytes = outcomeValue outcome
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

-- honored: source 100, one record at offset 30 length 5 (reaches
-- 35), declared 80. Expected: 80-byte output, single
-- IPSTruncationMarkerHonored warning, no clip warning.
test_applyHonoredSizesDeclared :: Assertion
test_applyHonoredSizesDeclared = do
  let patch  = makePatch (Just (FileSize 80)) [copyRecordOf 30 5 0xAA]
      source = makeSource 100
      expectedWarning =
        IPSTruncationMarkerHonored LabelIPS
          (DeclaredTargetSize (FileSize 80))
          (NaturalTargetSize  (FileSize 100))
  outcome <- runApplyOrFail source patch
  assertApplyResult "MarkerHonored" 80 [expectedWarning] outcome

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

-- honored-no-cross-no-clip: same as honored: declared, asserts no
-- IPSRecordsClippedByMarker warning is appended.
test_honoredNoCrossNoClip :: Assertion
test_honoredNoCrossNoClip = do
  let patch  = makePatch (Just (FileSize 80)) [copyRecordOf 30 5 0xAA]
      source = makeSource 100
      expectedWarning =
        IPSTruncationMarkerHonored LabelIPS
          (DeclaredTargetSize (FileSize 80))
          (NaturalTargetSize  (FileSize 100))
  outcome <- runApplyOrFail source patch
  assertApplyResult "MarkerHonored no-cross" 80 [expectedWarning] outcome

-- honored-records-cross-clip: source 100, one record at offset 80
-- length 30 (reaches 110), declared 90. Expected: 90-byte output,
-- two warnings (Honored + Clipped with count 1, first at index 0,
-- overshoot 20 bytes — record sits entirely past effective end).
test_honoredRecordsCrossClip :: Assertion
test_honoredRecordsCrossClip = do
  let patch  = makePatch (Just (FileSize 90)) [copyRecordOf 80 30 0xAA]
      source = makeSource 100
      honoredWarning =
        IPSTruncationMarkerHonored LabelIPS
          (DeclaredTargetSize (FileSize 90))
          (NaturalTargetSize  (FileSize 110))
      clippedWarning =
        IPSRecordsClippedByMarker LabelIPS
          (ClippedRecordCount 1) (actionAtPosition 0) (MarkerOvershootBytes (Length 20))
  outcome <- runApplyOrFail source patch
  assertApplyResult "MarkerHonored records-cross"
    90 [honoredWarning, clippedWarning] outcome

-- honored-record-straddles: source 100, one record at offset 70
-- length 30 (reaches 100), declared 80. Expected: 80-byte output,
-- two warnings (Honored + Clipped with count 1, first at index 0,
-- overshoot 20 bytes — record straddles, prefix written).
test_honoredRecordStraddles :: Assertion
test_honoredRecordStraddles = do
  let patch  = makePatch (Just (FileSize 80)) [copyRecordOf 70 30 0xAA]
      source = makeSource 100
      honoredWarning =
        IPSTruncationMarkerHonored LabelIPS
          (DeclaredTargetSize (FileSize 80))
          (NaturalTargetSize  (FileSize 100))
      clippedWarning =
        IPSRecordsClippedByMarker LabelIPS
          (ClippedRecordCount 1) (actionAtPosition 0) (MarkerOvershootBytes (Length 20))
  outcome <- runApplyOrFail source patch
  assertApplyResult "MarkerHonored straddles"
    80 [honoredWarning, clippedWarning] outcome
