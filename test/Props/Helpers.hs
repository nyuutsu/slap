module Props.Helpers
  ( -- * Generators
    genByteString
  , genNonEmptyByteString
  , genPair
  , genPairNoShrink
  , genShrinkingPair
  , genUPSEncodeablePair
  , genSameSizePair
  , genEofPair
    -- * Apply helpers
  , applySomePatch
    -- * Truncation
  , truncated
  , truncatedFile
    -- * IPS encoding helpers
  , ipsEncodedSize
  , narrowOne
    -- * NINJA2 helpers
  , emptyNINJA2Metadata
    -- * Warning helpers
  , isFieldTruncatedFor
    -- * Text-shaped assertions
  , assertFailureT
    -- * Re-exports for convenience
  , isLeft
  , isRight
  ) where

import qualified Slap.NINJA2.Types as NINJA2
import Slap.Status (SlapError, SlapAdvisory(..), Outcome(..))
import Slap.FormatLabel (FormatLabel)
import Slap.Measure (Hunk(..), Offset, splitHunksUnbounded)
import Slap.Narrow (EncodedHunk, EncodingLimits(..), narrowHunks)
import Slap.FileContents (InputFileContents(..), OutputFileContents(..), PatchFileContents(..))
import Slap.SomePatch (SomePatch(..), ApplyStrategy(..))

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.Text (Text)
import qualified Data.Text as Text
import Test.Tasty.HUnit (assertFailure)
import Test.Tasty.QuickCheck

----------------------------------------------------------------------------
-- Text-shaped assertions
----------------------------------------------------------------------------

-- | HUnit's 'assertFailure' takes 'String'; slap's renderers all
-- produce 'Text'. This wrapper does the one 'Text.unpack' at the
-- 'Test.Tasty.HUnit' boundary so test bodies can write
-- @assertFailureT (\"parseSome: \" <> renderSlapError err)@ instead
-- of inline-unpacking at every call site. Mirror of
-- 'Integration.Helpers.assertFailureT' for the prop-test suite.
-- Polymorphic in the return type for the same reason 'assertFailure'
-- is: it never returns, so any 'IO' shape will type-check.
assertFailureT :: Text -> IO a
assertFailureT = assertFailure . Text.unpack

----------------------------------------------------------------------------
-- Generators
----------------------------------------------------------------------------

-- | Arbitrary ByteString up to ~64 KB, biased toward small sizes and edge cases.
genByteString :: Gen ByteString
genByteString = frequency
  [ (1, pure ByteString.empty)
  , (2, ByteString.singleton <$> arbitrary)
  , (5, sized $ \sizeHint -> do
      byteCount <- choose (0, min (sizeHint * 64) 65536)
      ByteString.pack <$> vectorOf byteCount arbitrary)
  ]

-- | 'genByteString' restricted to non-empty values. Identity and
-- source-hash properties are only meaningful for a non-empty source;
-- drawing from this states that precondition in the domain rather than
-- generating empties and discarding them after the fact with '==>'.
-- 'suchThat' resamples internally, so it costs no QuickCheck discards.
genNonEmptyByteString :: Gen ByteString
genNonEmptyByteString = genByteString `suchThat` (not . ByteString.null)

-- | Arbitrary (source, target) pair with no size constraints.
genPair :: Gen (ByteString, ByteString)
genPair = (,) <$> genByteString <*> genByteString

-- | (source, target) where len(target) >= len(source).
-- Formats that lack truncation support can only grow or stay same-size.
genPairNoShrink :: Gen (ByteString, ByteString)
genPairNoShrink = do
  shorter <- genByteString
  longer <- genByteString
  pure $ if ByteString.length shorter <= ByteString.length longer then (shorter, longer) else (longer, shorter)

-- | (source, target) where len(source) > len(target).  Specifically
-- exercises the truncating-apply path: the NINJA2 truncate overflow
-- carries the discarded source tail on the wire, so an apply that
-- mistakes "carry on the wire" for "write into the output buffer"
-- writes past the end of a buffer sized for the (smaller) target.
genShrinkingPair :: Gen (ByteString, ByteString)
genShrinkingPair = do
  source <- ByteString.cons <$> arbitrary <*> genByteString
  targetLength <- choose (0, ByteString.length source - 1)
  target <- ByteString.pack <$> vectorOf targetLength arbitrary
  pure (source, target)

-- | (source, target) that UPS can encode in both directions. UPS's
-- bidirectional XOR has nowhere to store a non-zero source tail when
-- the source extends past the target, so 'createUPS' refuses such
-- pairs ('UPSSourceTailNonZero'). This generator stays inside the
-- encodeable domain by zeroing any source overhang — preserving the
-- shrink, grow, and same-size cases without the ~50% discard rate a
-- raw 'genPair' incurs (half its pairs shrink, and a random tail is
-- essentially never all-zero).
genUPSEncodeablePair :: Gen (ByteString, ByteString)
genUPSEncodeablePair = do
  (source, target) <- genPair
  let targetLength  = ByteString.length target
      overhangLength = ByteString.length source - targetLength
      encodeableSource
        | overhangLength > 0 = ByteString.take targetLength source
                                 <> ByteString.replicate overhangLength 0
        | otherwise          = source
  pure (encodeableSource, target)

-- | (source, target) of equal length. Used by formats whose wire
-- spec or upstream tooling permits only same-size patching: UPS undo
-- (only lossless when source and target sizes match) and PPF1\/PPF2\/PPF3
-- (whose @<format>RejectIncompatibleSizeChange@ checkers refuse any
-- size mismatch to match the upstream MakePPF reference encoders).
genSameSizePair :: Gen (ByteString, ByteString)
genSameSizePair = do
  source <- genByteString
  target <- ByteString.pack <$> vectorOf (ByteString.length source) arbitrary
  pure (source, target)

-- | Source and target that differ starting at exactly offset 0x454F46.
genEofPair :: Gen (ByteString, ByteString)
genEofPair = do
  let eofOffset = 0x454F46
  count <- choose (1, 100)
  diffBytes <- ByteString.pack <$> vectorOf count (choose (1, 255))
  let source = ByteString.replicate (eofOffset + count) 0
      target = ByteString.replicate eofOffset 0 <> diffBytes
  pure (source, target)

----------------------------------------------------------------------------
-- Apply helpers
----------------------------------------------------------------------------

-- | Apply through the SomePatch closure.
applySomePatch :: SomePatch -> InputFileContents -> IO (Either SlapError OutputFileContents)
applySomePatch somePatch source =
  fmap (fmap outcomeValue) (runApply (patchApply somePatch) source)

----------------------------------------------------------------------------
-- Truncation
----------------------------------------------------------------------------

-- | Truncate a patch to a random length and verify parse returns Left or Right
-- (never crashes).
truncated :: (PatchFileContents -> Either SlapError a) -> PatchFileContents -> Property
truncated parseFunction (PatchFileContents patch) =
  forAll (choose (0, ByteString.length patch - 1)) $ \truncationLength ->
    case parseFunction (PatchFileContents (ByteString.take truncationLength patch)) of
      Left _  -> property True
      Right _ -> property True

-- | Truncate a real patch file from disk to random lengths.
truncatedFile :: (PatchFileContents -> Either SlapError a) -> FilePath -> Property
truncatedFile parseFunction path = ioProperty $ do
  patchBytes <- ByteString.readFile path
  pure $ forAll (choose (0, ByteString.length patchBytes - 1)) $ \truncationLength ->
    case parseFunction (PatchFileContents (ByteString.take truncationLength patchBytes)) of
      Left _  -> property True
      Right _ -> property True

----------------------------------------------------------------------------
-- IPS encoding helpers
----------------------------------------------------------------------------

-- | Total encoded IPS record size (excluding magic/EOF marker).
-- Operates on raw payload bytes so the helper is indifferent to
-- whether the caller has a list of 'Hunk' or 'SplitHunk' or anything
-- else — only the payload shape matters for the cost model.
ipsEncodedSize :: Int -> [ByteString] -> Int
ipsEncodedSize offWidth = sum . map recordSize
  where
    recordSize payload
      | ByteString.length payload >= 4, ByteString.all (== ByteString.index payload 0) payload = offWidth + 5
      | otherwise = offWidth + 2 + ByteString.length payload

-- | Test helper: narrow a single hunk, fail loudly if it overflows.
-- Used by tests that need 'EncodedHunk' values as inputs to functions
-- which consume them. Routes through 'splitHunksUnbounded' so the
-- single-step constructor stays short — these tests are exercising
-- the narrow side, not the split cap.
narrowOne :: EncodingLimits -> Offset -> ByteString -> EncodedHunk
narrowOne limits offset payload =
  case narrowHunks limits (splitHunksUnbounded [Hunk offset payload]) of
    Right [encoded] -> encoded
    Right other     -> error ("narrowOne: unexpected list shape " ++ show (length other))
    Left failure    -> error ("narrowOne: test setup bug, narrow failed with " ++ show failure)

----------------------------------------------------------------------------
-- NINJA2 helpers
----------------------------------------------------------------------------

emptyNINJA2Metadata :: NINJA2.NINJA2CreateMetadata
emptyNINJA2Metadata = NINJA2.NINJA2CreateMetadata
  { NINJA2.ninja2CreateMetadataAuthor      = Nothing
  , NINJA2.ninja2CreateMetadataVersion     = Nothing
  , NINJA2.ninja2CreateMetadataTitle       = Nothing
  , NINJA2.ninja2CreateMetadataGenre       = Nothing
  , NINJA2.ninja2CreateMetadataLanguage    = Nothing
  , NINJA2.ninja2CreateMetadataDate        = Nothing
  , NINJA2.ninja2CreateMetadataWebsite     = Nothing
  , NINJA2.ninja2CreateMetadataDescription = Nothing
  , NINJA2.ninja2CreateTextMode           = NINJA2.TextModeUTF8
  , NINJA2.ninja2CreateMetadataPlatform    = Nothing
  }

----------------------------------------------------------------------------
-- Warning helpers
----------------------------------------------------------------------------

isFieldTruncatedFor :: FormatLabel -> SlapAdvisory -> Bool
isFieldTruncatedFor expectedLabel (FieldTruncated warningLabel _ _ _ _) = expectedLabel == warningLabel
isFieldTruncatedFor _ _ = False

----------------------------------------------------------------------------
-- Predicate helpers
----------------------------------------------------------------------------

isLeft :: Either a b -> Bool
isLeft (Left _) = True
isLeft _        = False

isRight :: Either a b -> Bool
isRight (Right _) = True
isRight _         = False
