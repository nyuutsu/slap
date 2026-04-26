module Props.Helpers
  ( -- * Generators
    genByteString
  , genPair
  , genPairNoShrink
  , genShrinkingPair
  , genSameSizePair
  , genEofPair
    -- * Apply helpers
  , applySomePatch
    -- * Truncation
  , truncated
  , truncatedFile
    -- * IPS encoding helpers
  , splitMax
  , ipsEncodedSize
    -- * NINJA2 helpers
  , emptyNINJA2Metadata
    -- * Warning helpers
  , isFieldTruncatedFor
    -- * Re-exports for convenience
  , isLeft
  , isRight
  ) where

import qualified Slap.NINJA2.Types as NINJA2
import Slap.Error (SlapError, SlapWarning(..))
import Slap.FormatLabel (FormatLabel)
import Slap.Measure (Offset(..), EncodedHunk(..), Hunk(..))
import Slap.FileContents (SourceFileContents(..), TargetFileContents(..), PatchFileContents(..))
import Slap.SomePatch (SomePatch(..), ApplyStrategy(..))

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Test.Tasty.QuickCheck

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

-- | (source, target) of equal length.  UPS undo is only lossless when
-- source and target sizes match (the normal ROM patching case).
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
applySomePatch :: SomePatch -> SourceFileContents -> IO (Either SlapError TargetFileContents)
applySomePatch somePatch source = inMemoryApply (patchApply somePatch) source

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

-- | Split hunks at maxSize boundaries.
splitMax :: Int -> [Hunk] -> [EncodedHunk]
splitMax maxRecordSize = concatMap splitRecord . map hunkToEncoded
  where
    hunkToEncoded (Hunk hunkOffset hunkPayload) = EncodedHunk hunkOffset hunkPayload
    splitRecord (EncodedHunk hunkOffset hunkPayload)
      | ByteString.length hunkPayload <= maxRecordSize = [EncodedHunk hunkOffset hunkPayload]
      | otherwise =
          let (chunk, remaining) = ByteString.splitAt maxRecordSize hunkPayload
          in EncodedHunk hunkOffset chunk : splitRecord (EncodedHunk (Offset (unOffset hunkOffset + fromIntegral maxRecordSize)) remaining)

-- | Total encoded IPS record size (excluding magic/EOF marker).
ipsEncodedSize :: Int -> [EncodedHunk] -> Int
ipsEncodedSize offWidth = sum . map recordSize
  where
    recordSize (EncodedHunk _ payload)
      | ByteString.length payload >= 3, ByteString.all (== ByteString.index payload 0) payload = offWidth + 5
      | otherwise = offWidth + 2 + ByteString.length payload

----------------------------------------------------------------------------
-- NINJA2 helpers
----------------------------------------------------------------------------

emptyNINJA2Metadata :: NINJA2.NINJA2Metadata
emptyNINJA2Metadata = NINJA2.NINJA2Metadata
  { NINJA2.ninja2MetadataAuthor      = Nothing
  , NINJA2.ninja2MetadataVersion     = Nothing
  , NINJA2.ninja2MetadataTitle       = Nothing
  , NINJA2.ninja2MetadataGenre       = Nothing
  , NINJA2.ninja2MetadataLanguage    = Nothing
  , NINJA2.ninja2MetadataDate        = Nothing
  , NINJA2.ninja2MetadataWebsite     = Nothing
  , NINJA2.ninja2MetadataDescription = Nothing
  , NINJA2.ninja2MetadataEncoding    = NINJA2.PatchEncodingUTF8
  , NINJA2.ninja2MetadataPlatform    = Nothing
  }

----------------------------------------------------------------------------
-- Warning helpers
----------------------------------------------------------------------------

isFieldTruncatedFor :: FormatLabel -> SlapWarning -> Bool
isFieldTruncatedFor expectedLabel (FieldTruncated warningLabel _ _ _) = expectedLabel == warningLabel
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
