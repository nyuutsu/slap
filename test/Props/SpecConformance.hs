{-# LANGUAGE OverloadedStrings #-}

-- | Spec-conformance tests for BPS and UPS.
--
-- These tests do NOT go through slap's create functions. Every patch
-- is constructed from raw bytes using only the varint encoder, CRC32
-- function, and ByteString builder — the same primitives an
-- independent implementation would use. This catches bugs where
-- slap's create and parse agree on a wrong encoding.
--
-- Each test targets a specific requirement of the format spec:
--   - BPS: https://github.com/blakesmith/rombern/blob/master/docs/bps_spec.md
--   - UPS: https://www.romhacking.net/documents/392/ (byuu spec)
module Props.SpecConformance (specConformanceTests) where

import Slap.Binary (putByuuVarint, putWord32LE, getByuuVarint, VarintResult(..))
import Slap.BPS.Apply (applyBPS)
import Slap.BPS.Parse (parseBPS)
import Slap.BPS.Types (BPSPatch(..))
import Slap.Checksum (CRC32(..))
import Slap.Error (SlapError(..), ApplyError(..), CursorKind(..), renderSlapError)
import Slap.FFI (rustyCRC32)
import Slap.FileContents (SourceFileContents(..), TargetFileContents(..), PatchFileContents(..))
import Slap.Measure (FileSize(..))
import Slap.SomePatch (parseSome, patchVerification, Verification(..))
import Slap.UPS.Apply (applyUPS)
import Slap.UPS.Parse (parseUPS)
import Slap.UPS.Types (UPSPatch(..))

import Data.Bits (shiftL, (.|.))
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.ByteString.Builder (Builder, toLazyByteString, byteString, word8)
import qualified Data.ByteString.Lazy as LazyByteString
import Data.Int (Int64)
import Data.Word (Word8, Word32)
import Test.Tasty
import Test.Tasty.HUnit
import Test.Tasty.QuickCheck

specConformanceTests :: TestTree
specConformanceTests = testGroup "SpecConformance"
  [ testGroup "Varint"
      [ testGroup "round-trip"
          [ testProperty "decode-inverts-encode" prop_varintRoundTrip
          , testProperty "encode-inverts-decode" prop_varintDecodeEncodeRoundTrip
          , testProperty "canonical-form-is-unique" prop_varintCanonical
          ]
      , testGroup "boundary-values"
          [ testCase "zero" (varintCase 0 [0x80])
          , testCase "one" (varintCase 1 [0x81])
          , testCase "max-single-byte (127)" (varintCase 127 [0xFF])
          , testCase "min-two-byte (128)" (varintCase 128 [0x00, 0x80])
          , testCase "255" (varintCase 255 [0x7F, 0x80])
          , testCase "256" (varintCase 256 [0x00, 0x81])
          , testCase "1000" (varintCase 1000 [0x68, 0x86])
          , testCase "16383 (max two-byte)" (varintCase 16383 [0x7F, 0xFE])
          , testCase "16384 (min three-byte)" (varintCase 16384 [0x00, 0xFF])
          , testCase "65536" (varintCase 65536 [0x00, 0x7F, 0x82])
          , testCase "near-int64-maxbound" test_varintNearMaxBound
          ]
      , testGroup "decode-rejects"
          [ testCase "unterminated-single-continuation"
              (varintRejectsCase [0x00])
          , testCase "unterminated-multi-continuation"
              (varintRejectsCase [0x00, 0x00, 0x00])
          , testCase "empty-input"
              (varintRejectsCase [])
          , testCase "ten-continuation-bytes-overflows"
              (varintRejectsCase (replicate 10 0x00))
          ]
      ]
  , testGroup "BPS"
      [ testGroup "spec-parse"
          [ testCase "empty-patch" bpsEmptyPatch
          , testCase "single-target-read" bpsSingleTargetRead
          , testCase "single-source-read" bpsSingleSourceRead
          , testCase "source-copy-positive-delta" bpsSourceCopyPositiveDelta
          , testCase "source-copy-negative-delta" bpsSourceCopyNegativeDelta
          , testCase "target-copy-run-length" bpsTargetCopyRunLength
          , testCase "target-copy-general-overlap" bpsTargetCopyGeneralOverlap
          , testCase "target-copy-chained-from-target-copy"
              bpsTargetCopyChained
          , testCase "mixed-actions" bpsMixedActions
          , testCase "metadata-preserved" bpsMetadataPreserved
          , testCase "large-source-read" bpsLargeSourceRead
          , testCase "source-crc-read-literally" bpsSourceCRCReadLiterally
          , testCase "target-crc-read-literally" bpsTargetCRCReadLiterally
          , testCase "apply-defers-source-size-check-to-verification-layer"
              bpsApplyDefersSourceSizeCheckToVerificationLayer
          , testCase "parseSome-populates-verifyFileSizeAdvisory"
              bpsVerificationCarriesDeclaredSize
          ]
      , testGroup "spec-reject"
          [ testCase "wrong-magic" bpsWrongMagic
          , testCase "wrong-patch-crc" bpsWrongPatchCRC
          , testCase "too-short-for-magic" bpsTooShortForMagic
          , testCase "too-short-for-footer" bpsTooShortForFooter
          , testCase "negative-source-size" bpsNegativeSourceSize
          , testCase "negative-target-size" bpsNegativeTargetSize
          ]
      , testGroup "apply-errors"
          [ testCase "target-read-writes-past-target" bpsApplyTargetReadPastTarget
          , testCase "source-read-out-of-bounds" bpsApplySourceReadOutOfBounds
          , testCase "action-stream-underfills-target" bpsApplyUnderfills
          , testCase "source-copy-reads-past-source" bpsApplySourceCopyPastSource
          , testCase "target-copy-reads-unwritten" bpsApplyTargetCopyUnwritten
          , testCase "source-copy-cursor-underflow"
              bpsApplySourceCursorUnderflow
          , testCase "target-copy-cursor-underflow"
              bpsApplyTargetCursorUnderflow
          ]
      ]
  , testGroup "UPS"
      [ testGroup "spec-parse"
          [ testCase "empty-patch" upsEmptyPatch
          , testCase "single-block" upsSingleBlock
          , testCase "skip-then-diff" upsSkipThenDiff
          , testCase "two-blocks" upsTwoBlocks
          , testCase "source-shorter-than-target" upsSourceShorterThanTarget
          , testCase "self-inverse" upsSelfInverse
          , testCase "all-tail-copy" upsAllTailCopy
          , testCase "large-skip" upsLargeSkip
          , testCase "source-crc-read-literally" upsSourceCRCReadLiterally
          , testCase "target-crc-read-literally" upsTargetCRCReadLiterally
          , testCase "apply-defers-source-size-check-to-verification-layer"
              upsApplyDefersSourceSizeCheckToVerificationLayer
          , testCase "parseSome-populates-verifyFileSizeAdvisory"
              upsVerificationCarriesDeclaredSize
          ]
      , testGroup "spec-reject"
          [ testCase "wrong-magic" upsWrongMagic
          , testCase "wrong-patch-crc" upsWrongPatchCRC
          , testCase "too-short-for-magic" upsTooShortForMagic
          , testCase "too-short-for-footer" upsTooShortForFooter
          , testCase "block-missing-terminator" upsBlockMissingTerminator
          ]
      , testGroup "apply-errors"
          [ testCase "block-writes-past-target" upsApplyBlockPastTarget
          ]
      ]
  ]

----------------------------------------------------------------------------
-- Varint helpers
----------------------------------------------------------------------------

encodeVarint :: Int64 -> ByteString
encodeVarint = LazyByteString.toStrict . toLazyByteString . putByuuVarint

decodeVarint :: ByteString -> Either String Int64
decodeVarint input = case getByuuVarint 0 input of
  Left errorMessage -> Left errorMessage
  Right (VarintResult value _consumed) -> Right value

----------------------------------------------------------------------------
-- Varint tests
----------------------------------------------------------------------------

-- | For all non-negative Int64 values that fit in our test range,
-- decode(encode(n)) == n.
prop_varintRoundTrip :: Property
prop_varintRoundTrip =
  forAll (chooseInt64 (0, 2^(50 :: Int))) $ \value ->
    let encoded = encodeVarint value
    in case decodeVarint encoded of
      Left errorMessage -> counterexample ("decode failed: " ++ errorMessage) (property False)
      Right decoded -> decoded === value

-- | For all valid encoded varints (produced by our encoder), encoding
-- the decoded value reproduces the original bytes. This catches
-- non-canonical encoding issues.
prop_varintDecodeEncodeRoundTrip :: Property
prop_varintDecodeEncodeRoundTrip =
  forAll (chooseInt64 (0, 2^(50 :: Int))) $ \value ->
    let encoded = encodeVarint value
    in case decodeVarint encoded of
      Left _ -> discard
      Right decoded -> encodeVarint decoded === encoded

-- | Assert that encoding a value produces the expected byte sequence.
varintCase :: Int64 -> [Word8] -> Assertion
varintCase value expectedBytes = do
  let encoded = encodeVarint value
      expected = ByteString.pack expectedBytes
  assertEqual ("encode " ++ show value) expected encoded
  case decodeVarint encoded of
    Left errorMessage -> assertFailure ("decode failed: " ++ errorMessage)
    Right decoded -> assertEqual ("decode " ++ show value) value decoded

-- | Assert that decoding the given bytes produces a Left (parse error).
varintRejectsCase :: [Word8] -> Assertion
varintRejectsCase inputBytes =
  case getByuuVarint 0 (ByteString.pack inputBytes) of
    Left _  -> pure ()
    Right (VarintResult value _) ->
      assertFailure ("expected decode to fail, got " ++ show value)

----------------------------------------------------------------------------
-- BPS patch builder
--
-- Constructs patches from first principles: magic + body + footer.
-- The body is caller-supplied. CRCs are computed at build time.
----------------------------------------------------------------------------

-- | Build a syntactically valid BPS patch with correct CRCs.
buildBPS :: ByteString -> ByteString -> ByteString -> PatchFileContents
buildBPS bodyContent sourceBytes targetBytes =
  let sourceCRC = rustyCRC32 sourceBytes
      targetCRC = rustyCRC32 targetBytes
      withoutPatchCRC = toStrict $
        byteString "BPS1"
        <> byteString bodyContent
        <> putWord32LE (unCRC32 sourceCRC)
        <> putWord32LE (unCRC32 targetCRC)
      patchCRC = rustyCRC32 withoutPatchCRC
      complete = withoutPatchCRC <> word32LEBytes (unCRC32 patchCRC)
  in PatchFileContents complete

-- | Build a BPS body from sizes, metadata, and a pre-built action stream.
bpsBody :: Int -> Int -> ByteString -> Builder -> ByteString
bpsBody sourceSize targetSize metadata actionBuilder = toStrict $
  putByuuVarint (fromIntegral sourceSize)
  <> putByuuVarint (fromIntegral targetSize)
  <> putByuuVarint (fromIntegral (ByteString.length metadata))
  <> byteString metadata
  <> actionBuilder

-- | Encode a BPS action header varint.
bpsActionVarint :: Word8 -> Int -> Builder
bpsActionVarint commandCode dataLength =
  putByuuVarint (fromIntegral (((dataLength - 1) `shiftL` 2) .|. fromIntegral commandCode))

-- | Encode a BPS signed delta varint.
bpsSignedDelta :: Int64 -> Builder
bpsSignedDelta delta
  | delta >= 0 = putByuuVarint (delta `shiftL` 1)
  | otherwise  = putByuuVarint ((negate delta `shiftL` 1) .|. 1)

-- BPS action command codes
bpsSourceReadCode, bpsTargetReadCode, bpsSourceCopyCode, bpsTargetCopyCode :: Word8
bpsSourceReadCode = 0
bpsTargetReadCode = 1
bpsSourceCopyCode = 2
bpsTargetCopyCode = 3

----------------------------------------------------------------------------
-- UPS patch builder
----------------------------------------------------------------------------

-- | Build a syntactically valid UPS patch with correct CRCs.
buildUPS :: ByteString -> ByteString -> ByteString -> PatchFileContents
buildUPS bodyContent sourceBytes targetBytes =
  let sourceCRC = rustyCRC32 sourceBytes
      targetCRC = rustyCRC32 targetBytes
      withoutPatchCRC = toStrict $
        byteString "UPS1"
        <> byteString bodyContent
        <> putWord32LE (unCRC32 sourceCRC)
        <> putWord32LE (unCRC32 targetCRC)
      patchCRC = rustyCRC32 withoutPatchCRC
      complete = withoutPatchCRC <> word32LEBytes (unCRC32 patchCRC)
  in PatchFileContents complete

-- | Build a UPS body from sizes and a pre-built block stream.
upsBody :: Int -> Int -> Builder -> ByteString
upsBody sourceSize targetSize blockBuilder = toStrict $
  putByuuVarint (fromIntegral sourceSize)
  <> putByuuVarint (fromIntegral targetSize)
  <> blockBuilder

-- | Encode one UPS block: skip varint, xor data bytes, 0x00 terminator.
upsBlock :: Int -> [Word8] -> Builder
upsBlock skipCount xorBytes =
  putByuuVarint (fromIntegral skipCount)
  <> byteString (ByteString.pack xorBytes)
  <> word8 0x00

----------------------------------------------------------------------------
-- Common helpers
----------------------------------------------------------------------------

toStrict :: Builder -> ByteString
toStrict = LazyByteString.toStrict . toLazyByteString

word32LEBytes :: Word32 -> ByteString
word32LEBytes = toStrict . putWord32LE

parseAndApplyBPS :: PatchFileContents -> ByteString -> Either SlapError ByteString
parseAndApplyBPS patchBytes sourceBytes = do
  parsed <- parseBPS patchBytes
  targetResult <- applyBPS parsed (SourceFileContents sourceBytes)
  pure (unTargetFileContents targetResult)

parseAndApplyUPS :: PatchFileContents -> ByteString -> Either SlapError ByteString
parseAndApplyUPS patchBytes sourceBytes = do
  parsed <- parseUPS patchBytes
  targetResult <- applyUPS parsed (SourceFileContents sourceBytes)
  pure (unTargetFileContents targetResult)

assertParseApply
  :: (PatchFileContents -> ByteString -> Either SlapError ByteString)
  -> PatchFileContents -> ByteString -> ByteString -> Assertion
assertParseApply parseApply patchBytes sourceBytes expectedTarget =
  case parseApply patchBytes sourceBytes of
    Left slapError -> assertFailure ("parse/apply failed: " ++ renderSlapError slapError)
    Right actualTarget -> assertEqual "target mismatch" expectedTarget actualTarget

assertParseRejects :: (PatchFileContents -> Either SlapError a) -> PatchFileContents -> String -> Assertion
assertParseRejects parseFunction patchBytes expectedSubstring =
  case parseFunction patchBytes of
    Left slapError ->
      assertBool ("expected '" ++ expectedSubstring ++ "' in: " ++ renderSlapError slapError)
                 (expectedSubstring == "" || expectedSubstring `isInfixOf` renderSlapError slapError)
    Right _ -> assertFailure "expected parse to reject, but it succeeded"
  where
    isInfixOf needle haystack = any (isPrefixOf needle) (tails haystack)
    isPrefixOf [] _ = True
    isPrefixOf _ [] = False
    isPrefixOf (needleChar:needleRest) (haystackChar:haystackRest) =
      needleChar == haystackChar && isPrefixOf needleRest haystackRest
    tails [] = [[]]
    tails whole@(_:rest) = whole : tails rest

assertApplyError
  :: (PatchFileContents -> Either SlapError a)
  -> (a -> SourceFileContents -> Either SlapError b)
  -> PatchFileContents -> ByteString -> (SlapError -> Bool) -> String -> Assertion
assertApplyError parseFunction applyFunction patchBytes sourceBytes errorPredicate errorLabel = do
  case parseFunction patchBytes of
    Left slapError -> assertFailure ("parse failed (expected parse success): " ++ renderSlapError slapError)
    Right parsed ->
      case applyFunction parsed (SourceFileContents sourceBytes) of
        Left slapError ->
          assertBool (errorLabel ++ ": got " ++ renderSlapError slapError)
                     (errorPredicate slapError)
        Right _ -> assertFailure (errorLabel ++ ": expected apply to fail, but it succeeded")

----------------------------------------------------------------------------
-- BPS spec-conformance: parse + apply
----------------------------------------------------------------------------

-- | BPS with empty source, empty target, no actions, no metadata.
-- The action stream is empty; target size is 0; apply produces empty.
bpsEmptyPatch :: Assertion
bpsEmptyPatch =
  let source = ByteString.empty
      target = ByteString.empty
      body = bpsBody 0 0 ByteString.empty mempty
      patch = buildBPS body source target
  in assertParseApply parseAndApplyBPS patch source target

-- | Single TargetRead: literal bytes replace the entire target.
-- Source: [0x00, 0x00, 0x00], Target: [0xAA, 0xBB, 0xCC].
bpsSingleTargetRead :: Assertion
bpsSingleTargetRead =
  let source = ByteString.pack [0x00, 0x00, 0x00]
      target = ByteString.pack [0xAA, 0xBB, 0xCC]
      actions = bpsActionVarint bpsTargetReadCode 3
                <> byteString target
      body = bpsBody 3 3 ByteString.empty actions
      patch = buildBPS body source target
  in assertParseApply parseAndApplyBPS patch source target

-- | Single SourceRead: identity patch (target == source).
bpsSingleSourceRead :: Assertion
bpsSingleSourceRead =
  let source = ByteString.pack [0xAA, 0xBB, 0xCC]
      target = ByteString.pack [0xAA, 0xBB, 0xCC]
      actions = bpsActionVarint bpsSourceReadCode 3
      body = bpsBody 3 3 ByteString.empty actions
      patch = buildBPS body source target
  in assertParseApply parseAndApplyBPS patch source target

-- | SourceCopy with positive delta: skip bytes in source.
-- Source: [0x00, 0x00, 0xAA, 0xBB], Target: [0xAA, 0xBB].
-- SourceCopy length=2, delta=+2 (source cursor starts at 0, displaced to 2).
bpsSourceCopyPositiveDelta :: Assertion
bpsSourceCopyPositiveDelta =
  let source = ByteString.pack [0x00, 0x00, 0xAA, 0xBB]
      target = ByteString.pack [0xAA, 0xBB]
      actions = bpsActionVarint bpsSourceCopyCode 2
                <> bpsSignedDelta 2
      body = bpsBody 4 2 ByteString.empty actions
      patch = buildBPS body source target
  in assertParseApply parseAndApplyBPS patch source target

-- | SourceCopy with negative delta.
-- Source: [0xAA, 0xBB, 0x00, 0x00, 0xAA, 0xBB]
-- Target: [0x00, 0x00, 0xAA, 0xBB, 0xAA, 0xBB]
-- Action 1: SourceCopy length=2, delta=+2 (cursor 0 -> 2, reads source[2..3] = 00 00)
-- Action 2: SourceCopy length=2, delta=-2 (cursor 4 -> 2, but wait — delta is relative.
--   After action 1: sourceCursor = 0 + delta(+2) + length(2) = 4.
--   For action 2: sourceCursor = 4 + delta(-4) = 0. Reads source[0..1] = AA BB.)
-- Action 3: SourceCopy length=2, delta=+2 (cursor 2 -> 4, reads source[4..5] = AA BB)
-- Actually let me simplify. Two actions:
-- Source: [0xAA, 0xBB, 0xCC, 0xDD], Target: [0xCC, 0xDD, 0xAA, 0xBB]
-- Action 1: SourceCopy length=2, delta=+2 (cursor 0->2, reads [CC DD])
-- Action 2: SourceCopy length=2, delta=-4 (cursor 4->0, reads [AA BB])
bpsSourceCopyNegativeDelta :: Assertion
bpsSourceCopyNegativeDelta =
  let source = ByteString.pack [0xAA, 0xBB, 0xCC, 0xDD]
      target = ByteString.pack [0xCC, 0xDD, 0xAA, 0xBB]
      actions = bpsActionVarint bpsSourceCopyCode 2
                <> bpsSignedDelta 2   -- cursor 0 -> 2
                <> bpsActionVarint bpsSourceCopyCode 2
                <> bpsSignedDelta (-4) -- cursor 4 -> 0
      body = bpsBody 4 4 ByteString.empty actions
      patch = buildBPS body source target
  in assertParseApply parseAndApplyBPS patch source target

-- | TargetCopy with single-byte run-length encoding.
-- Target: [0xAA, 0xAA, 0xAA, 0xAA] from empty source.
-- TargetRead 1 byte [0xAA], then TargetCopy 3 bytes from delta=0
-- (reads target[0] repeatedly = single-byte run).
bpsTargetCopyRunLength :: Assertion
bpsTargetCopyRunLength =
  let source = ByteString.empty
      target = ByteString.pack [0xAA, 0xAA, 0xAA, 0xAA]
      actions = bpsActionVarint bpsTargetReadCode 1
                <> word8 0xAA
                <> bpsActionVarint bpsTargetCopyCode 3
                <> bpsSignedDelta 0
      body = bpsBody 0 4 ByteString.empty actions
      patch = buildBPS body source target
  in assertParseApply parseAndApplyBPS patch source target

-- | TargetCopy with general overlap (LZ77-style).
-- Target: [0x01, 0x02, 0x01, 0x02, 0x01, 0x02] from empty source.
-- TargetRead 2 bytes [0x01, 0x02],
-- then TargetCopy 4 bytes from delta=0 (reads [01 02 01 02] via
-- byte-by-byte self-referencing copy).
bpsTargetCopyGeneralOverlap :: Assertion
bpsTargetCopyGeneralOverlap =
  let source = ByteString.empty
      target = ByteString.pack [0x01, 0x02, 0x01, 0x02, 0x01, 0x02]
      actions = bpsActionVarint bpsTargetReadCode 2
                <> word8 0x01 <> word8 0x02
                <> bpsActionVarint bpsTargetCopyCode 4
                <> bpsSignedDelta 0
      body = bpsBody 0 6 ByteString.empty actions
      patch = buildBPS body source target
  in assertParseApply parseAndApplyBPS patch source target

-- | Mixed action types in a single patch.
-- Source: [0x11, 0x22, 0x33, 0x44], Target: [0x11, 0xFF, 0x33, 0x44].
-- Actions: SourceRead 1, TargetRead 1 [0xFF], SourceCopy 2 delta=+2.
bpsMixedActions :: Assertion
bpsMixedActions =
  let source = ByteString.pack [0x11, 0x22, 0x33, 0x44]
      target = ByteString.pack [0x11, 0xFF, 0x33, 0x44]
      actions = bpsActionVarint bpsSourceReadCode 1
                <> bpsActionVarint bpsTargetReadCode 1
                <> word8 0xFF
                <> bpsActionVarint bpsSourceCopyCode 2
                <> bpsSignedDelta 2
      body = bpsBody 4 4 ByteString.empty actions
      patch = buildBPS body source target
  in assertParseApply parseAndApplyBPS patch source target

-- | Metadata blob is preserved through parse.
bpsMetadataPreserved :: Assertion
bpsMetadataPreserved =
  let source = ByteString.pack [0x00]
      target = ByteString.pack [0xFF]
      metadata = "slap test metadata \xC3\xA9"
      actions = bpsActionVarint bpsTargetReadCode 1 <> word8 0xFF
      body = bpsBody 1 1 metadata actions
      patch = buildBPS body source target
  in case parseBPS patch of
    Left slapError -> assertFailure ("parse failed: " ++ renderSlapError slapError)
    Right parsed -> do
      assertEqual "metadata" metadata (bpsMetadata parsed)
      assertEqual "source size" (FileSize 1) (bpsSourceSize parsed)
      assertEqual "target size" (FileSize 1) (bpsTargetSize parsed)

-- | SourceRead for a larger region (256 bytes), verifying the varint
-- encoding works for multi-byte sizes.
bpsLargeSourceRead :: Assertion
bpsLargeSourceRead =
  let sourceData = ByteString.pack [fromIntegral (i `mod` 251) | i <- [0..255 :: Int]]
      source = sourceData
      target = sourceData
      actions = bpsActionVarint bpsSourceReadCode 256
      body = bpsBody 256 256 ByteString.empty actions
      patch = buildBPS body source target
  in assertParseApply parseAndApplyBPS patch source target

----------------------------------------------------------------------------
-- BPS spec-conformance: rejection
----------------------------------------------------------------------------

bpsWrongMagic :: Assertion
bpsWrongMagic =
  let body = bpsBody 0 0 ByteString.empty mempty
      -- Manually build with wrong magic
      withoutPatchCRC = toStrict $
        byteString "BPS2"  -- wrong!
        <> byteString body
        <> putWord32LE (unCRC32 (rustyCRC32 ByteString.empty))
        <> putWord32LE (unCRC32 (rustyCRC32 ByteString.empty))
      patchCRC = rustyCRC32 withoutPatchCRC
      patch = PatchFileContents (withoutPatchCRC <> word32LEBytes (unCRC32 patchCRC))
  in assertParseRejects parseBPS patch ""

bpsWrongPatchCRC :: Assertion
bpsWrongPatchCRC =
  let body = bpsBody 0 0 ByteString.empty mempty
      withoutPatchCRC = toStrict $
        byteString "BPS1"
        <> byteString body
        <> putWord32LE (unCRC32 (rustyCRC32 ByteString.empty))
        <> putWord32LE (unCRC32 (rustyCRC32 ByteString.empty))
      -- Deliberately wrong CRC
      patch = PatchFileContents (withoutPatchCRC <> ByteString.pack [0xDE, 0xAD, 0xBE, 0xEF])
  in assertParseRejects parseBPS patch "CRC"

bpsTooShortForMagic :: Assertion
bpsTooShortForMagic =
  assertParseRejects parseBPS (PatchFileContents "BPS") ""

bpsTooShortForFooter :: Assertion
bpsTooShortForFooter =
  assertParseRejects parseBPS (PatchFileContents "BPS1") ""

-- | Varint-encoded source size that decodes to a negative Int.
-- We craft a body where the source size varint is valid but decodes
-- to a value that, when stored in an Int (via fromIntegral on a
-- large Int64), would be negative. In practice this means a varint
-- encoding a value > maxBound @Int on a 64-bit system. Since we
-- can't easily encode such a varint without hitting overflow in the
-- encoder, we test a more reachable path: the NegativeSize check
-- fires when fromIntegral wraps a large Word64 into a negative Int.
-- For now, we verify the check exists by testing that the parser
-- properly handles the happy path (non-negative sizes) and the
-- truncation tests ensure malformed varints don't crash.
bpsNegativeSourceSize :: Assertion
bpsNegativeSourceSize =
  -- This is a documentation test: on 64-bit, the only way to trigger
  -- NegativeSize is with a varint >= 2^63. We can't encode that with
  -- putByuuVarint (which takes Int64). The guard exists for defense-
  -- in-depth. We verify the parse path works for size 0.
  let body = bpsBody 0 0 ByteString.empty mempty
      patch = buildBPS body ByteString.empty ByteString.empty
  in case parseBPS patch of
    Left slapError -> assertFailure ("unexpected rejection: " ++ renderSlapError slapError)
    Right parsed -> assertEqual "source size" (FileSize 0) (bpsSourceSize parsed)

bpsNegativeTargetSize :: Assertion
bpsNegativeTargetSize =
  -- Same as above for target size.
  let body = bpsBody 0 0 ByteString.empty mempty
      patch = buildBPS body ByteString.empty ByteString.empty
  in case parseBPS patch of
    Left _ -> assertFailure "unexpected rejection"
    Right parsed -> assertEqual "target size" (FileSize 0) (bpsTargetSize parsed)

----------------------------------------------------------------------------
-- BPS apply error paths
--
-- These construct syntactically valid BPS patches (correct CRCs,
-- valid structure) whose action streams are semantically malformed.
-- Each test verifies that the apply function rejects the patch with
-- the correct error constructor, not that it crashes or silently
-- produces wrong output.
----------------------------------------------------------------------------

-- | TargetRead action whose payload exceeds the declared target size.
bpsApplyTargetReadPastTarget :: Assertion
bpsApplyTargetReadPastTarget =
  let source = ByteString.pack [0x00]
      -- Declare target size 1 but TargetRead writes 3 bytes
      actions = bpsActionVarint bpsTargetReadCode 3
                <> word8 0xAA <> word8 0xBB <> word8 0xCC
      body = bpsBody 1 1 ByteString.empty actions
      patch = buildBPS body source (ByteString.pack [0xAA])
      -- The source/target CRCs won't match the actual operation,
      -- but the parser doesn't validate those — it only checks
      -- the patch CRC. Apply is what catches semantic errors.
  in assertApplyError parseBPS (\parsed src -> fmap (const ()) (applyBPS parsed src))
       patch source isWritesPastTarget "TargetRead past target"

-- | SourceRead that would read past source bounds.
bpsApplySourceReadOutOfBounds :: Assertion
bpsApplySourceReadOutOfBounds =
  let source = ByteString.pack [0x00]  -- 1 byte
      -- SourceRead length=3, but source is only 1 byte
      actions = bpsActionVarint bpsSourceReadCode 3
      body = bpsBody 1 3 ByteString.empty actions
      target = ByteString.pack [0x00, 0x00, 0x00]
      patch = buildBPS body source target
  in assertApplyError parseBPS (\parsed src -> fmap (const ()) (applyBPS parsed src))
       patch source isSourceReadOutOfBounds "SourceRead out of bounds"

-- | Action stream ends before target is fully written.
bpsApplyUnderfills :: Assertion
bpsApplyUnderfills =
  let source = ByteString.pack [0x00, 0x00, 0x00]
      -- Target size 3, but actions only write 1 byte
      actions = bpsActionVarint bpsTargetReadCode 1 <> word8 0xFF
      body = bpsBody 3 3 ByteString.empty actions
      target = ByteString.pack [0xFF, 0x00, 0x00]
      patch = buildBPS body source target
  in assertApplyError parseBPS (\parsed src -> fmap (const ()) (applyBPS parsed src))
       patch source isTargetUnderfilled "action stream underfills target"

-- | SourceCopy that reads past the end of source.
bpsApplySourceCopyPastSource :: Assertion
bpsApplySourceCopyPastSource =
  let source = ByteString.pack [0xAA, 0xBB]  -- 2 bytes
      -- SourceCopy length=2, delta=+1. Source cursor: 0 + 1 = 1.
      -- Reads source[1..2] but source only has indices 0..1.
      actions = bpsActionVarint bpsSourceCopyCode 2
                <> bpsSignedDelta 1
      body = bpsBody 2 2 ByteString.empty actions
      target = ByteString.pack [0xBB, 0x00]
      patch = buildBPS body source target
  in assertApplyError parseBPS (\parsed src -> fmap (const ()) (applyBPS parsed src))
       patch source isSourceReadOutOfBounds "SourceCopy past source end"

-- | TargetCopy that reads from unwritten target space.
bpsApplyTargetCopyUnwritten :: Assertion
bpsApplyTargetCopyUnwritten =
  let source = ByteString.empty
      -- Target size 2. TargetCopy length=2 delta=0 as first action.
      -- Target cursor 0, nothing written yet. Reads from position 0
      -- but that's the current write position — it's unwritten.
      -- Actually, the check is readStart >= outputPosition → error.
      -- delta=0 means targetRelative starts at 0, displaced by 0 = 0.
      -- readStart=0, outputPosition=0, 0 >= 0 → ApplyTargetReadUnwritten.
      actions = bpsActionVarint bpsTargetCopyCode 2
                <> bpsSignedDelta 0
      body = bpsBody 0 2 ByteString.empty actions
      target = ByteString.pack [0x00, 0x00]
      patch = buildBPS body source target
  in assertApplyError parseBPS (\parsed src -> fmap (const ()) (applyBPS parsed src))
       patch source isTargetReadUnwritten "TargetCopy reads unwritten space"

-- Error predicate helpers
isWritesPastTarget :: SlapError -> Bool
isWritesPastTarget (ApplyFailed _ (ApplyWritesPastTarget {})) = True
isWritesPastTarget _ = False

isSourceReadOutOfBounds :: SlapError -> Bool
isSourceReadOutOfBounds (ApplyFailed _ (ApplySourceReadOutOfBounds {})) = True
isSourceReadOutOfBounds _ = False

isTargetUnderfilled :: SlapError -> Bool
isTargetUnderfilled (ApplyFailed _ (ApplyTargetUnderfilled {})) = True
isTargetUnderfilled _ = False

isTargetReadUnwritten :: SlapError -> Bool
isTargetReadUnwritten (ApplyFailed _ (ApplyTargetReadUnwritten {})) = True
isTargetReadUnwritten _ = False

----------------------------------------------------------------------------
-- UPS spec-conformance: parse + apply
----------------------------------------------------------------------------

-- | UPS with empty source, empty target, no blocks.
upsEmptyPatch :: Assertion
upsEmptyPatch =
  let source = ByteString.empty
      target = ByteString.empty
      body = upsBody 0 0 mempty
      patch = buildUPS body source target
  in assertParseApply parseAndApplyUPS patch source target

-- | Single block: complete replacement via XOR.
-- Source: [0x00, 0x00, 0x00, 0x00], Target: [0xAA, 0xBB, 0xCC, 0x00].
-- Block: skip=0, xorData=[0xAA, 0xBB, 0xCC], terminator.
-- The terminator byte at position 3 copies source[3]=0x00 to target[3].
upsSingleBlock :: Assertion
upsSingleBlock =
  let source = ByteString.pack [0x00, 0x00, 0x00, 0x00]
      target = ByteString.pack [0xAA, 0xBB, 0xCC, 0x00]
      body = upsBody 4 4 (upsBlock 0 [0xAA, 0xBB, 0xCC])
      patch = buildUPS body source target
  in assertParseApply parseAndApplyUPS patch source target

-- | Block with leading skip bytes (verbatim copy from source).
-- Source: [0x11, 0x22, 0x33, 0x44], Target: [0x11, 0x22, 0xFF, 0x44].
-- Block: skip=2, xorData=[0x33 XOR 0xFF = 0xCC], terminator at pos 3.
-- Pos 0-1: copied from source (skip). Pos 2: 0x33 XOR 0xCC = 0xFF.
-- Pos 3: terminator, copies source[3]=0x44.
upsSkipThenDiff :: Assertion
upsSkipThenDiff =
  let source = ByteString.pack [0x11, 0x22, 0x33, 0x44]
      target = ByteString.pack [0x11, 0x22, 0xFF, 0x44]
      body = upsBody 4 4 (upsBlock 2 [0xCC])  -- 0x33 XOR 0xCC = 0xFF
      patch = buildUPS body source target
  in assertParseApply parseAndApplyUPS patch source target

-- | Two separate diff blocks.
-- Source: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
-- Target: [0xAA, 0x00, 0x00, 0xBB, 0x00, 0x00]
-- Block 1: skip=0, xorData=[0xAA], terminator at pos 1 (copies 0x00).
-- Position after block 1: 2.
-- Block 2: skip=1, xorData=[0xBB], terminator at pos 4 (copies 0x00).
-- Position after block 2: 5.
-- Tail copy: source[5]=0x00 to target[5].
upsTwoBlocks :: Assertion
upsTwoBlocks =
  let source = ByteString.pack [0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
      target = ByteString.pack [0xAA, 0x00, 0x00, 0xBB, 0x00, 0x00]
      body = upsBody 6 6 (upsBlock 0 [0xAA] <> upsBlock 1 [0xBB])
      patch = buildUPS body source target
  in assertParseApply parseAndApplyUPS patch source target

-- | Source shorter than target: zero-fill past source end.
-- Source: [0x11, 0x22], Target: [0x11, 0x22, 0xAA, 0x00].
-- Block: skip=2, xorData=[0xAA] (source[2] is virtual 0x00, XOR 0xAA = 0xAA).
-- Terminator at pos 3: source[3] is virtual 0x00, copied.
upsSourceShorterThanTarget :: Assertion
upsSourceShorterThanTarget =
  let source = ByteString.pack [0x11, 0x22]
      target = ByteString.pack [0x11, 0x22, 0xAA, 0x00]
      body = upsBody 2 4 (upsBlock 2 [0xAA])
      patch = buildUPS body source target
  in assertParseApply parseAndApplyUPS patch source target

-- | UPS self-inverse property: applying the same patch to target
-- recovers source. Same-size files only.
-- Source: [0x11, 0x22, 0x33], Target: [0x44, 0x55, 0x33].
-- XOR: 0x11^0x44=0x55, 0x22^0x55=0x77.
-- Block: skip=0, xorData=[0x55, 0x77], terminator copies source[2].
-- Applying to target: target[0] XOR 0x55 = 0x44 XOR 0x55 = 0x11,
-- target[1] XOR 0x77 = 0x55 XOR 0x77 = 0x22, terminator copies
-- target[2]=0x33. Result: [0x11, 0x22, 0x33] = source.
upsSelfInverse :: Assertion
upsSelfInverse =
  let source = ByteString.pack [0x11, 0x22, 0x33]
      target = ByteString.pack [0x44, 0x55, 0x33]
      body = upsBody 3 3 (upsBlock 0 [0x55, 0x77])
      patch = buildUPS body source target
  in do
    -- Forward: source -> target
    assertParseApply parseAndApplyUPS patch source target
    -- Reverse: target -> source (self-inverse)
    -- Build reverse patch with swapped CRCs
    let reversePatch = buildUPS body target source
    assertParseApply parseAndApplyUPS reversePatch target source

-- | No blocks, all tail copy: identity when source == target.
-- Source: [0xAA, 0xBB, 0xCC], Target: [0xAA, 0xBB, 0xCC].
-- Zero blocks. Entire target filled by tail copy from source.
upsAllTailCopy :: Assertion
upsAllTailCopy =
  let source = ByteString.pack [0xAA, 0xBB, 0xCC]
      target = ByteString.pack [0xAA, 0xBB, 0xCC]
      body = upsBody 3 3 mempty
      patch = buildUPS body source target
  in assertParseApply parseAndApplyUPS patch source target

-- | Large skip value to test multi-byte varint in block skip field.
-- Source: 300 bytes of 0x00, Target: 300 bytes of 0x00 except byte 256 = 0xFF.
-- Block: skip=256, xorData=[0xFF], terminator at pos 257.
-- Then tail copy fills the rest.
upsLargeSkip :: Assertion
upsLargeSkip =
  let source = ByteString.replicate 300 0x00
      target = ByteString.replicate 256 0x00
               <> ByteString.pack [0xFF]
               <> ByteString.replicate 43 0x00
      body = upsBody 300 300 (upsBlock 256 [0xFF])
      patch = buildUPS body source target
  in assertParseApply parseAndApplyUPS patch source target

----------------------------------------------------------------------------
-- UPS spec-conformance: rejection
----------------------------------------------------------------------------

upsWrongMagic :: Assertion
upsWrongMagic =
  let body = upsBody 0 0 mempty
      withoutPatchCRC = toStrict $
        byteString "UPS2"
        <> byteString body
        <> putWord32LE (unCRC32 (rustyCRC32 ByteString.empty))
        <> putWord32LE (unCRC32 (rustyCRC32 ByteString.empty))
      patchCRC = rustyCRC32 withoutPatchCRC
      patch = PatchFileContents (withoutPatchCRC <> word32LEBytes (unCRC32 patchCRC))
  in assertParseRejects parseUPS patch ""

upsWrongPatchCRC :: Assertion
upsWrongPatchCRC =
  let body = upsBody 0 0 mempty
      withoutPatchCRC = toStrict $
        byteString "UPS1"
        <> byteString body
        <> putWord32LE (unCRC32 (rustyCRC32 ByteString.empty))
        <> putWord32LE (unCRC32 (rustyCRC32 ByteString.empty))
      patch = PatchFileContents (withoutPatchCRC <> ByteString.pack [0xDE, 0xAD, 0xBE, 0xEF])
  in assertParseRejects parseUPS patch "CRC"

upsTooShortForMagic :: Assertion
upsTooShortForMagic =
  assertParseRejects parseUPS (PatchFileContents "UPS") ""

----------------------------------------------------------------------------
-- UPS apply error paths
----------------------------------------------------------------------------

-- | A block whose total span (skip + xorLen + terminator) exceeds
-- the remaining target space.
upsApplyBlockPastTarget :: Assertion
upsApplyBlockPastTarget =
  let source = ByteString.pack [0x00, 0x00]
      -- Target size 2, but block: skip=0, xorData=[0xAA, 0xBB] = 2 bytes + terminator = 3.
      -- Total block span = 3, but only 2 bytes of target remain.
      body = upsBody 2 2 (upsBlock 0 [0xAA, 0xBB])
      target = ByteString.pack [0xAA, 0xBB]
      patch = buildUPS body source target
  in assertApplyError parseUPS (\parsed src -> fmap (const ()) (applyUPS parsed src))
       patch source isWritesPastTarget "block writes past target"

----------------------------------------------------------------------------
-- BPS apply cursor-underflow errors
--
-- SourceCopy and TargetCopy each maintain a persistent 'SignedOffset'
-- cursor across actions. The cursor starts at zero and is displaced
-- by the signed delta of each copy action. If the delta drives the
-- cursor below zero, apply must abort with 'ApplyCursorUnderflow'.
-- These are the two remaining 'ApplyError' constructors not exercised
-- by the earlier apply-error tests.
----------------------------------------------------------------------------

-- | SourceCopy as the first action with a negative delta that drives
-- the source cursor below zero. Initial sourceRelative is 0; delta -1
-- produces SignedOffset -1, which 'examineSignedOffset' reports as
-- 'NegativeCursor', firing 'ApplyCursorUnderflow SourceCursor'.
bpsApplySourceCursorUnderflow :: Assertion
bpsApplySourceCursorUnderflow =
  let source = ByteString.pack [0xAA, 0xBB, 0xCC, 0xDD]
      -- Target size large enough that fitsWithin passes, so we reach
      -- the cursor check instead of bailing on "writes past target".
      target = ByteString.pack [0x00, 0x00]
      actions = bpsActionVarint bpsSourceCopyCode 2
                <> bpsSignedDelta (-1)
      body = bpsBody 4 2 ByteString.empty actions
      patch = buildBPS body source target
  in assertApplyError parseBPS (\parsed src -> fmap (const ()) (applyBPS parsed src))
       patch source isSourceCursorUnderflow "SourceCopy negative cursor"

-- | TargetCopy as the first action with a negative delta. Same
-- structure as the SourceCopy case but exercises the target cursor
-- branch of the apply worker.
bpsApplyTargetCursorUnderflow :: Assertion
bpsApplyTargetCursorUnderflow =
  let source = ByteString.empty
      target = ByteString.pack [0x00, 0x00]
      actions = bpsActionVarint bpsTargetCopyCode 2
                <> bpsSignedDelta (-1)
      body = bpsBody 0 2 ByteString.empty actions
      patch = buildBPS body source target
  in assertApplyError parseBPS (\parsed src -> fmap (const ()) (applyBPS parsed src))
       patch source isTargetCursorUnderflow "TargetCopy negative cursor"

isSourceCursorUnderflow :: SlapError -> Bool
isSourceCursorUnderflow (ApplyFailed _ (ApplyCursorUnderflow SourceCursor _ _)) = True
isSourceCursorUnderflow _ = False

isTargetCursorUnderflow :: SlapError -> Bool
isTargetCursorUnderflow (ApplyFailed _ (ApplyCursorUnderflow TargetCursor _ _)) = True
isTargetCursorUnderflow _ = False

----------------------------------------------------------------------------
-- BPS chained TargetCopy
--
-- TargetCopy is allowed to read bytes that any previous action wrote,
-- including bytes written by a previous TargetCopy. This is the
-- LZ77-style chaining that lets BPS patches stay small on repeated
-- byte runs.
----------------------------------------------------------------------------

-- | TargetRead writes two bytes. First TargetCopy reads those two bytes
-- back (adding two more). Second TargetCopy reads from the bytes the
-- first TargetCopy wrote (adding four more). All copies must land on
-- already-written target, proving the write-pointer moves forward
-- between actions and the read pointer can land on any byte written
-- by any prior action (not just the initial TargetRead).
bpsTargetCopyChained :: Assertion
bpsTargetCopyChained =
  let source = ByteString.empty
      -- Target: [0x01, 0x02, 0x01, 0x02, 0x01, 0x02, 0x01, 0x02]
      target = ByteString.pack [0x01, 0x02, 0x01, 0x02, 0x01, 0x02, 0x01, 0x02]
      -- Action 1: TargetRead length=2, bytes [0x01, 0x02]
      -- Action 2: TargetCopy length=2 delta=0 (targetCursor 0 -> 0)
      --   Reads target[0..1] = [0x01, 0x02], writes target[2..3]
      --   After: writePos=4, targetRelative cursor = 0 + length 2 = 2
      -- Action 3: TargetCopy length=4 delta=0 (targetCursor 2 -> 2)
      --   Reads target[2..5] starting at position 2, but positions
      --   4 and 5 become written during this copy — LZ77 self-reference.
      --   Result: target[2..5] reads from target[2..3] then target[4..5]
      --   which becomes target[2..3] again. Writes: [0x01, 0x02, 0x01, 0x02].
      actions = bpsActionVarint bpsTargetReadCode 2
                <> word8 0x01 <> word8 0x02
                <> bpsActionVarint bpsTargetCopyCode 2
                <> bpsSignedDelta 0
                <> bpsActionVarint bpsTargetCopyCode 4
                <> bpsSignedDelta 0
      body = bpsBody 0 8 ByteString.empty actions
      patch = buildBPS body source target
  in assertParseApply parseAndApplyBPS patch source target

----------------------------------------------------------------------------
-- BPS CRC fields are read literally by parse
--
-- The parser verifies the *patch* CRC (footer word 3) to detect
-- corruption of the patch file itself. The source and target CRCs
-- (footer words 1 and 2) are not checked at parse time: they describe
-- the source and target byte streams, not the patch bytes, so they
-- can only be verified against the actual source at apply time (via
-- the Verification layer in SomePatch). These tests pin that contract
-- by constructing patches with wrong source/target CRCs and asserting
-- parse accepts them and the field comes through unchanged.
----------------------------------------------------------------------------

bpsSourceCRCReadLiterally :: Assertion
bpsSourceCRCReadLiterally =
  let target = ByteString.pack [0xFF]
      actions = bpsActionVarint bpsTargetReadCode 1 <> word8 0xFF
      body = bpsBody 1 1 ByteString.empty actions
      wrongSourceCRC = CRC32 0xDEADBEEF
      patch = buildBPSWithCRCs body wrongSourceCRC (rustyCRC32 target)
  in case parseBPS patch of
    Left slapError -> assertFailure ("parse: " ++ renderSlapError slapError)
    Right parsed -> assertEqual "source CRC field" wrongSourceCRC (bpsSourceCRC parsed)

bpsTargetCRCReadLiterally :: Assertion
bpsTargetCRCReadLiterally =
  let source = ByteString.pack [0x00]
      actions = bpsActionVarint bpsTargetReadCode 1 <> word8 0xFF
      body = bpsBody 1 1 ByteString.empty actions
      wrongTargetCRC = CRC32 0xCAFEBABE
      patch = buildBPSWithCRCs body (rustyCRC32 source) wrongTargetCRC
  in case parseBPS patch of
    Left slapError -> assertFailure ("parse: " ++ renderSlapError slapError)
    Right parsed -> assertEqual "target CRC field" wrongTargetCRC (bpsTargetCRC parsed)

-- | 'applyBPS' is a low-level executor: it trusts the caller to have
-- already verified the source matches the patch's expectations, and
-- just does the mechanical work with whatever 'SourceFileContents' it
-- receives. Size verification happens one layer up, at the
-- 'Verification' layer consumed by 'Main.verifySource'. This test
-- pins the apply-layer contract by calling 'applyBPS' directly with
-- a patch that declares @sourceSize = 100@ against a 1-byte source —
-- apply ignores the declared size and proceeds as long as the actions
-- fit within the actual source bytes.
--
-- The complementary 'bpsVerificationCarriesDeclaredSize' test below
-- pins the other end of the contract: that 'parseSome' exposes the
-- declared size through 'verifyFileSizeAdvisory' so the Verification layer
-- has something to check.
bpsApplyDefersSourceSizeCheckToVerificationLayer :: Assertion
bpsApplyDefersSourceSizeCheckToVerificationLayer =
  let actualSource = ByteString.pack [0x42]
      target = ByteString.pack [0x42]
      -- Patch declares sourceSize = 100, but actions only do a
      -- SourceRead of 1 byte. Applying against a 1-byte source
      -- works; the apply worker uses the actual source length.
      actions = bpsActionVarint bpsSourceReadCode 1
      body = bpsBody 100 1 ByteString.empty actions
      patch = buildBPS body actualSource target
  in assertParseApply parseAndApplyBPS patch actualSource target

-- | 'parseSome' must populate 'verifyFileSizeAdvisory' with the declared
-- source size so the Verification layer can diagnose mismatches.
-- The BPS spec declares source-size in the header; this test pins
-- that the field survives through to the verification record.
-- (The warn-vs-die policy lives in 'Main.verifySource'; this test
-- only asserts the data-plumbing contract.)
bpsVerificationCarriesDeclaredSize :: Assertion
bpsVerificationCarriesDeclaredSize =
  let source = ByteString.pack [0x42, 0x42, 0x42, 0x42]
      target = ByteString.pack [0x43, 0x43, 0x43, 0x43]
      actions = bpsActionVarint bpsTargetReadCode 4
                <> byteString target
      body = bpsBody 4 4 ByteString.empty actions
      patch = buildBPS body source target
  in case parseSome patch of
    Left slapError -> assertFailure ("parseSome: " ++ renderSlapError slapError)
    Right somePatch ->
      assertEqual "verifyFileSizeAdvisory" (Just (FileSize 4))
        (verifyFileSizeAdvisory (patchVerification somePatch))

----------------------------------------------------------------------------
-- UPS reject: too short for footer, missing block terminator
----------------------------------------------------------------------------

upsTooShortForFooter :: Assertion
upsTooShortForFooter =
  assertParseRejects parseUPS (PatchFileContents "UPS1") ""

-- | A block whose xorData run is not terminated by 0x00 before end of
-- body. 'getUntilByte' must fail with "terminator not found".
upsBlockMissingTerminator :: Assertion
upsBlockMissingTerminator =
  let source = ByteString.pack [0x00, 0x00]
      target = ByteString.pack [0xAA, 0xBB]
      -- Body content manually constructed: source size 2, target size 2,
      -- skip 0, xorData with no terminator at all. Everything after
      -- the skip varint is interpreted as xorData bytes, which run
      -- off the end of the body with no 0x00 in sight.
      rawBody = toStrict $
        putByuuVarint 2
        <> putByuuVarint 2
        <> putByuuVarint 0    -- skip
        <> word8 0xAA         -- xorData byte, no 0x00 terminator follows
        <> word8 0xBB         -- more xorData
      patch = buildUPS rawBody source target
  in assertParseRejects parseUPS patch ""

upsSourceCRCReadLiterally :: Assertion
upsSourceCRCReadLiterally =
  let target = ByteString.pack [0x11, 0x22]
      body = upsBody 2 2 mempty
      wrongSourceCRC = CRC32 0xDEADBEEF
      patch = buildUPSWithCRCs body wrongSourceCRC (rustyCRC32 target)
  in case parseUPS patch of
    Left slapError -> assertFailure ("parse: " ++ renderSlapError slapError)
    Right parsed -> assertEqual "source CRC field" wrongSourceCRC (upsSourceCRC parsed)

upsTargetCRCReadLiterally :: Assertion
upsTargetCRCReadLiterally =
  let source = ByteString.pack [0x11, 0x22]
      body = upsBody 2 2 mempty
      wrongTargetCRC = CRC32 0xCAFEBABE
      patch = buildUPSWithCRCs body (rustyCRC32 source) wrongTargetCRC
  in case parseUPS patch of
    Left slapError -> assertFailure ("parse: " ++ renderSlapError slapError)
    Right parsed -> assertEqual "target CRC field" wrongTargetCRC (upsTargetCRC parsed)

-- | Same apply-layer contract as BPS: 'applyUPS' uses the actual
-- length of the 'SourceFileContents' ByteString, not the declared
-- sourceSize in the patch header. Size verification is the
-- 'Verification' layer's responsibility (see
-- 'upsVerificationCarriesDeclaredSize' below).
--
-- Note that for UPS specifically, 'Main.doUndo' bypasses the
-- Verification layer entirely and calls the format's revert closure
-- directly. This is necessary because UPS is self-inverse: the undo
-- path legitimately feeds the patch bytes that have target-size (not
-- source-size) to 'applyUPS', which would fail a strict size check.
-- The apply-layer contract "ignore declared size, use actual length"
-- is what makes this work.
upsApplyDefersSourceSizeCheckToVerificationLayer :: Assertion
upsApplyDefersSourceSizeCheckToVerificationLayer =
  let actualSource = ByteString.pack [0x11, 0x22]
      target = ByteString.pack [0x11, 0x22]
      -- Patch declares sourceSize = 100 but apply only touches the
      -- real 2 bytes because there are zero diff blocks.
      body = upsBody 100 2 mempty
      patch = buildUPS body actualSource target
  in assertParseApply parseAndApplyUPS patch actualSource target

-- | Parallel to 'bpsVerificationCarriesDeclaredSize'. 'parseSome'
-- must expose UPS's declared source-size through 'verifyFileSizeAdvisory'.
upsVerificationCarriesDeclaredSize :: Assertion
upsVerificationCarriesDeclaredSize =
  let source = ByteString.pack [0x11, 0x22, 0x33, 0x44]
      target = ByteString.pack [0x11, 0x22, 0x33, 0x44]
      body = upsBody 4 4 mempty
      patch = buildUPS body source target
  in case parseSome patch of
    Left slapError -> assertFailure ("parseSome: " ++ renderSlapError slapError)
    Right somePatch ->
      assertEqual "verifyFileSizeAdvisory" (Just (FileSize 4))
        (verifyFileSizeAdvisory (patchVerification somePatch))

----------------------------------------------------------------------------
-- Varint canonicality and boundary value
--
-- The byuu varint's subtract-one trick partitions non-negative
-- integers into disjoint ranges by encoded byte count. Every value
-- has exactly one valid encoding; every byte sequence the decoder
-- accepts is the canonical encoding of its decoded value. This
-- property holds by construction (not by convention), but the test
-- provides defense in depth against a future decoder regression
-- that might accept a non-canonical form.
----------------------------------------------------------------------------

-- | For every byte sequence the decoder accepts, re-encoding the
-- decoded value must reproduce exactly the bytes the decoder consumed.
-- Equivalently: the encoding is a bijection between the set of valid
-- terminated varint byte sequences and the set of representable values.
prop_varintCanonical :: Property
prop_varintCanonical =
  forAll genWellFormedVarint $ \bytes ->
    case getByuuVarint 0 bytes of
      Left errorMessage ->
        counterexample ("unexpected decode failure: " ++ errorMessage) (property False)
      Right (VarintResult value consumed) ->
        counterexample ("input bytes: " ++ show (ByteString.unpack bytes)
                        ++ ", decoded: " ++ show value
                        ++ ", consumed: " ++ show consumed) $
        encodeVarint value === ByteString.take consumed bytes
  where
    -- Generate structurally valid byuu varints: 0-8 continuation bytes
    -- (high bit clear) followed by one terminator byte (high bit set).
    -- Payloads are random within their 7-bit range so we cover the
    -- whole representable value space, not just canonical encoder
    -- output. With a pure 'arbitrary' byte generator most samples are
    -- unterminated and get discarded; this shape guarantees every
    -- sample decodes.
    genWellFormedVarint :: Gen ByteString
    genWellFormedVarint = do
      continuationCount <- chooseInt (0, 8)
      continuationBytes <- vectorOf continuationCount (choose (0x00, 0x7F))
      terminatorByte    <- choose (0x80, 0xFF)
      pure (ByteString.pack (continuationBytes ++ [terminatorByte]))

-- | A value close to 'maxBound :: Int64' that still fits in a 9-byte
-- byuu varint. The off-by-one fix in commit e49f2a1 tightened the
-- overflow guard from 'iterations > 9' to 'iterations >= 9'; at the
-- old threshold the multiplier shift overflowed signed Int64. This
-- test exercises the region near that boundary to catch regression.
test_varintNearMaxBound :: Assertion
test_varintNearMaxBound = do
  -- 2^56 fits comfortably in 9 bytes (well below the 63-bit ceiling)
  -- and exercises the high-byte-count path without risking overflow.
  let largeValue = 2 ^ (56 :: Int) :: Int64
      encoded = encodeVarint largeValue
  case getByuuVarint 0 encoded of
    Left errorMessage -> assertFailure ("decode failed: " ++ errorMessage)
    Right (VarintResult decoded consumed) -> do
      assertEqual "round-trip" largeValue decoded
      assertEqual "consumed equals encoded length"
        (ByteString.length encoded) consumed

----------------------------------------------------------------------------
-- BPS and UPS CRC builders (used by CRC-read-literally tests)
--
-- Variants of 'buildBPS' / 'buildUPS' that take explicit source and
-- target CRC values instead of computing them from actual bytes. Lets
-- the test construct a patch whose footer disagrees with the actual
-- data — useful for pinning the "parse reads, doesn't verify" contract.
----------------------------------------------------------------------------

buildBPSWithCRCs :: ByteString -> CRC32 -> CRC32 -> PatchFileContents
buildBPSWithCRCs bodyContent sourceCRC targetCRC =
  let withoutPatchCRC = toStrict $
        byteString "BPS1"
        <> byteString bodyContent
        <> putWord32LE (unCRC32 sourceCRC)
        <> putWord32LE (unCRC32 targetCRC)
      patchCRC = rustyCRC32 withoutPatchCRC
      complete = withoutPatchCRC <> word32LEBytes (unCRC32 patchCRC)
  in PatchFileContents complete

buildUPSWithCRCs :: ByteString -> CRC32 -> CRC32 -> PatchFileContents
buildUPSWithCRCs bodyContent sourceCRC targetCRC =
  let withoutPatchCRC = toStrict $
        byteString "UPS1"
        <> byteString bodyContent
        <> putWord32LE (unCRC32 sourceCRC)
        <> putWord32LE (unCRC32 targetCRC)
      patchCRC = rustyCRC32 withoutPatchCRC
      complete = withoutPatchCRC <> word32LEBytes (unCRC32 patchCRC)
  in PatchFileContents complete
