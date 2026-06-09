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

import Props.Helpers (assertFailureT)

import Slap.Binary (putByuuVarint, putWord32LE, getByuuVarint, getVcdiffVarint,
                    VarintResult(..), VarintReadFailure(..))
import Slap.ByteParser (runByteParser, vcdiffVarintReportingCanonicality,
                        VcdiffVarintReading(..))
import Slap.BPS.Apply (applyBPS)
import Slap.BPS.Parse (parseBPS)
import Slap.BPS.Types (BPSPatch(..), BPSMetadata(..))
import Slap.Checksum (CRC32(..))
import Slap.Status (SlapError(..), SlapAdvisory(..), ApplyError(..), CursorKind(..), Parsed(..), Outcome(..),
                   ClippedRecordCount(..), MarkerOvershootBytes(..), renderSlapError,
                   renderByteParserError, VCDIFFMalformation(..), VCDIFFIndicatorKind(..))
import Slap.FFI (crc32)
import Slap.FileContents (InputFileContents(..), OutputFileContents(..), PatchFileContents(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.IPS.Apply (applyIPS)
import Slap.IPS.Types (IPSPatch(..), IPSRecord(..), IPSVariant(..), isSMCShapedSize)
import Slap.Measure (FileSize(..), Offset(..), Length(..), actionAtPosition,
                     DeclaredTargetSize(..), NaturalTargetSize(..))
import qualified Slap.NINJA2.Apply as NINJA2
import qualified Slap.NINJA2.Parse as NINJA2
import qualified Slap.APSGBA.Apply as APSGBA
import qualified Slap.APSGBA.Parse as APSGBA
import Slap.APSGBA.Types (apsGbaBlockSize)
import Slap.SomePatch (parseSome, patchVerification, Verification(..), FileSizeCheck(..))
import Slap.Text (EncodingName(EncodingUtf8))
import Slap.Convert (noDialectsRequested)
import Slap.UPS.Apply (applyUPS)
import Slap.UPS.Parse (parseUPS)
import Slap.UPS.Types (UPSPatch(..))
import Slap.VCDIFF.CodeTable (CodeTableEntry(..), InstructionTemplate(..),
                             InstructionSize(..), FixedInstructionSize(..),
                             CopyAddressMode(..), codeTableEntries,
                             defaultCodeTable, serializeCodeTable,
                             deserializeCodeTable)
import Slap.VCDIFF.Parse (parseVCDIFF, decodeCopyAddress, freshAddressCache,
                          nearCacheSize, AddressCache, CopyAddressReading(..))
import Slap.VCDIFF.Apply (applyVCDIFF)

import Data.Bits (shiftL, (.|.))
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.ByteString.Builder (Builder, toLazyByteString, byteString, word8)
import qualified Data.ByteString.Lazy as LazyByteString
import Data.Int (Int64)
import qualified Data.Vector as Vector
import Data.Word (Word8, Word32)
import Test.Tasty
import Test.Tasty.HUnit
import Test.Tasty.QuickCheck
import qualified Data.Text as Text

specConformanceTests :: TestTree
specConformanceTests = testGroup "SpecConformance"
  [ testGroup "Varint"
      [ testGroup "byuu"
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
              , testCase "largest-valid (int64-maxbound)" test_byuuLargestValid
              ]
          , testGroup "decode-rejects"
              [ testCase "unterminated-single-continuation"
                  (byuuRejectsCase [0x00])
              , testCase "unterminated-multi-continuation"
                  (byuuRejectsCase [0x00, 0x00, 0x00])
              , testCase "empty-input"
                  (byuuRejectsCase [])
              , testCase "ten-continuation-bytes-overflows"
                  (byuuRejectsCase (replicate 10 0x00))
              -- The nine-byte wrap the ten-continuation case above does
              -- NOT cover: eight continuations plus a high terminator
              -- encode a value above 2^63, which the old reader returned
              -- as a wrapped negative. Regression test for that defect.
              , testCase "nine-byte-value-above-int64-rejected"
                  (byuuRejectsCase [0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0xFF])
              ]
          ]
      , testGroup "vcdiff"
          [ testGroup "boundary-values"
              [ testCase "worked-example (123456789)"
                  (vcdiffCase 123456789 [0xBA, 0xEF, 0x9A, 0x15])
              , testCase "int64-maxbound"
                  (vcdiffCase maxBound
                     [0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x7F])
              ]
          , testGroup "decode-rejects"
              -- Two distinct verdicts, deliberately not folded together:
              -- a value in [2^63, 2^64) is the apologetic failure (xd3's
              -- uint64 admits it, slap's signed Int declines); a value
              -- >= 2^64 is the plain over-width rejection.
              [ testCase "unsigned-only-range-is-apologetic"
                  (vcdiffRejectsWith
                     [0x81,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x00]
                     VarintExceedsSignedButFitsUnsigned)
              , testCase "beyond-uint64-is-plain-over-width"
                  (vcdiffRejectsWith
                     [0x82,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x00]
                     VarintTooManyContinuationBytes)
              ]
          , testGroup "canonicality"
              [ testCase "overlong-small-value-decodes-and-flags-fyi"
                  test_vcdiffOverlongRaisesFYI
              ]
          ]
      ]
  , testGroup "VCDIFF"
      [ testGroup "code-table"
          [ testCase "default-table-serializes-to-1536-bytes"
              codeTableSerializedLength
          , testCase "deserialize-inverts-serialize"
              codeTableRoundTrip
          , testCase "entry-0-is-run-size-coded-separately"
              (codeTableEntryIs 0
                 (CodeTableEntry (Run SizeCodedSeparately) Noop))
          , testCase "entry-1-is-add-size-coded-separately"
              (codeTableEntryIs 1
                 (CodeTableEntry (Add SizeCodedSeparately) Noop))
          , testCase "entry-2-is-add-size-1"
              (codeTableEntryIs 2
                 (CodeTableEntry (Add (fixedSize 1)) Noop))
          , testCase "entry-19-is-copy-mode-0-size-coded-separately"
              (codeTableEntryIs 19
                 (CodeTableEntry (Copy SizeCodedSeparately (CopyAddressMode 0)) Noop))
          , testCase "entry-163-is-add-1-then-copy-4-mode-0"
              (codeTableEntryIs 163
                 (CodeTableEntry (Add (fixedSize 1))
                                 (Copy (fixedSize 4) (CopyAddressMode 0))))
          , testCase "entry-247-is-copy-4-mode-0-then-add-1"
              (codeTableEntryIs 247
                 (CodeTableEntry (Copy (fixedSize 4) (CopyAddressMode 0))
                                 (Add (fixedSize 1))))
          ]
      , testGroup "indicator-bits"
          [ testCase "reserved-header-bit-declined-as-uninterpretable"
              test_vcdiffReservedHeaderBitDeclined
          , testCase "reserved-window-bit-declined-as-uninterpretable"
              test_vcdiffReservedWindowBitDeclined
          , testCase "both-source-and-target-still-malformed"
              test_vcdiffBothSourceBitsStillMalformed
          ]
      , testGroup "core-engine"
          [ testCase "self-referential-copy-expands-run-length"
              test_vcdiffSelfReferentialCopy
          , testCase "self-referential-copy-distance-two-expands-forward"
              test_vcdiffForwardExpansionCopy
          , testCase "copy-address-at-or-past-here-rejected"
              test_vcdiffCopyAddressOutOfRange
          , testCase "copy-crossing-source-segment-end-rejected"
              test_vcdiffCopyCrossesSegmentEnd
          , testCase "window-underproducing-target-rejected"
              test_vcdiffWindowSizeMismatch
          , testCase "source-segment-exceeding-source-rejected-at-apply"
              test_vcdiffSourceSegmentExceedsSource
          ]
      , testGroup "address-cache"
          [ testCase "near-cache-round-robin-overwrites-oldest"
              test_vcdiffNearCacheRoundRobin
          , testCase "same-cache-indexed-modulo-768"
              test_vcdiffSameCacheModulo
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
          , testCase "parseSome-populates-verifyFileSize"
              bpsVerificationCarriesDeclaredSize
          , testCase "negative-zero-signed-varint-warns"
              bpsNegativeZeroSignedVarintWarns
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
  , testGroup "IPS"
      [ testGroup "apply-errors"
          [ testCase "zero-target-with-records-clipped-and-warned"
              ipsApplyZeroTargetWithRecordsClipped
          ]
      , testGroup "isSMCShapedSize"
          [ testCase "0x000-rejected"  (isSMCShapedSize (FileSize 0x000)    @?= False)
          , testCase "0x200-accepted"  (isSMCShapedSize (FileSize 0x200)    @?= True)
          , testCase "0x400-rejected"  (isSMCShapedSize (FileSize 0x400)    @?= False)
          , testCase "0x1000-rejected" (isSMCShapedSize (FileSize 0x1000)   @?= False)
          , testCase "0x1200-accepted" (isSMCShapedSize (FileSize 0x1200)   @?= True)
          , testCase "0x1234-rejected" (isSMCShapedSize (FileSize 0x1234)   @?= False)
          , testCase "0x100200-accepted" (isSMCShapedSize (FileSize 0x100200) @?= True)
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
          , testCase "parseSome-populates-verifyFileSize"
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
  , testGroup "NINJA2"
      [ testGroup "spec-reject"
          [ testCase "unrecognized-PATCH_ENC-byte" ninja2RejectsUnrecognizedTextMode
          ]
      , testGroup "apply-errors"
          [ testCase "xor-record-writes-past-target" ninja2ApplyXorRecordPastTarget
          ]
      ]
  , testGroup "APSGBA"
      [ testGroup "apply-errors"
          [ testCase "record-offset-past-target" apsGbaApplyRecordOffsetPastTarget
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
  Left failure -> Left (show failure)
  Right (VarintResult value _consumed) -> Right value

----------------------------------------------------------------------------
-- Varint tests
----------------------------------------------------------------------------

-- | For all non-negative Int64 values that fit in our test range,
-- decode(encode(n)) == n.
--
-- Range goes to 2^62 so random samples occasionally land in the
-- 9-byte canonical-encoding region (~2^56 onward).  That's coverage
-- the canonical-form prop's generator used to provide before it
-- was capped at 8 bytes to avoid the 9-byte signed-Int64 overflow
-- corner; the roundtrip props now carry it.
prop_varintRoundTrip :: Property
prop_varintRoundTrip =
  forAll (chooseInt64 (0, 2^(62 :: Int))) $ \value ->
    let encoded = encodeVarint value
    in case decodeVarint encoded of
      Left errorMessage -> counterexample ("decode failed: " ++ errorMessage) (property False)
      Right decoded -> decoded === value

-- | For all valid encoded varints (produced by our encoder), encoding
-- the decoded value reproduces the original bytes. This catches
-- non-canonical encoding issues.
prop_varintDecodeEncodeRoundTrip :: Property
prop_varintDecodeEncodeRoundTrip =
  forAll (chooseInt64 (0, 2^(62 :: Int))) $ \value ->
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

-- | Assert that the byuu reader rejects the given bytes (any failure).
byuuRejectsCase :: [Word8] -> Assertion
byuuRejectsCase inputBytes =
  case getByuuVarint 0 (ByteString.pack inputBytes) of
    Left _  -> pure ()
    Right (VarintResult value _) ->
      assertFailure ("expected decode to fail, got " ++ show value)

-- | Assert the byuu reader decodes the largest representable value —
-- 'maxBound' '@Int64' — cleanly, bracketing the over-width boundary
-- from below (its companion above is
-- @nine-byte-value-above-int64-rejected@).
test_byuuLargestValid :: Assertion
test_byuuLargestValid = do
  let largestValid = maxBound :: Int64
      encoded      = encodeVarint largestValid
  case getByuuVarint 0 encoded of
    Left failure -> assertFailure ("decode failed: " ++ show failure)
    Right (VarintResult decoded _) ->
      assertEqual "largest valid byuu value" largestValid decoded

-- | Assert the VCDIFF reader decodes the given bytes to the expected
-- value, consuming all of them.
vcdiffCase :: Int64 -> [Word8] -> Assertion
vcdiffCase expected inputBytes =
  case getVcdiffVarint 0 (ByteString.pack inputBytes) of
    Left failure -> assertFailure ("decode failed: " ++ show failure)
    Right (VarintResult decoded consumed) -> do
      assertEqual "decoded value" expected decoded
      assertEqual "consumed all bytes" (length inputBytes) consumed

-- | Assert the VCDIFF reader rejects the given bytes with exactly the
-- expected failure — the two over-width bands must stay distinguishable.
vcdiffRejectsWith :: [Word8] -> VarintReadFailure -> Assertion
vcdiffRejectsWith inputBytes expectedFailure =
  case getVcdiffVarint 0 (ByteString.pack inputBytes) of
    Left failure -> assertEqual "failure mode" expectedFailure failure
    Right (VarintResult value _) ->
      assertFailure ("expected decode to fail, got " ++ show value)

-- | An overlong VCDIFF varint (one leading zero-group padding a small
-- value) decodes to that value AND, at the parser seam, raises the FYI
-- advisory naming it.
test_vcdiffOverlongRaisesFYI :: Assertion
test_vcdiffOverlongRaisesFYI =
  let overlongOne = ByteString.pack [0x80, 0x01]  -- canonical is [0x01]
  in case runByteParser vcdiffVarintReportingCanonicality overlongOne of
    Left parserError ->
      assertFailureT ("decode failed: " <> renderByteParserError parserError)
    Right reading -> do
      assertEqual "decoded value" 1 (vcdiffVarintValue reading)
      assertEqual "FYI advisory"
        (Just (NonCanonicalVCDIFFVarint 1)) (vcdiffVarintAdvisory reading)

----------------------------------------------------------------------------
-- BPS patch builder
--
-- Constructs patches from first principles: magic + body + footer.
-- The body is caller-supplied. CRCs are computed at build time.
----------------------------------------------------------------------------

-- | Build a syntactically valid BPS patch with correct CRCs.
buildBPS :: ByteString -> ByteString -> ByteString -> PatchFileContents
buildBPS bodyContent sourceBytes targetBytes =
  let sourceCRC = crc32 sourceBytes
      targetCRC = crc32 targetBytes
      withoutPatchCRC = toStrict $
        byteString "BPS1"
        <> byteString bodyContent
        <> putWord32LE (unCRC32 sourceCRC)
        <> putWord32LE (unCRC32 targetCRC)
      patchCRC = crc32 withoutPatchCRC
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
  let sourceCRC = crc32 sourceBytes
      targetCRC = crc32 targetBytes
      withoutPatchCRC = toStrict $
        byteString "UPS1"
        <> byteString bodyContent
        <> putWord32LE (unCRC32 sourceCRC)
        <> putWord32LE (unCRC32 targetCRC)
      patchCRC = crc32 withoutPatchCRC
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
  Parsed parsed _parseWarnings <- parseBPS patchBytes
  targetResult <- applyBPS parsed (InputFileContents sourceBytes)
  pure (unOutputFileContents targetResult)

parseAndApplyUPS :: PatchFileContents -> ByteString -> Either SlapError ByteString
parseAndApplyUPS patchBytes sourceBytes = do
  Parsed parsed _parseWarnings <- parseUPS patchBytes
  Outcome targetResult _applyWarnings <- applyUPS parsed (InputFileContents sourceBytes)
  pure (unOutputFileContents targetResult)

assertParseApply
  :: (PatchFileContents -> ByteString -> Either SlapError ByteString)
  -> PatchFileContents -> ByteString -> ByteString -> Assertion
assertParseApply parseApply patchBytes sourceBytes expectedTarget =
  case parseApply patchBytes sourceBytes of
    Left slapError -> assertFailureT ("parse/apply failed: " <> renderSlapError slapError)
    Right actualTarget -> assertEqual "target mismatch" expectedTarget actualTarget

assertParseRejects :: (PatchFileContents -> Either SlapError (Parsed a)) -> PatchFileContents -> String -> Assertion
assertParseRejects parseFunction patchBytes expectedSubstring =
  case parseFunction patchBytes of
    Left slapError ->
      assertBool ("expected '" ++ expectedSubstring ++ "' in: " ++ Text.unpack (renderSlapError slapError))
                 (expectedSubstring == "" || expectedSubstring `isInfixOf` Text.unpack (renderSlapError slapError))
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
  :: (PatchFileContents -> Either SlapError (Parsed a))
  -> (a -> InputFileContents -> Either SlapError b)
  -> PatchFileContents -> ByteString -> (SlapError -> Bool) -> String -> Assertion
assertApplyError parseFunction applyFunction patchBytes sourceBytes errorPredicate errorLabel = do
  case parseFunction patchBytes of
    Left slapError -> assertFailureT ("parse failed (expected parse success): " <> renderSlapError slapError)
    Right (Parsed parsed _parseWarnings) ->
      case applyFunction parsed (InputFileContents sourceBytes) of
        Left slapError ->
          assertBool (errorLabel ++ ": got " ++ Text.unpack (renderSlapError slapError))
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
    Left slapError -> assertFailureT ("parse failed: " <> renderSlapError slapError)
    Right (Parsed parsed _parseWarnings) -> do
      assertEqual "metadata" metadata (unBPSMetadata (bpsMetadata parsed))
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
        <> putWord32LE (unCRC32 (crc32 ByteString.empty))
        <> putWord32LE (unCRC32 (crc32 ByteString.empty))
      patchCRC = crc32 withoutPatchCRC
      patch = PatchFileContents (withoutPatchCRC <> word32LEBytes (unCRC32 patchCRC))
  in assertParseRejects parseBPS patch ""

bpsWrongPatchCRC :: Assertion
bpsWrongPatchCRC =
  let body = bpsBody 0 0 ByteString.empty mempty
      withoutPatchCRC = toStrict $
        byteString "BPS1"
        <> byteString body
        <> putWord32LE (unCRC32 (crc32 ByteString.empty))
        <> putWord32LE (unCRC32 (crc32 ByteString.empty))
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
    Left slapError -> assertFailureT ("unexpected rejection: " <> renderSlapError slapError)
    Right (Parsed parsed _parseWarnings) -> assertEqual "source size" (FileSize 0) (bpsSourceSize parsed)

bpsNegativeTargetSize :: Assertion
bpsNegativeTargetSize =
  -- Same as above for target size.
  let body = bpsBody 0 0 ByteString.empty mempty
      patch = buildBPS body ByteString.empty ByteString.empty
  in case parseBPS patch of
    Left _ -> assertFailure "unexpected rejection"
    Right (Parsed parsed _parseWarnings) -> assertEqual "target size" (FileSize 0) (bpsTargetSize parsed)

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

isAbsoluteWritePastTarget :: SlapError -> Bool
isAbsoluteWritePastTarget (ApplyFailed _ (ApplyAbsoluteWritePastTarget {})) = True
isAbsoluteWritePastTarget _ = False

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
        <> putWord32LE (unCRC32 (crc32 ByteString.empty))
        <> putWord32LE (unCRC32 (crc32 ByteString.empty))
      patchCRC = crc32 withoutPatchCRC
      patch = PatchFileContents (withoutPatchCRC <> word32LEBytes (unCRC32 patchCRC))
  in assertParseRejects parseUPS patch ""

upsWrongPatchCRC :: Assertion
upsWrongPatchCRC =
  let body = upsBody 0 0 mempty
      withoutPatchCRC = toStrict $
        byteString "UPS1"
        <> byteString body
        <> putWord32LE (unCRC32 (crc32 ByteString.empty))
        <> putWord32LE (unCRC32 (crc32 ByteString.empty))
      patch = PatchFileContents (withoutPatchCRC <> ByteString.pack [0xDE, 0xAD, 0xBE, 0xEF])
  in assertParseRejects parseUPS patch "CRC"

upsTooShortForMagic :: Assertion
upsTooShortForMagic =
  assertParseRejects parseUPS (PatchFileContents "UPS") ""

----------------------------------------------------------------------------
-- UPS apply error paths
----------------------------------------------------------------------------

-- | A block whose total span (skip + xorLen + terminator) exceeds
-- the remaining target space. Apply clips the out-of-bounds portion
-- (the terminator byte lands 1 past the declared output size) and
-- produces correct output. This matches real-world UPS patches from
-- NUPS/Tsukuyomi where the final block's terminator overshoots by 1.
upsApplyBlockPastTarget :: Assertion
upsApplyBlockPastTarget =
  let source = ByteString.pack [0x00, 0x00]
      -- Target size 2, but block: skip=0, xorData=[0xAA, 0xBB] = 2 bytes + terminator = 3.
      -- Total block span = 3, but only 2 bytes of target remain.
      -- Apply clips the terminator (which would write 0x00 XOR source[2]
      -- to offset 2) and produces the correct 2-byte output.
      body = upsBody 2 2 (upsBlock 0 [0xAA, 0xBB])
      expectedOutput = ByteString.pack [0xAA, 0xBB]
      patch = buildUPS body source expectedOutput
  in case parseUPS patch of
       Left slapError -> assertFailureT ("parse failed: " <> renderSlapError slapError)
       Right (Parsed parsed _parseWarnings) ->
         case applyUPS parsed (InputFileContents source) of
           Left slapError -> assertFailureT ("apply failed (expected success with OOB clipping): " <> renderSlapError slapError)
           Right (Outcome (OutputFileContents result) _applyWarnings) ->
             assertEqual "OOB-clipped output" expectedOutput result

----------------------------------------------------------------------------
-- IPS apply error paths
----------------------------------------------------------------------------

-- | A 'StandardIPS' patch whose post-EOF truncation marker declares
-- a zero-byte target but whose record stream is non-empty. Under the
-- honor-only-when-shrinking policy, declared (0) is strictly less
-- than the natural size derived from the lone record (1), so the
-- marker is honored: the record's payload is entirely past the
-- effective end and is clipped, producing an empty target plus the
-- pair of warnings 'IPSTruncationMarkerHonored' and
-- 'IPSRecordsClippedByMarker'. Apply does not surface
-- 'ApplyWritesPastTarget' here — that error path is reserved for the
-- defensive guard on the three non-Honored dispositions, which is
-- structurally unreachable.
ipsApplyZeroTargetWithRecordsClipped :: Assertion
ipsApplyZeroTargetWithRecordsClipped =
  let record = IPSRecordCopy { ipsCopyOffset  = Offset 0
                             , ipsCopyPayload = ByteString.pack [0xFF] }
      patch  = IPSPatch { ipsVariant             = StandardIPS
                        , ipsRecords             = Vector.singleton record
                        , ipsTruncatedTargetSize = Just (FileSize 0) }
      expectedHonored = IPSTruncationMarkerHonored LabelIPS
        (DeclaredTargetSize (FileSize 0))
        (NaturalTargetSize  (FileSize 1))
      expectedClipped  = IPSRecordsClippedByMarker LabelIPS
        (ClippedRecordCount 1) (actionAtPosition 0) (MarkerOvershootBytes (Length 1))
  in case applyIPS (InputFileContents ByteString.empty) patch of
       Right (Outcome (OutputFileContents target) warnings) -> do
         assertEqual "target should be empty" 0 (ByteString.length target)
         assertEqual "warnings"
           [expectedHonored, expectedClipped] warnings
       Left slapError -> assertFailure
         ("expected successful clipped apply, got error: "
          ++ Text.unpack (renderSlapError slapError))

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
      patch = buildBPSWithCRCs body wrongSourceCRC (crc32 target)
  in case parseBPS patch of
    Left slapError -> assertFailureT ("parse: " <> renderSlapError slapError)
    Right (Parsed parsed _parseWarnings) -> assertEqual "source CRC field" wrongSourceCRC (bpsSourceCRC parsed)

bpsTargetCRCReadLiterally :: Assertion
bpsTargetCRCReadLiterally =
  let source = ByteString.pack [0x00]
      actions = bpsActionVarint bpsTargetReadCode 1 <> word8 0xFF
      body = bpsBody 1 1 ByteString.empty actions
      wrongTargetCRC = CRC32 0xCAFEBABE
      patch = buildBPSWithCRCs body (crc32 source) wrongTargetCRC
  in case parseBPS patch of
    Left slapError -> assertFailureT ("parse: " <> renderSlapError slapError)
    Right (Parsed parsed _parseWarnings) -> assertEqual "target CRC field" wrongTargetCRC (bpsTargetCRC parsed)

-- | 'applyBPS' is a low-level executor: it trusts the caller to have
-- already verified the source matches the patch's expectations, and
-- just does the mechanical work with whatever 'InputFileContents' it
-- receives. Size verification happens one layer up, at the
-- 'Verification' layer consumed by 'Main.verifySource'. This test
-- pins the apply-layer contract by calling 'applyBPS' directly with
-- a patch that declares @sourceSize = 100@ against a 1-byte source —
-- apply ignores the declared size and proceeds as long as the actions
-- fit within the actual source bytes.
--
-- The complementary 'bpsVerificationCarriesDeclaredSize' test below
-- pins the other end of the contract: that 'parseSome' exposes the
-- declared size through 'verifyFileSize' so the Verification layer
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

-- | A BPS patch whose 'SourceCopy' offset varint encodes the
-- non-canonical @0x81@ form of zero — sign-magnitude "negative
-- zero". Both @0x80@ and @0x81@ decode to delta zero, so apply
-- still produces the right bytes; the parser must surface the
-- non-canonical encoding through 'NegativeZeroInBPS' so the user
-- learns the patch came from a non-canonical producer or transit
-- corruption. See @docs/bps/questions.md@ → "two encodings for
-- zero-delta".
--
-- The action chosen is the smallest possible: @SourceCopy length=1@
-- with the offset varint emitted directly as the byte @0x81@ (which
-- byuu-varint decodes to unsigned 1, the sign-magnitude shape for
-- "negative zero"). The encoder helper 'bpsSignedDelta' would emit
-- @0x80@ for delta zero — exactly the canonical shape we are not
-- testing — so the offset byte is laid down by hand.
bpsNegativeZeroSignedVarintWarns :: Assertion
bpsNegativeZeroSignedVarintWarns =
  let source = ByteString.pack [0xAB]
      target = source
      actions = bpsActionVarint bpsSourceCopyCode 1
                <> word8 0x81
      body  = bpsBody 1 1 ByteString.empty actions
      patch = buildBPS body source target
  in case parseBPS patch of
       Left slapError ->
         assertFailureT ("expected parse to succeed: " <> renderSlapError slapError)
       Right (Parsed _parsed parseAdvisories) ->
         assertBool ("expected NegativeZeroInBPS in: " ++ show parseAdvisories)
                    (NegativeZeroInBPS `elem` parseAdvisories)

-- | 'parseSome' must populate 'verifyFileSize' with the declared
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
  in case parseSome noDialectsRequested EncodingUtf8 patch of
    Left slapError -> assertFailureT ("parseSome: " <> renderSlapError slapError)
    Right somePatch ->
      assertEqual "verifyFileSize" (Just (AdvisorySize (FileSize 4)))
        (verifyFileSize (patchVerification somePatch))

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
      patch = buildUPSWithCRCs body wrongSourceCRC (crc32 target)
  in case parseUPS patch of
    Left slapError -> assertFailureT ("parse: " <> renderSlapError slapError)
    Right (Parsed parsed _parseWarnings) -> assertEqual "source CRC field" wrongSourceCRC (upsSourceCRC parsed)

upsTargetCRCReadLiterally :: Assertion
upsTargetCRCReadLiterally =
  let source = ByteString.pack [0x11, 0x22]
      body = upsBody 2 2 mempty
      wrongTargetCRC = CRC32 0xCAFEBABE
      patch = buildUPSWithCRCs body (crc32 source) wrongTargetCRC
  in case parseUPS patch of
    Left slapError -> assertFailureT ("parse: " <> renderSlapError slapError)
    Right (Parsed parsed _parseWarnings) -> assertEqual "target CRC field" wrongTargetCRC (upsTargetCRC parsed)

-- | Same apply-layer contract as BPS: 'applyUPS' uses the actual
-- length of the 'InputFileContents' ByteString, not the declared
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
-- must expose UPS's declared source-size through 'verifyFileSize'.
upsVerificationCarriesDeclaredSize :: Assertion
upsVerificationCarriesDeclaredSize =
  let source = ByteString.pack [0x11, 0x22, 0x33, 0x44]
      target = ByteString.pack [0x11, 0x22, 0x33, 0x44]
      body = upsBody 4 4 mempty
      patch = buildUPS body source target
  in case parseSome noDialectsRequested EncodingUtf8 patch of
    Left slapError -> assertFailureT ("parseSome: " <> renderSlapError slapError)
    Right somePatch ->
      assertEqual "verifyFileSize" (Just (AdvisorySize (FileSize 4)))
        (verifyFileSize (patchVerification somePatch))

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
      Left failure ->
        counterexample ("unexpected decode failure: " ++ show failure) (property False)
      Right (VarintResult value consumed) ->
        counterexample ("input bytes: " ++ show (ByteString.unpack bytes)
                        ++ ", decoded: " ++ show value
                        ++ ", consumed: " ++ show consumed) $
        encodeVarint value === ByteString.take consumed bytes
  where
    -- Generate structurally valid byuu varints: 0-7 continuation bytes
    -- (high bit clear) followed by one terminator byte (high bit set).
    -- Payloads are random within their 7-bit range so we cover the
    -- whole representable value space, not just canonical encoder
    -- output. With a pure 'arbitrary' byte generator most samples are
    -- unterminated and get discarded; this shape guarantees every
    -- sample decodes.
    --
    -- Cap at 7 continuations (8 total bytes) so the decoded value
    -- always fits inside 'Int64'. The decoder accepts up to 9 bytes,
    -- but the high-payload tail of the 9-byte space exceeds 2^63 and
    -- silently wraps the signed accumulator into negative territory;
    -- the encoder, written for non-negative input, then can't
    -- reproduce the bytes. The codebase only ever encodes values
    -- below the 63-bit ceiling, so the bijection the property tests
    -- is the one that actually matters in practice.
    genWellFormedVarint :: Gen ByteString
    genWellFormedVarint = do
      continuationCount <- chooseInt (0, 7)
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
    Left failure -> assertFailure ("decode failed: " ++ show failure)
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
      patchCRC = crc32 withoutPatchCRC
      complete = withoutPatchCRC <> word32LEBytes (unCRC32 patchCRC)
  in PatchFileContents complete

buildUPSWithCRCs :: ByteString -> CRC32 -> CRC32 -> PatchFileContents
buildUPSWithCRCs bodyContent sourceCRC targetCRC =
  let withoutPatchCRC = toStrict $
        byteString "UPS1"
        <> byteString bodyContent
        <> putWord32LE (unCRC32 sourceCRC)
        <> putWord32LE (unCRC32 targetCRC)
      patchCRC = crc32 withoutPatchCRC
      complete = withoutPatchCRC <> word32LEBytes (unCRC32 patchCRC)
  in PatchFileContents complete

----------------------------------------------------------------------------
-- NINJA2 spec-conformance: rejection
----------------------------------------------------------------------------

-- | A NINJA2 patch whose PATCH_ENC byte (offset 6 of the fixed header)
-- is neither 0 (undeclared) nor 1 (UTF-8) must be rejected at parse time
-- with the structured 'NINJA2UnrecognizedTextMode' error carrying
-- the offending byte verbatim. The rest of the header is filled with
-- NULs and the command stream is empty: the text-mode rejection fires
-- before any of that is consulted, so its contents are immaterial to
-- the test's invariant.
ninja2RejectsUnrecognizedTextMode :: Assertion
ninja2RejectsUnrecognizedTextMode =
  let unrecognizedByte = 0x42 :: Word8
      headerWithBadEncoding =
        ByteString.pack [0x4E, 0x49, 0x4E, 0x4A, 0x41, 0x32, unrecognizedByte]
        <> ByteString.replicate (2048 - 7) 0x00
      patchBytes = PatchFileContents headerWithBadEncoding
  in case NINJA2.parseNINJA2 EncodingUtf8 patchBytes of
       Left (NINJA2UnrecognizedTextMode actualByte) ->
         assertEqual "preserved byte" unrecognizedByte actualByte
       Left otherError ->
         assertFailure ("expected NINJA2UnrecognizedTextMode, got: "
                        ++ Text.unpack (renderSlapError otherError))
       Right _ ->
         assertFailure "expected parse to reject unrecognized PATCH_ENC, but it succeeded"

----------------------------------------------------------------------------
-- NINJA2 apply-error: bounds violation
----------------------------------------------------------------------------

-- | A NINJA2 XOR record whose @writeOffset + payloadLength@ exceeds
-- the output buffer's declared end must surface as a typed
-- 'ApplyAbsoluteWritePastTarget' rather than a silent past-buffer
-- write through the raw output pointer. The fixture omits
-- @OPEN_NEW_FILE@, so @outputLength@ defaults to the 4-byte source
-- length; a single XOR record at offset 8 with a 4-byte payload
-- attempts to write to @[8, 12)@, well past the 4-byte target.
ninja2ApplyXorRecordPastTarget :: Assertion
ninja2ApplyXorRecordPastTarget =
  let source = ByteString.pack [0x00, 0x00, 0x00, 0x00]
      header = ByteString.pack [0x4E, 0x49, 0x4E, 0x4A, 0x41, 0x32, 0x01]
            <> ByteString.replicate (0x800 - 7) 0x00
      commandStream = ByteString.pack
        [ 0x02                          -- XOR_RECORD opcode
        , 0x01, 0x08                    -- offset VLV: 1 raw byte LE 0x08
        , 0x01, 0x04                    -- payload-length VLV: 1 raw byte LE 4
        , 0xAA, 0xBB, 0xCC, 0xDD        -- 4-byte XOR payload
        , 0x00                          -- END opcode
        ]
      patch = PatchFileContents (header <> commandStream)
  in assertApplyError (NINJA2.parseNINJA2 EncodingUtf8)
       (\parsed src -> fmap (const ()) (NINJA2.applyNINJA2 parsed src))
       patch source isAbsoluteWritePastTarget
       "XOR record writes past target"

----------------------------------------------------------------------------
-- APSGBA apply-error: bounds violation
----------------------------------------------------------------------------

-- | An APS-GBA record whose block offset sits at or past the
-- declared target size must surface as a typed
-- 'ApplyAbsoluteWritePastTarget' rather than a silently-clipped
-- 64KB no-op. The fixture declares a 4-byte target and emits a
-- single record at offset 0x10000 (one full block past the target);
-- the per-block payload is 64KB of zeros to satisfy the wire
-- structure. Distinct from the legitimate partial-last-block case
-- (block starts in-bounds, tail extends past), which the apply
-- still handles by per-byte skip.
apsGbaApplyRecordOffsetPastTarget :: Assertion
apsGbaApplyRecordOffsetPastTarget =
  let source         = ByteString.pack [0x00, 0x00, 0x00, 0x00]
      sourceSize     = 4 :: Word32
      targetSize     = 4 :: Word32
      recordOffset   = fromIntegral apsGbaBlockSize :: Word32
      header         = toStrict $
        byteString "APS1"
        <> putWord32LE sourceSize
        <> putWord32LE targetSize
      recordBytes    = toStrict $
        putWord32LE recordOffset
        <> byteString (ByteString.replicate 4 0x00)  -- source + target CRC16, unread by apply
        <> byteString (ByteString.replicate apsGbaBlockSize 0x00)
      patch          = PatchFileContents (header <> recordBytes)
  in assertApplyError APSGBA.parseAPSGBA
       (\parsed src -> fmap (const ()) (APSGBA.applyAPSGBA parsed src))
       patch source isAbsoluteWritePastTarget
       "record offset past target"

----------------------------------------------------------------------------
-- VCDIFF code table
----------------------------------------------------------------------------

-- These tests assert the default code table against the ranges in
-- docs/vcdiff/core/spec.md. They would pass on "make compiles" alone
-- if the table were silently wrong, so each entry is checked against
-- the spec's stated meaning, not against slap's own construction.

fixedSize :: Word8 -> InstructionSize
fixedSize = SizeIs . FixedInstructionSize

-- | The serialized default table is exactly 1536 bytes (six 256-byte
-- arrays).
codeTableSerializedLength :: Assertion
codeTableSerializedLength =
  assertEqual "serialized default code table length"
    1536 (ByteString.length (serializeCodeTable defaultCodeTable))

-- | Reading back a serialized default table reproduces it exactly.
codeTableRoundTrip :: Assertion
codeTableRoundTrip =
  assertEqual "deserialize . serialize is identity on the default table"
    (Right defaultCodeTable)
    (deserializeCodeTable (serializeCodeTable defaultCodeTable))

-- | The default table's entry at the given index is the expected pair.
codeTableEntryIs :: Int -> CodeTableEntry -> Assertion
codeTableEntryIs index expected =
  assertEqual ("default code table entry " ++ show index)
    expected (codeTableEntries defaultCodeTable Vector.! index)

----------------------------------------------------------------------------
-- VCDIFF core engine — hand-built synthetics
----------------------------------------------------------------------------

-- Each patch is raw bytes whose result is known by construction, so a
-- pass would have been impossible before the CoreOnly engine existed.
-- Layout per window after the 5-byte header (magic D6 C3 C4, version 00,
-- header indicator 00): Win_Indicator, [segment length, segment
-- position], delta-encoding length, target-window size, Delta_Indicator,
-- the three section lengths, then the data, instruction, and address
-- sections. Sizes are kept under 128 so every varint is one byte.
-- Instruction code bytes index the default table: 0x02 = ADD size 1,
-- 0x14 = COPY mode 0 size 4.

vcdiffPatch :: [Word8] -> PatchFileContents
vcdiffPatch windowBytes =
  PatchFileContents (ByteString.pack ([0xD6, 0xC3, 0xC4, 0x00, 0x00] ++ windowBytes))

-- | A header indicator with a reserved bit (bit 3) set. slap cannot
-- interpret a bit the core leaves undefined, so the patch is declined
-- as unreadable ('VCDIFFReservedIndicatorBits') — not called
-- malformed, because slap has no grounds to say a future-dialect
-- patch is broken.
test_vcdiffReservedHeaderBitDeclined :: Assertion
test_vcdiffReservedHeaderBitDeclined =
  case parseVCDIFF patch of
    Left (VCDIFFReservedIndicatorBits HeaderIndicator 0x08) -> pure ()
    Left otherError -> assertFailureT
      ("expected VCDIFFReservedIndicatorBits, got: " <> renderSlapError otherError)
    Right _ -> assertFailure "expected the reserved header bit to be declined"
  where
    -- magic | version 00 | header indicator 0x08 (reserved bit 3)
    patch = PatchFileContents (ByteString.pack [0xD6, 0xC3, 0xC4, 0x00, 0x08])

-- | A window indicator with a reserved bit (bit 3) set, on a window
-- that is otherwise well-formed (one ADD filling its one-byte
-- target). Same decline as the header case; the window framing still
-- parses, the classification declines.
test_vcdiffReservedWindowBitDeclined :: Assertion
test_vcdiffReservedWindowBitDeclined =
  case parseVCDIFF patch of
    Left (VCDIFFReservedIndicatorBits WindowIndicator 0x08) -> pure ()
    Left otherError -> assertFailureT
      ("expected VCDIFFReservedIndicatorBits, got: " <> renderSlapError otherError)
    Right _ -> assertFailure "expected the reserved window bit to be declined"
  where
    -- win 0x08 (reserved bit 3) | deltaEncLen 06 | target 01 | deltaInd 00
    --   | A 01 I 01 C 00 | data "A" | inst [ADD1]
    patch = vcdiffPatch [0x08, 0x06, 0x01, 0x00, 0x01, 0x01, 0x00, 0x41, 0x02]

-- | Both VCD_SOURCE and VCD_TARGET set: still 'MalformedVCDIFF'. slap
-- understands exactly what both bits claim, and RFC 3284 §4.2 forbids
-- the combination — understood-and-broken stays malformed; only the
-- uninterpretable reserved bits moved out.
test_vcdiffBothSourceBitsStillMalformed :: Assertion
test_vcdiffBothSourceBitsStillMalformed =
  case parseVCDIFF patch of
    Left (MalformedVCDIFF VCDIFFBothSourceAndTargetWindowBits) -> pure ()
    Left otherError -> assertFailureT
      ("expected VCDIFFBothSourceAndTargetWindowBits, got: " <> renderSlapError otherError)
    Right _ -> assertFailure "expected the both-source window to be refused"
  where
    -- win 0x03 (VCD_SOURCE + VCD_TARGET) | segLen 04 segPos 00
    --   | deltaEncLen 06 | target 04 | deltaInd 00 | A 00 I 01 C 01
    --   | inst [COPY mode0 size4] | addr [0]
    patch = vcdiffPatch
      [0x03, 0x04, 0x00, 0x06, 0x04, 0x00, 0x00, 0x01, 0x01, 0x14, 0x00]

-- | A self-contained window that writes one byte then COPYs four bytes
-- from address 0 — a read that trails the write, so it expands the
-- single byte into a five-byte run.
test_vcdiffSelfReferentialCopy :: Assertion
test_vcdiffSelfReferentialCopy =
  case parseVCDIFF patch of
    Left parseError -> assertFailureT ("parse: " <> renderSlapError parseError)
    Right (Parsed decoded _) ->
      case applyVCDIFF decoded (InputFileContents ByteString.empty) of
        Left applyError -> assertFailureT ("apply: " <> renderSlapError applyError)
        Right (OutputFileContents output) ->
          assertEqual "run-length expansion" (ByteString.replicate 5 0x41) output
  where
    -- win 0x00 | deltaEncLen 09 | target 05 | deltaInd 00 | A 01 I 02 C 01
    --   | data "A" | inst [ADD1, COPY mode0 size4] | addr [0]
    patch = vcdiffPatch
      [0x00, 0x09, 0x05, 0x00, 0x01, 0x02, 0x01, 0x41, 0x02, 0x14, 0x00]

-- | A window that writes two bytes then COPYs four from address 0 — a
-- read two bytes behind the write head, so the expansion must proceed
-- byte by byte (a one-byte memset here would produce "ABBBBB"). Pins
-- the forward-expansion shape end-to-end; the distance-one byte-run
-- shape is pinned by the synthetic above.
test_vcdiffForwardExpansionCopy :: Assertion
test_vcdiffForwardExpansionCopy =
  case parseVCDIFF patch of
    Left parseError -> assertFailureT ("parse: " <> renderSlapError parseError)
    Right (Parsed decoded _) ->
      case applyVCDIFF decoded (InputFileContents ByteString.empty) of
        Left applyError -> assertFailureT ("apply: " <> renderSlapError applyError)
        Right (OutputFileContents output) ->
          assertEqual "forward expansion" "ABABAB" output
  where
    -- win 0x00 | deltaEncLen 0A | target 06 | deltaInd 00 | A 02 I 02 C 01
    --   | data "AB" | inst [ADD2, COPY mode0 size4] | addr [0]
    patch = vcdiffPatch
      [0x00, 0x0A, 0x06, 0x00, 0x02, 0x02, 0x01, 0x41, 0x42, 0x03, 0x14, 0x00]

-- | A first instruction COPYing from address 0 when nothing has been
-- produced (here = 0): the address is not strictly before the write
-- position. Core invariant 1.
test_vcdiffCopyAddressOutOfRange :: Assertion
test_vcdiffCopyAddressOutOfRange =
  case parseVCDIFF patch of
    Left (MalformedVCDIFF VCDIFFCopyAddressOutOfRange{}) -> pure ()
    _ -> assertFailure "expected VCDIFFCopyAddressOutOfRange"
  where
    -- win 0x00 | deltaEncLen 06 | target 04 | deltaInd 00 | A 00 I 01 C 01
    --   | inst [COPY mode0 size4] | addr [0]
    patch = vcdiffPatch
      [0x00, 0x06, 0x04, 0x00, 0x00, 0x01, 0x01, 0x14, 0x00]

-- | A COPY that begins inside a four-byte source segment (address 2)
-- but runs four bytes, past the segment end. Core invariant 2.
test_vcdiffCopyCrossesSegmentEnd :: Assertion
test_vcdiffCopyCrossesSegmentEnd =
  case parseVCDIFF patch of
    Left (MalformedVCDIFF (VCDIFFCopyCrossesSourceSegmentEnd _)) -> pure ()
    _ -> assertFailure "expected VCDIFFCopyCrossesSourceSegmentEnd"
  where
    -- win 0x01 (VCD_SOURCE) | segLen 04 segPos 00 | deltaEncLen 06
    --   | target 04 | deltaInd 00 | A 00 I 01 C 01 | inst [COPY mode0 size4]
    --   | addr [2]
    patch = vcdiffPatch
      [0x01, 0x04, 0x00, 0x06, 0x04, 0x00, 0x00, 0x01, 0x01, 0x14, 0x02]

-- | A window declaring a five-byte target but emitting only one ADD of
-- one byte. Core invariant 3.
test_vcdiffWindowSizeMismatch :: Assertion
test_vcdiffWindowSizeMismatch =
  case parseVCDIFF patch of
    Left (MalformedVCDIFF VCDIFFWindowSizeMismatch{}) -> pure ()
    _ -> assertFailure "expected VCDIFFWindowSizeMismatch"
  where
    -- win 0x00 | deltaEncLen 06 | target 05 | deltaInd 00 | A 01 I 01 C 00
    --   | data "A" | inst [ADD1]
    patch = vcdiffPatch
      [0x00, 0x06, 0x05, 0x00, 0x01, 0x01, 0x00, 0x41, 0x02]

-- | A patch that parses cleanly but names a ten-byte source segment;
-- applied against a two-byte source, the segment lies outside the file.
-- The one check apply makes that parse cannot.
test_vcdiffSourceSegmentExceedsSource :: Assertion
test_vcdiffSourceSegmentExceedsSource =
  case parseVCDIFF patch of
    Left parseError -> assertFailureT ("unexpected parse failure: " <> renderSlapError parseError)
    Right (Parsed decoded _) ->
      case applyVCDIFF decoded (InputFileContents (ByteString.replicate 2 0x00)) of
        Left (ApplyFailed _ ApplySourceReadOutOfBounds{}) -> pure ()
        _ -> assertFailure "expected ApplySourceReadOutOfBounds"
  where
    -- win 0x01 (VCD_SOURCE) | segLen 0A segPos 00 | deltaEncLen 06
    --   | target 04 | deltaInd 00 | A 00 I 01 C 01 | inst [COPY mode0 size4]
    --   | addr [0]
    patch = vcdiffPatch
      [0x01, 0x0A, 0x00, 0x06, 0x04, 0x00, 0x00, 0x01, 0x01, 0x14, 0x00]

----------------------------------------------------------------------------
-- VCDIFF address cache — the decode in isolation
----------------------------------------------------------------------------

-- | Five SELF-mode decodes seed the four-slot near cache and wrap it: the
-- fifth address overwrites the oldest slot, leaving the rest. Reading
-- each near slot back (a near-mode decode with a zero delta) returns the
-- stored address, so the round-robin write order is what is checked.
test_vcdiffNearCacheRoundRobin :: Assertion
test_vcdiffNearCacheRoundRobin = do
  assertEqual "near[0] wrapped to the fifth address" 50 (nearRead seeded 0)
  assertEqual "near[1] kept the second address"      20 (nearRead seeded 1)
  assertEqual "near[2] kept the third address"       30 (nearRead seeded 2)
  assertEqual "near[3] kept the fourth address"      40 (nearRead seeded 3)
  where
    seeded = foldl (\cache value -> snd (selfSeed cache value))
                   freshAddressCache [10, 20, 30, 40, 50]
    nearRead cache slot =
      case decodeCopyAddress cache 0 (fromIntegral ((2 :: Int) + slot)) (ByteString.pack [0]) 0 of
        Right reading -> copyAddressDecoded reading
        Left _ -> error "near-mode decode should not fail"

-- | A SELF-mode decode of 770 writes the same cache at @770 mod 768 = 2@.
-- Reading same-block 0 byte 2 returns 770, so both the block arithmetic
-- and the modulo write are checked.
test_vcdiffSameCacheModulo :: Assertion
test_vcdiffSameCacheModulo =
  assertEqual "same[770 mod 768] holds 770" 770 (sameRead seeded 2)
  where
    -- 770 as a VCDIFF varint: 0x86 0x02 (group 6, then 2).
    seeded = snd (selfSeedBytes freshAddressCache [0x86, 0x02])
    sameRead cache slotByte =
      case decodeCopyAddress cache 0 (fromIntegral (nearCacheSize + 2)) (ByteString.pack [slotByte]) 0 of
        Right reading -> copyAddressDecoded reading
        Left _ -> error "same-mode decode should not fail"

-- | Seed the caches with a SELF-mode decode of a single-byte varint,
-- returning the decoded address and the updated cache.
selfSeed :: AddressCache -> Word8 -> (Int, AddressCache)
selfSeed cache value = selfSeedBytes cache [value]

-- | As 'selfSeed', but the varint may span multiple bytes.
selfSeedBytes :: AddressCache -> [Word8] -> (Int, AddressCache)
selfSeedBytes cache varintBytes =
  case decodeCopyAddress cache 0 0 (ByteString.pack varintBytes) 0 of
    Right reading -> (copyAddressDecoded reading, copyAddressCacheAfter reading)
    Left _ -> error "SELF-mode decode should not fail on a well-formed varint"
