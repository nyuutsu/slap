module Main (main) where

import qualified Slap.BPS.Apply as BPS
import Slap.BPS.Apply (TargetCopyStrategy(..), classifyTargetCopy)
import qualified Slap.BPS.Create as BPS
import qualified Slap.BPS.Parse as BPS
import qualified Slap.BPS.Types as BPS
import qualified Slap.IPS.Apply as IPS
import qualified Slap.IPS.Parse as IPS
import Slap.IPS.Create (avoidSentinel, optimalIPSRecords, ebpJson)
import Slap.IPS.Describe (jsonPairs, jsonFieldCI)
import qualified Slap.UPS.Apply as UPS
import qualified Slap.UPS.Create as UPS
import qualified Slap.UPS.Parse as UPS
import qualified Slap.PMSR.Parse as PMSR
import qualified Slap.PMSR.Apply as PMSR
import qualified Slap.NINJA1.Types as NINJA1
import qualified Slap.NINJA1.Parse as NINJA1
import qualified Slap.NINJA1.Apply as NINJA1
import qualified Slap.DPS.Types as DPS
import qualified Slap.DPS.Parse as DPS
import qualified Slap.DPS.Apply as DPS
import qualified Slap.DPS.Create as DPS
import qualified Slap.RUP.Types as RUP
import qualified Slap.RUP.Parse as RUP
import qualified Slap.RUP.Apply as RUP
import qualified Slap.RUP.Create as RUP
import qualified Slap.APSN64.Types as APSN64
import qualified Slap.APSN64.Parse as APSN64
import qualified Slap.APSN64.Apply as APSN64
import qualified Slap.APSN64.Create as APSN64
import qualified Slap.APSGBA.Parse as APSGBA
import qualified Slap.APSGBA.Apply as APSGBA
import qualified Slap.APSGBA.Create as APSGBA
import qualified Slap.GDIFF.Parse as GDIFF
import qualified Slap.GDIFF.Apply as GDIFF
import qualified Slap.GDIFF.Create as GDIFF
import qualified Slap.PPF.Types as PPF
import qualified Slap.PPF.Parse as PPF
import qualified Slap.PPF.Apply as PPF
import qualified Slap.PPF.Create as PPF
import qualified Slap.VCDIFF.Parse as VCDIFF
import qualified Slap.BSDiff.Parse as BSDiff
import qualified Slap.XDelta1.Parse as XDelta1
import qualified Slap.PCHTXT.Types as PCHTXT
import qualified Slap.PCHTXT.Parse as PCHTXT
import           Slap.TextEncoding (truncateUtf8, isValidUtf8,
                   encodeUtf8Field, decodeUtf8Field,
                   encodeLocaleField, decodeLocaleField,
                   encodeBoundedUtf8, encodeBoundedLocale,
                   truncateLocale, BoundedResult(..))
import qualified Slap.PCHTXT.Apply as PCHTXT

import Slap.Binary (md5, sha1, diffHunks, trimNull)
import Slap.Checksum (CRC32(..), MD5Hash(..), SHA1Hash(..))
import Slap.Error (SlapError, SlapWarning(..), CreateResult(..), FieldName(..), renderSlapError, renderSlapWarning)
import Slap.FormatLabel (FormatLabel(..))
import Slap.Measure (Offset(..), Length(..), FileSize(..),
                      Hunk(..), EncodedHunk(..), UndoHunk(..))
import Slap.FFI (rustyCRC32)
import Slap.SomePatch (SomePatch(..), ApplyStrategy(..), parseSome)
import Slap.Convert (PatchContents(..), DirectCreate(..), DiffCreate(..), CreateFormat(..),
                      FormatSpecification(..), CreateMeta(..), PatchEncoding(..),
                      emptyContents, formatSpecification, defaultMeta,
                      canConvert, convertDirect, conversionNotes, createFromMemory)
import Slap.PatchField (PatchField(..))
import Slap.Platform (PlatformType(..))

import Data.ByteString (ByteString)
import Data.List (isInfixOf, isPrefixOf)
import Data.Maybe (fromMaybe, isJust)
import qualified Data.ByteString as ByteString
import qualified Data.Set as Set
import qualified Data.Text as Text
import qualified Data.Text.Encoding as Text
import System.Directory (getTemporaryDirectory, removeFile)
import System.IO (hClose, openBinaryTempFile)
import Test.Tasty
import Test.Tasty.HUnit (testCase, assertBool, assertEqual)
import Test.Tasty.QuickCheck

main :: IO ()
main = defaultMain $ testGroup "Properties"
  [ testGroup "BPS"
      [ testProperty "round-trip" prop_bps
      , testProperty "parse-truncated" prop_bpsTrunc
      , testProperty "block-move" prop_bpsBlockMove
      , testProperty "no-size-regression" prop_bpsNoSizeRegression
      , testProperty "metadata-round-trip" prop_bpsMetadata ]
  , testGroup "classifyTargetCopy"
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
  , testGroup "IPS"
      [ testProperty "round-trip" prop_ips
      , testProperty "eof-collision" prop_ipsEofCollision
      , testProperty "avoidSentinel" prop_avoidSentinel
      , testProperty "dp-not-larger" prop_dpNotLarger
      , testProperty "parse-truncated" prop_ipsTrunc ]
  , testGroup "IPS32"
      [ testProperty "round-trip" prop_ips32
      , testProperty "dp-not-larger" prop_dpIPS32NotLarger
      , testProperty "parse-truncated" prop_ips32Trunc ]
  , testGroup "EBP"
      [ testProperty "round-trip" prop_ebp
      , testProperty "parse-truncated" prop_ebpTrunc
      , testCase "non-ascii-utf8" test_ebpUtf8 ]
  , testGroup "UPS"
      [ testProperty "round-trip" prop_ups
      , testProperty "parse-truncated" prop_upsTrunc ]
  , testGroup "PPF3"
      [ testProperty "round-trip" prop_ppf3
      , testProperty "parse-truncated" prop_ppf3Trunc ]
  , testGroup "PMSR"
      [ testProperty "round-trip" prop_pmsr
      , testProperty "parse-truncated" prop_pmsrTrunc ]
  , testGroup "NINJA1"
      [ testProperty "round-trip" prop_ninja1
      , testProperty "hashes" prop_ninja1Hashes
      , testProperty "parse-truncated" prop_ninja1Trunc ]
  , testGroup "DPS"
      [ testProperty "round-trip" prop_dps
      , testProperty "parse-truncated" prop_dpsTrunc ]
  , testGroup "RUP"
      [ testProperty "round-trip" prop_rup
      , testProperty "hashes" prop_rupHashes
      , testProperty "parse-truncated" prop_rupTrunc
      , testProperty "round-trip-utf8" prop_rupUTF8RoundTrip
      , testProperty "round-trip-system" prop_rupSystemRoundTrip
      , testProperty "non-ascii-utf8" prop_rupNonAsciiUTF8
      , testProperty "field-overflow-truncated" prop_rupFieldOverflow
      , testProperty "patch-enc-byte-utf8" prop_rupPatchEncByteUTF8
      , testProperty "patch-enc-byte-system" prop_rupPatchEncByteSystem
      , testProperty "utf8-decode-round-trip" prop_rupUTF8Decode ]
  , testGroup "APS-N64"
      [ testProperty "round-trip" prop_apsN64
      , testProperty "parse-truncated" prop_apsN64Trunc ]
  , testGroup "APS-GBA"
      [ testProperty "round-trip" prop_apsGba
      , testProperty "parse-truncated" prop_apsGbaTrunc ]
  , testGroup "GDIFF"
      [ testProperty "round-trip" prop_gdiff
      , testProperty "parse-truncated" prop_gdiffTrunc ]
  , testGroup "PCHTXT"
      [ testProperty "round-trip" prop_pchtxt
      , testProperty "parse-truncated" prop_pchtxtTrunc
      , testCase "parse-escapes" parsePchtxtEscapes
      , testCase "parse-sphinx" parsePchtxtSphinx ]
  , testGroup "VCDIFF"
      [ testProperty "parse-truncated" prop_vcdiffTrunc ]
  , testGroup "BSDiff"
      [ testProperty "parse-truncated" prop_bsdiffTrunc ]
  , testGroup "XDelta1"
      [ testProperty "parse-truncated" prop_xdelta1Trunc ]
  , testGroup "Identity"
      [ testProperty name (prop_identity format)
      | (name, format) <- allCreateFormats
      ]
  , testGroup "Undo"
      [ testProperty "UPS" prop_upsUndo
      , testProperty "PPF3" prop_ppf3Undo
      ]
  , testGroup "Contracts"
      [ testProperty "canConvert-full" prop_canConvertFull
      , testProperty "no-surplus-no-notes" prop_noSurplusNoNotes
      , testProperty "ninja1-accepts-empty" prop_ninja1AcceptsEmpty
      , testProperty "apsn64-rejects-empty" prop_apsn64RejectsEmpty
      , testProperty "ppf3-undo-rejects-empty" prop_ppf3UndoRejectsEmpty
      , testProperty "ppf3-validate-rejects-empty" prop_ppf3ValidateRejectsEmpty
      , testProperty "ips-sentinel-collision-direct" prop_ipsSentinelDirect
      , testProperty "ips32-sentinel-collision-direct" prop_ips32SentinelDirect
      , testProperty "ips-sentinel-split-direct" prop_ipsSentinelSplitDirect
      , testProperty "ips32-sentinel-split-direct" prop_ips32SentinelSplitDirect
      , testProperty "ips-sentinel-with-source" prop_ipsSentinelWithSource
      ]
  , testGroup "TextEncoding"
      [ testGroup "truncateUtf8"
          [ testProperty "never-exceeds-byte-budget" prop_truncateNeverExceedsBudget
          , testProperty "output-is-valid-utf8" prop_truncateOutputIsValidUtf8
          , testProperty "output-is-prefix-of-input" prop_truncateOutputIsPrefixOfInput
          , testProperty "identity-when-budget-sufficient" prop_truncateIdentityWhenSufficient
          , testCase "café-truncated-to-5-bytes" test_truncateCafe
          , testCase "emoji-at-various-budgets" test_truncateEmoji
          , testCase "empty-string-any-budget" test_truncateEmpty
          , testCase "adversarial-all-continuation-bytes" test_truncateAdversarial
          ]
      , testGroup "encodeBoundedUtf8"
          [ testProperty "output-is-exactly-fieldWidth-bytes" prop_boundedUtf8ExactWidth
          , testProperty "reports-truncation-iff-overflow" prop_boundedUtf8TruncationIff
          ]
      , testGroup "encodeBoundedLocale"
          [ testProperty "output-is-exactly-fieldWidth-bytes" prop_boundedLocaleExactWidth
          ]
      , testGroup "truncateLocale"
          [ testCase "byte-level-not-codepoint-level" test_truncateLocaleByteLevel
          ]
      , testGroup "isValidUtf8"
          [ testCase "valid-ascii" test_isValidUtf8Ascii
          , testCase "valid-multibyte" test_isValidUtf8Multibyte
          , testCase "truncated-multibyte" test_isValidUtf8Truncated
          , testCase "empty" test_isValidUtf8Empty
          , testCase "bare-continuation" test_isValidUtf8BareContinuation
          ]
      , testGroup "round-trips"
          [ testProperty "utf8-round-trip" prop_utf8RoundTrip
          , testProperty "locale-round-trip-ascii" prop_localeRoundTripAscii
          ]
      ]
  , testGroup "Encoding"
      [ testCase "ppf3-non-ascii-round-trip" test_ppf3NonAsciiRoundTrip
      , testCase "ppf3-overflow-warning" test_ppf3OverflowWarning
      , testCase "ppf3-empty-description" test_ppf3EmptyDescription
      , testCase "dps-non-ascii-round-trip" test_dpsNonAsciiRoundTrip
      , testCase "dps-overflow-per-field" test_dpsOverflowPerField
      , testCase "dps-all-fields-overflow" test_dpsAllFieldsOverflow
      , testCase "apsn64-non-ascii-round-trip" test_apsN64NonAsciiRoundTrip
      , testCase "apsn64-overflow-warning" test_apsN64OverflowWarning
      , testCase "rup-non-ascii-system" test_rupNonAsciiSystem
      , testCase "encoding-gap-ppf3" test_encodingGapPPF3
      , testCase "encoding-gap-apsn64" test_encodingGapAPSN64
      , testCase "conversion-metadata-round-trip" test_conversionMetadataRoundTrip
      , testCase "utf8-inference-valid" test_utf8InferenceValid
      , testCase "utf8-inference-invalid" test_utf8InferenceInvalid
      ]
  , testGroup "DPS Detection"
      [ testCase "valid-dps-zero-records" test_isDPSValidZeroRecords
      , testCase "valid-header-invalid-record-mode" test_isDPSInvalidRecordMode
      , testCase "printable-ascii-not-dps" test_isDPSPrintableAsciiNotDPS
      ]
  ]

emptyRupInfo :: RUP.RUPInfo
emptyRupInfo = RUP.RUPInfo Nothing Nothing Nothing Nothing Nothing Nothing Nothing Nothing


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
-- Affected: PPF3, PMSR, NINJA1, APS-N64, PCHTXT (direct), DPS (differential).
genPairNoShrink :: Gen (ByteString, ByteString)
genPairNoShrink = do
  shorter <- genByteString
  longer <- genByteString
  pure $ if ByteString.length shorter <= ByteString.length longer then (shorter, longer) else (longer, shorter)

-- | (source, target) of equal length.  UPS undo is only lossless when
-- source and target sizes match (the normal ROM patching case).
genSameSizePair :: Gen (ByteString, ByteString)
genSameSizePair = do
  source <- genByteString
  target <- ByteString.pack <$> vectorOf (ByteString.length source) arbitrary
  pure (source, target)

-- | Apply a patch via temp file, return result bytes.
applyViaFile :: (patch -> FilePath -> IO result) -> patch -> ByteString -> IO ByteString
applyViaFile applyFunction parsed source = do
  directory <- getTemporaryDirectory
  (temporary, handle) <- openBinaryTempFile directory "slap-prop"
  ByteString.hPut handle source
  hClose handle
  _ <- applyFunction parsed temporary
  output <- ByteString.readFile temporary
  removeFile temporary
  pure output

----------------------------------------------------------------------------
-- Delta formats: handle any size combination
----------------------------------------------------------------------------

prop_bps :: Property
prop_bps = forAll genPair $ \(source, target) ->
  let patch = BPS.createBPS source target ByteString.empty
  in case BPS.parseBPS patch of
       Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
       Right parsed -> BPS.applyBPS parsed source === Right target

prop_bpsMetadata :: Property
prop_bpsMetadata = forAll genPair $ \(source, target) ->
  forAll genByteString $ \meta ->
    let patch = BPS.createBPS source target meta
    in case BPS.parseBPS patch of
         Left slapError -> counterexample (renderSlapError slapError) $ property False
         Right parsed -> BPS.bpsMetadata parsed === meta

prop_ups :: Property
prop_ups = forAll genPair $ \(source, target) ->
  let patch = UPS.createUPS source target
  in case UPS.parseUPS patch of
       Left slapError -> counterexample (renderSlapError slapError) $ property False
       Right parsed -> UPS.applyUPS parsed source === Right target

prop_ips :: Property
prop_ips = forAll genPair $ \(source, target) ->
  case createFromMemory (CreateDirect CreateIPS) source target defaultMeta Nothing of
    Left slapError -> counterexample ("create: " ++ renderSlapError slapError) $ property False
    Right (CreateResult patch _) -> case IPS.parseIPS patch of
      Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
      Right parsed -> ioProperty $ do
        result <- applyViaFile IPS.applyIPS parsed source
        pure $ result === target

-- | Source and target that differ starting at exactly offset 0x454F46.
genEofPair :: Gen (ByteString, ByteString)
genEofPair = do
  let eofOffset = 0x454F46
  count <- choose (1, 100)
  diffBytes <- ByteString.pack <$> vectorOf count (choose (1, 255))
  let source = ByteString.replicate (eofOffset + count) 0
      target = ByteString.replicate eofOffset 0 <> diffBytes
  pure (source, target)

prop_ipsEofCollision :: Property
prop_ipsEofCollision = withNumTests 20 $ forAll genEofPair $ \(source, target) ->
  case createFromMemory (CreateDirect CreateIPS) source target defaultMeta Nothing of
    Left slapError -> counterexample ("create: " ++ renderSlapError slapError) $ property False
    Right (CreateResult patch _) -> case IPS.parseIPS patch of
      Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
      Right parsed -> ioProperty $ do
        result <- applyViaFile IPS.applyIPS parsed source
        pure $ result === target

prop_avoidSentinel :: Property
prop_avoidSentinel = property $
  let source = ByteString.pack [0, 1, 2, 3, 4, 5, 6, 7]
  in conjoin
    [ -- Record at sentinel is shifted back
      avoidSentinel 5 source [EncodedHunk (Offset 5) (ByteString.pack [0xFF])]
        === [EncodedHunk (Offset 4) (ByteString.pack [4, 0xFF])]
    , -- Record NOT at sentinel is unchanged
      avoidSentinel 5 source [EncodedHunk (Offset 3) (ByteString.pack [0xAA])]
        === [EncodedHunk (Offset 3) (ByteString.pack [0xAA])]
    , -- Source too short: no-op
      avoidSentinel 5 ByteString.empty [EncodedHunk (Offset 5) (ByteString.pack [0xFF])]
        === [EncodedHunk (Offset 5) (ByteString.pack [0xFF])]
    , -- Sentinel at offset 0: can't extend backward, no-op
      avoidSentinel 0 source [EncodedHunk (Offset 0) (ByteString.pack [0xFF])]
        === [EncodedHunk (Offset 0) (ByteString.pack [0xFF])]
    ]

-- | Split hunks at maxSize boundaries (same logic as Slap.Convert.splitHunks).
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

-- | DP patch size must not exceed greedy patch size for IPS (offWidth=3).
prop_dpNotLarger :: Property
prop_dpNotLarger = forAll genPair $ \(source, target) ->
  let dynamicProgrammingRecords     = optimalIPSRecords 3 source target
      greedyRecords = splitMax 0xFFFF (diffHunks source target)
      dynamicProgrammingSize     = ipsEncodedSize 3 dynamicProgrammingRecords
      greedySize = ipsEncodedSize 3 greedyRecords
  in counterexample ("DP: " ++ show dynamicProgrammingSize ++ ", greedy: " ++ show greedySize) $
     dynamicProgrammingSize <= greedySize

-- | DP patch size must not exceed greedy patch size for IPS32 (offWidth=4).
prop_dpIPS32NotLarger :: Property
prop_dpIPS32NotLarger = forAll genPair $ \(source, target) ->
  let dynamicProgrammingRecords     = optimalIPSRecords 4 source target
      greedyRecords = splitMax 0xFFFF (diffHunks source target)
      dynamicProgrammingSize     = ipsEncodedSize 4 dynamicProgrammingRecords
      greedySize = ipsEncodedSize 4 greedyRecords
  in counterexample ("DP: " ++ show dynamicProgrammingSize ++ ", greedy: " ++ show greedySize) $
     dynamicProgrammingSize <= greedySize

prop_gdiff :: Property
prop_gdiff = forAll genPair $ \(source, target) ->
  let patch = GDIFF.createGDIFF source target
  in case GDIFF.parseGDIFF patch of
       Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
       Right parsed -> GDIFF.applyGDIFF parsed source === target

prop_apsGba :: Property
prop_apsGba = forAll genPair $ \(source, target) ->
  let patch = APSGBA.createAPSGBA source target
  in case APSGBA.parseAPSGBA patch of
       Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
       Right parsed -> ioProperty $ do
         result <- applyViaFile APSGBA.applyAPSGBA parsed source
         pure $ result === target

----------------------------------------------------------------------------
-- Formats with truncation support (any size combination)
----------------------------------------------------------------------------

prop_ips32 :: Property
prop_ips32 = forAll genPair $ \(source, target) ->
  case createFromMemory (CreateDirect CreateIPS32) source target defaultMeta Nothing of
    Left slapError -> counterexample ("create: " ++ renderSlapError slapError) $ property False
    Right (CreateResult patch _) -> case IPS.parseIPS patch of
      Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
      Right parsed -> ioProperty $ do
        result <- applyViaFile IPS.applyIPS parsed source
        pure $ result === target

prop_ebp :: Property
prop_ebp = forAll genPair $ \(source, target) ->
  case createFromMemory (CreateDirect CreateEBP) source target defaultMeta Nothing of
    Left slapError -> counterexample ("create: " ++ renderSlapError slapError) $ property False
    Right (CreateResult patch _) -> case IPS.parseIPS patch of
      Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
      Right parsed -> ioProperty $ do
        result <- applyViaFile IPS.applyIPS parsed source
        pure $ result === target

-- Direct formats: no truncation, target must be >= source
prop_ppf3 :: Property
prop_ppf3 = forAll genPairNoShrink $ \(source, target) ->
  case createFromMemory (CreateDirect CreatePPF3) source target defaultMeta Nothing of
    Left slapError -> counterexample ("create: " ++ renderSlapError slapError) $ property False
    Right (CreateResult patch _) -> case PPF.parsePatch patch of
       Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
       Right parsed -> PPF.applyPatchMemory parsed source === target

prop_pmsr :: Property
prop_pmsr = forAll genPairNoShrink $ \(source, target) ->
  case createFromMemory (CreateDirect CreatePMSR) source target defaultMeta Nothing of
    Left slapError -> counterexample ("create: " ++ renderSlapError slapError) $ property False
    Right (CreateResult patch _) -> case PMSR.parsePMSR patch of
       Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
       Right parsed -> ioProperty $ do
         result <- applyViaFile PMSR.applyPMSR parsed source
         pure $ result === target

prop_ninja1 :: Property
prop_ninja1 = forAll genPairNoShrink $ \(source, target) ->
  case createFromMemory (CreateDirect CreateNINJA1) source target defaultMeta Nothing of
    Left slapError -> counterexample ("create: " ++ renderSlapError slapError) $ property False
    Right (CreateResult patch _) -> case NINJA1.parseNINJA1 patch of
       Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
       Right parsed -> ioProperty $ do
         result <- applyViaFile NINJA1.applyNINJA1 parsed source
         pure $ result === target

prop_ninja1Hashes :: Property
prop_ninja1Hashes = forAll genPairNoShrink $ \(source, _) ->
  not (ByteString.null source) ==>
  case createFromMemory (CreateDirect CreateNINJA1) source source defaultMeta Nothing of
    Left slapError -> counterexample ("create: " ++ renderSlapError slapError) $ property False
    Right (CreateResult patch _) -> case NINJA1.parseNINJA1 patch of
       Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
       Right parsed ->
         NINJA1.ninja1SourceCRC parsed === Just (rustyCRC32 source) .&&.
         NINJA1.ninja1SourceMD5 parsed === Just (md5 source) .&&.
         NINJA1.ninja1SourceSHA1 parsed === Just (sha1 source)

-- DPS: differential, no truncation
prop_dps :: Property
prop_dps = forAll genPairNoShrink $ \(source, target) ->
  let patch = resultBytes (DPS.createDPS source target "" "" "" DPS.DPSStable)
  in case DPS.parseDPS patch of
       Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
       Right parsed -> DPS.applyDPS parsed source === target

prop_rup :: Property
prop_rup = forAll genPair $ \(source, target) ->
  let patch = RUP.createRUP source target emptyRupInfo RUP.Ninja2Raw RUP.PatchEncodingUTF8
  in case RUP.parseRUP patch of
       Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
       Right parsed -> ioProperty $ do
         result <- applyViaFile RUP.applyRUP parsed source
         pure $ result === target

prop_rupHashes :: Property
prop_rupHashes = forAll genPair $ \(source, target) ->
  let patch = RUP.createRUP source target emptyRupInfo RUP.Ninja2Raw RUP.PatchEncodingUTF8
  in case RUP.parseRUP patch of
       Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
       Right parsed ->
         RUP.rupSourceMD5 parsed === Just (unMD5Hash (md5 source)) .&&.
         RUP.rupTargetMD5 parsed === Just (unMD5Hash (md5 target))

-- PCHTXT: pure direct, no truncation
prop_pchtxt :: Property
prop_pchtxt = forAll genPairNoShrink $ \(source, target) ->
  case createFromMemory (CreateDirect CreatePCHTXT) source target defaultMeta Nothing of
    Left slapError -> counterexample ("create: " ++ renderSlapError slapError) $ property False
    Right (CreateResult patch _) -> case PCHTXT.parsePCHTXT patch of
       Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
       Right parsed -> ioProperty $ do
         result <- applyViaFile PCHTXT.applyPCHTXT parsed source
         pure $ result === target

-- APS-N64: pure direct, no truncation
prop_apsN64 :: Property
prop_apsN64 = forAll genPairNoShrink $ \(source, target) ->
  case createFromMemory (CreateDirect CreateAPSN64) source target defaultMeta Nothing of
    Left slapError -> counterexample ("create: " ++ renderSlapError slapError) $ property False
    Right (CreateResult patch _) -> case APSN64.parseAPSN64 patch of
       Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
       Right parsed -> ioProperty $ do
         result <- applyViaFile APSN64.applyAPSN64 parsed source
         pure $ result === target

----------------------------------------------------------------------------
-- Identity: create(src, src) -> parse -> apply == src
----------------------------------------------------------------------------

allCreateFormats :: [(String, CreateFormat)]
allCreateFormats =
  [ ("BPS",     CreateDiff CreateBPS)
  , ("IPS",     CreateDirect CreateIPS)
  , ("IPS32",   CreateDirect CreateIPS32)
  , ("EBP",     CreateDirect CreateEBP)
  , ("UPS",     CreateDiff CreateUPS)
  , ("PPF3",    CreateDirect CreatePPF3)
  , ("PMSR",    CreateDirect CreatePMSR)
  , ("NINJA1",  CreateDirect CreateNINJA1)
  , ("DPS",     CreateDiff CreateDPS)
  , ("RUP",     CreateDiff CreateRUP)
  , ("APS-N64", CreateDirect CreateAPSN64)
  , ("APS-GBA", CreateDiff CreateAPSGBA)
  , ("GDIFF",   CreateDiff CreateGDIFF)
  , ("PCHTXT",  CreateDirect CreatePCHTXT)
  ]

-- | For any non-empty source, create(src, src) should be an identity patch.
prop_identity :: CreateFormat -> Property
prop_identity format = forAll genByteString $ \source -> not (ByteString.null source) ==>
  case createFromMemory format source source defaultMeta Nothing of
    Left _ -> discard
    Right (CreateResult patch _) -> case parseSome patch of
      Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
      Right parsed -> ioProperty $ do
        result <- applySomePatch parsed source
        pure $ case result of
          Left slapError -> counterexample ("apply: " ++ renderSlapError slapError) $ property False
          Right out -> out === source

-- | Apply through the SomePatch closure.
applySomePatch :: SomePatch -> ByteString -> IO (Either SlapError ByteString)
applySomePatch somePatch source = inMemoryApply (patchApply somePatch) source

----------------------------------------------------------------------------
-- Undo: create -> apply -> undo == original
----------------------------------------------------------------------------

-- | UPS XOR is symmetric: applying the same patch to the target yields
-- the source.  Only holds for same-size inputs (different sizes lose
-- information in the size field).
prop_upsUndo :: Property
prop_upsUndo = forAll genSameSizePair $ \(source, target) ->
  let patch = UPS.createUPS source target
  in case UPS.parseUPS patch of
       Left slapError -> counterexample (renderSlapError slapError) $ property False
       Right parsed -> (UPS.applyUPS parsed source >>= UPS.applyUPS parsed) === Right source

-- | PPF3 with undo data: apply then undo recovers the original.
-- Same-size pairs only — PPF3 undo writes back original bytes but can't
-- truncate the file, so growth is irreversible.
prop_ppf3Undo :: Property
prop_ppf3Undo = forAll genSameSizePair $ \(source, target) -> not (ByteString.null source) ==>
  case createFromMemory (CreateDirect CreatePPF3) source target (defaultMeta { metaUndo = Just True }) Nothing of
    Left _ -> discard
    Right (CreateResult patch _) -> case PPF.parsePatch patch of
      Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
      Right parsed ->
        let applied = PPF.applyPatchMemory parsed source
        in PPF.undoPatchMemory parsed applied === source

----------------------------------------------------------------------------
-- Contract properties
----------------------------------------------------------------------------

-- | Direct formats that go through buildContents -> encodeDirect.
directFormats :: [DirectCreate]
directFormats =
  [CreateIPS, CreateIPS32, CreateEBP, CreatePPF3, CreateNINJA1, CreatePMSR, CreatePCHTXT, CreateAPSN64]

-- | PatchContents with every field populated.
fullContents :: PatchContents
fullContents = PatchContents
  { contentsRecords     = [Hunk (Offset 0) (ByteString.pack [0xFF])]
  , contentsDescription = Just (ByteString.pack [0x74, 0x65, 0x73, 0x74])
  , contentsSourceCRC32 = Just (CRC32 0xDEADBEEF)
  , contentsSourceMD5   = Just (MD5Hash (ByteString.replicate 16 0xAA))
  , contentsSourceSHA1  = Just (SHA1Hash (ByteString.replicate 20 0xBB))
  , contentsDestinationSize    = Just (FileSize 1024)
  , contentsValidation  = Just (ByteString.replicate 1024 0)
  , contentsUndoData    = Just [UndoHunk (Offset 0) (ByteString.pack [0x00]) (ByteString.pack [0xFF])]
  , contentsTruncation  = Just (FileSize 512)
  , contentsEBPMeta     = Just (ByteString.pack [0x7B, 0x7D])
  , contentsRomType     = Just PlatformRaw
  , contentsImageType   = Nothing
  , contentsFileIdDiz   = Nothing
  , contentsPCHTXTBlocks = Nothing
  , contentsNINJA1Compressed = Nothing
  , contentsMetadata = Nothing
  , contentsPatchEncoding = Nothing
  }

-- | canConvert succeeds for every direct format when all fields are present.
prop_canConvertFull :: Property
prop_canConvertFull = conjoin
  [ counterexample (show format) $
      canConvert fullContents (formatSpecification format True True) === Right ()
  | format <- directFormats
  ]

-- | No dropped-field notes when provides exactly matches required + accepted.
prop_noSurplusNoNotes :: Property
prop_noSurplusNoNotes = conjoin
  [ counterexample (show format) $
      let spec = formatSpecification format True True
          kept = specificationRequired spec `Set.union` specificationAccepted spec
          trimmed = fullContents
            { contentsDescription = if FDescription `Set.member` kept then contentsDescription fullContents else Nothing
            , contentsSourceCRC32 = if FSourceCRC32 `Set.member` kept then contentsSourceCRC32 fullContents else Nothing
            , contentsSourceMD5   = if FSourceMD5   `Set.member` kept then contentsSourceMD5   fullContents else Nothing
            , contentsSourceSHA1  = if FSourceSHA1  `Set.member` kept then contentsSourceSHA1  fullContents else Nothing
            , contentsDestinationSize    = if FDestinationSize    `Set.member` kept then contentsDestinationSize    fullContents else Nothing
            , contentsValidation  = if FValidation  `Set.member` kept then contentsValidation  fullContents else Nothing
            , contentsUndoData    = if FUndoData    `Set.member` kept then contentsUndoData    fullContents else Nothing
            , contentsTruncation  = if FTruncation  `Set.member` kept then contentsTruncation  fullContents else Nothing
            , contentsEBPMeta     = if FEBPMeta     `Set.member` kept then contentsEBPMeta     fullContents else Nothing
            , contentsRomType     = if FRomType     `Set.member` kept then contentsRomType     fullContents else Nothing
            , contentsImageType   = if FImageType   `Set.member` kept then contentsImageType   fullContents else Nothing
            }
          -- filter to only dropped-field notes; interop notes are tested separately
          droppedNotes = filter ("note: dropping" `isPrefixOf`) (map renderSlapWarning (conversionNotes trimmed format spec defaultMeta))
      in droppedNotes === []
  | format <- directFormats
  ]

-- | NINJA1 no longer requires hashes (spec allows zero) -- empty contents must succeed.
prop_ninja1AcceptsEmpty :: Property
prop_ninja1AcceptsEmpty =
  property $ isRight (canConvert (emptyContents []) (formatSpecification CreateNINJA1 False False))

-- | APS-N64 requires dest size -- empty contents must fail.
prop_apsn64RejectsEmpty :: Property
prop_apsn64RejectsEmpty =
  property $ isLeft (canConvert (emptyContents []) (formatSpecification CreateAPSN64 False False))

-- | PPF3 with undo requires undo data -- empty contents must fail.
prop_ppf3UndoRejectsEmpty :: Property
prop_ppf3UndoRejectsEmpty =
  property $ isLeft (canConvert (emptyContents []) (formatSpecification CreatePPF3 True False))

-- | PPF3 with validation requires validation block -- empty contents must fail.
prop_ppf3ValidateRejectsEmpty :: Property
prop_ppf3ValidateRejectsEmpty =
  property $ isLeft (canConvert (emptyContents []) (formatSpecification CreatePPF3 False True))

-- | Direct conversion to IPS must reject a record at the EOF sentinel offset.
prop_ipsSentinelDirect :: Property
prop_ipsSentinelDirect =
  let patchContent = emptyContents [Hunk (Offset 0x454F46) (ByteString.pack [0xFF])]
  in property $ case convertDirect patchContent (CreateDirect CreateIPS) defaultMeta of
       Left slapError -> "collides with sentinel" `isInfixOf` renderSlapError slapError
       Right _  -> False

-- | Direct conversion to IPS32 must reject a record at the EEOF sentinel offset.
prop_ips32SentinelDirect :: Property
prop_ips32SentinelDirect =
  let patchContent = emptyContents [Hunk (Offset 0x45454F46) (ByteString.pack [0xFF])]
  in property $ case convertDirect patchContent (CreateDirect CreateIPS32) defaultMeta of
       Left slapError -> "collides with sentinel" `isInfixOf` renderSlapError slapError
       Right _  -> False

-- | A hunk that doesn't start at the sentinel but produces a split fragment
-- at the sentinel offset must be rejected.  Splitting at 0xFFFF turns a hunk
-- at 0x444F47 into chunks at 0x444F47 and 0x454F46 (the EOF sentinel).
prop_ipsSentinelSplitDirect :: Property
prop_ipsSentinelSplitDirect =
  let startOffset = 0x454F46 - 0xFFFF  -- 0x444F47: split fragment lands on sentinel
      payload = ByteString.replicate 0x10000 0xFF  -- > 0xFFFF, forces split
      patchContent = emptyContents [Hunk (Offset startOffset) payload]
  in property $ case convertDirect patchContent (CreateDirect CreateIPS) defaultMeta of
       Left slapError -> "collides with sentinel" `isInfixOf` renderSlapError slapError
       Right _  -> False

-- | Same as above for IPS32: split fragment at EEOF sentinel 0x45454F46.
prop_ips32SentinelSplitDirect :: Property
prop_ips32SentinelSplitDirect =
  let startOffset = 0x45454F46 - 0xFFFF
      payload = ByteString.replicate 0x10000 0xFF
      patchContent = emptyContents [Hunk (Offset startOffset) payload]
  in property $ case convertDirect patchContent (CreateDirect CreateIPS32) defaultMeta of
       Left slapError -> "collides with sentinel" `isInfixOf` renderSlapError slapError
       Right _  -> False

-- | Create path (with source bytes) must handle the sentinel offset correctly.
prop_ipsSentinelWithSource :: Property
prop_ipsSentinelWithSource =
  let eofOffset = 0x454F46
      source = ByteString.replicate (eofOffset + 1) 0
      target = ByteString.replicate eofOffset 0 <> ByteString.pack [0xFF]
  in case createFromMemory (CreateDirect CreateIPS) source target defaultMeta Nothing of
       Left slapError -> counterexample ("create should succeed: " ++ renderSlapError slapError) $ property False
       Right (CreateResult patch _) -> case IPS.parseIPS patch of
         Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
         Right parsed -> ioProperty $ do
           result <- applyViaFile IPS.applyIPS parsed source
           pure $ result === target

isLeft :: Either a b -> Bool
isLeft (Left _) = True
isLeft _        = False

isRight :: Either a b -> Bool
isRight (Right _) = True
isRight _         = False

----------------------------------------------------------------------------
-- Parse-truncated: truncate valid patches to random lengths, verify no crash
----------------------------------------------------------------------------

-- | Truncate a patch to a random length and verify parse returns Left or Right
-- (never crashes).  Parsers with StrictData build results eagerly, so
-- evaluating the Either constructor is sufficient to trigger any index errors.
truncated :: (ByteString -> Either SlapError a) -> ByteString -> Property
truncated parseFunction patch =
  forAll (choose (0, ByteString.length patch - 1)) $ \truncationLength ->
    case parseFunction (ByteString.take truncationLength patch) of
      Left _  -> property True
      Right _ -> property True

prop_bpsTrunc :: Property
prop_bpsTrunc = forAll genPair $ \(source, target) ->
  truncated BPS.parseBPS (BPS.createBPS source target ByteString.empty)

-- | Block move: 4 KB of data moves from offset 0x1000 to offset 0x8000.
-- The rolling-hash diff should emit SourceCopy, producing a small patch
-- rather than 4 KB of literal bytes.
prop_bpsBlockMove :: Property
prop_bpsBlockMove = once $
  let blockSize = 4096
      -- Distinctive block content that won't match surrounding zeros
      block = ByteString.pack [fromIntegral ((index * 7 + 3) `mod` 251) | index <- [0..blockSize-1] :: [Int]]
      padding1  = 0x1000
      padding2  = 0x8000
      sourceLength = padding2 + blockSize
      source = ByteString.replicate padding1 0 <> block <> ByteString.replicate (sourceLength - padding1 - blockSize) 0
      target = ByteString.replicate padding2 0 <> block
      patch  = BPS.createBPS source target ByteString.empty
  in counterexample ("patch size: " ++ show (ByteString.length patch)
                      ++ " (block: " ++ show blockSize ++ ")") $
     conjoin
       [ case BPS.parseBPS patch of
           Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
           Right parsed -> BPS.applyBPS parsed source === Right target
       , property (ByteString.length patch < 1024)
       ]

-- | Patch size should not regress: a random diff with the rolling-hash
-- algorithm must produce patches no larger than a pure-literal encoding
-- (TargetRead for every byte), which costs targetLen + small overhead.
prop_bpsNoSizeRegression :: Property
prop_bpsNoSizeRegression = forAll genPair $ \(source, target) ->
  let patch = BPS.createBPS source target ByteString.empty
      -- Worst case: entire target as TargetRead + BPS header/footer
      maxPatchSize = ByteString.length target + 100
  in counterexample ("patch size: " ++ show (ByteString.length patch)
                      ++ ", max: " ++ show maxPatchSize) $
     ByteString.length patch <= maxPatchSize

----------------------------------------------------------------------------
-- classifyTargetCopy properties
----------------------------------------------------------------------------

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

prop_ipsTrunc :: Property
prop_ipsTrunc = forAll genPair $ \(source, target) ->
  case createFromMemory (CreateDirect CreateIPS) source target defaultMeta Nothing of
    Left _ -> discard
    Right (CreateResult patch _) -> truncated IPS.parseIPS patch

prop_ips32Trunc :: Property
prop_ips32Trunc = forAll genPair $ \(source, target) ->
  case createFromMemory (CreateDirect CreateIPS32) source target defaultMeta Nothing of
    Left _ -> discard
    Right (CreateResult patch _) -> truncated IPS.parseIPS patch

prop_ebpTrunc :: Property
prop_ebpTrunc = forAll genPair $ \(source, target) ->
  case createFromMemory (CreateDirect CreateEBP) source target defaultMeta Nothing of
    Left _ -> discard
    Right (CreateResult patch _) -> truncated IPS.parseIPS patch

-- | EBP JSON metadata must round-trip non-ASCII characters through UTF-8.
test_ebpUtf8 :: IO ()
test_ebpUtf8 = do
  let json = ebpJson "Pokémon" "André" "Ünïcödé ™"
      pairs = jsonPairs json
  assertEqual "title" (Just "Pokémon") (jsonFieldCI pairs "title")
  assertEqual "author" (Just "André") (jsonFieldCI pairs "author")
  assertEqual "description" (Just "Ünïcödé ™") (jsonFieldCI pairs "description")

prop_upsTrunc :: Property
prop_upsTrunc = forAll genPair $ \(source, target) ->
  truncated UPS.parseUPS (UPS.createUPS source target)

prop_ppf3Trunc :: Property
prop_ppf3Trunc = forAll genPairNoShrink $ \(source, target) ->
  case createFromMemory (CreateDirect CreatePPF3) source target defaultMeta Nothing of
    Left _ -> discard
    Right (CreateResult patch _) -> truncated PPF.parsePatch patch

prop_pmsrTrunc :: Property
prop_pmsrTrunc = forAll genPairNoShrink $ \(source, target) ->
  case createFromMemory (CreateDirect CreatePMSR) source target defaultMeta Nothing of
    Left _ -> discard
    Right (CreateResult patch _) -> truncated PMSR.parsePMSR patch

prop_ninja1Trunc :: Property
prop_ninja1Trunc = forAll genPairNoShrink $ \(source, target) ->
  case createFromMemory (CreateDirect CreateNINJA1) source target defaultMeta Nothing of
    Left _ -> discard
    Right (CreateResult patch _) -> truncated NINJA1.parseNINJA1 patch

prop_dpsTrunc :: Property
prop_dpsTrunc = forAll genPairNoShrink $ \(source, target) ->
  truncated DPS.parseDPS (resultBytes (DPS.createDPS source target "" "" "" DPS.DPSStable))

prop_rupTrunc :: Property
prop_rupTrunc = forAll genPair $ \(source, target) ->
  truncated RUP.parseRUP (RUP.createRUP source target emptyRupInfo RUP.Ninja2Raw RUP.PatchEncodingUTF8)

-- RUP encoding tests

-- Round-trip with ASCII metadata using UTF-8 encoding
prop_rupUTF8RoundTrip :: Property
prop_rupUTF8RoundTrip = forAll genPair $ \(source, target) ->
  let info = emptyRupInfo { RUP.rupTitle = Just (RUP.encodeRUPString RUP.PatchEncodingUTF8 "Test Patch")
                          , RUP.rupAuthor = Just (RUP.encodeRUPString RUP.PatchEncodingUTF8 "slap") }
  in let patch = RUP.createRUP source target info RUP.Ninja2Raw RUP.PatchEncodingUTF8
     in case RUP.parseRUP patch of
      Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
      Right parsed ->
        fmap (RUP.decodeRUPField RUP.PatchEncodingUTF8) (RUP.rupTitle (RUP.rupHeader parsed)) === Just "Test Patch" .&&.
        fmap (RUP.decodeRUPField RUP.PatchEncodingUTF8) (RUP.rupAuthor (RUP.rupHeader parsed)) === Just "slap"

-- Round-trip with ASCII metadata using system encoding
prop_rupSystemRoundTrip :: Property
prop_rupSystemRoundTrip = forAll genPair $ \(source, target) ->
  let info = emptyRupInfo { RUP.rupTitle = Just (RUP.encodeRUPString RUP.PatchEncodingSystem "Test Patch")
                          , RUP.rupAuthor = Just (RUP.encodeRUPString RUP.PatchEncodingSystem "slap") }
      patch = RUP.createRUP source target info RUP.Ninja2Raw RUP.PatchEncodingSystem
  in case RUP.parseRUP patch of
      Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
      Right parsed ->
        fmap (RUP.decodeRUPField RUP.PatchEncodingSystem) (RUP.rupTitle (RUP.rupHeader parsed)) === Just "Test Patch" .&&.
        fmap (RUP.decodeRUPField RUP.PatchEncodingSystem) (RUP.rupAuthor (RUP.rupHeader parsed)) === Just "slap"

-- Non-ASCII Latin-1 characters (accented) round-trip through UTF-8
prop_rupNonAsciiUTF8 :: Property
prop_rupNonAsciiUTF8 = forAll genPair $ \(source, target) ->
  let titleStr = "Pok\233mon \241" -- "Pokémon ñ"
      info = emptyRupInfo { RUP.rupTitle = Just (RUP.encodeRUPString RUP.PatchEncodingUTF8 titleStr) }
  in let patch = RUP.createRUP source target info RUP.Ninja2Raw RUP.PatchEncodingUTF8
     in case RUP.parseRUP patch of
      Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
      Right parsed ->
        fmap (RUP.decodeRUPField RUP.PatchEncodingUTF8) (RUP.rupTitle (RUP.rupHeader parsed)) === Just titleStr

-- Truncation: title whose UTF-8 encoding exceeds 256 bytes is silently truncated
prop_rupFieldOverflow :: Property
prop_rupFieldOverflow = once $
  let longTitle = replicate 128 '\233' ++ "X" -- 128 × 2-byte 'é' + 1 ASCII = 257 UTF-8 bytes > 256
      encodedTitle = RUP.encodeRUPString RUP.PatchEncodingUTF8 longTitle
      info = emptyRupInfo { RUP.rupTitle = Just encodedTitle }
      source = ByteString.pack [0]
      target = ByteString.pack [1]
      patch = RUP.createRUP source target info RUP.Ninja2Raw RUP.PatchEncodingUTF8
  in case RUP.parseRUP patch of
      Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
      Right parsed ->
        let titleBytes = fromMaybe ByteString.empty (RUP.rupTitle (RUP.rupHeader parsed))
        in counterexample ("title length: " ++ show (ByteString.length titleBytes)) $
           ByteString.length titleBytes <= 256 .&&.
           ByteString.isPrefixOf titleBytes encodedTitle .&&.
           isValidUtf8 titleBytes

-- PATCH_ENC byte is 1 for UTF-8
prop_rupPatchEncByteUTF8 :: Property
prop_rupPatchEncByteUTF8 = forAll genPair $ \(source, target) ->
  let patch = RUP.createRUP source target emptyRupInfo RUP.Ninja2Raw RUP.PatchEncodingUTF8
  in case RUP.parseRUP patch of
      Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
      Right parsed -> RUP.rupPatchEncoding parsed === RUP.PatchEncodingUTF8

-- PATCH_ENC byte is 0 for system encoding
prop_rupPatchEncByteSystem :: Property
prop_rupPatchEncByteSystem = forAll genPair $ \(source, target) ->
  let patch = RUP.createRUP source target emptyRupInfo RUP.Ninja2Raw RUP.PatchEncodingSystem
  in case RUP.parseRUP patch of
      Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
      Right parsed -> RUP.rupPatchEncoding parsed === RUP.PatchEncodingSystem

-- Read path: PATCH_ENC=1 patch decodes non-ASCII content correctly
prop_rupUTF8Decode :: Property
prop_rupUTF8Decode = forAll genPair $ \(source, target) ->
  let titleStr = "\1055\1072\1090\1095" -- "Патч" (Cyrillic)
      info = emptyRupInfo { RUP.rupTitle = Just (RUP.encodeRUPString RUP.PatchEncodingUTF8 titleStr) }
  in let patch = RUP.createRUP source target info RUP.Ninja2Raw RUP.PatchEncodingUTF8
     in case RUP.parseRUP patch of
      Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
      Right parsed ->
        fmap (RUP.decodeRUPField RUP.PatchEncodingUTF8) (RUP.rupTitle (RUP.rupHeader parsed)) === Just titleStr

prop_apsN64Trunc :: Property
prop_apsN64Trunc = forAll genPairNoShrink $ \(source, target) ->
  case createFromMemory (CreateDirect CreateAPSN64) source target defaultMeta Nothing of
    Left _ -> discard
    Right (CreateResult patch _) -> truncated APSN64.parseAPSN64 patch

prop_apsGbaTrunc :: Property
prop_apsGbaTrunc = forAll genPair $ \(source, target) ->
  truncated APSGBA.parseAPSGBA (APSGBA.createAPSGBA source target)

prop_gdiffTrunc :: Property
prop_gdiffTrunc = forAll genPair $ \(source, target) ->
  truncated GDIFF.parseGDIFF (GDIFF.createGDIFF source target)

prop_pchtxtTrunc :: Property
prop_pchtxtTrunc = forAll genPairNoShrink $ \(source, target) ->
  case createFromMemory (CreateDirect CreatePCHTXT) source target defaultMeta Nothing of
    Left _ -> discard
    Right (CreateResult patch _) -> truncated PCHTXT.parsePCHTXT patch

-- | Parse escapes.pchtxt: exercises quoted string escapes (\n, \t, \\, \").
parsePchtxtEscapes :: IO ()
parsePchtxtEscapes = do
  raw <- ByteString.readFile "test/data/pchtxt/escapes.pchtxt"
  case PCHTXT.parsePCHTXT raw of
    Left slapError -> assertBool ("parse failed: " ++ renderSlapError slapError) False
    Right parsed -> assertBool "expected 2 entries"
      (length (concatMap PCHTXT.pchtxtBlockEntries (PCHTXT.pchtxtBlocks parsed)) == 2)

-- | Parse sphinx.pchtxt: exercises @nsobid, @flag offset_shift, @disabled, @stop.
parsePchtxtSphinx :: IO ()
parsePchtxtSphinx = do
  raw <- ByteString.readFile "test/data/pchtxt/sphinx.pchtxt"
  case PCHTXT.parsePCHTXT raw of
    Left slapError -> assertBool ("parse failed: " ++ renderSlapError slapError) False
    Right parsed -> do
      assertBool "expected nsobid" (PCHTXT.pchtxtNsobid parsed /= Nothing)
      case PCHTXT.pchtxtBlocks parsed of
        [block] -> assertBool "block should be disabled" (not (PCHTXT.pchtxtBlockEnabled block))
        blocks  -> assertBool ("expected 1 block, got " ++ show (length blocks)) False

----------------------------------------------------------------------------
-- Consume-only formats: truncation on real test data
----------------------------------------------------------------------------

-- | Truncate a real patch file from disk to random lengths.
-- These formats have no create function; use known-good patches instead.
truncatedFile :: (ByteString -> Either SlapError a) -> FilePath -> Property
truncatedFile parseFunction path = ioProperty $ do
  patchBytes <- ByteString.readFile path
  pure $ forAll (choose (0, ByteString.length patchBytes - 1)) $ \truncationLength ->
    case parseFunction (ByteString.take truncationLength patchBytes) of
      Left _  -> property True
      Right _ -> property True

prop_vcdiffTrunc :: Property
prop_vcdiffTrunc = truncatedFile VCDIFF.parseVCDIFF "test/data/dm4y/patch.vcdiff"

prop_bsdiffTrunc :: Property
prop_bsdiffTrunc = truncatedFile BSDiff.parseBSDiff "test/data/dm4y/patch.bsdiff"

prop_xdelta1Trunc :: Property
prop_xdelta1Trunc = truncatedFile XDelta1.parseXDelta1 "test/data/dm4y/patch.xdelta1"

----------------------------------------------------------------------------
-- TextEncoding
----------------------------------------------------------------------------

-- truncateUtf8 properties

prop_truncateNeverExceedsBudget :: Property
prop_truncateNeverExceedsBudget =
  forAll arbitrary $ \inputString ->
    forAll (chooseInt (0, 256)) $ \budget ->
      let encoded = Text.encodeUtf8 (Text.pack inputString)
          truncatedBytes = truncateUtf8 budget encoded
      in ByteString.length truncatedBytes <= budget

prop_truncateOutputIsValidUtf8 :: Property
prop_truncateOutputIsValidUtf8 =
  forAll arbitrary $ \inputString ->
    forAll (chooseInt (0, 256)) $ \budget ->
      let encoded = Text.encodeUtf8 (Text.pack inputString)
          truncatedBytes = truncateUtf8 budget encoded
      in isValidUtf8 truncatedBytes

prop_truncateOutputIsPrefixOfInput :: Property
prop_truncateOutputIsPrefixOfInput =
  forAll arbitrary $ \inputString ->
    forAll (chooseInt (0, 256)) $ \budget ->
      let encoded = Text.encodeUtf8 (Text.pack inputString)
          truncatedBytes = truncateUtf8 budget encoded
      in truncatedBytes `ByteString.isPrefixOf` encoded

prop_truncateIdentityWhenSufficient :: Property
prop_truncateIdentityWhenSufficient =
  forAll arbitrary $ \inputString ->
    let encoded = Text.encodeUtf8 (Text.pack inputString)
        budget = ByteString.length encoded
    in truncateUtf8 budget encoded === encoded

-- truncateUtf8 unit cases

test_truncateCafe :: IO ()
test_truncateCafe = do
  let cafeBytes = encodeUtf8Field "café"  -- 63 61 66 C3 A9 = 5 bytes
  assertEqual "budget 5 fits exactly" cafeBytes (truncateUtf8 5 cafeBytes)
  assertEqual "budget 4 drops é"      (encodeUtf8Field "caf") (truncateUtf8 4 cafeBytes)
  assertEqual "budget 3 gives caf"    (encodeUtf8Field "caf") (truncateUtf8 3 cafeBytes)

test_truncateEmoji :: IO ()
test_truncateEmoji = do
  let gamepadBytes = encodeUtf8Field "🎮"   -- F0 9F 8E AE = 4 bytes
      prefixedBytes = encodeUtf8Field "a🎮" -- 61 F0 9F 8E AE = 5 bytes
  assertEqual "budget 3 → empty"       ByteString.empty (truncateUtf8 3 gamepadBytes)
  assertEqual "budget 4 → 🎮"          gamepadBytes (truncateUtf8 4 gamepadBytes)
  assertEqual "a🎮 budget 4 → a"       (encodeUtf8Field "a") (truncateUtf8 4 prefixedBytes)
  assertEqual "a🎮 budget 5 → a🎮"     prefixedBytes (truncateUtf8 5 prefixedBytes)

test_truncateEmpty :: IO ()
test_truncateEmpty =
  assertEqual "empty at any budget" ByteString.empty (truncateUtf8 10 ByteString.empty)

test_truncateAdversarial :: IO ()
test_truncateAdversarial = do
  let allContinuations = ByteString.pack [0x80, 0x80, 0x80]
      result = truncateUtf8 2 allContinuations
  assertBool "output is valid UTF-8" (isValidUtf8 result)
  assertBool "output length <= 2"    (ByteString.length result <= 2)

-- encodeBoundedUtf8 properties

prop_boundedUtf8ExactWidth :: Property
prop_boundedUtf8ExactWidth =
  forAll (chooseInt (1, 128)) $ \fieldWidth ->
    forAll (listOf arbitraryASCIIChar) $ \inputString ->
      let result = encodeBoundedUtf8 fieldWidth inputString
      in ByteString.length (boundedField result) === fieldWidth

prop_boundedUtf8TruncationIff :: Property
prop_boundedUtf8TruncationIff =
  forAll (chooseInt (1, 128)) $ \fieldWidth ->
    forAll arbitrary $ \inputString ->
      let result = encodeBoundedUtf8 fieldWidth inputString
          encodedLength = ByteString.length (encodeUtf8Field inputString)
      in isJust (boundedTruncation result) === (encodedLength > fieldWidth)

-- encodeBoundedLocale property

prop_boundedLocaleExactWidth :: Property
prop_boundedLocaleExactWidth =
  forAll (chooseInt (1, 128)) $ \fieldWidth ->
    forAll (listOf arbitraryASCIIChar) $ \inputString ->
      let result = encodeBoundedLocale fieldWidth inputString
      in ByteString.length (boundedField result) === fieldWidth

-- truncateLocale unit case

test_truncateLocaleByteLevel :: IO ()
test_truncateLocaleByteLevel = do
  let localeEncoded = encodeLocaleField "é"
      truncatedOneByte = truncateLocale 1 localeEncoded
  assertEqual "truncateLocale is byte-level" 1 (ByteString.length truncatedOneByte)

-- isValidUtf8 unit cases

test_isValidUtf8Ascii :: IO ()
test_isValidUtf8Ascii =
  assertBool "valid ASCII" (isValidUtf8 (encodeUtf8Field "hello"))

test_isValidUtf8Multibyte :: IO ()
test_isValidUtf8Multibyte =
  assertBool "valid multibyte" (isValidUtf8 (encodeUtf8Field "André"))

test_isValidUtf8Truncated :: IO ()
test_isValidUtf8Truncated =
  assertBool "truncated multibyte is invalid"
    (not (isValidUtf8 (ByteString.take 1 (encodeUtf8Field "é"))))

test_isValidUtf8Empty :: IO ()
test_isValidUtf8Empty =
  assertBool "empty is valid" (isValidUtf8 ByteString.empty)

test_isValidUtf8BareContinuation :: IO ()
test_isValidUtf8BareContinuation =
  assertBool "bare continuation is invalid"
    (not (isValidUtf8 (ByteString.pack [0x80])))

-- Round-trip properties

prop_utf8RoundTrip :: Property
prop_utf8RoundTrip =
  forAll arbitrary $ \inputString ->
    decodeUtf8Field (encodeUtf8Field inputString) === inputString

prop_localeRoundTripAscii :: Property
prop_localeRoundTripAscii =
  forAll (listOf (choose ('\x20', '\x7E'))) $ \inputString ->
    decodeLocaleField (encodeLocaleField inputString) === inputString

----------------------------------------------------------------------------
-- Encoding: format create round-trip tests
----------------------------------------------------------------------------

-- PPF3 create → parse → decode with non-ASCII description
test_ppf3NonAsciiRoundTrip :: IO ()
test_ppf3NonAsciiRoundTrip = do
  let description = "Pokémon André"
      CreateResult patchBytes _ = PPF.encodePPF3 [] description Nothing Nothing PPF.BIN
  case PPF.parsePatch patchBytes of
    Left slapError -> assertBool ("parse: " ++ renderSlapError slapError) False
    Right parsed ->
      let decoded = decodeLocaleField (trimNull (PPF.ppfDescription parsed))
      in assertEqual "description round-trip" description decoded

-- PPF3 create with overlong description produces FieldTruncated warning
test_ppf3OverflowWarning :: IO ()
test_ppf3OverflowWarning = do
  let longDescription = replicate 60 'A'
      CreateResult patchBytes warnings = PPF.encodePPF3 [] longDescription Nothing Nothing PPF.BIN
      hasFieldTruncated = any (isFieldTruncatedFor LabelPPF3) warnings
  assertBool "expected FieldTruncated warning" hasFieldTruncated
  case PPF.parsePatch patchBytes of
    Left slapError -> assertBool ("parse: " ++ renderSlapError slapError) False
    Right parsed ->
      assertBool "description at most 50 bytes"
        (ByteString.length (PPF.ppfDescription parsed) <= PPF.ppfDescriptionWidth)

-- PPF3 create with empty description: no warnings, empty after trimming
test_ppf3EmptyDescription :: IO ()
test_ppf3EmptyDescription = do
  let CreateResult patchBytes warnings = PPF.encodePPF3 [] "" Nothing Nothing PPF.BIN
  assertBool "no FieldTruncated warning" (not (any (isFieldTruncatedFor LabelPPF3) warnings))
  case PPF.parsePatch patchBytes of
    Left slapError -> assertBool ("parse: " ++ renderSlapError slapError) False
    Right parsed ->
      assertEqual "empty description" "" (decodeLocaleField (trimNull (PPF.ppfDescription parsed)))

-- DPS create → parse → decode with non-ASCII metadata fields
test_dpsNonAsciiRoundTrip :: IO ()
test_dpsNonAsciiRoundTrip = do
  let source = ByteString.pack [0]
      target = ByteString.pack [1]
      CreateResult patchBytes _ = DPS.createDPS source target "Pokémon" "André" "1.0" DPS.DPSStable
  case DPS.parseDPS patchBytes of
    Left slapError -> assertBool ("parse: " ++ renderSlapError slapError) False
    Right parsed -> do
      assertEqual "name"    "Pokémon" (decodeLocaleField (DPS.dpsName parsed))
      assertEqual "author"  "André"   (decodeLocaleField (DPS.dpsAuthor parsed))
      assertEqual "version" "1.0"     (decodeLocaleField (DPS.dpsVersion parsed))

-- DPS create with one overflowing field: exactly one FieldTruncated warning for name
test_dpsOverflowPerField :: IO ()
test_dpsOverflowPerField = do
  let source = ByteString.pack [0]
      target = ByteString.pack [1]
      longName = replicate 80 'A'
      CreateResult patchBytes warnings = DPS.createDPS source target longName "ok" "1.0" DPS.DPSStable
      truncatedWarnings = filter (isFieldTruncatedFor LabelDPS) warnings
  assertEqual "exactly one FieldTruncated" 1 (length truncatedWarnings)
  assertBool "truncated field is name"
    (all (\warning -> case warning of FieldTruncated _ FieldPatchName _ _ -> True; _ -> False) truncatedWarnings)
  case DPS.parseDPS patchBytes of
    Left slapError -> assertBool ("parse: " ++ renderSlapError slapError) False
    Right parsed -> do
      assertBool "name at most 64 bytes" (ByteString.length (DPS.dpsName parsed) <= DPS.dpsFieldWidth)
      assertEqual "author intact"  "ok"  (decodeLocaleField (DPS.dpsAuthor parsed))
      assertEqual "version intact" "1.0" (decodeLocaleField (DPS.dpsVersion parsed))

-- DPS create with all three fields overflowing
test_dpsAllFieldsOverflow :: IO ()
test_dpsAllFieldsOverflow = do
  let source = ByteString.pack [0]
      target = ByteString.pack [1]
      longField = replicate 80 'A'
      CreateResult _ warnings = DPS.createDPS source target longField longField longField DPS.DPSStable
      truncatedWarnings = filter (isFieldTruncatedFor LabelDPS) warnings
  assertEqual "exactly three FieldTruncated" 3 (length truncatedWarnings)

-- APS-N64 create → parse → decode with non-ASCII description
test_apsN64NonAsciiRoundTrip :: IO ()
test_apsN64NonAsciiRoundTrip = do
  let description = "Pokémon"
      CreateResult patchBytes _ = APSN64.encodeAPSN64 [] 256 description
  case APSN64.parseAPSN64 patchBytes of
    Left slapError -> assertBool ("parse: " ++ renderSlapError slapError) False
    Right (APSN64.APSN64Patch header _) ->
      assertEqual "description round-trip" description
        (decodeLocaleField (trimNull (APSN64.apsN64Description header)))

-- APS-N64 create with overlong description produces FieldTruncated warning
test_apsN64OverflowWarning :: IO ()
test_apsN64OverflowWarning = do
  let longDescription = replicate 60 'A'
      CreateResult _ warnings = APSN64.encodeAPSN64 [] 256 longDescription
      hasFieldTruncated = any (isFieldTruncatedFor LabelAPSN64) warnings
  assertBool "expected FieldTruncated warning" hasFieldTruncated

-- RUP create with PatchEncodingSystem and non-ASCII title
test_rupNonAsciiSystem :: IO ()
test_rupNonAsciiSystem = do
  let source = ByteString.pack [0]
      target = ByteString.pack [1]
      titleString = "Pokémon"
      info = emptyRupInfo { RUP.rupTitle = Just (RUP.encodeRUPString RUP.PatchEncodingSystem titleString) }
      patch = RUP.createRUP source target info RUP.Ninja2Raw RUP.PatchEncodingSystem
  case RUP.parseRUP patch of
    Left slapError -> assertBool ("parse: " ++ renderSlapError slapError) False
    Right parsed ->
      assertEqual "title round-trip" titleString
        (RUP.decodeRUPField RUP.PatchEncodingSystem
          (fromMaybe ByteString.empty (RUP.rupTitle (RUP.rupHeader parsed))))

-- EncodingGap warning: PatchContents with known encoding → format without encoding flag

test_encodingGapPPF3 :: IO ()
test_encodingGapPPF3 = do
  let contents = (emptyContents [Hunk (Offset 0) (ByteString.pack [1])])
        { contentsPatchEncoding = Just PatchEncodingUTF8
        , contentsDescription   = Just (encodeLocaleField "hello")
        }
      spec = formatSpecification CreatePPF3 False False
      warnings = conversionNotes contents CreatePPF3 spec defaultMeta
      hasEncodingGap = any isEncodingGap warnings
  assertBool "expected EncodingGap warning for PPF3" hasEncodingGap
  where
    isEncodingGap (EncodingGap _ _) = True
    isEncodingGap _                 = False

test_encodingGapAPSN64 :: IO ()
test_encodingGapAPSN64 = do
  let contents = (emptyContents [Hunk (Offset 0) (ByteString.pack [1])])
        { contentsPatchEncoding = Just PatchEncodingUTF8
        , contentsDescription   = Just (encodeLocaleField "hello")
        , contentsDestinationSize = Just (FileSize 256)
        }
      spec = formatSpecification CreateAPSN64 False False
      warnings = conversionNotes contents CreateAPSN64 spec defaultMeta
      hasEncodingGap = any isEncodingGap warnings
  assertBool "expected EncodingGap warning for APS-N64" hasEncodingGap
  where
    isEncodingGap (EncodingGap _ _) = True
    isEncodingGap _                 = False

-- Conversion metadata round-trip: locale bytes through convertDirect to PPF3

test_conversionMetadataRoundTrip :: IO ()
test_conversionMetadataRoundTrip = do
  let contents = (emptyContents [Hunk (Offset 0) (ByteString.pack [1])])
        { contentsDescription = Just (encodeLocaleField "Pokémon")
        }
  case convertDirect contents (CreateDirect CreatePPF3) defaultMeta of
    Left slapError -> assertBool ("convert: " ++ renderSlapError slapError) False
    Right (CreateResult patchBytes _) ->
      case PPF.parsePatch patchBytes of
        Left slapError -> assertBool ("parse: " ++ renderSlapError slapError) False
        Right parsed ->
          assertEqual "description round-trip through conversion"
            "Pokémon"
            (decodeLocaleField (trimNull (PPF.ppfDescription parsed)))

-- isValidUtf8 conversion inference: opaque description bytes → RUP PATCH_ENC

test_utf8InferenceValid :: IO ()
test_utf8InferenceValid = do
  let source = ByteString.pack [0]
      target = ByteString.pack [1]
      contents = (emptyContents [])
        { contentsDescription = Just (encodeUtf8Field "André")
        }
  case createFromMemory (CreateDiff CreateRUP) source target defaultMeta (Just contents) of
    Left slapError -> assertBool ("create: " ++ renderSlapError slapError) False
    Right (CreateResult patchBytes _) ->
      case RUP.parseRUP patchBytes of
        Left slapError -> assertBool ("parse: " ++ renderSlapError slapError) False
        Right parsed ->
          assertEqual "valid UTF-8 description → PatchEncodingUTF8"
            RUP.PatchEncodingUTF8 (RUP.rupPatchEncoding parsed)

test_utf8InferenceInvalid :: IO ()
test_utf8InferenceInvalid = do
  let source = ByteString.pack [0]
      target = ByteString.pack [1]
      contents = (emptyContents [])
        { contentsDescription = Just (ByteString.pack [0xC0, 0x41])
        }
  case createFromMemory (CreateDiff CreateRUP) source target defaultMeta (Just contents) of
    Left slapError -> assertBool ("create: " ++ renderSlapError slapError) False
    Right (CreateResult patchBytes _) ->
      case RUP.parseRUP patchBytes of
        Left slapError -> assertBool ("parse: " ++ renderSlapError slapError) False
        Right parsed ->
          assertEqual "invalid UTF-8 description → PatchEncodingSystem"
            RUP.PatchEncodingSystem (RUP.rupPatchEncoding parsed)

-- Helpers for FieldTruncated matching

isFieldTruncatedFor :: FormatLabel -> SlapWarning -> Bool
isFieldTruncatedFor expectedLabel (FieldTruncated warningLabel _ _ _) = expectedLabel == warningLabel
isFieldTruncatedFor _ _ = False

----------------------------------------------------------------------------
-- DPS Detection
----------------------------------------------------------------------------

-- Valid DPS with zero records: 198 bytes, correct version and stability
test_isDPSValidZeroRecords :: IO ()
test_isDPSValidZeroRecords = do
  let metadata = ByteString.replicate DPS.dpsMetadataSize 0    -- 192 bytes of nulls
      stabilityByte = ByteString.singleton 0                    -- stable
      versionByte = ByteString.singleton 1                      -- DPSVersion1
      originalSize = ByteString.pack [0x00, 0x00, 0x00, 0x00]  -- 4 bytes LE
      input = metadata <> stabilityByte <> versionByte <> originalSize
  assertEqual "input length" DPS.dpsMinimumFileSize (ByteString.length input)
  assertBool "isDPS returns True" (DPS.isDPS input)

-- Valid header but first record byte is an invalid mode (2)
test_isDPSInvalidRecordMode :: IO ()
test_isDPSInvalidRecordMode = do
  let metadata = ByteString.replicate DPS.dpsMetadataSize 0
      stabilityByte = ByteString.singleton 0
      versionByte = ByteString.singleton 1
      originalSize = ByteString.pack [0x00, 0x00, 0x00, 0x00]
      invalidMode = ByteString.singleton 2  -- not 0 or 1
      input = metadata <> stabilityByte <> versionByte <> originalSize <> invalidMode
  assertEqual "input length" (DPS.dpsMinimumFileSize + 1) (ByteString.length input)
  assertBool "isDPS returns False" (not (DPS.isDPS input))

-- 198 bytes of 'A': version byte at dpsVersionOffset is 0x41, not 1
test_isDPSPrintableAsciiNotDPS :: IO ()
test_isDPSPrintableAsciiNotDPS = do
  let input = ByteString.replicate DPS.dpsMinimumFileSize 0x41
  assertBool "isDPS returns False" (not (DPS.isDPS input))
