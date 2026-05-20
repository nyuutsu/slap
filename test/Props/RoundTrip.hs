{-# LANGUAGE OverloadedStrings #-}

-- | Create-parse-apply round-trip tests for every format that supports
-- creation. The single property every format satisfies:
--
-- > applyFmt (parseFmt (createFmt src tgt)) src == tgt
--
-- Plus a handful of format-specific round-trip-adjacent properties
-- (hash preservation for NINJA1/NINJA2, patch size bounds for BPS,
-- COPY-chunk planning for GDIFF, etc.) that are naturally expressed
-- as extensions of the basic round-trip.
module Props.RoundTrip (roundTripTests) where

import qualified Slap.BPS.Apply as BPS
import qualified Slap.BPS.Parse as BPS
import qualified Slap.BPS.Types as BPS
import Slap.BPS.Types (BPSMetadata(..))
import qualified Slap.IPS.Apply as IPS
import qualified Slap.IPS.Parse as IPS
import Slap.IPS.Create (resolveSentinelCollisions, optimalIPSRecords)
import Slap.IPS.Types (OffsetWidth(..), EBPPatch(..), IPSParseResult(..),
                       ipsMaxRecordPayload)
import qualified Slap.UPS.Apply as UPS
import qualified Slap.UPS.Parse as UPS
import qualified Slap.PMSR.Parse as PMSR
import qualified Slap.PMSR.Apply as PMSR
import qualified Slap.NINJA1.Parse as NINJA1
import qualified Slap.NINJA1.Apply as NINJA1
import qualified Slap.NINJA1.Types as NINJA1
import qualified Slap.DPS.Types as DPS
import qualified Slap.DPS.Parse as DPS
import qualified Slap.DPS.Apply as DPS
import Slap.DPS.Types (DPSRecord(..), narrowDPSRecord, narrowDPSSourceSize)
import qualified Slap.NINJA2.Types as NINJA2
import qualified Slap.NINJA2.Parse as NINJA2
import qualified Slap.NINJA2.Apply as NINJA2
import qualified Slap.APSN64.Parse as APSN64
import qualified Slap.APSN64.Apply as APSN64
import qualified Slap.APSGBA.Parse as APSGBA
import qualified Slap.APSGBA.Apply as APSGBA
import Slap.APSGBA.Types (narrowAPSGBASourceSize)
import qualified Slap.GDIFF.Apply as GDIFF
import qualified Slap.GDIFF.Create as GDIFF
import qualified Slap.GDIFF.Parse as GDIFF
import qualified Slap.GDIFF.Types as GDIFF
import qualified Slap.XDelta1.Apply as XDelta1
import qualified Slap.XDelta1.Parse as XDelta1
import qualified Slap.XDelta1.Types as XDelta1
import Slap.XDelta1.Types (XDelta1PatchCompression(..),
                           ResolvedXDelta1FileNames,
                           resolveXDelta1FileNames)
import qualified Slap.PPF1.Apply as PPF1
import qualified Slap.PPF1.Create as PPF1
import qualified Slap.PPF1.Parse as PPF1
import qualified Slap.PPF1.Types as PPF1
import Slap.PPF1.Types (PPF1Origin(..))
import qualified Slap.PPF2.Apply as PPF2
import qualified Slap.PPF2.Create as PPF2
import qualified Slap.PPF2.Parse as PPF2
import qualified Slap.PPF2.Types as PPF2
import Slap.PPF2.Types (narrowPPF2FileId, narrowPPF2SourceSize)
import Slap.Narrow (NarrowingFailure(..))
import qualified Slap.PPF3.Apply as PPF3
import qualified Slap.PPF3.Create as PPF3
import qualified Slap.PPF3.Parse as PPF3
import qualified Slap.PPF3.Types as PPF3
import Slap.PPF3.Types (PPF3ImageType(..), narrowPPF3FileId)
import qualified Slap.PCHTXT.Parse as PCHTXT
import qualified Slap.PCHTXT.Apply as PCHTXT
import qualified Slap.PCHTXT.Types as PCHTXT

import Slap.Binary (md5, sha1, diffHunks)
import Slap.Status (CreateResult(..), Parsed(..), SlapError(..), Outcome(..),
                   SlapAdvisory(..), renderSlapError)
import Slap.FieldName (FieldName(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.Measure (Offset(..), Length(..), FileSize(..),
                     Hunk(..), SentinelOffset(..),
                     OriginalLength(..), TruncatedLength(..),
                     byteLength, splitHunks, splitPayload)
import Slap.FFI (crc32)
import Slap.FileContents (InputFileContents(..), OutputFileContents(..), PatchFileContents(..))
import Slap.Convert (DirectCreate(..), CreateFormat(..),
                     noMetadataRequested, noConstraintsRequested, noDialectsRequested,
                     RequestedDialects(..),
                     VerificationInclusion(..),
                     convertDirect, emptyContents)
import Slap.Create (createBPS, createUPS, createDPS, createNINJA2,
                    createAPSGBA, createGDIFF, createXDelta1, createPatch)

import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Lazy as LazyByteString
import qualified Data.Text as Text
import qualified Slap.Text as SlapText
import Data.Bits (shiftL)
import qualified Data.Bits as Bits
import Data.ByteString.Builder (word8, byteString, toLazyByteString)
import Data.List (isInfixOf)
import Slap.Binary (getWord32BE)
import Test.Tasty
import Test.Tasty.HUnit (testCase, assertBool, assertEqual, assertFailure, Assertion)
import Test.Tasty.QuickCheck

import Props.Helpers

roundTripTests :: TestTree
roundTripTests = testGroup "RoundTrip"
  [ testGroup "BPS"
      [ testProperty "round-trip" prop_bps
      , testProperty "block-move" prop_bpsBlockMove
      , testProperty "no-size-regression" prop_bpsNoSizeRegression
      , testProperty "metadata-round-trip" prop_bpsMetadata
      ]
  , testGroup "IPS"
      [ testProperty "round-trip" prop_ips
      , testProperty "eof-collision" prop_ipsEofCollision
      , testProperty "resolveSentinelCollisions" prop_resolveSentinelCollisions
      , testProperty "source-less convert rejects sentinel" prop_sourcelessSentinelRejected
      , testCase     "max-payload at sentinel round-trips" ipsSentinelMaxPayloadRoundTrips
      , testProperty "dp-not-larger" prop_dpNotLarger
      ]
  , testGroup "IPS32"
      [ testProperty "round-trip" prop_ips32
      , testProperty "dp-not-larger" prop_dpIPS32NotLarger
      ]
  , testGroup "EBP"
      [ testProperty "round-trip" prop_ebp
      ]
  , testGroup "UPS"
      [ testProperty "round-trip" prop_ups
      ]
  , testGroup "PPF1"
      [ testProperty "round-trip" prop_ppf1
      , testCase "description: UTF-8 codepoints round-trip byte-faithfully"
                 ppf1DescriptionUtf8RoundTrip
      , testCase "description: 4-byte codepoint at the 50-byte cap is dropped whole"
                 ppf1DescriptionCodepointAwareTruncation
      ]
  , testGroup "PPF2"
      [ testProperty "round-trip" prop_ppf2
      , testCase     "rejects header source size > 0xFFFFFFFF"
                     ppf2SourceSizeAdversarial
      , testCase "description: UTF-8 codepoints round-trip byte-faithfully"
                 ppf2DescriptionUtf8RoundTrip
      , testCase "description: 4-byte codepoint at the 50-byte cap is dropped whole"
                 ppf2DescriptionCodepointAwareTruncation
      , testCase "file_id.diz: locale-encoded body round-trips byte-faithfully"
                 ppf2FileIdDizRoundTrip
      ]
  , testGroup "PPF3"
      [ testProperty "round-trip" prop_ppf3
      , testCase "description: UTF-8 codepoints round-trip byte-faithfully"
                 ppf3DescriptionUtf8RoundTrip
      , testCase "description: 4-byte codepoint at the 50-byte cap is dropped whole"
                 ppf3DescriptionCodepointAwareTruncation
      , testCase "file_id.diz: locale-encoded body round-trips byte-faithfully"
                 ppf3FileIdDizRoundTrip
      ]
  , testGroup "PMSR"
      [ testProperty "round-trip" prop_pmsr
      ]
  , testGroup "NINJA1"
      [ testProperty "round-trip" prop_ninja1
      , testProperty "hashes" prop_ninja1Hashes
      , testProperty "eof-collision" prop_ninja1EofCollision
      , testProperty "source-less convert rejects sentinel" prop_ninja1SourcelessSentinelRejected
      ]
  , testGroup "DPS"
      [ testProperty "round-trip" prop_dps
      , testCase     "rejects header source size > 0xFFFFFFFF"
                     dpsSourceSizeAdversarial
      , testCase     "rejects per-record offset > 0xFFFFFFFF"
                     dpsRecordOffsetAdversarial
      ]
  , testGroup "NINJA2"
      [ testProperty "round-trip" prop_ninja2
      , testProperty "truncate-round-trip" prop_ninja2Truncate
      , testProperty "hashes" prop_ninja2Hashes
      , testCase "encoding-utf8-round-trips"   (ninja2EncodingRoundTrips NINJA2.PatchEncodingUTF8)
      , testCase "encoding-system-round-trips" (ninja2EncodingRoundTrips NINJA2.PatchEncodingSystem)
      , testCase "single-file sentinel is one zero byte" ninja2SingleFileSentinelIsZero
      , testCase "field-truncation-warning-reports-actual-stored-length"
          ninja2FieldTruncationWarningReportsActualStoredLength
      ]
  , testGroup "APS-N64"
      [ testProperty "round-trip" prop_apsN64
      ]
  , testGroup "APS-GBA"
      [ testProperty "round-trip" prop_apsGba
      , testCase     "rejects header source size > 0xFFFFFFFF"
                     apsGbaSourceSizeAdversarial
      ]
  , testGroup "GDIFF"
      [ testProperty "round-trip"                                    prop_gdiff
      , testProperty "planCopy chunk lengths sum to total"           prop_planCopyLengthSum
      , testProperty "planCopy chunk offsets chain without gaps"     prop_planCopyOffsetsChain
      , testProperty "planCopy above-threshold yields only Copy255"  prop_planCopyAboveThresholdAllCopy255
      , testProperty "planCopy round-trips through parseGDIFF"       prop_planCopyRoundTrips
      ]
  , testGroup "PCHTXT"
      [ testProperty "round-trip" prop_pchtxt
      , testCase "parse-escapes" parsePchtxtEscapes
      , testCase "parse-sphinx" parsePchtxtSphinx
      ]
  , testGroup "XDelta1"
      [ testProperty "round-trip"                       prop_xdelta1RoundTrips
      , testProperty "compression posture round-trips"  prop_xdelta1CompressionPostureRoundTrips
      , testProperty "create produces Verify"           prop_xdelta1CreateProducesVerifyPosture
      , testProperty "no-verify round-trips and warns"  prop_xdelta1NoVerifyRoundTrip
      , testCase     "empty target round-trips"         xdelta1EmptyTarget
      , testCase     "single-byte target round-trips"   xdelta1SingleByteTarget
      , testCase     "target equals source"             xdelta1TargetEqualsSource
      , testCase     "no-verify sets FLAG_NO_VERIFY"    xdelta1NoVerifySetsFlagBit
      , testCase     "include-verify clears FLAG_NO_VERIFY" xdelta1IncludeVerifyClearsFlagBit
      , testCase     "parser rejects corrupted control type tag" xdelta1RejectsWrongControlTypeTag
      ]
  ]

----------------------------------------------------------------------------
-- Delta formats: handle any size combination
----------------------------------------------------------------------------

prop_bps :: Property
prop_bps = forAll genPair $ \(source, target) ->
  case createBPS (InputFileContents source) (OutputFileContents target) (BPSMetadata ByteString.empty) of
    Left createError -> counterexample ("create: " ++ renderSlapError createError) $ property False
    Right (CreateResult patch _) -> case BPS.parseBPS patch of
      Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
      Right (Parsed parsed _parseWarnings) -> BPS.applyBPS parsed (InputFileContents source) === Right (OutputFileContents target)

prop_bpsMetadata :: Property
prop_bpsMetadata = forAll genPair $ \(source, target) ->
  forAll genByteString $ \meta ->
    case createBPS (InputFileContents source) (OutputFileContents target) (BPSMetadata meta) of
      Left createError -> counterexample ("create: " ++ renderSlapError createError) $ property False
      Right (CreateResult patch _) -> case BPS.parseBPS patch of
        Left slapError -> counterexample (renderSlapError slapError) $ property False
        Right (Parsed parsed _parseWarnings) -> BPS.unBPSMetadata (BPS.bpsMetadata parsed) === meta

prop_ups :: Property
prop_ups = forAll genPair $ \(source, target) ->
  case createUPS (InputFileContents source) (OutputFileContents target) of
    Left _createError -> property True
    Right (CreateResult patch _) ->
      case UPS.parseUPS patch of
        Left parseError ->
          counterexample (renderSlapError parseError) $ property False
        Right (Parsed parsed _parseWarnings) ->
          fmap outcomeValue (UPS.applyUPS parsed (InputFileContents source))
            === Right (OutputFileContents target)

prop_ips :: Property
prop_ips = forAll genPair $ \(source, target) ->
  case createPatch (CreateDirect CreateIPS) Nothing (InputFileContents source) (OutputFileContents target) noMetadataRequested Nothing noConstraintsRequested noDialectsRequested of
    Left slapError -> counterexample ("create: " ++ renderSlapError slapError) $ property False
    Right (CreateResult patch _) -> case IPS.parseIPS patch of
      Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
      Right (Parsed (IPSParseCleanIPS ipsPatch) _parseWarnings) ->
        fmap outcomeValue (IPS.applyIPS (InputFileContents source) ipsPatch)
          === Right (OutputFileContents target)
      Right (Parsed (IPSParseCleanEBP _ebpPatch) _parseWarnings) ->
        counterexample "test fixture unexpectedly EBP" $ property False
      Right (Parsed (IPSParseTruncated _ _) _parseWarnings) ->
        counterexample "round-tripped IPS unexpectedly truncated" $ property False

prop_ipsEofCollision :: Property
prop_ipsEofCollision = withNumTests 20 $ forAll genEofPair $ \(source, target) ->
  case createPatch (CreateDirect CreateIPS) Nothing (InputFileContents source) (OutputFileContents target) noMetadataRequested Nothing noConstraintsRequested noDialectsRequested of
    Left slapError -> counterexample ("create: " ++ renderSlapError slapError) $ property False
    Right (CreateResult patch _) -> case IPS.parseIPS patch of
      Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
      Right (Parsed (IPSParseCleanIPS ipsPatch) _parseWarnings) ->
        fmap outcomeValue (IPS.applyIPS (InputFileContents source) ipsPatch)
          === Right (OutputFileContents target)
      Right (Parsed (IPSParseCleanEBP _ebpPatch) _parseWarnings) ->
        counterexample "test fixture unexpectedly EBP" $ property False
      Right (Parsed (IPSParseTruncated _ _) _parseWarnings) ->
        counterexample "round-tripped IPS unexpectedly truncated" $ property False

prop_resolveSentinelCollisions :: Property
prop_resolveSentinelCollisions = once $
  let source       = InputFileContents (ByteString.pack [0, 1, 2, 3, 4, 5, 6, 7])
      emptySource  = InputFileContents ByteString.empty
      sentinelAt5  = SentinelOffset (Offset 5)
      sentinelAt0  = SentinelOffset (Offset 0)
      -- 'resolveSentinelCollisions' consumes 'SplitHunk's; the only
      -- way to obtain those from this layer is to run 'splitHunks'.
      -- Use an ample cap so the split pass passes inputs through
      -- unchanged and the test is exercising the resolver, not
      -- splitting. Outputs are raw '[Hunk]' because the resolver drops
      -- the proof on output — the byte-prepend dodge can push a payload
      -- one byte past the original cap, so the convert pipeline re-runs
      -- 'splitHunks' afterward to restore the bound.
      asSplit = splitHunks ipsMaxRecordPayload
  in conjoin
    [ -- Record at sentinel is shifted back and the preceding source byte prepended.
      resolveSentinelCollisions LabelIPS sentinelAt5 source
        (asSplit [Hunk (Offset 5) (ByteString.pack [0xFF])])
        === Right [Hunk (Offset 4) (ByteString.pack [4, 0xFF])]
    , -- Record NOT at sentinel passes through unchanged.
      resolveSentinelCollisions LabelIPS sentinelAt5 source
        (asSplit [Hunk (Offset 3) (ByteString.pack [0xAA])])
        === Right [Hunk (Offset 3) (ByteString.pack [0xAA])]
    , -- Empty source: collision is unfixable, returns a structured error.
      resolveSentinelCollisions LabelIPS sentinelAt5 emptySource
        (asSplit [Hunk (Offset 5) (ByteString.pack [0xFF])])
        === Left (SentinelCollisionUnfixable LabelIPS sentinelAt5)
    , -- Sentinel at offset 0: no preceding byte exists, returns a structured error.
      resolveSentinelCollisions LabelIPS sentinelAt0 source
        (asSplit [Hunk (Offset 0) (ByteString.pack [0xFF])])
        === Left (SentinelCollisionUnfixable LabelIPS sentinelAt0)
    ]

-- | Source-less conversion of a record sitting on the IPS sentinel offset must
-- raise 'SentinelCollisionUnfixable' rather than silently passing through or
-- crashing. Exercises the 'convertDirect' path, which is the live home of the
-- source-less code branch introduced by the sentinel-unification refactor.
-- 'CreateResult' has no 'Eq' instance, so the property pattern-matches on the
-- expected 'Left' rather than comparing with @===@.
prop_sourcelessSentinelRejected :: Property
prop_sourcelessSentinelRejected = once $
  let ipsSentinelOffset = SentinelOffset (Offset 0x454F46)
      collidingContents =
        emptyContents [Hunk (Offset 0x454F46) (ByteString.pack [0xFF])]
  in case convertDirect collidingContents (CreateDirect CreateIPS) noMetadataRequested noConstraintsRequested noDialectsRequested of
       Left (SentinelCollisionUnfixable LabelIPS offset) ->
         offset === ipsSentinelOffset
       Left other ->
         counterexample ("unexpected error: " ++ renderSlapError other) $
           property False
       Right _ ->
         counterexample "expected Left SentinelCollisionUnfixable, got Right" $
           property False

-- | Corner case for the post-resolve payload bound. When the input
-- record sits on the sentinel offset and carries exactly
-- 'ipsMaxRecordPayload' (@0xFFFF@) bytes, the byte-prepend dodge in
-- 'resolveSentinelCollisions' grows the payload to @0x10000@ bytes —
-- one over IPS's 16-bit length field. Without the second 'splitHunks'
-- pass that the convert pipeline runs after sentinel resolution, the
-- wire encoder's @putWord16BE (fromIntegral payloadLength)@ would
-- truncate to @0x0000@ (the RLE record sentinel) and emit a
-- structurally different record from the one intended. With the
-- second pass, the over-cap payload re-splits into pieces that fit
-- the wire format, and the patch round-trips.
ipsSentinelMaxPayloadRoundTrips :: Assertion
ipsSentinelMaxPayloadRoundTrips =
  let eofOffset       = 0x454F46
      maxPayloadCount = 0xFFFF
      source = ByteString.replicate (eofOffset + 1) 0
      target = ByteString.replicate eofOffset 0
            <> ByteString.replicate maxPayloadCount 0xAB
  in case createPatch (CreateDirect CreateIPS) Nothing
                      (InputFileContents source) (OutputFileContents target)
                      noMetadataRequested Nothing
                      noConstraintsRequested noDialectsRequested of
       Left slapError ->
         assertFailure ("create: " ++ renderSlapError slapError)
       Right (CreateResult patch _) -> case IPS.parseIPS patch of
         Left slapError ->
           assertFailure ("parse: " ++ renderSlapError slapError)
         Right (Parsed (IPSParseCleanIPS ipsPatch) _) ->
           case IPS.applyIPS (InputFileContents source) ipsPatch of
             Right outcome ->
               assertEqual "round-trip"
                 (OutputFileContents target) (outcomeValue outcome)
             Left slapError ->
               assertFailure ("apply: " ++ renderSlapError slapError)
         Right (Parsed (IPSParseCleanEBP _) _) ->
           assertFailure "unexpectedly parsed as EBP"
         Right (Parsed (IPSParseTruncated _ _) _) ->
           assertFailure "unexpectedly parsed as truncated"

-- | DP patch size must not exceed greedy patch size for IPS (offWidth=3).
prop_dpNotLarger :: Property
prop_dpNotLarger = forAll genPair $ \(source, target) ->
  let dynamicProgrammingRecords =
        optimalIPSRecords Offset24 (InputFileContents source) (OutputFileContents target)
      greedyRecords = splitHunks (Length 0xFFFF)
                                 (diffHunks (InputFileContents source) (OutputFileContents target))
      dynamicProgrammingSize = ipsEncodedSize 3 (map hunkPayload dynamicProgrammingRecords)
      greedySize = ipsEncodedSize 3 (map splitPayload greedyRecords)
  in counterexample ("DP: " ++ show dynamicProgrammingSize ++ ", greedy: " ++ show greedySize) $
     dynamicProgrammingSize <= greedySize

-- | DP patch size must not exceed greedy patch size for IPS32 (offWidth=4).
prop_dpIPS32NotLarger :: Property
prop_dpIPS32NotLarger = forAll genPair $ \(source, target) ->
  let dynamicProgrammingRecords =
        optimalIPSRecords Offset32 (InputFileContents source) (OutputFileContents target)
      greedyRecords = splitHunks (Length 0xFFFF)
                                 (diffHunks (InputFileContents source) (OutputFileContents target))
      dynamicProgrammingSize = ipsEncodedSize 4 (map hunkPayload dynamicProgrammingRecords)
      greedySize = ipsEncodedSize 4 (map splitPayload greedyRecords)
  in counterexample ("DP: " ++ show dynamicProgrammingSize ++ ", greedy: " ++ show greedySize) $
     dynamicProgrammingSize <= greedySize

prop_gdiff :: Property
prop_gdiff = forAll genPair $ \(source, target) ->
  case createGDIFF (InputFileContents source) (OutputFileContents target) of
    Left createError -> counterexample ("create: " ++ renderSlapError createError) $ property False
    Right (CreateResult patch _) -> case GDIFF.parseGDIFF patch of
      Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
      Right (Parsed parsed _parseWarnings) ->
        case GDIFF.applyGDIFF parsed (InputFileContents source) of
          Left applyError       -> counterexample ("apply: " ++ renderSlapError applyError) $ property False
          Right outputContents  -> outputContents === OutputFileContents target

----------------------------------------------------------------------------
-- GDIFF planCopy properties
--
-- The W3C GDIFF spec defines its @int@ type as signed 32-bit, so a
-- single COPY command's length field tops out at 'maxSingleCommandLength'
-- (2^31-1 bytes). 'planCopy' is the encoder's chunking pass: it splits
-- requests larger than that limit into a run of in-range chunks. These
-- properties pin its behavior down without ever allocating a multi-
-- gigabyte payload — COPY commands carry only an offset and a length,
-- so synthetic large inputs cost nothing to test.
----------------------------------------------------------------------------

-- Test-only accessors for 'CopyEncoding'. Verbose by design: a shortcut
-- would silently become a partial selector if a future opcode were
-- added.

encodingLength :: GDIFF.CopyEncoding -> Int
encodingLength = \case
  GDIFF.Copy249 _ wireLength -> fromIntegral wireLength
  GDIFF.Copy250 _ wireLength -> fromIntegral wireLength
  GDIFF.Copy251 _ wireLength -> fromIntegral wireLength
  GDIFF.Copy252 _ wireLength -> fromIntegral wireLength
  GDIFF.Copy253 _ wireLength -> fromIntegral wireLength
  GDIFF.Copy254 _ wireLength -> fromIntegral wireLength
  GDIFF.Copy255 _ wireLength -> fromIntegral wireLength

encodingOffset :: GDIFF.CopyEncoding -> Int
encodingOffset = \case
  GDIFF.Copy249 wireOffset _ -> fromIntegral wireOffset
  GDIFF.Copy250 wireOffset _ -> fromIntegral wireOffset
  GDIFF.Copy251 wireOffset _ -> fromIntegral wireOffset
  GDIFF.Copy252 wireOffset _ -> fromIntegral wireOffset
  GDIFF.Copy253 wireOffset _ -> fromIntegral wireOffset
  GDIFF.Copy254 wireOffset _ -> fromIntegral wireOffset
  GDIFF.Copy255 wireOffset _ -> fromIntegral wireOffset

-- | Offsets spanning every opcode-offset bucket (ushort, int, long),
-- capped well below 'Int's 64-bit range so chained-offset arithmetic
-- never overflows.
genCopyOffset :: Gen Offset
genCopyOffset = oneof
  [ Offset <$> chooseInt (0,                0xFFFF)
  , Offset <$> chooseInt (0xFFFF + 1,       0xFFFFFFFF)
  , Offset <$> chooseInt (0xFFFFFFFF + 1,   1 `shiftL` 48)
  ]

-- | Offsets that always select the @long@ offset bucket. The
-- "above-threshold yields only 'Copy255'" property would otherwise
-- see legitimate 'Copy251'/'Copy254' chunks for small offsets, since
-- the encoder picks the narrowest opcode whose fields fit.
genCopyLongOffset :: Gen Offset
genCopyLongOffset = Offset <$> chooseInt (0xFFFFFFFF + 1, 1 `shiftL` 48)

-- | Lengths spanning every opcode-length bucket plus the chunked-by-
-- 'planCopy' regime above 'maxSingleCommandLength'.
genCopyLength :: Gen Length
genCopyLength = oneof
  [ Length <$> chooseInt (0,          0xFF)
  , Length <$> chooseInt (0xFF + 1,   0xFFFF)
  , Length <$> chooseInt (0xFFFF + 1, unLength GDIFF.maxSingleCommandLength)
  , genCopyAboveThresholdLength
  ]

-- | Lengths strictly larger than 'maxSingleCommandLength', forcing
-- 'planCopy' to chunk.
genCopyAboveThresholdLength :: Gen Length
genCopyAboveThresholdLength = Length <$>
  chooseInt (unLength GDIFF.maxSingleCommandLength + 1, 100 * unLength GDIFF.maxSingleCommandLength)

-- | Chunk lengths must sum to the requested length.
prop_planCopyLengthSum :: Property
prop_planCopyLengthSum = forAll genCopyOffset $ \initialOffset ->
  forAll genCopyLength $ \requestedLength ->
    let chunks = GDIFF.planCopy initialOffset requestedLength
    in sum (fmap encodingLength chunks) === unLength requestedLength

-- | Successive chunk offsets must chain: each chunk's offset equals
-- the preceding chunk's offset plus the preceding chunk's length, with
-- neither gap nor overlap. The first chunk's offset must equal the
-- requested initial offset.
prop_planCopyOffsetsChain :: Property
prop_planCopyOffsetsChain = forAll genCopyOffset $ \initialOffset ->
  forAll genCopyLength $ \requestedLength ->
    case GDIFF.planCopy initialOffset requestedLength of
      []                  -> property True
      firstChunk : others ->
        encodingOffset firstChunk === unOffset initialOffset
        .&&. conjoin (zipWith chainStep (firstChunk : others) others)
  where
    chainStep precedingChunk followingChunk =
      encodingOffset followingChunk
        === encodingOffset precedingChunk + encodingLength precedingChunk

-- | Above-threshold inputs at long offsets must produce only 'Copy255'
-- chunks. Restricted to offsets above 0xFFFFFFFF because the encoder
-- legitimately picks 'Copy251'/'Copy254' for chunks whose offset still
-- fits a 16- or 32-bit field; only beyond that range is 'Copy255' the
-- only choice.
prop_planCopyAboveThresholdAllCopy255 :: Property
prop_planCopyAboveThresholdAllCopy255 = forAll genCopyLongOffset $ \initialOffset ->
  forAll genCopyAboveThresholdLength $ \requestedLength ->
    all isCopy255 (GDIFF.planCopy initialOffset requestedLength)
  where
    isCopy255 GDIFF.Copy255{} = True
    isCopy255 _               = False

-- | Round-trip: encode a synthetic above-threshold COPY through
-- 'encodeCopy', wrap it with the GDIFF magic + version + EOF marker,
-- and parse it back. The parsed COPY commands' lengths must sum to the
-- requested length, and their offsets must chain from the requested
-- initial offset with neither gap nor overlap. Synthetic patches carry
-- no payload bytes — COPY commands reference offsets, not data — so
-- multi-gigabyte 'Length' values cost nothing to test.
prop_planCopyRoundTrips :: Property
prop_planCopyRoundTrips = forAll genCopyOffset $ \initialOffset ->
  forAll genCopyAboveThresholdLength $ \requestedLength ->
    let patchBytes = LazyByteString.toStrict $ toLazyByteString $
          byteString GDIFF.gdiffMagicBytes
          <> word8 4
          <> GDIFF.encodeCopy initialOffset requestedLength
          <> word8 0
    in case GDIFF.parseGDIFF (PatchFileContents patchBytes) of
      Left parseError ->
        counterexample (renderSlapError parseError) (property False)
      Right (Parsed parsed _parseWarnings) ->
        let parsedCommands = GDIFF.gdiffCommands parsed
            parsedCopies =
              [ (commandOffset, commandLength)
              | GDIFF.GDiffCommandCopy { GDIFF.gdiffCopyOffset = commandOffset, GDIFF.gdiffCopyLength = Length commandLength } <- parsedCommands ]
            actualOffsets   = fmap (unOffset . fst) parsedCopies
            chunkLengths    = fmap snd parsedCopies
            expectedOffsets = scanl (+) (unOffset initialOffset) chunkLengths
        in counterexample ("commands: " ++ show parsedCommands) $
           conjoin
             [ sum chunkLengths === unLength requestedLength
             , conjoin (zipWith (===) actualOffsets expectedOffsets)
             ]

prop_apsGba :: Property
prop_apsGba = forAll genPair $ \(source, target) ->
  case createAPSGBA (InputFileContents source) (OutputFileContents target) of
    Left createError -> counterexample ("create: " ++ renderSlapError createError) $ property False
    Right (CreateResult patch _) -> case APSGBA.parseAPSGBA patch of
      Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
      Right (Parsed parsed _parseWarnings) ->
        APSGBA.applyAPSGBA parsed (InputFileContents source) === Right (OutputFileContents target)

----------------------------------------------------------------------------
-- IPS32 / EBP: no truncation marker, target must be >= source
----------------------------------------------------------------------------

prop_ips32 :: Property
prop_ips32 = forAll genPairNoShrink $ \(source, target) ->
  case createPatch (CreateDirect CreateIPS32) Nothing (InputFileContents source) (OutputFileContents target) noMetadataRequested Nothing noConstraintsRequested noDialectsRequested of
    Left slapError -> counterexample ("create: " ++ renderSlapError slapError) $ property False
    Right (CreateResult patch _) -> case IPS.parseIPS patch of
      Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
      Right (Parsed (IPSParseCleanIPS ipsPatch) _parseWarnings) ->
        fmap outcomeValue (IPS.applyIPS (InputFileContents source) ipsPatch)
          === Right (OutputFileContents target)
      Right (Parsed (IPSParseCleanEBP _ebpPatch) _parseWarnings) ->
        counterexample "test fixture unexpectedly EBP" $ property False
      Right (Parsed (IPSParseTruncated _ _) _parseWarnings) ->
        counterexample "round-tripped IPS32 unexpectedly truncated" $ property False

prop_ebp :: Property
prop_ebp = forAll genPairNoShrink $ \(source, target) ->
  case createPatch (CreateDirect CreateEBP) Nothing (InputFileContents source) (OutputFileContents target) noMetadataRequested Nothing noConstraintsRequested noDialectsRequested of
    Left slapError -> counterexample ("create: " ++ renderSlapError slapError) $ property False
    Right (CreateResult patch _) -> case IPS.parseIPS patch of
      Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
      Right (Parsed (IPSParseCleanEBP ebpPatch) _parseWarnings) ->
        fmap outcomeValue (IPS.applyIPS (InputFileContents source) (ebpBasePatch ebpPatch))
          === Right (OutputFileContents target)
      Right (Parsed (IPSParseCleanIPS _ipsPatch) _parseWarnings) ->
        counterexample "test fixture unexpectedly plain IPS" $ property False
      Right (Parsed (IPSParseTruncated _ _) _parseWarnings) ->
        counterexample "round-tripped EBP unexpectedly truncated" $ property False

-- Direct formats: no truncation, target must be >= source.
-- PPF1's offset endianness is a dialect axis; the round-trip must hold
-- under both PC-origin (LE) and Amiga-origin (BE) settings, with the
-- same origin used on both sides of the round-trip.
prop_ppf1 :: Property
prop_ppf1 = forAll genPairNoShrink $ \(source, target) ->
  forAll (elements [PPF1OriginPC, PPF1OriginAmiga]) $ \origin ->
    let dialects = noDialectsRequested { requestedPPF1Origin = origin }
    in case createPatch (CreateDirect CreatePPF1) Nothing (InputFileContents source) (OutputFileContents target) noMetadataRequested Nothing noConstraintsRequested dialects of
         Left slapError -> counterexample ("create: " ++ renderSlapError slapError) $ property False
         Right (CreateResult patch _) -> case PPF1.parsePPF1 origin patch of
            Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
            Right (Parsed parsed _parseWarnings) -> PPF1.applyPPF1 parsed (InputFileContents source) === Right (OutputFileContents target)

-- | PPF2 needs the source ROM to be at least 'ppf2ValidationOffset +
-- ppf2ValidationSize' = 0x9720 bytes for the validation block. Use a
-- generator that always produces sources past that threshold.
prop_ppf2 :: Property
prop_ppf2 = forAll genPPF2SizedPair $ \(source, target) ->
  case createPatch (CreateDirect CreatePPF2) Nothing (InputFileContents source) (OutputFileContents target) noMetadataRequested Nothing noConstraintsRequested noDialectsRequested of
    Left slapError -> counterexample ("create: " ++ renderSlapError slapError) $ property False
    Right (CreateResult patch _) -> case PPF2.parsePPF2 patch of
       Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
       Right (Parsed parsed _parseWarnings) -> PPF2.applyPPF2 parsed (InputFileContents source) === Right (OutputFileContents target)
  where
    -- 0x9720 is the absolute minimum; bump to 0xA000 so QuickCheck-shrunk
    -- examples still fit, with a few KB of records-target headroom.
    minimumPPF2Source = 0xA000
    genPPF2SizedPair = do
      sourceLen <- choose (minimumPPF2Source, minimumPPF2Source + 8192)
      growth    <- choose (0, 1024)
      src <- ByteString.pack <$> vectorOf sourceLen arbitrary
      tgt <- ByteString.pack <$> vectorOf (sourceLen + growth) arbitrary
      pure (src, tgt)

-- | A 'FileSize' one byte past the 'Word32' wire-field ceiling
-- ('0x100000000') is what the convert pipeline would have silently
-- truncated before 'narrowPPF2SourceSize' became the only entry point
-- to 'PPF2SourceSize'. The test exercises the narrowing function
-- directly rather than building a 4 GiB 'ByteString' to drive the
-- pipeline; the convert arm's only behavior on overflow is to bubble
-- this 'NarrowingError' up unchanged.
ppf2SourceSizeAdversarial :: Assertion
ppf2SourceSizeAdversarial =
  case narrowPPF2SourceSize (FileSize 0x100000000) of
    Left (NarrowingError (FieldValueExceedsBound LabelPPF2 FieldSourceSize
                            actual maxValue)) -> do
      assertEqual "actual"  0x100000000 actual
      assertEqual "maximum" 0xFFFFFFFF  maxValue
    other -> assertFailure
               ("expected NarrowingError FieldValueExceedsBound, got " ++ show other)

-- | Parallel to 'ppf2SourceSizeAdversarial': an oversize source ROM
-- has to bottom out as 'NarrowingError' rather than silently truncate
-- through the DPS header's 4-byte LE source-size field. Driving the
-- narrowing function directly avoids a 4 GiB 'ByteString'.
dpsSourceSizeAdversarial :: Assertion
dpsSourceSizeAdversarial =
  case narrowDPSSourceSize (FileSize 0x100000000) of
    Left (NarrowingError (FieldValueExceedsBound LabelDPS FieldSourceSize
                            actual maxValue)) -> do
      assertEqual "actual"  0x100000000 actual
      assertEqual "maximum" 0xFFFFFFFF  maxValue
    other -> assertFailure
               ("expected NarrowingError FieldValueExceedsBound, got " ++ show other)

-- | Parallel to 'dpsSourceSizeAdversarial' for the per-record
-- offset: a 'DPSRecord' carrying an offset above 'Word32' max has
-- to bottom out as 'NarrowingError' rather than silently truncate
-- through the record's 4-byte LE output-offset field.
dpsRecordOffsetAdversarial :: Assertion
dpsRecordOffsetAdversarial =
  let oversize = Offset 0x100000000
      record   = DPSCopyFromROM oversize (Offset 0) (Length 0)
  in case narrowDPSRecord record of
       Left (NarrowingError (FieldValueExceedsBound LabelDPS FieldRecordOutputOffset
                               actual maxValue)) -> do
         assertEqual "actual"  0x100000000 actual
         assertEqual "maximum" 0xFFFFFFFF  maxValue
       other -> assertFailure
                  ("expected NarrowingError FieldValueExceedsBound, got " ++ show other)

-- | Parallel to 'ppf2SourceSizeAdversarial' for APS-GBA. APS-GBA
-- has no parser-side roundtrip through 'APSGBASourceSize', so this
-- exercises the narrow function directly.
apsGbaSourceSizeAdversarial :: Assertion
apsGbaSourceSizeAdversarial =
  case narrowAPSGBASourceSize (FileSize 0x100000000) of
    Left (NarrowingError (FieldValueExceedsBound LabelAPSGBA FieldSourceSize
                            actual maxValue)) -> do
      assertEqual "actual"  0x100000000 actual
      assertEqual "maximum" 0xFFFFFFFF  maxValue
    other -> assertFailure
               ("expected NarrowingError FieldValueExceedsBound, got " ++ show other)

prop_ppf3 :: Property
prop_ppf3 = forAll genPairNoShrink $ \(source, target) ->
  case createPatch (CreateDirect CreatePPF3) Nothing (InputFileContents source) (OutputFileContents target) noMetadataRequested Nothing noConstraintsRequested noDialectsRequested of
    Left slapError -> counterexample ("create: " ++ renderSlapError slapError) $ property False
    Right (CreateResult patch _) -> case PPF3.parsePPF3 patch of
       Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
       Right (Parsed parsed _parseWarnings) -> PPF3.applyPPF3 parsed (InputFileContents source) === Right (OutputFileContents target)

prop_pmsr :: Property
prop_pmsr = forAll genPairNoShrink $ \(source, target) ->
  case createPatch (CreateDirect CreatePMSR) Nothing (InputFileContents source) (OutputFileContents target) noMetadataRequested Nothing noConstraintsRequested noDialectsRequested of
    Left slapError -> counterexample ("create: " ++ renderSlapError slapError) $ property False
    Right (CreateResult patch _) -> case PMSR.parsePMSR patch of
       Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
       Right (Parsed parsed _parseWarnings) ->
         PMSR.applyPMSR parsed (InputFileContents source) === Right (OutputFileContents target)

prop_ninja1 :: Property
prop_ninja1 = forAll genPairNoShrink $ \(source, target) ->
  case createPatch (CreateDirect CreateNINJA1) Nothing (InputFileContents source) (OutputFileContents target) noMetadataRequested Nothing noConstraintsRequested noDialectsRequested of
    Left slapError -> counterexample ("create: " ++ renderSlapError slapError) $ property False
    Right (CreateResult patch _) -> case NINJA1.parseNINJA1 patch of
       Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
       Right (Parsed parsed _parseWarnings) ->
         NINJA1.applyNINJA1 parsed (InputFileContents source) === Right (OutputFileContents target)

prop_ninja1Hashes :: Property
prop_ninja1Hashes = forAll genPairNoShrink $ \(source, _) ->
  not (ByteString.null source) ==>
  case createPatch (CreateDirect CreateNINJA1) Nothing (InputFileContents source) (OutputFileContents source) noMetadataRequested Nothing noConstraintsRequested noDialectsRequested of
    Left slapError -> counterexample ("create: " ++ renderSlapError slapError) $ property False
    Right (CreateResult patch _) -> case NINJA1.parseNINJA1 patch of
       Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
       Right (Parsed parsed _parseWarnings) ->
         NINJA1.ninja1SourceCRC parsed === Just (crc32 source) .&&.
         NINJA1.ninja1SourceMD5 parsed === Just (md5 source) .&&.
         NINJA1.ninja1SourceSHA1 parsed === Just (sha1 source)

-- | NINJA1's binary footer is @[0x03][0x45][0x4F][0x46]@ — a width
-- prefix of 3 followed by the bytes @"EOF"@. A record at offset
-- @0x454F46@ minimally encodes to those same three bytes; without
-- 'NINJA1.resolveSentinelCollisions' the parser stops at the
-- colliding record and silently drops every record after it. This
-- property exercises the shift-and-prepend fix on the live create
-- path: source and target differ at exactly the sentinel offset, so
-- a record there is both inevitable and the only record in the
-- patch — making any silent drop catastrophic for round-trip.
prop_ninja1EofCollision :: Property
prop_ninja1EofCollision = withNumTests 20 $ forAll genEofPair $ \(source, target) ->
  case createPatch (CreateDirect CreateNINJA1) Nothing (InputFileContents source) (OutputFileContents target) noMetadataRequested Nothing noConstraintsRequested noDialectsRequested of
    Left slapError -> counterexample ("create: " ++ renderSlapError slapError) $ property False
    Right (CreateResult patch _) -> case NINJA1.parseNINJA1 patch of
      Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
      Right (Parsed parsed _parseWarnings) ->
        NINJA1.applyNINJA1 parsed (InputFileContents source) === Right (OutputFileContents target)

-- | Source-less conversion of a record sitting on the NINJA1 sentinel
-- offset must raise 'SentinelCollisionUnfixable' rather than silently
-- passing through or crashing. Mirrors 'prop_sourcelessSentinelRejected'
-- for IPS; the two formats share the sentinel offset value but their
-- resolution code paths are deliberately separate.
prop_ninja1SourcelessSentinelRejected :: Property
prop_ninja1SourcelessSentinelRejected = once $
  let ninja1Sentinel = SentinelOffset (Offset 0x454F46)
      collidingContents =
        emptyContents [Hunk (Offset 0x454F46) (ByteString.pack [0xFF])]
  in case convertDirect collidingContents (CreateDirect CreateNINJA1) noMetadataRequested noConstraintsRequested noDialectsRequested of
       Left (SentinelCollisionUnfixable LabelNINJA1 offset) ->
         offset === ninja1Sentinel
       Left other ->
         counterexample ("unexpected error: " ++ renderSlapError other) $
           property False
       Right _ ->
         counterexample "expected Left SentinelCollisionUnfixable, got Right" $
           property False

-- DPS: differential, no truncation
prop_dps :: Property
prop_dps = forAll genPairNoShrink $ \(source, target) ->
  case createDPS (InputFileContents source) (OutputFileContents target)
         (DPS.DPSMetadata { DPS.dpsMetadataName = "", DPS.dpsMetadataAuthor = "", DPS.dpsMetadataVersion = "" })
         DPS.DPSStable of
    Left createError -> counterexample ("create: " ++ renderSlapError createError) $ property False
    Right (CreateResult patch _) -> case DPS.parseDPS patch of
      Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
      Right (Parsed parsed _parseWarnings) -> DPS.applyDPS parsed (InputFileContents source) === Right (OutputFileContents target)

prop_ninja2 :: Property
prop_ninja2 = forAll genPair $ \(source, target) ->
  case createNINJA2 (InputFileContents source) (OutputFileContents target) emptyNINJA2Metadata of
    Left createError -> counterexample ("create: " ++ renderSlapError createError) $ property False
    Right (CreateResult patch _) -> case NINJA2.parseNINJA2 patch of
      Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
      Right (Parsed parsed _parseWarnings) ->
        NINJA2.applyNINJA2 parsed (InputFileContents source) === Right (OutputFileContents target)

-- | Round-trip restricted to the @len(source) > len(target)@ regime,
-- where the NINJA2 wire carries the discarded source tail as a
-- truncate-mode overflow.  The general 'prop_ninja2' covers this
-- regime probabilistically; this property guarantees every test
-- case lands on it, so a regression that overruns the output buffer
-- by re-applying the truncate overflow gets caught immediately.
prop_ninja2Truncate :: Property
prop_ninja2Truncate = forAll genShrinkingPair $ \(source, target) ->
  case createNINJA2 (InputFileContents source) (OutputFileContents target) emptyNINJA2Metadata of
    Left createError -> counterexample ("create: " ++ renderSlapError createError) $ property False
    Right (CreateResult patch _) -> case NINJA2.parseNINJA2 patch of
      Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
      Right (Parsed parsed _parseWarnings) ->
        NINJA2.applyNINJA2 parsed (InputFileContents source) === Right (OutputFileContents target)

prop_ninja2Hashes :: Property
prop_ninja2Hashes = forAll genPair $ \(source, target) ->
  case createNINJA2 (InputFileContents source) (OutputFileContents target) emptyNINJA2Metadata of
    Left createError -> counterexample ("create: " ++ renderSlapError createError) $ property False
    Right (CreateResult patch _) -> case NINJA2.parseNINJA2 patch of
      Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
      Right (Parsed parsed _parseWarnings) ->
        fmap NINJA2.openNewFileSourceMD5 (NINJA2.ninja2OpenNewFile parsed) === Just (md5 source) .&&.
        fmap NINJA2.openNewFileTargetMD5 (NINJA2.ninja2OpenNewFile parsed) === Just (md5 target)

-- | The NINJA2 file spec specifies that the first byte of an
-- OPEN_NEW_FILE block (FILE_N_MUL) "0 Signals single-file" — meaning a
-- literal zero byte is the sentinel and FILE_N_LEN/FILE_NAME do not
-- follow. This is structurally distinct from a length-1 VLV holding the
-- value 0 (@01 00@), which would mean "filename of length 0" and force
-- a parser to read zero further bytes — fragile by design. The 2006
-- ninja-2.0 PHP reference applier crashes on the latter shape with
-- @fread(): length must be greater than 0@, exposing that a length-1
-- VLV is not what the spec means.
--
-- This test pins slap's encoder to emit the spec-correct sentinel: the
-- byte at offset 0x801 (immediately after the 0x01 OPEN_NEW_FILE
-- opcode) must be @0x00@, and the byte that follows must be the ROM
-- type (0x00 for raw, given an empty metadata bag), not another VLV
-- length byte.
ninja2SingleFileSentinelIsZero :: Assertion
ninja2SingleFileSentinelIsZero =
  case createNINJA2 (InputFileContents ByteString.empty) (OutputFileContents ByteString.empty) emptyNINJA2Metadata of
    Left createError -> assertFailure ("create: " ++ renderSlapError createError)
    Right (CreateResult (PatchFileContents bytes) _) -> do
      assertEqual "OPEN_NEW_FILE opcode at 0x800"  0x01 (ByteString.index bytes 0x800)
      assertEqual "FILE_N_MUL single-file sentinel at 0x801" 0x00 (ByteString.index bytes 0x801)
      assertEqual "ROM type byte at 0x802 (raw default)"     0x00 (ByteString.index bytes 0x802)

-- | Both PATCH_ENC values the NINJA2 spec defines must survive a
-- create-then-parse trip intact: the byte the encoder writes at offset
-- 6 must round-trip through the parser back into the same
-- 'PatchEncoding' constructor it was created with. Empty source and
-- target keep the test focused on the header byte the property is
-- about; the round-trip body is exercised exhaustively by 'prop_ninja2'.
ninja2EncodingRoundTrips :: NINJA2.PatchEncoding -> Assertion
ninja2EncodingRoundTrips encoding =
  let metadata = emptyNINJA2Metadata { NINJA2.ninja2MetadataEncoding = encoding }
  in case createNINJA2 (InputFileContents ByteString.empty) (OutputFileContents ByteString.empty) metadata of
       Left createError -> assertFailure ("create: " ++ renderSlapError createError)
       Right (CreateResult patch _) -> case NINJA2.parseNINJA2 patch of
         Left slapError -> assertFailure ("parse: " ++ renderSlapError slapError)
         Right (Parsed parsed _parseWarnings) ->
           assertEqual "PATCH_ENC round-trip" encoding (NINJA2.ninja2PatchEncoding parsed)

-- | A NINJA2 description whose UTF-8 encoding ends with a 4-byte
-- codepoint placed exactly one byte past the field's wire width
-- forces 'truncateUtf8' to drop the entire codepoint at the
-- codepoint boundary, leaving stored bytes 3 shorter than the field
-- width. The warning the create path emits reports the
-- actually-stored byte count in 'TruncatedLength', not the field
-- width — matching DPS, APSN64, and PPF3, and matching what the
-- parser will read back from the same patch. Pre-fix, the warning
-- carried 'fieldLength' as the truncated value, which silently
-- diverged from the bytes actually stored.
ninja2FieldTruncationWarningReportsActualStoredLength :: Assertion
ninja2FieldTruncationWarningReportsActualStoredLength =
  let asciiPrefixLength       = unLength NINJA2.ninja2DescriptionWidth - 3
      asciiPrefix             = replicate asciiPrefixLength 'a'
      fourByteCodepoint       = '\x1F3AE'   -- 🎮 (U+1F3AE), encodes to 4 UTF-8 bytes
      description             = asciiPrefix ++ [fourByteCodepoint]
      expectedOriginalLength  = Length (asciiPrefixLength + 4)
      expectedStoredLength    = Length asciiPrefixLength
      metadata                = emptyNINJA2Metadata
        { NINJA2.ninja2MetadataDescription = Just description
        , NINJA2.ninja2MetadataEncoding    = NINJA2.PatchEncodingUTF8
        }
  in case createNINJA2 (InputFileContents ByteString.empty) (OutputFileContents ByteString.empty) metadata of
       Left createError -> assertFailure ("create: " ++ renderSlapError createError)
       Right (CreateResult patch warnings) -> do
         (reportedOriginalLength, reportedTruncatedLength) <-
           case [(originalLen, truncatedLen)
                | FieldTruncated LabelNINJA2 FieldDescription originalLen truncatedLen
                    <- warnings] of
             [singletonPair] -> pure singletonPair
             []              -> assertFailure "expected exactly one FieldTruncated warning for description"
             multiplePairs   -> assertFailure ("expected one warning, got " ++ show (length multiplePairs))
         let OriginalLength reportedOriginal = reportedOriginalLength
             TruncatedLength reportedTruncated = reportedTruncatedLength
         assertEqual "warning's OriginalLength == full encoded byte count"
           expectedOriginalLength reportedOriginal
         assertEqual "warning's TruncatedLength == actual stored byte count"
           expectedStoredLength reportedTruncated
         case NINJA2.parseNINJA2 patch of
           Left slapError -> assertFailure ("parse: " ++ renderSlapError slapError)
           Right (Parsed parsed _) -> case NINJA2.ninja2Description (NINJA2.ninja2Header parsed) of
             Nothing -> assertFailure "parsed description was Nothing; expected the truncated bytes"
             Just storedBytes ->
               assertEqual "parsed-back stored byte count matches the warning"
                 (byteLength storedBytes) reportedTruncated

----------------------------------------------------------------------------
-- PPF1/2/3 description text-encoding round-trip and truncation
----------------------------------------------------------------------------

-- | A non-ASCII codepoint payload that takes 9 UTF-8 bytes and fits
-- comfortably inside the 50-byte PPF description field. Under a UTF-8
-- process locale the encode+decode round-trips byte-for-byte; under
-- a non-UTF-8 locale the test still expects the same Text back
-- because slap re-encodes through the same locale resolver on both
-- ends.
ppfNonAsciiDescriptionText :: Text.Text
ppfNonAsciiDescriptionText = Text.pack "\x65E5\x672C\x8A9E"  -- "Japanese language"

-- | An overflow probe: 47 ASCII bytes plus a 4-byte UTF-8 codepoint
-- (🎮, U+1F3AE) — encoded length 51, one byte past the 50-byte cap.
-- 'encodeTextBounded' drops the 4-byte codepoint whole and keeps the
-- 47-byte prefix; pre-stage-3a 'encodeBoundedLocale' would have cut
-- at a raw byte boundary (it relied on iconv's locale-encoded
-- truncation which has no codepoint awareness for non-UTF-8 locales).
ppfTruncationProbeText :: Text.Text
ppfTruncationProbeText = Text.pack (replicate 47 'a' ++ ['\x1F3AE'])

ppfTruncationProbeExpectedOriginal :: Length
ppfTruncationProbeExpectedOriginal = Length 51

ppfTruncationProbeExpectedTruncated :: Length
ppfTruncationProbeExpectedTruncated = Length 47

-- | A non-ASCII description round-trips byte-faithfully when re-encoding
-- the parsed-back text under the same locale produces wire bytes
-- identical to the original encode. Slap parses the description with
-- its padding bytes intact, so a text-level @==@ comparison would
-- need format-specific padding-stripping; the byte-level identity
-- check is the cleaner end-to-end claim: parse-then-re-create
-- preserves the field exactly.
ppfDescriptionRoundTripsByteFaithfully
  :: CreateResult
  -> (PatchFileContents -> Either SlapError (Parsed a))
  -> (a -> SlapText.EncodedText)
  -> (SlapText.EncodedText -> CreateResult)
  -> String
  -> Assertion
ppfDescriptionRoundTripsByteFaithfully
    (CreateResult originalBytes _) parseFn descriptionOf reEncode formatName =
  case parseFn originalBytes of
    Left slapError -> assertFailure (formatName ++ " parse: " ++ renderSlapError slapError)
    Right (Parsed parsed _) ->
      let CreateResult reEncodedBytes _ = reEncode (descriptionOf parsed)
      in assertEqual (formatName ++ " parse-then-re-create produces byte-identical wire bytes")
           (unPatchFileContents originalBytes)
           (unPatchFileContents reEncodedBytes)

-- | Codepoint-aware-truncation assertion shared by PPF1/PPF2/PPF3:
-- exactly one 'FieldTruncated' warning, naming the right format, the
-- description field, and matching the byte-count probe.
assertPPFDescriptionTruncationWarning
  :: FormatLabel -> [SlapAdvisory] -> Assertion
assertPPFDescriptionTruncationWarning expectedLabel advisories =
  case [(originalLen, truncatedLen)
        | FieldTruncated formatLabel FieldDescription originalLen truncatedLen <- advisories
        , formatLabel == expectedLabel] of
    [(OriginalLength original, TruncatedLength storedLength)] -> do
      assertEqual "OriginalLength reports the full encoded byte count"
        ppfTruncationProbeExpectedOriginal original
      assertEqual "TruncatedLength reports the actually-stored byte count"
        ppfTruncationProbeExpectedTruncated storedLength
    []         -> assertFailure ("expected one FieldTruncated warning for "
                                 ++ show expectedLabel ++ " description")
    multiple   -> assertFailure ("expected one warning, got "
                                 ++ show (length multiple))

ppf1DescriptionUtf8RoundTrip :: Assertion
ppf1DescriptionUtf8RoundTrip =
  let descriptionTyped = SlapText.EncodedText SlapText.EncodingLocale ppfNonAsciiDescriptionText
      patchResult      = PPF1.encodePPF1 PPF1OriginPC [] descriptionTyped
  in ppfDescriptionRoundTripsByteFaithfully patchResult
       (PPF1.parsePPF1 PPF1OriginPC)
       PPF1.ppf1Description
       (PPF1.encodePPF1 PPF1OriginPC [])
       "PPF1"

ppf1DescriptionCodepointAwareTruncation :: Assertion
ppf1DescriptionCodepointAwareTruncation =
  let descriptionTyped = SlapText.EncodedText SlapText.EncodingLocale ppfTruncationProbeText
      CreateResult _ advisories =
        PPF1.encodePPF1 PPF1OriginPC [] descriptionTyped
  in assertPPFDescriptionTruncationWarning LabelPPF1 advisories

ppf2DescriptionUtf8RoundTrip :: Assertion
ppf2DescriptionUtf8RoundTrip =
  let descriptionTyped = SlapText.EncodedText SlapText.EncodingLocale ppfNonAsciiDescriptionText
      sourceSize       = case narrowPPF2SourceSize (FileSize 0x9720) of
        Right size -> size
        Left  err  -> error ("narrowPPF2SourceSize: " ++ renderSlapError err)
      validation       = PPF2.PPF2ValidationBlock (ByteString.replicate 1024 0)
      patchResult      = PPF2.encodePPF2 [] descriptionTyped sourceSize validation
      reEncodePPF2 d   = PPF2.encodePPF2 [] d sourceSize validation
  in ppfDescriptionRoundTripsByteFaithfully patchResult
       PPF2.parsePPF2
       PPF2.ppf2Description
       reEncodePPF2
       "PPF2"

ppf2DescriptionCodepointAwareTruncation :: Assertion
ppf2DescriptionCodepointAwareTruncation =
  let descriptionTyped = SlapText.EncodedText SlapText.EncodingLocale ppfTruncationProbeText
      sourceSize       = case narrowPPF2SourceSize (FileSize 0x9720) of
        Right size -> size
        Left  err  -> error ("narrowPPF2SourceSize: " ++ renderSlapError err)
      validation       = PPF2.PPF2ValidationBlock (ByteString.replicate 1024 0)
      CreateResult _ advisories =
        PPF2.encodePPF2 [] descriptionTyped sourceSize validation
  in assertPPFDescriptionTruncationWarning LabelPPF2 advisories

ppf3DescriptionUtf8RoundTrip :: Assertion
ppf3DescriptionUtf8RoundTrip =
  let descriptionTyped = SlapText.EncodedText SlapText.EncodingLocale ppfNonAsciiDescriptionText
      patchResult      = PPF3.encodePPF3 [] descriptionTyped Nothing Nothing BIN
      reEncodePPF3 d   = PPF3.encodePPF3 [] d Nothing Nothing BIN
  in ppfDescriptionRoundTripsByteFaithfully patchResult
       PPF3.parsePPF3
       PPF3.ppf3Description
       reEncodePPF3
       "PPF3"

ppf3DescriptionCodepointAwareTruncation :: Assertion
ppf3DescriptionCodepointAwareTruncation =
  let descriptionTyped = SlapText.EncodedText SlapText.EncodingLocale ppfTruncationProbeText
      CreateResult _ advisories =
        PPF3.encodePPF3 [] descriptionTyped Nothing Nothing BIN
  in assertPPFDescriptionTruncationWarning LabelPPF3 advisories

-- | A FILE_ID.DIZ body that round-trips byte-faithfully under a
-- UTF-8 locale: the typed text encodes to identical bytes whether
-- read by parse or rewritten by create, so the trailer wraps and
-- unwraps cleanly with the format's wire-level marker/length frame.
ppfFileIdDizSampleText :: Text.Text
ppfFileIdDizSampleText = Text.pack "slap sample FILE_ID.DIZ\nline two\n"

ppf2FileIdDizRoundTrip :: Assertion
ppf2FileIdDizRoundTrip =
  let descriptionTyped = SlapText.EncodedText SlapText.EncodingLocale Text.empty
      sourceSize       = case narrowPPF2SourceSize (FileSize 0x9720) of
        Right size -> size
        Left  err  -> error ("narrowPPF2SourceSize: " ++ renderSlapError err)
      validation       = PPF2.PPF2ValidationBlock (ByteString.replicate 1024 0)
      fileIdText       = SlapText.EncodedText SlapText.EncodingLocale ppfFileIdDizSampleText
      fileId = case narrowPPF2FileId fileIdText of
        Right value -> value
        Left  err   -> error ("narrowPPF2FileId: " ++ renderSlapError err)
      CreateResult patchBytes _ =
        PPF2.encodePPF2 [] descriptionTyped sourceSize validation
      (trailerBytes, _trailerAdv) = PPF2.encodeFileIdDiz fileId
      stitched = PatchFileContents (unPatchFileContents patchBytes <> trailerBytes)
  in case PPF2.parsePPF2 stitched of
       Left slapError -> assertFailure ("PPF2 parse: " ++ renderSlapError slapError)
       Right (Parsed parsed _) -> case PPF2.ppf2FileId parsed of
         Nothing  -> assertFailure "PPF2 parsed file_id.diz was Nothing; expected trailer"
         Just fid ->
           assertEqual "PPF2 parsed file_id.diz content matches the original"
             ppfFileIdDizSampleText
             (SlapText.encodedTextContent (PPF2.unPPF2FileId fid))

ppf3FileIdDizRoundTrip :: Assertion
ppf3FileIdDizRoundTrip =
  let descriptionTyped = SlapText.EncodedText SlapText.EncodingLocale Text.empty
      fileIdText       = SlapText.EncodedText SlapText.EncodingLocale ppfFileIdDizSampleText
      fileId = case narrowPPF3FileId fileIdText of
        Right value -> value
        Left  err   -> error ("narrowPPF3FileId: " ++ renderSlapError err)
      CreateResult patchBytes _ =
        PPF3.encodePPF3 [] descriptionTyped Nothing Nothing BIN
      (trailerBytes, _trailerAdv) = PPF3.encodeFileIdDiz fileId
      stitched = PatchFileContents (unPatchFileContents patchBytes <> trailerBytes)
  in case PPF3.parsePPF3 stitched of
       Left slapError -> assertFailure ("PPF3 parse: " ++ renderSlapError slapError)
       Right (Parsed parsed _) -> case PPF3.ppf3FileId parsed of
         Nothing  -> assertFailure "PPF3 parsed file_id.diz was Nothing; expected trailer"
         Just fid ->
           assertEqual "PPF3 parsed file_id.diz content matches the original"
             ppfFileIdDizSampleText
             (SlapText.encodedTextContent (PPF3.unPPF3FileId fid))

-- PCHTXT: pure direct, no truncation
prop_pchtxt :: Property
prop_pchtxt = forAll genPairNoShrink $ \(source, target) ->
  case createPatch (CreateDirect CreatePCHTXT) Nothing (InputFileContents source) (OutputFileContents target) noMetadataRequested Nothing noConstraintsRequested noDialectsRequested of
    Left slapError -> counterexample ("create: " ++ renderSlapError slapError) $ property False
    Right (CreateResult patch _) -> case PCHTXT.parsePCHTXT patch of
       Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
       Right (Parsed parsed _parseWarnings) ->
         PCHTXT.applyPCHTXT parsed (InputFileContents source) === Right (OutputFileContents target)

-- APS-N64: pure direct, no truncation
prop_apsN64 :: Property
prop_apsN64 = forAll genPairNoShrink $ \(source, target) ->
  case createPatch (CreateDirect CreateAPSN64) Nothing (InputFileContents source) (OutputFileContents target) noMetadataRequested Nothing noConstraintsRequested noDialectsRequested of
    Left slapError -> counterexample ("create: " ++ renderSlapError slapError) $ property False
    Right (CreateResult patch _) -> case APSN64.parseAPSN64 patch of
       Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
       Right (Parsed parsed _parseWarnings) ->
         APSN64.applyAPSN64 parsed (InputFileContents source) === Right (OutputFileContents target)

----------------------------------------------------------------------------
-- BPS efficiency properties
----------------------------------------------------------------------------

-- | Block move: 4 KB of data moves from offset 0x1000 to offset 0x8000.
-- The rolling-hash diff should emit SourceCopy, producing a small patch
-- rather than 4 KB of literal bytes.
prop_bpsBlockMove :: Property
prop_bpsBlockMove = once $
  let blockSize = 4096
      block = ByteString.pack [fromIntegral ((index * 7 + 3) `mod` 251) | index <- [0..blockSize-1] :: [Int]]
      padding1 = 0x1000
      padding2 = 0x8000
      sourceLength = padding2 + blockSize
      source = ByteString.replicate padding1 0 <> block <> ByteString.replicate (sourceLength - padding1 - blockSize) 0
      target = ByteString.replicate padding2 0 <> block
  in case createBPS (InputFileContents source) (OutputFileContents target) (BPSMetadata ByteString.empty) of
       Left createError -> counterexample ("create: " ++ renderSlapError createError) $ property False
       Right (CreateResult patch _) ->
         counterexample ("patch size: " ++ show (ByteString.length (unPatchFileContents patch))
                          ++ " (block: " ++ show blockSize ++ ")") $
         conjoin
           [ case BPS.parseBPS patch of
               Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
               Right (Parsed parsed _parseWarnings) -> BPS.applyBPS parsed (InputFileContents source) === Right (OutputFileContents target)
           , property (ByteString.length (unPatchFileContents patch) < 1024)
           ]

-- | Patch size should not regress: a random diff with the rolling-hash
-- algorithm must produce patches no larger than a pure-literal encoding
-- (TargetRead for every byte), which costs targetLen + small overhead.
prop_bpsNoSizeRegression :: Property
prop_bpsNoSizeRegression = forAll genPair $ \(source, target) ->
  case createBPS (InputFileContents source) (OutputFileContents target) (BPSMetadata ByteString.empty) of
    Left createError -> counterexample ("create: " ++ renderSlapError createError) $ property False
    Right (CreateResult patch _) ->
      let maxPatchSize = ByteString.length target + 100
          patchSize = ByteString.length (unPatchFileContents patch)
      in counterexample ("patch size: " ++ show patchSize
                          ++ ", max: " ++ show maxPatchSize) $
         patchSize <= maxPatchSize

----------------------------------------------------------------------------
-- PCHTXT parse unit tests
----------------------------------------------------------------------------

parsePchtxtEscapes :: IO ()
parsePchtxtEscapes = do
  raw <- ByteString.readFile "test/data/pchtxt/escapes.pchtxt"
  case PCHTXT.parsePCHTXT (PatchFileContents raw) of
    Left slapError -> assertEqual ("parse failed: " ++ renderSlapError slapError) True False
    Right (Parsed parsed _parseWarnings) -> assertEqual "expected 2 entries" 2
      (length (concatMap PCHTXT.pchtxtBlockEntries (PCHTXT.pchtxtBlocks parsed)))

parsePchtxtSphinx :: IO ()
parsePchtxtSphinx = do
  raw <- ByteString.readFile "test/data/pchtxt/sphinx.pchtxt"
  case PCHTXT.parsePCHTXT (PatchFileContents raw) of
    Left slapError -> assertEqual ("parse failed: " ++ renderSlapError slapError) True False
    Right (Parsed parsed _parseWarnings) -> do
      assertEqual "expected nsobid" True (PCHTXT.pchtxtNsobid parsed /= Nothing)
      case PCHTXT.pchtxtBlocks parsed of
        [block] -> assertEqual "block should be disabled" False (PCHTXT.pchtxtBlockEnabled block)
        blocks  -> assertEqual ("expected 1 block, got " ++ show (length blocks)) 1 (length blocks)

----------------------------------------------------------------------------
-- XDelta1 round-trip
--
-- The differ is a placeholder today (entire target inline as data
-- segment, one instruction copies it); these tests pin the
-- create→parse→apply round-trip under that shape. When the real
-- differ lands later, these properties stay green — only the size
-- of the produced patch changes.
----------------------------------------------------------------------------

-- | Stand-in 'ResolvedXDelta1FileNames' used by every xdelta1
-- round-trip property here: the names are immaterial to the
-- create→parse→apply invariant under test (apply consults
-- 'xdelta1SourceMD5' and 'xdelta1Verification', not the display
-- labels), so a once-resolved pair feeds every call. Routing
-- through 'resolveXDelta1FileNames' rather than constructing the
-- smart-constructor type directly is the only way: the bare
-- constructor isn't exported from "Slap.XDelta1.Types".
xdelta1FixtureNames :: ResolvedXDelta1FileNames
xdelta1FixtureNames =
  case resolveXDelta1FileNames (Just "source") (Just "target")
                               "ignored-source-path" "ignored-target-path" of
    Right resolved -> resolved
    Left err -> error ("xdelta1FixtureNames: " ++ renderSlapError err)

prop_xdelta1RoundTrips :: Property
prop_xdelta1RoundTrips =
  forAll genPair $ \(sourceBytes, targetBytes) ->
  forAll genCompression $ \compression ->
  case createXDelta1 IncludeVerification compression xdelta1FixtureNames (InputFileContents sourceBytes) (OutputFileContents targetBytes) of
    Left createError -> counterexample ("create: " ++ renderSlapError createError) (property False)
    Right (CreateResult patch _) -> case XDelta1.parseXDelta1 patch of
      Left parseError -> counterexample ("parse: " ++ renderSlapError parseError) (property False)
      Right (Parsed parsed _) -> case XDelta1.applyXDelta1 parsed (InputFileContents sourceBytes) of
        Left applyError    -> counterexample ("apply: " ++ renderSlapError applyError) (property False)
        Right outputBytes  -> outputBytes === OutputFileContents targetBytes

-- | The compression posture round-trips: parsing a created patch back
-- recovers the 'XDelta1PatchCompression' it was emitted under.
prop_xdelta1CompressionPostureRoundTrips :: Property
prop_xdelta1CompressionPostureRoundTrips =
  forAll genPair $ \(sourceBytes, targetBytes) ->
  forAll genCompression $ \compression ->
  case createXDelta1 IncludeVerification compression xdelta1FixtureNames (InputFileContents sourceBytes) (OutputFileContents targetBytes) of
    Left createError -> counterexample ("create: " ++ renderSlapError createError) (property False)
    Right (CreateResult patch _) -> case XDelta1.parseXDelta1 patch of
      Left parseError -> counterexample ("parse: " ++ renderSlapError parseError) (property False)
      Right (Parsed parsed _) -> XDelta1.xdelta1PatchCompression parsed === compression

prop_xdelta1CreateProducesVerifyPosture :: Property
prop_xdelta1CreateProducesVerifyPosture =
  forAll genPair $ \(sourceBytes, targetBytes) ->
  forAll genCompression $ \compression ->
  case createXDelta1 IncludeVerification compression xdelta1FixtureNames (InputFileContents sourceBytes) (OutputFileContents targetBytes) of
    Left createError -> counterexample ("create: " ++ renderSlapError createError) (property False)
    Right (CreateResult patch _) -> case XDelta1.parseXDelta1 patch of
      Left parseError -> counterexample ("parse: " ++ renderSlapError parseError) (property False)
      Right (Parsed parsed _) -> case XDelta1.xdelta1Verification parsed of
        XDelta1.VerifyAgainstStoredMD5s _     -> property True
        XDelta1.CreatorOptedOutOfVerification ->
          counterexample "expected VerifyAgainstStoredMD5s from create" (property False)

-- | When slap creates an xdelta1 patch with 'OmitVerification' policy,
-- the resulting patch parses back to 'CreatorOptedOutOfVerification'
-- posture, applies correctly, and surfaces the
-- 'VerificationOptedOutByCreator' warning on parse.
prop_xdelta1NoVerifyRoundTrip :: Property
prop_xdelta1NoVerifyRoundTrip =
  forAll genPair $ \(sourceBytes, targetBytes) ->
  forAll genCompression $ \compression ->
  case createXDelta1 OmitVerification compression xdelta1FixtureNames (InputFileContents sourceBytes) (OutputFileContents targetBytes) of
    Left createError -> counterexample ("create: " ++ renderSlapError createError) (property False)
    Right (CreateResult patch _) -> case XDelta1.parseXDelta1 patch of
      Left parseError -> counterexample ("parse: " ++ renderSlapError parseError) (property False)
      Right (Parsed parsed warnings) ->
        let postureCheck = XDelta1.xdelta1Verification parsed === XDelta1.CreatorOptedOutOfVerification
            warningCheck = counterexample
              ("expected VerificationOptedOutByCreator warning, got: " ++ show warnings)
              (any isOptedOutByCreatorWarning warnings)
            applyCheck = case XDelta1.applyXDelta1 parsed (InputFileContents sourceBytes) of
              Left applyError    -> counterexample ("apply: " ++ renderSlapError applyError) (property False)
              Right outputBytes  -> outputBytes === OutputFileContents targetBytes
        in postureCheck .&&. warningCheck .&&. applyCheck
  where
    isOptedOutByCreatorWarning warning = case warning of
      VerificationOptedOutByCreator _ -> True
      _ -> False

genCompression :: Gen XDelta1PatchCompression
genCompression = elements [CompressedPatch, UncompressedPatch]

xdelta1EmptyTarget :: Assertion
xdelta1EmptyTarget = xdelta1RoundTripCase "hello world" ByteString.empty

xdelta1SingleByteTarget :: Assertion
xdelta1SingleByteTarget = xdelta1RoundTripCase "hello world" (ByteString.singleton 0x42)

xdelta1TargetEqualsSource :: Assertion
xdelta1TargetEqualsSource = xdelta1RoundTripCase payload payload
  where payload = "the source and target are identical"

xdelta1RoundTripCase :: ByteString.ByteString -> ByteString.ByteString -> Assertion
xdelta1RoundTripCase sourceBytes targetBytes =
  case createXDelta1 IncludeVerification CompressedPatch xdelta1FixtureNames (InputFileContents sourceBytes) (OutputFileContents targetBytes) of
    Left createError -> assertFailure ("create: " ++ renderSlapError createError)
    Right (CreateResult patch _) -> case XDelta1.parseXDelta1 patch of
      Left parseError -> assertFailure ("parse: " ++ renderSlapError parseError)
      Right (Parsed parsed _) -> case XDelta1.applyXDelta1 parsed (InputFileContents sourceBytes) of
        Left applyError -> assertFailure ("apply: " ++ renderSlapError applyError)
        Right outputBytes -> assertEqual "round-trip target" (OutputFileContents targetBytes) outputBytes

-- | The wire bit for @FLAG_NO_VERIFY@ is bit 0 of the first 32-bit
-- header word, which lives at file offset 8..11 (after the 8-byte
-- magic). Big-endian: bit 0 is the lowest-order bit of byte 11.
xdelta1NoVerifySetsFlagBit :: Assertion
xdelta1NoVerifySetsFlagBit =
  case createXDelta1 OmitVerification CompressedPatch xdelta1FixtureNames (InputFileContents "abcdef") (OutputFileContents "ghijkl") of
    Left createError -> assertFailure ("create: " ++ renderSlapError createError)
    Right (CreateResult (PatchFileContents patchBytes) _) -> do
      assertBool ("patch must be at least 12 bytes, got " ++ show (ByteString.length patchBytes))
        (ByteString.length patchBytes >= 12)
      let flagsLowByte = ByteString.index patchBytes 11
      assertBool ("FLAG_NO_VERIFY (bit 0) should be set; flags low byte = " ++ show flagsLowByte)
        (flagsLowByte `Bits.testBit` 0)

xdelta1IncludeVerifyClearsFlagBit :: Assertion
xdelta1IncludeVerifyClearsFlagBit =
  case createXDelta1 IncludeVerification CompressedPatch xdelta1FixtureNames (InputFileContents "abcdef") (OutputFileContents "ghijkl") of
    Left createError -> assertFailure ("create: " ++ renderSlapError createError)
    Right (CreateResult (PatchFileContents patchBytes) _) -> do
      assertBool "patch must be at least 12 bytes"
        (ByteString.length patchBytes >= 12)
      let flagsLowByte = ByteString.index patchBytes 11
      assertBool ("FLAG_NO_VERIFY (bit 0) should be clear under IncludeVerification; flags low byte = " ++ show flagsLowByte)
        (not (flagsLowByte `Bits.testBit` 0))

-- | Pins the parser-side half of the @ST_XdeltaControl@ type-tag fix
-- in 'Slap.XDelta1.Parse.parseControlBody': slap previously
-- @skip (Length 8)@ed the type tag + allocation prelude without
-- inspection, which is how it failed to notice that its own encoder
-- was writing all-zero bytes there — a shape canonical xdelta-1.x
-- rejects with "Unregistered library: 0".
--
-- This test creates an uncompressed patch (so the control prelude is
-- on the wire literally, not behind a gzip stream), corrupts the
-- high byte of the type tag, and asserts the parser refuses with an
-- error message that names what went wrong.
xdelta1RejectsWrongControlTypeTag :: Assertion
xdelta1RejectsWrongControlTypeTag =
  case createXDelta1 IncludeVerification UncompressedPatch
                     xdelta1FixtureNames
                     (InputFileContents "abcdef")
                     (OutputFileContents "ghijkl") of
    Left createError -> assertFailure ("create: " ++ renderSlapError createError)
    Right (CreateResult (PatchFileContents patchBytes) _) ->
      let totalLength    = ByteString.length patchBytes
          controlOffset  = fromIntegral (getWord32BE (totalLength - 12) patchBytes) :: Int
          corruptedBytes = ByteString.concat
            [ ByteString.take controlOffset patchBytes
            , ByteString.singleton 0xFF        -- flip high byte of type tag
            , ByteString.drop (controlOffset + 1) patchBytes
            ]
      in case XDelta1.parseXDelta1 (PatchFileContents corruptedBytes) of
        Right _ -> assertFailure
          "expected parser to reject corrupted control type tag; parse succeeded"
        Left parseError ->
          let rendered = renderSlapError parseError
          in assertBool
               ("rejection should name the type tag (got: " ++ rendered ++ ")")
               (   "type tag"        `isInfixOf` rendered
                || "ST_XdeltaControl" `isInfixOf` rendered)
