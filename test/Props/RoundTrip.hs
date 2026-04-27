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
import Slap.IPS.Types (OffsetWidth(..), EBPPatch(..), IPSParseResult(..))
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
import qualified Slap.NINJA2.Types as NINJA2
import qualified Slap.NINJA2.Parse as NINJA2
import qualified Slap.NINJA2.Apply as NINJA2
import qualified Slap.APSN64.Parse as APSN64
import qualified Slap.APSN64.Apply as APSN64
import qualified Slap.APSGBA.Parse as APSGBA
import qualified Slap.APSGBA.Apply as APSGBA
import qualified Slap.GDIFF.Apply as GDIFF
import qualified Slap.GDIFF.Create as GDIFF
import qualified Slap.GDIFF.Parse as GDIFF
import qualified Slap.GDIFF.Types as GDIFF
import qualified Slap.PPF.Parse as PPF
import qualified Slap.PPF.Apply as PPF
import qualified Slap.PCHTXT.Parse as PCHTXT
import qualified Slap.PCHTXT.Apply as PCHTXT
import qualified Slap.PCHTXT.Types as PCHTXT

import Slap.Binary (md5, sha1, diffHunks)
import Slap.Error (CreateResult(..), Parsed(..), SlapError(..), renderSlapError)
import Slap.FormatLabel (FormatLabel(..))
import Slap.Measure (Offset(..), Length(..), FileSize(..),
                     EncodedHunk(..), Hunk(..), SentinelOffset(..))
import Slap.FFI (rustyCRC32)
import Slap.FileContents (SourceFileContents(..), TargetFileContents(..), PatchFileContents(..))
import Slap.Convert (DirectCreate(..), CreateFormat(..),
                     noMetadataRequested, noConstraintsRequested, convertDirect, emptyContents)
import Slap.Create (createBPS, createUPS, createDPS, createNINJA2,
                    createAPSGBA, createGDIFF, createFromMemory)

import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Lazy as LazyByteString
import Data.Bits (shiftL)
import Data.ByteString.Builder (word8, byteString, toLazyByteString)
import Test.Tasty
import Test.Tasty.HUnit (testCase, assertEqual, assertFailure, Assertion)
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
  , testGroup "PPF3"
      [ testProperty "round-trip" prop_ppf3
      ]
  , testGroup "PMSR"
      [ testProperty "round-trip" prop_pmsr
      ]
  , testGroup "NINJA1"
      [ testProperty "round-trip" prop_ninja1
      , testProperty "hashes" prop_ninja1Hashes
      ]
  , testGroup "DPS"
      [ testProperty "round-trip" prop_dps
      ]
  , testGroup "NINJA2"
      [ testProperty "round-trip" prop_ninja2
      , testProperty "truncate-round-trip" prop_ninja2Truncate
      , testProperty "hashes" prop_ninja2Hashes
      , testCase "encoding-utf8-round-trips"   (ninja2EncodingRoundTrips NINJA2.PatchEncodingUTF8)
      , testCase "encoding-system-round-trips" (ninja2EncodingRoundTrips NINJA2.PatchEncodingSystem)
      ]
  , testGroup "APS-N64"
      [ testProperty "round-trip" prop_apsN64
      ]
  , testGroup "APS-GBA"
      [ testProperty "round-trip" prop_apsGba
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
  ]

----------------------------------------------------------------------------
-- Delta formats: handle any size combination
----------------------------------------------------------------------------

prop_bps :: Property
prop_bps = forAll genPair $ \(source, target) ->
  case createBPS (SourceFileContents source) (TargetFileContents target) (BPSMetadata ByteString.empty) of
    Left createError -> counterexample ("create: " ++ renderSlapError createError) $ property False
    Right (CreateResult patch _) -> case BPS.parseBPS patch of
      Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
      Right (Parsed parsed _parseWarnings) -> BPS.applyBPS parsed (SourceFileContents source) === Right (TargetFileContents target)

prop_bpsMetadata :: Property
prop_bpsMetadata = forAll genPair $ \(source, target) ->
  forAll genByteString $ \meta ->
    case createBPS (SourceFileContents source) (TargetFileContents target) (BPSMetadata meta) of
      Left createError -> counterexample ("create: " ++ renderSlapError createError) $ property False
      Right (CreateResult patch _) -> case BPS.parseBPS patch of
        Left slapError -> counterexample (renderSlapError slapError) $ property False
        Right (Parsed parsed _parseWarnings) -> BPS.unBPSMetadata (BPS.bpsMetadata parsed) === meta

prop_ups :: Property
prop_ups = forAll genPair $ \(source, target) ->
  case createUPS (SourceFileContents source) (TargetFileContents target) of
    Left _createError -> property True
    Right (CreateResult patch _) ->
      case UPS.parseUPS patch of
        Left parseError ->
          counterexample (renderSlapError parseError) $ property False
        Right (Parsed parsed _parseWarnings) ->
          UPS.applyUPS parsed (SourceFileContents source) === Right (TargetFileContents target)

prop_ips :: Property
prop_ips = forAll genPair $ \(source, target) ->
  case createFromMemory (CreateDirect CreateIPS) (SourceFileContents source) (TargetFileContents target) noMetadataRequested Nothing noConstraintsRequested of
    Left slapError -> counterexample ("create: " ++ renderSlapError slapError) $ property False
    Right (CreateResult patch _) -> case IPS.parseIPS patch of
      Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
      Right (Parsed (IPSParseCleanIPS ipsPatch) _parseWarnings) ->
        IPS.applyIPS (SourceFileContents source) ipsPatch === Right (TargetFileContents target)
      Right (Parsed (IPSParseCleanEBP _ebpPatch) _parseWarnings) ->
        counterexample "test fixture unexpectedly EBP" $ property False
      Right (Parsed (IPSParseTruncated _ _) _parseWarnings) ->
        counterexample "round-tripped IPS unexpectedly truncated" $ property False

prop_ipsEofCollision :: Property
prop_ipsEofCollision = withNumTests 20 $ forAll genEofPair $ \(source, target) ->
  case createFromMemory (CreateDirect CreateIPS) (SourceFileContents source) (TargetFileContents target) noMetadataRequested Nothing noConstraintsRequested of
    Left slapError -> counterexample ("create: " ++ renderSlapError slapError) $ property False
    Right (CreateResult patch _) -> case IPS.parseIPS patch of
      Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
      Right (Parsed (IPSParseCleanIPS ipsPatch) _parseWarnings) ->
        IPS.applyIPS (SourceFileContents source) ipsPatch === Right (TargetFileContents target)
      Right (Parsed (IPSParseCleanEBP _ebpPatch) _parseWarnings) ->
        counterexample "test fixture unexpectedly EBP" $ property False
      Right (Parsed (IPSParseTruncated _ _) _parseWarnings) ->
        counterexample "round-tripped IPS unexpectedly truncated" $ property False

prop_resolveSentinelCollisions :: Property
prop_resolveSentinelCollisions = once $
  let source       = SourceFileContents (ByteString.pack [0, 1, 2, 3, 4, 5, 6, 7])
      emptySource  = SourceFileContents ByteString.empty
      sentinelAt5  = SentinelOffset (Offset 5)
      sentinelAt0  = SentinelOffset (Offset 0)
  in conjoin
    [ -- Record at sentinel is shifted back and the preceding source byte prepended.
      resolveSentinelCollisions LabelIPS sentinelAt5 source
        [EncodedHunk (Offset 5) (ByteString.pack [0xFF])]
        === Right [EncodedHunk (Offset 4) (ByteString.pack [4, 0xFF])]
    , -- Record NOT at sentinel passes through unchanged.
      resolveSentinelCollisions LabelIPS sentinelAt5 source
        [EncodedHunk (Offset 3) (ByteString.pack [0xAA])]
        === Right [EncodedHunk (Offset 3) (ByteString.pack [0xAA])]
    , -- Empty source: collision is unfixable, returns a structured error.
      resolveSentinelCollisions LabelIPS sentinelAt5 emptySource
        [EncodedHunk (Offset 5) (ByteString.pack [0xFF])]
        === Left (SentinelCollisionUnfixable LabelIPS sentinelAt5)
    , -- Sentinel at offset 0: no preceding byte exists, returns a structured error.
      resolveSentinelCollisions LabelIPS sentinelAt0 source
        [EncodedHunk (Offset 0) (ByteString.pack [0xFF])]
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
  in case convertDirect collidingContents (CreateDirect CreateIPS) noMetadataRequested noConstraintsRequested of
       Left (SentinelCollisionUnfixable LabelIPS offset) ->
         offset === ipsSentinelOffset
       Left other ->
         counterexample ("unexpected error: " ++ renderSlapError other) $
           property False
       Right _ ->
         counterexample "expected Left SentinelCollisionUnfixable, got Right" $
           property False

-- | DP patch size must not exceed greedy patch size for IPS (offWidth=3).
prop_dpNotLarger :: Property
prop_dpNotLarger = forAll genPair $ \(source, target) ->
  let dynamicProgrammingRecords =
        optimalIPSRecords Offset24 (SourceFileContents source) (TargetFileContents target)
      greedyRecords = splitMax 0xFFFF (diffHunks source target)
      dynamicProgrammingSize = ipsEncodedSize 3 dynamicProgrammingRecords
      greedySize = ipsEncodedSize 3 greedyRecords
  in counterexample ("DP: " ++ show dynamicProgrammingSize ++ ", greedy: " ++ show greedySize) $
     dynamicProgrammingSize <= greedySize

-- | DP patch size must not exceed greedy patch size for IPS32 (offWidth=4).
prop_dpIPS32NotLarger :: Property
prop_dpIPS32NotLarger = forAll genPair $ \(source, target) ->
  let dynamicProgrammingRecords =
        optimalIPSRecords Offset32 (SourceFileContents source) (TargetFileContents target)
      greedyRecords = splitMax 0xFFFF (diffHunks source target)
      dynamicProgrammingSize = ipsEncodedSize 4 dynamicProgrammingRecords
      greedySize = ipsEncodedSize 4 greedyRecords
  in counterexample ("DP: " ++ show dynamicProgrammingSize ++ ", greedy: " ++ show greedySize) $
     dynamicProgrammingSize <= greedySize

prop_gdiff :: Property
prop_gdiff = forAll genPair $ \(source, target) ->
  case createGDIFF (SourceFileContents source) (TargetFileContents target) of
    Left createError -> counterexample ("create: " ++ renderSlapError createError) $ property False
    Right (CreateResult patch _) -> case GDIFF.parseGDIFF patch of
      Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
      Right (Parsed parsed _parseWarnings) ->
        case GDIFF.applyGDIFF parsed (SourceFileContents source) of
          Left applyError       -> counterexample ("apply: " ++ renderSlapError applyError) $ property False
          Right targetContents  -> targetContents === TargetFileContents target

----------------------------------------------------------------------------
-- GDIFF planCopy properties
--
-- The W3C GDIFF spec defines its @int@ type as signed 32-bit, so a
-- single COPY command's length field tops out at 'maxSingleCommandLength'
-- (2^31-1 bytes). 'planCopy' is the encoder's chunking pass: it splits
-- requests larger than that limit into a run of in-range chunks. These
-- properties pin its behaviour down without ever allocating a multi-
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
              | GDIFF.GDiffCopy commandOffset (FileSize commandLength) <- parsedCommands ]
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
  case createAPSGBA (SourceFileContents source) (TargetFileContents target) of
    Left createError -> counterexample ("create: " ++ renderSlapError createError) $ property False
    Right (CreateResult patch _) -> case APSGBA.parseAPSGBA patch of
      Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
      Right (Parsed parsed _parseWarnings) ->
        APSGBA.applyAPSGBAMemory parsed (SourceFileContents source) === TargetFileContents target

----------------------------------------------------------------------------
-- IPS32 / EBP: no truncation marker, target must be >= source
----------------------------------------------------------------------------

prop_ips32 :: Property
prop_ips32 = forAll genPairNoShrink $ \(source, target) ->
  case createFromMemory (CreateDirect CreateIPS32) (SourceFileContents source) (TargetFileContents target) noMetadataRequested Nothing noConstraintsRequested of
    Left slapError -> counterexample ("create: " ++ renderSlapError slapError) $ property False
    Right (CreateResult patch _) -> case IPS.parseIPS patch of
      Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
      Right (Parsed (IPSParseCleanIPS ipsPatch) _parseWarnings) ->
        IPS.applyIPS (SourceFileContents source) ipsPatch === Right (TargetFileContents target)
      Right (Parsed (IPSParseCleanEBP _ebpPatch) _parseWarnings) ->
        counterexample "test fixture unexpectedly EBP" $ property False
      Right (Parsed (IPSParseTruncated _ _) _parseWarnings) ->
        counterexample "round-tripped IPS32 unexpectedly truncated" $ property False

prop_ebp :: Property
prop_ebp = forAll genPairNoShrink $ \(source, target) ->
  case createFromMemory (CreateDirect CreateEBP) (SourceFileContents source) (TargetFileContents target) noMetadataRequested Nothing noConstraintsRequested of
    Left slapError -> counterexample ("create: " ++ renderSlapError slapError) $ property False
    Right (CreateResult patch _) -> case IPS.parseIPS patch of
      Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
      Right (Parsed (IPSParseCleanEBP ebpPatch) _parseWarnings) ->
        IPS.applyIPS (SourceFileContents source) (ebpBasePatch ebpPatch) === Right (TargetFileContents target)
      Right (Parsed (IPSParseCleanIPS _ipsPatch) _parseWarnings) ->
        counterexample "test fixture unexpectedly plain IPS" $ property False
      Right (Parsed (IPSParseTruncated _ _) _parseWarnings) ->
        counterexample "round-tripped EBP unexpectedly truncated" $ property False

-- Direct formats: no truncation, target must be >= source
prop_ppf3 :: Property
prop_ppf3 = forAll genPairNoShrink $ \(source, target) ->
  case createFromMemory (CreateDirect CreatePPF3) (SourceFileContents source) (TargetFileContents target) noMetadataRequested Nothing noConstraintsRequested of
    Left slapError -> counterexample ("create: " ++ renderSlapError slapError) $ property False
    Right (CreateResult patch _) -> case PPF.parsePatch patch of
       Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
       Right (Parsed parsed _parseWarnings) -> PPF.applyPatchMemory parsed (SourceFileContents source) === Right (TargetFileContents target)

prop_pmsr :: Property
prop_pmsr = forAll genPairNoShrink $ \(source, target) ->
  case createFromMemory (CreateDirect CreatePMSR) (SourceFileContents source) (TargetFileContents target) noMetadataRequested Nothing noConstraintsRequested of
    Left slapError -> counterexample ("create: " ++ renderSlapError slapError) $ property False
    Right (CreateResult patch _) -> case PMSR.parsePMSR patch of
       Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
       Right (Parsed parsed _parseWarnings) ->
         PMSR.applyPMSRMemory parsed (SourceFileContents source) === TargetFileContents target

prop_ninja1 :: Property
prop_ninja1 = forAll genPairNoShrink $ \(source, target) ->
  case createFromMemory (CreateDirect CreateNINJA1) (SourceFileContents source) (TargetFileContents target) noMetadataRequested Nothing noConstraintsRequested of
    Left slapError -> counterexample ("create: " ++ renderSlapError slapError) $ property False
    Right (CreateResult patch _) -> case NINJA1.parseNINJA1 patch of
       Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
       Right (Parsed parsed _parseWarnings) ->
         NINJA1.applyNINJA1Memory parsed (SourceFileContents source) === TargetFileContents target

prop_ninja1Hashes :: Property
prop_ninja1Hashes = forAll genPairNoShrink $ \(source, _) ->
  not (ByteString.null source) ==>
  case createFromMemory (CreateDirect CreateNINJA1) (SourceFileContents source) (TargetFileContents source) noMetadataRequested Nothing noConstraintsRequested of
    Left slapError -> counterexample ("create: " ++ renderSlapError slapError) $ property False
    Right (CreateResult patch _) -> case NINJA1.parseNINJA1 patch of
       Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
       Right (Parsed parsed _parseWarnings) ->
         NINJA1.ninja1SourceCRC parsed === Just (rustyCRC32 source) .&&.
         NINJA1.ninja1SourceMD5 parsed === Just (md5 source) .&&.
         NINJA1.ninja1SourceSHA1 parsed === Just (sha1 source)

-- DPS: differential, no truncation
prop_dps :: Property
prop_dps = forAll genPairNoShrink $ \(source, target) ->
  case createDPS (SourceFileContents source) (TargetFileContents target)
         (DPS.DPSMetadata { DPS.dpsMetadataName = "", DPS.dpsMetadataAuthor = "", DPS.dpsMetadataVersion = "" })
         DPS.DPSStable of
    Left createError -> counterexample ("create: " ++ renderSlapError createError) $ property False
    Right (CreateResult patch _) -> case DPS.parseDPS patch of
      Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
      Right (Parsed parsed _parseWarnings) -> DPS.applyDPS parsed (SourceFileContents source) === Right (TargetFileContents target)

prop_ninja2 :: Property
prop_ninja2 = forAll genPair $ \(source, target) ->
  case createNINJA2 (SourceFileContents source) (TargetFileContents target) emptyNINJA2Metadata of
    Left createError -> counterexample ("create: " ++ renderSlapError createError) $ property False
    Right (CreateResult patch _) -> case NINJA2.parseNINJA2 patch of
      Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
      Right (Parsed parsed _parseWarnings) ->
        NINJA2.applyNINJA2Memory parsed (SourceFileContents source) === TargetFileContents target

-- | Round-trip restricted to the @len(source) > len(target)@ regime,
-- where the NINJA2 wire carries the discarded source tail as a
-- truncate-mode overflow.  The general 'prop_ninja2' covers this
-- regime probabilistically; this property guarantees every test
-- case lands on it, so a regression that overruns the output buffer
-- by re-applying the truncate overflow gets caught immediately.
prop_ninja2Truncate :: Property
prop_ninja2Truncate = forAll genShrinkingPair $ \(source, target) ->
  case createNINJA2 (SourceFileContents source) (TargetFileContents target) emptyNINJA2Metadata of
    Left createError -> counterexample ("create: " ++ renderSlapError createError) $ property False
    Right (CreateResult patch _) -> case NINJA2.parseNINJA2 patch of
      Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
      Right (Parsed parsed _parseWarnings) ->
        NINJA2.applyNINJA2Memory parsed (SourceFileContents source) === TargetFileContents target

prop_ninja2Hashes :: Property
prop_ninja2Hashes = forAll genPair $ \(source, target) ->
  case createNINJA2 (SourceFileContents source) (TargetFileContents target) emptyNINJA2Metadata of
    Left createError -> counterexample ("create: " ++ renderSlapError createError) $ property False
    Right (CreateResult patch _) -> case NINJA2.parseNINJA2 patch of
      Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
      Right (Parsed parsed _parseWarnings) ->
        fmap NINJA2.openNewFileSourceMD5 (NINJA2.ninja2OpenNewFile parsed) === Just (md5 source) .&&.
        fmap NINJA2.openNewFileTargetMD5 (NINJA2.ninja2OpenNewFile parsed) === Just (md5 target)

-- | Both PATCH_ENC values the NINJA2 spec defines must survive a
-- create-then-parse trip intact: the byte the encoder writes at offset
-- 6 must round-trip through the parser back into the same
-- 'PatchEncoding' constructor it was created with. Empty source and
-- target keep the test focused on the header byte the property is
-- about; the round-trip body is exercised exhaustively by 'prop_ninja2'.
ninja2EncodingRoundTrips :: NINJA2.PatchEncoding -> Assertion
ninja2EncodingRoundTrips encoding =
  let metadata    = emptyNINJA2Metadata { NINJA2.ninja2MetadataEncoding = encoding }
      emptyBytes  = ByteString.empty
  in case createNINJA2 (SourceFileContents emptyBytes) (TargetFileContents emptyBytes) metadata of
       Left createError -> assertFailure ("create: " ++ renderSlapError createError)
       Right (CreateResult patch _) -> case NINJA2.parseNINJA2 patch of
         Left slapError -> assertFailure ("parse: " ++ renderSlapError slapError)
         Right (Parsed parsed _parseWarnings) ->
           assertEqual "PATCH_ENC round-trip" encoding (NINJA2.ninja2PatchEncoding parsed)

-- PCHTXT: pure direct, no truncation
prop_pchtxt :: Property
prop_pchtxt = forAll genPairNoShrink $ \(source, target) ->
  case createFromMemory (CreateDirect CreatePCHTXT) (SourceFileContents source) (TargetFileContents target) noMetadataRequested Nothing noConstraintsRequested of
    Left slapError -> counterexample ("create: " ++ renderSlapError slapError) $ property False
    Right (CreateResult patch _) -> case PCHTXT.parsePCHTXT patch of
       Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
       Right (Parsed parsed _parseWarnings) ->
         PCHTXT.applyPCHTXTMemory parsed (SourceFileContents source) === TargetFileContents target

-- APS-N64: pure direct, no truncation
prop_apsN64 :: Property
prop_apsN64 = forAll genPairNoShrink $ \(source, target) ->
  case createFromMemory (CreateDirect CreateAPSN64) (SourceFileContents source) (TargetFileContents target) noMetadataRequested Nothing noConstraintsRequested of
    Left slapError -> counterexample ("create: " ++ renderSlapError slapError) $ property False
    Right (CreateResult patch _) -> case APSN64.parseAPSN64 patch of
       Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
       Right (Parsed parsed _parseWarnings) ->
         APSN64.applyAPSN64Memory parsed (SourceFileContents source) === TargetFileContents target

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
  in case createBPS (SourceFileContents source) (TargetFileContents target) (BPSMetadata ByteString.empty) of
       Left createError -> counterexample ("create: " ++ renderSlapError createError) $ property False
       Right (CreateResult patch _) ->
         counterexample ("patch size: " ++ show (ByteString.length (unPatchFileContents patch))
                          ++ " (block: " ++ show blockSize ++ ")") $
         conjoin
           [ case BPS.parseBPS patch of
               Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
               Right (Parsed parsed _parseWarnings) -> BPS.applyBPS parsed (SourceFileContents source) === Right (TargetFileContents target)
           , property (ByteString.length (unPatchFileContents patch) < 1024)
           ]

-- | Patch size should not regress: a random diff with the rolling-hash
-- algorithm must produce patches no larger than a pure-literal encoding
-- (TargetRead for every byte), which costs targetLen + small overhead.
prop_bpsNoSizeRegression :: Property
prop_bpsNoSizeRegression = forAll genPair $ \(source, target) ->
  case createBPS (SourceFileContents source) (TargetFileContents target) (BPSMetadata ByteString.empty) of
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
