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
import qualified Slap.BSDiff.Apply as BSDiff
import qualified Slap.BSDiff.Parse as BSDiff
import qualified Slap.BSDiff.Types as BSDiff
import qualified Slap.IPS.Apply as IPS
import qualified Slap.IPS.Parse as IPS
import Slap.IPS.Create (resolveSentinelCollisions, optimalIPSRecords)
import Slap.IPS.Types (OffsetWidth(..), EBPPatch(..), IPSParseResult(..),
                       ipsMaxRecordPayload, ipsMagicBytes, ipsEOFMarkerBytes)
import Slap.SomePatch (SomePatch(..), PatchKind(..), parseSome)
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
import qualified Slap.VCDIFF.Apply as VCDIFF
import qualified Slap.VCDIFF.Parse as VCDIFF
import Slap.VCDIFF.Types (VCDIFFPatch(..), Window(..), VCDIFFInstruction(..),
                          RFCHeader(..), CustomCodeTable(..), patchWindows,
                          SourceSegment(..), SegmentOrigin(..),
                          XDelta3Header(..), xdelta3WindowAdler32, xdelta3WindowBody, vcdiffAppHeader,
                          EmissionWindowSize, emissionWindowSizeOfBytes, RFCWindowing(..),
                          defaultXDelta3WindowSize, xdelta3ReferenceDecoderWindowCap)
import Slap.VCDIFF.SecondaryCompression (XDelta3SecondaryCompressor(..),
                                         secondaryCompressorCatalog, secondaryCompressorId,
                                         SectionCompressor, sectionCompressorAlgorithm,
                                         lzmaSectionCompressor, djwSectionCompressor)
import Slap.VCDIFF.Create (createFromCover, createConsideringCustomTable,
                           coverToInstructions, resolveInstructionAddresses,
                           designCandidateTable, rejectUnaddressablePair,
                           WindowArmCompete(..), ChosenWindowArm(..),
                           recompeteArmsUnderCandidateTable)
import Slap.VCDIFF.CodeTable (serializeCodeTable, deserializeCodeTable)
import qualified Slap.VCDIFF.CodeTable as Table
import Slap.VCDIFF.Describe (vcdiffMeta)
import Slap.Display.Common (InfoLine(..))
import Slap.VCDIFF.Cover (Cover(..), CoverSegment(..))
import Slap.VCDIFF.FFI (vcdiffCover)
import Slap.VCDIFF.AddressCache
  ( selectCopyAddressMode, SelectedCopyAddress(..), CopyAddressOperand(..), SameSlotByte(..)
  , recordAddress, freshAddressCache, defaultAddressCacheConfig
  , nearSlotCount, unNearSlotCount
  , classifyAddressMode, modeFamilyToByte, modeCeiling
  , decodeCopyAddress, CopyAddressReading(..) )
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
import qualified Slap.PPF4.Apply as PPF4
import qualified Slap.PPF4.Parse as PPF4
import Slap.PPF3.Types (PPF3ImageType(..), narrowPPF3FileId)

import Slap.Binary (md5, sha1, diffHunks)
import Slap.Binary (minimalVcdiffVarintLength, getVcdiffVarint, VarintResult(..), putVcdiffVarint)
import Slap.Status (CreateResult(..), Parsed(..), SlapError(..), Outcome(..),
                   noAdvisories, UnencodeabilityReason(..), CompressionAlgorithm(..),
                   SlapAdvisory(..), renderSlapError)
import Slap.FieldName (FieldName(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.Measure (Offset(..), Length(..), FileSize(..),
                     Hunk(..), SentinelOffset(..),
                     OriginalLength(..), TruncatedLength(..),
                     SourceFileSize(..), TargetFileSize(..),
                     byteLength, splitHunks, splitPayload)
import Slap.FFI (adler32, crc32)
import Slap.FileContents (InputFileContents(..), OutputFileContents(..), PatchFileContents(..))
import Slap.Convert (DirectCreate(..), DifferentialCreate(..), CreateFormat(..),
                     RequestedPatchMetadata(..),
                     noMetadataRequested, noConstraintsRequested, noDialectsRequested,
                     RequestedDialects(..),
                     VerificationInclusion(..), CompressionInclusion(..),
                     xdelta3CompressionEmission, mergeRequestedMetadata,
                     createDefaultAdvisories,
                     convertDirect, emptyContents)
import Slap.Create (createBPS, createUPS, createDPS, createNINJA2,
                    createAPSGBA, createGDIFF, createBSDiff, createXDelta1,
                    createRFCVCDIFF, createXDelta3,
                    WindowCompressionEmission(..), createPatch)

import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Char8 as ByteString8
import qualified Data.ByteString.Lazy as LazyByteString
import qualified Data.Text as Text
import qualified Data.Text.Encoding as TextEncoding
import qualified Slap.Text as SlapText
import Data.Bits (shiftL)
import qualified Data.Bits as Bits
import Data.ByteString.Builder (word8, byteString, toLazyByteString)
import Data.List (isInfixOf)
import Data.Foldable (toList)
import Slap.Binary (getWord32BE)
import qualified Data.Word as Word
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
  , testGroup "BSDiff"
      [ testProperty "round-trip" prop_bsdiff
      , testProperty "scattered edits become few long instructions" prop_bsdiffScatteredEdits
      , testProperty "padding-heavy input completes" prop_bsdiffPaddingRun
      ]
  , testGroup "IPS"
      [ testProperty "round-trip" prop_ips
      , testProperty "eof-collision" prop_ipsEofCollision
      , testProperty "resolveSentinelCollisions" prop_resolveSentinelCollisions
      , testProperty "source-less convert rejects sentinel" prop_sourcelessSentinelRejected
      , testCase     "max-payload at sentinel round-trips" ipsSentinelMaxPayloadRoundTrips
      , testCase     "sentinel collision mid-diff round-trips" ipsSentinelCollisionMidDiffRoundTrips
      , testCase     "truncation past the marker's reach is refused" ipsTruncationPastMarkerReachRefused
      , testCase     "truncation at the marker's maximum round-trips" ipsTruncationAtMarkerMaximumRoundTrips
      , testCase     "zero-count RLE sizes nothing" ipsZeroCountRleSizesNothing
      , testCase     "zero-count RLE drops out of conversion" ipsZeroCountRleConvertRoundTrips
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
  , testGroup "VCDIFF"
      [ testProperty "round-trip (through the matcher)"  prop_vcdiff
      , testCase     "matcher: a real diff round-trips and shrinks below the floor" vcdiffRealDiffShrinks
      , testCase     "matcher: several copies and literals survive the FFI crossing" vcdiffMatcherMultipleCopies
      , testCase     "matcher: agrees with a hand-built greedy cover" vcdiffMatcherAgreesWithHandBuiltCover
      , testCase     "matcher: a match-free pair falls back to the floor bytes" vcdiffFloorReachableThroughMatcher
      , testCase     "emitter: one self-contained ADD window (all-literal cover)" vcdiffFloorStructure
      , testCase     "emitter: exact wire bytes for a two-byte target" vcdiffExactWireBytes
      , testCase     "cover: copy from the source region round-trips" vcdiffSourceCopyRoundTrips
      , testCase     "cover: copy from the produced target round-trips" vcdiffTargetCopyRoundTrips
      , testCase     "cover: repeated-byte literal becomes RUN" vcdiffRunRoundTrips
      , testCase     "cover: exact wire bytes with a COPY" vcdiffCopyExactWireBytes
      , testCase     "cover: an overrunning COPY round-trips (run-length expansion)" vcdiffOverlapCopyRoundTrips
      , testCase     "cover: ADD + RUN + two COPYs interleave and round-trip" vcdiffInterleavedRoundTrips
      , testCase     "cover: instruction selection at the RUN/ADD boundary" vcdiffInstructionSelection
      , testCase     "address modes: SAME emits a single address byte" vcdiffSameModeIsOneByte
      , testCase     "address modes: the address section shrinks below SELF-only" vcdiffAddressModesShrinkTheAddressSection
      , testCase     "address modes: every mode byte round-trips through the family classifier" vcdiffAddressModeByteRoundTrip
      , testProperty "address modes: encode/decode round-trip at large addresses" prop_vcdiffAddressModeRoundTrips
      , testCase     "dense: combined ADD+COPY is one opcode for the pair" vcdiffCombinedAddCopyIsOneOpcode
      , testCase     "dense: combined COPY+ADD is one opcode for the pair" vcdiffCombinedCopyAddIsOneOpcode
      , testCase     "dense: a small lone ADD drops its size varint" vcdiffFixedSizeAddDropsVarint
      , testCase     "dense: oversize ADD and COPY fall back to coded singles" vcdiffOversizeFallsBackToCoded
      , testCase     "dense: the instruction section shrinks below coded-only" vcdiffDenseShrinksInstructionSection
      , testCase     "custom table: a designed table is wire-valid" vcdiffDesignedTableIsWireValid
      , testCase     "custom table: the patch-in-a-patch round-trips" vcdiffCustomTableRoundTrips
      , testCase     "custom table: beats the default on a lopsided cover" vcdiffCustomTableBeatsDefault
      , testCase     "custom table: the gate declines a table that won't pay" vcdiffCustomTableGateHolds
      , testCase     "cache: a grown geometry is declared and round-trips" vcdiffGrownCacheRoundTrips
      , testCase     "cache: a grown geometry beats the default config" vcdiffGrownCacheBeatsDefault
      , testCase     "cache: the grown geometry is visible to info/explain" vcdiffGrownCacheGeometryVisible
      , testCase     "cache: the geometry is not grown past where it pays" vcdiffCacheNotInflatedWhenDefaultHolds
      , testCase     "single: a repeated odd-size ADD beats the default and round-trips" vcdiffOddSizeSingleBeatsDefault
      , testCase     "single: the repeated odd-size ADD is minted into the table" vcdiffOddSizeSingleIsMinted
      , testProperty "xdelta3: round-trip carrying the window's Adler32" prop_xdelta3
      , testProperty "xdelta3: both extensions omitted emits the core shape" prop_xdelta3OmitBothIsCoreShaped
      , testProperty "xdelta3: many tiny windows partition, checksum, and round-trip" prop_xdelta3ManyWindows
      , testCase     "xdelta3: uneven window sizes earn the note; slap's own emission does not" vcdiffUnevenWindowNote
      , testCase     "xdelta3: a window size past the reference decoder's cap earns the note" xdelta3WindowCapNote
      , testCase     "xdelta3: exact wire bytes for a two-byte target" xdelta3ExactWireBytes
      , testCase     "xdelta3: compression pays on a repetitive cover and declares LZMA"
          (xdelta3CompressionPaysOnARepetitiveCover lzmaSectionCompressor)
      , testCase     "xdelta3: compression pays on a repetitive cover and declares DJW"
          (xdelta3CompressionPaysOnARepetitiveCover djwSectionCompressor)
      , testCase     "xdelta3: unpaying compression leaves the core shape" xdelta3UnpayingCompressionLeavesTheCoreShape
      , testCase     "xdelta3: a source patch's compressor inherits on convert"
          xdelta3DeclaredCompressorInheritsOnConvert
      , testCase     "xdelta3: application header round-trips" xdelta3AppHeaderRoundTrips
      , testCase     "xdelta3: app header offered for inheritance on convert"
          xdelta3AppHeaderOfferedForInheritance
      , testCase     "xdelta3: app header carries across convert" xdelta3AppHeaderCarriesAcrossConvert
      , testCase     "xdelta3: empty app header emits the bit and reads as no metadata"
          xdelta3EmptyAppHeader
      , testCase     "xdelta3: selecting fgk is declined by name" xdelta3FGKSelectionDeclinedByName
      , testCase     "xdelta3: compressor ids round-trip through the catalog" xdelta3CompressorIdsRoundTripThroughTheCatalog
      , testProperty "windowed rfc: many tiny windows round-trip" prop_windowedRFC
      , testCase     "windowed rfc: the target arm wins the repeats and earns the RFC flavor" windowedRFCTargetArmWins
      , testCase     "windowed rfc: a source-favoring pair matches the plain xdelta3 emission byte for byte" windowedRFCSourceArmMatchesXDelta3
      , testCase     "windowed rfc: a pooled custom table amortizes across the windows" windowedRFCCustomTableAmortizes
      , testCase     "windowed rfc: an empty target is one empty window" windowedRFCEmptyTarget
      , testCase     "windowed rfc: the rematch flips an arm the designed table favors" armRematchFlipsUnderMintedTable
      , testCase     "windowed rfc: the rematch stands pat when the mints favor neither arm" armRematchStandsPatWithoutAdvantage
      , testCase     "create: the matcher's addressable-range wall holds at its exact boundary" vcdiffUnaddressablePairRefused
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
      , testCase "file_id.diz: UTF-8-encoded body round-trips byte-faithfully"
                 ppf2FileIdDizRoundTrip
      , testCase "growth: target longer than source round-trips with a grow note"
                 ppf2GrowthRoundTrip
      , testCase "validation: exact-fit source round-trips"
                 ppf2ExactFitValidationSourceRoundTrips
      , testCase "validation: source one byte short is refused"
                 ppf2OneByteShortValidationSourceRejected
      ]
  , testGroup "PPF3"
      [ testProperty "round-trip" prop_ppf3
      , testCase "description: UTF-8 codepoints round-trip byte-faithfully"
                 ppf3DescriptionUtf8RoundTrip
      , testCase "description: 4-byte codepoint at the 50-byte cap is dropped whole"
                 ppf3DescriptionCodepointAwareTruncation
      , testCase "file_id.diz: UTF-8-encoded body round-trips byte-faithfully"
                 ppf3FileIdDizRoundTrip
      ]
  , testGroup "PPF4"
      [ testProperty "round-trip" prop_ppf4
      , testCase "straddling hunk splits at the source boundary"
                 ppf4StraddleRoundTrip
      ]
  , testGroup "PMSR"
      [ testProperty "round-trip" prop_pmsr
      , testCase "shrinking target is refused" (assertShrinkRefused CreatePMSR LabelPMSR)
      ]
  , testGroup "NINJA1"
      [ testProperty "round-trip" prop_ninja1
      , testProperty "hashes" prop_ninja1Hashes
      , testProperty "eof-collision" prop_ninja1EofCollision
      , testProperty "source-less convert rejects sentinel" prop_ninja1SourcelessSentinelRejected
      , testProperty "missing EOF footer rejected" prop_ninja1FooterRequired
      , testCase "shrinking target is refused" (assertShrinkRefused CreateNINJA1 LabelNINJA1)
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
      , testCase "encoding-utf8-round-trips"       (ninja2EncodingRoundTrips NINJA2.TextModeUTF8)
      , testCase "encoding-undeclared-round-trips" (ninja2EncodingRoundTrips NINJA2.TextModeUndeclared)
      , testCase "single-file sentinel is one zero byte" ninja2SingleFileSentinelIsZero
      , testCase "field-truncation-warning-reports-actual-stored-length"
          ninja2FieldTruncationWarningReportsActualStoredLength
      , testCase "mode-1 UTF-8 non-ASCII title round-trips byte-faithfully"
          ninja2Mode1Utf8NonAsciiTitleRoundTrips
      , testCase "parse tags mode-1 fields as EncodingUtf8"
          ninja2ParseTagsMode1FieldsAsUtf8
      , testCase "parse tags mode-0 fields under the chosen metadata encoding"
          ninja2ParseTagsMode0FieldsUnderChosenEncoding
      , testCase "CLI --ninja2-text-mode selects PATCH_ENC"
          ninja2DetectionCliSelectsTextMode
      , testCase "detection without CLI defaults to PATCH_ENC=1"
          ninja2DetectionDefaultsToUtf8
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
  , testGroup "XDelta1"
      [ testProperty "round-trip"                       prop_xdelta1RoundTrips
      , testProperty "compression posture round-trips"  prop_xdelta1CompressionPostureRoundTrips
      , testProperty "create produces Verify"           prop_xdelta1CreateProducesVerifyPosture
      , testCase     "wire postures offered for inheritance on convert"
          xdelta1PosturesInheritOnConvert
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
    Left createError -> counterexample ("create: " ++ Text.unpack (renderSlapError createError)) $ property False
    Right (CreateResult patch _) -> case BPS.parseBPS patch of
      Left slapError -> counterexample ("parse: " ++ Text.unpack (renderSlapError slapError)) $ property False
      Right (Parsed parsed _parseWarnings) -> BPS.applyBPS parsed (InputFileContents source) === Right (OutputFileContents target)

prop_bpsMetadata :: Property
prop_bpsMetadata = forAll genPair $ \(source, target) ->
  forAll genByteString $ \meta ->
    case createBPS (InputFileContents source) (OutputFileContents target) (BPSMetadata meta) of
      Left createError -> counterexample ("create: " ++ Text.unpack (renderSlapError createError)) $ property False
      Right (CreateResult patch _) -> case BPS.parseBPS patch of
        Left slapError -> counterexample (Text.unpack (renderSlapError slapError)) $ property False
        Right (Parsed parsed _parseWarnings) -> BPS.unBPSMetadata (BPS.bpsMetadata parsed) === meta

prop_bsdiff :: Property
prop_bsdiff = forAll genPair $ \(source, target) ->
  case createBSDiff (InputFileContents source) (OutputFileContents target) of
    Left createError -> counterexample ("create: " ++ Text.unpack (renderSlapError createError)) $ property False
    Right (CreateResult patch _) -> case BSDiff.parseBSDiff patch of
      Left slapError -> counterexample ("parse: " ++ Text.unpack (renderSlapError slapError)) $ property False
      Right (Parsed parsed _parseWarnings) ->
        BSDiff.applyBSDiff parsed (InputFileContents source) === Right (OutputFileContents target)

-- | The format's signature behavior, asserted at the patch level: a
-- large file with a scatter of single-byte edits must come back as a
-- few long instructions whose diff stream is nearly all zeros — and
-- the whole patch, bzip2 having crushed those zeros, stays tiny.
-- That behavior is what makes the output a bsdiff in spirit and not
-- just in magic bytes.
prop_bsdiffScatteredEdits :: Property
prop_bsdiffScatteredEdits = once $
  let source = pseudoRandomBytes 0x1001 (256 * 1024)
      editPositions = [5000 + editIndex * 12000 | editIndex <- [0 .. 19 :: Int]]
      target = ByteString.pack
        [ if index `elem` editPositions then byte `Bits.xor` 0x5A else byte
        | (index, byte) <- zip [0 ..] (ByteString.unpack source)
        ]
  in case createBSDiff (InputFileContents source) (OutputFileContents target) of
       Left createError -> counterexample ("create: " ++ Text.unpack (renderSlapError createError)) $ property False
       Right (CreateResult patch _) -> case BSDiff.parseBSDiff patch of
         Left slapError -> counterexample ("parse: " ++ Text.unpack (renderSlapError slapError)) $ property False
         Right (Parsed parsed _parseWarnings) ->
           let instructionCount = length (BSDiff.bsdiffInstructions parsed)
               nonZeroDeltas    = ByteString.length (ByteString.filter (/= 0) (BSDiff.bsdiffDiffData parsed))
               patchSize        = ByteString.length (unPatchFileContents patch)
           in counterexample ("instructions: " ++ show instructionCount
                               ++ ", nonzero deltas: " ++ show nonZeroDeltas
                               ++ ", patch size: " ++ show patchSize) $
              conjoin
                [ BSDiff.applyBSDiff parsed (InputFileContents source) === Right (OutputFileContents target)
                , property (instructionCount <= 25)
                , property (nonZeroDeltas <= 20)
                , property (patchSize < 4096)
                ]

-- | The padding-heavy input shape: megabytes of one repeated byte
-- around a sparse content island that shifts between source and
-- target. Every window hashes into one seeder bucket, and the probe
-- cap is what holds the runtime line — the observable here is that
-- create completes at test speed at all (a cliff would blow the
-- suite's wall clock, and the onecore CSV would name this test).
prop_bsdiffPaddingRun :: Property
prop_bsdiffPaddingRun = once $
  let island = pseudoRandomBytes 0x1002 4096
      source = ByteString.concat
        [ByteString.replicate 1000000 0xFF, island, ByteString.replicate 3000000 0xFF]
      target = ByteString.concat
        [ByteString.replicate 1001000 0xFF, island, ByteString.replicate 2999000 0xFF]
  in case createBSDiff (InputFileContents source) (OutputFileContents target) of
       Left createError -> counterexample ("create: " ++ Text.unpack (renderSlapError createError)) $ property False
       Right (CreateResult patch _) -> case BSDiff.parseBSDiff patch of
         Left slapError -> counterexample ("parse: " ++ Text.unpack (renderSlapError slapError)) $ property False
         Right (Parsed parsed _parseWarnings) ->
           BSDiff.applyBSDiff parsed (InputFileContents source) === Right (OutputFileContents target)

-- | SplitMix64 stream, matching the pseudo-random helper rusty-slap's
-- test modules use: deterministic content with no short period, so
-- instruction counting over it stays meaningful.
pseudoRandomBytes :: Word.Word64 -> Int -> ByteString.ByteString
pseudoRandomBytes seed byteCount = fst (ByteString.unfoldrN byteCount nextByte seed)
  where
    nextByte state =
      let advanced   = state + 0x9e3779b97f4a7c15
          mixedOnce  = (advanced `Bits.xor` (advanced `Bits.shiftR` 30)) * 0xbf58476d1ce4e5b9
          mixedTwice = (mixedOnce `Bits.xor` (mixedOnce `Bits.shiftR` 27)) * 0x94d049bb133111eb
          finalMix   = mixedTwice `Bits.xor` (mixedTwice `Bits.shiftR` 31)
      in Just (fromIntegral finalMix, advanced)

prop_ups :: Property
prop_ups = forAll genUPSEncodeablePair $ \(source, target) ->
  case createUPS (InputFileContents source) (OutputFileContents target) of
    Left createError ->
      counterexample ("create on encodeable pair: "
                       ++ Text.unpack (renderSlapError createError)) $ property False
    Right (CreateResult patch _) ->
      case UPS.parseUPS patch of
        Left parseError ->
          counterexample (Text.unpack (renderSlapError parseError)) $ property False
        Right (Parsed parsed _parseWarnings) ->
          fmap outcomeValue (UPS.applyUPS parsed (InputFileContents source))
            === Right (OutputFileContents target)

-- | The load-bearing test: a created VCDIFF patch, parsed and applied
-- to the source, reconstructs the target exactly — through the matcher.
prop_vcdiff :: Property
prop_vcdiff = forAll genPair $ \(source, target) ->
  case createRFCVCDIFF OneWholeTargetWindow (InputFileContents source) (OutputFileContents target) of
    Left createError -> counterexample ("create: " ++ Text.unpack (renderSlapError createError)) $ property False
    Right (CreateResult patch _) -> case VCDIFF.parseVCDIFF patch of
      Left slapError -> counterexample ("parse: " ++ Text.unpack (renderSlapError slapError)) $ property False
      Right (Parsed parsed _parseWarnings) ->
        VCDIFF.applyVCDIFF parsed (InputFileContents source) === Right (OutputFileContents target)

-- | The xdelta3 sibling of 'prop_vcdiff': created with the porcelain's defaults (verification
-- and LZMA compression), the patch parses back as the xdelta3 flavor, its one window carries the
-- target's Adler32, and apply reconstructs the target. Random pairs are usually too small for
-- compression to pay, so the property also exercises the plain-unless-smaller gate; the Adler32
-- fixes the flavor either way.
prop_xdelta3 :: Property
prop_xdelta3 = forAll genPair $ \(source, target) ->
  case createXDelta3 IncludeVerification (CompressSectionsWith lzmaSectionCompressor)
                     defaultXDelta3WindowSize Nothing (InputFileContents source) (OutputFileContents target) of
    Left createError -> counterexample ("create: " ++ Text.unpack (renderSlapError createError)) $ property False
    Right (CreateResult patch _) -> case VCDIFF.parseVCDIFF patch of
      Left slapError -> counterexample ("parse: " ++ Text.unpack (renderSlapError slapError)) $ property False
      Right (Parsed parsed _parseWarnings) -> case parsed of
        PatchXDelta3 _header windows ->
          map xdelta3WindowAdler32 (toList windows) === [Just (adler32 target)]
            .&&. VCDIFF.applyVCDIFF parsed (InputFileContents source) === Right (OutputFileContents target)
        otherFlavor -> counterexample ("parsed flavor: " ++ show otherFlavor) $ property False

-- | With both extensions omitted the patch reaches for no xdelta3 feature at all, so it
-- parses back as 'PatchCoreOnly' — the create token names the arc, the bytes earn the flavor —
-- and still applies.
prop_xdelta3OmitBothIsCoreShaped :: Property
prop_xdelta3OmitBothIsCoreShaped = forAll genPair $ \(source, target) ->
  case createXDelta3 OmitVerification EmitSectionsPlain defaultXDelta3WindowSize Nothing (InputFileContents source) (OutputFileContents target) of
    Left createError -> counterexample ("create: " ++ Text.unpack (renderSlapError createError)) $ property False
    Right (CreateResult patch _) -> case VCDIFF.parseVCDIFF patch of
      Left slapError -> counterexample ("parse: " ++ Text.unpack (renderSlapError slapError)) $ property False
      Right (Parsed parsed _parseWarnings) -> case parsed of
        PatchCoreOnly _windows ->
          VCDIFF.applyVCDIFF parsed (InputFileContents source) === Right (OutputFileContents target)
        otherFlavor -> counterexample ("parsed flavor: " ++ show otherFlavor) $ property False

-- | Many tiny windows: a window size far below the generated pairs forces a real multi-window
-- emission, which must partition the target exactly (every window's declared size is its slice's),
-- carry one Adler32 per window — each attesting its own slice, not the whole —
-- and still apply back to the target through slap's own decode.
prop_xdelta3ManyWindows :: Property
prop_xdelta3ManyWindows = forAll genPair $ \(source, target) ->
  case createXDelta3 IncludeVerification (CompressSectionsWith lzmaSectionCompressor)
                     sixtyFourByteWindows Nothing (InputFileContents source) (OutputFileContents target) of
    Left createError -> counterexample ("create: " ++ Text.unpack (renderSlapError createError)) $ property False
    Right (CreateResult patch _) -> case VCDIFF.parseVCDIFF patch of
      Left slapError -> counterexample ("parse: " ++ Text.unpack (renderSlapError slapError)) $ property False
      Right (Parsed parsed _parseWarnings) -> case parsed of
        PatchXDelta3 _header windows ->
          let slices = windowSlicesOf 64 target
          in map (windowTargetSize . xdelta3WindowBody) (toList windows)
               === map (FileSize . ByteString.length) slices
             .&&. map xdelta3WindowAdler32 (toList windows) === map (Just . adler32) slices
             .&&. VCDIFF.applyVCDIFF parsed (InputFileContents source) === Right (OutputFileContents target)
        otherFlavor -> counterexample ("parsed flavor: " ++ show otherFlavor) $ property False
  where
    windowSlicesOf sliceLength bytes
      | ByteString.null bytes = [ByteString.empty]
      | ByteString.length bytes <= sliceLength = [bytes]
      | otherwise = let (slice, rest) = ByteString.splitAt sliceLength bytes
                    in slice : windowSlicesOf sliceLength rest

-- | A deliberately tiny window size, so ordinary property pairs emit many windows.
sixtyFourByteWindows :: EmissionWindowSize
sixtyFourByteWindows = case emissionWindowSizeOfBytes 64 of
  Just windowSize -> windowSize
  Nothing         -> error "sixty-four bytes is positive"

-- | slap's own multi-window emission is a run of equal windows and a remainder, so the
-- uneven-windows note must stay silent on it — and must fire on a hand-built patch whose
-- windows run 5, 1, 3 bytes (three self-contained ADD windows, decoded correctly by
-- slap and the reference tool alike; window sizing is the encoder's own affair).
vcdiffUnevenWindowNote :: Assertion
vcdiffUnevenWindowNote = do
  let unevenPatch = PatchFileContents (ByteString.pack (concat
        [ [0xD6, 0xC3, 0xC4, 0x00, 0x00]
        , addOnlyWindow [0x41, 0x41, 0x41, 0x41, 0x41]
        , addOnlyWindow [0x43]
        , addOnlyWindow [0x42, 0x42, 0x42]
        ]))
      -- A self-contained window carrying one fixed-size ADD: the default
      -- table holds ADD(n) at opcode 1 + n for sizes 1-17.
      addOnlyWindow payload = concat
        [ [0x00, fromIntegral (6 + length payload)]
        , [fromIntegral (length payload), 0x00, fromIntegral (length payload), 0x01, 0x00]
        , payload
        , [fromIntegral (1 + length payload)]
        ]
  case VCDIFF.parseVCDIFF unevenPatch of
    Left slapError -> assertFailureT ("uneven parse: " <> renderSlapError slapError)
    Right (Parsed _parsed advisories) ->
      assertBool "the uneven note fires" (VCDIFFUnevenWindowSizes `elem` advisories)
  case createXDelta3 OmitVerification EmitSectionsPlain sixtyFourByteWindows Nothing
         (InputFileContents ByteString.empty)
         (OutputFileContents (ByteString.replicate 200 0x55)) of
    Left createError -> assertFailureT ("create: " <> renderSlapError createError)
    Right (CreateResult patch _) -> case VCDIFF.parseVCDIFF patch of
      Left slapError -> assertFailureT ("parse: " <> renderSlapError slapError)
      Right (Parsed _parsed advisories) ->
        assertBool "slap's own emission stays silent"
          (VCDIFFUnevenWindowSizes `notElem` advisories)

-- | The over-cap note names the one decoder that will refuse the patch: present past the
-- reference build's 16 MiB ceiling, absent at the default.
xdelta3WindowCapNote :: Assertion
xdelta3WindowCapNote = do
  let advisoriesAt windowSize = createDefaultAdvisories
        (CreateDifferential CreateXDelta3)
        noMetadataRequested { requestedWindowSize = windowSize }
      isCapNote XDelta3WindowSizePastReferenceDecoder{} = True
      isCapNote _                                       = False
  assertBool "a 17 MiB window earns the note"
    (any isCapNote (advisoriesAt (emissionWindowSizeOfBytes (17 * 1024 * 1024))))
  assertBool "the default earns none"
    (not (any isCapNote (advisoriesAt (Just defaultXDelta3WindowSize))))
  assertBool "the cap itself earns none"
    (not (any isCapNote (advisoriesAt (Just xdelta3ReferenceDecoderWindowCap))))

-- | The exact-wire twin of 'vcdiffExactWireBytes' for the xdelta3 entry: the same two-byte target,
-- now with the VCD_ADLER32 bit in the Win_Indicator and the four checksum bytes
-- between the section lengths and the data section.
-- Compression is included but cannot pay on two bytes (the stream's framing alone is 24 bytes),
-- so these bytes also pin the plain-unless-smaller gate: nothing shrank, nothing is declared.
xdelta3ExactWireBytes :: Assertion
xdelta3ExactWireBytes =
  let target = ByteString.pack [0x41, 0x42]
      expected = ByteString.pack
        [ 0xD6, 0xC3, 0xC4, 0x00, 0x00        -- magic, version, bare header
        , 0x04, 0x0C                          -- Win_Indicator (VCD_ADLER32), delta-encoding length
        , 0x02, 0x00, 0x02, 0x01, 0x00        -- target size, Delta_Indicator, three section lengths
        , 0x00, 0xC6, 0x00, 0x84              -- Adler32 of "AB", big-endian
        , 0x41, 0x42                          -- data section
        , 0x03 ]                              -- instruction section: ADD(2)'s opcode
  in case createXDelta3 IncludeVerification (CompressSectionsWith lzmaSectionCompressor)
                        defaultXDelta3WindowSize Nothing (InputFileContents ByteString.empty) (OutputFileContents target) of
       Left createError -> assertFailureT ("create: " <> renderSlapError createError)
       Right (CreateResult (PatchFileContents patch) _) ->
         assertEqual "exact wire bytes" expected patch

-- | A pair engineered so section compression pays: the target is a patterned source with
-- every 256th byte disturbed, so the cover is a thousand alternating COPY/ADD pairs and
-- all three sections are highly repetitive.
repetitiveCoverPair :: (ByteString.ByteString, ByteString.ByteString)
repetitiveCoverPair = (source, target)
  where
    source = ByteString.pack
      [ fromIntegral ((position * 7 + position `div` 251) `mod` 256)
      | position <- [0 :: Int .. (1 `shiftL` 18) - 1] ]
    target = ByteString.pack
      [ if position `mod` 256 == 0 then byte `Bits.xor` 0x5A else byte
      | (position, byte) <- zip [0 :: Int ..] (ByteString.unpack source) ]

-- | Compression on 'repetitiveCoverPair' must undercut the plain emission,
-- declare the compressor in the header (the declaration is earned only by use), parse back
-- as the xdelta3 flavor carrying that compressor, and still reconstruct the target through
-- the secondary-decompression path. Run once per compressor slap encodes with, so each
-- encoder's output rides slap's own decode of it end to end.
xdelta3CompressionPaysOnARepetitiveCover :: SectionCompressor -> Assertion
xdelta3CompressionPaysOnARepetitiveCover compressor = do
  let (source, target) = repetitiveCoverPair
      createWith compressionEmission =
        createXDelta3 IncludeVerification compressionEmission defaultXDelta3WindowSize Nothing
                      (InputFileContents source) (OutputFileContents target)
  case (createWith (CompressSectionsWith compressor), createWith EmitSectionsPlain) of
    (Right (CreateResult compressedPatch _), Right (CreateResult (PatchFileContents plainBytes) _)) -> do
      let PatchFileContents compressedBytes = compressedPatch
      assertBool "the compressed emission undercuts the plain one"
        (ByteString.length compressedBytes < ByteString.length plainBytes)
      case VCDIFF.parseVCDIFF compressedPatch of
        Left slapError -> assertFailureT ("parse: " <> renderSlapError slapError)
        Right (Parsed parsed _parseWarnings) -> case parsed of
          PatchXDelta3 header _windows -> do
            assertEqual "declared compressor"
              (Just (sectionCompressorAlgorithm compressor)) (xdelta3SecondaryCompressor header)
            assertEqual "apply reconstructs the target"
              (Right (OutputFileContents target))
              (VCDIFF.applyVCDIFF parsed (InputFileContents source))
          otherFlavor -> assertFailure ("parsed flavor: " ++ show otherFlavor)
    (Left createError, _) -> assertFailureT ("compressed create: " <> renderSlapError createError)
    (_, Left createError) -> assertFailureT ("plain create: " <> renderSlapError createError)

-- | Compression that never pays leaves no trace: with verification also omitted, the
-- requested-but-unpaying compression ships bytes identical to the uncompressed emission,
-- which parse back as the core shape — the other road to 'PatchCoreOnly' that
-- 'Slap.VCDIFF.Create.createXDelta3' documents beside the both-omitted one.
xdelta3UnpayingCompressionLeavesTheCoreShape :: Assertion
xdelta3UnpayingCompressionLeavesTheCoreShape =
  let target = ByteString.pack [0x41, 0x42]
      createWith compressionEmission =
        createXDelta3 OmitVerification compressionEmission defaultXDelta3WindowSize Nothing
                      (InputFileContents ByteString.empty) (OutputFileContents target)
  in case (createWith (CompressSectionsWith lzmaSectionCompressor), createWith EmitSectionsPlain) of
       (Right (CreateResult requestedPatch _), Right (CreateResult declinedPatch _)) -> do
         assertEqual "unpaying compression is byte-identical to the plain emission"
           declinedPatch requestedPatch
         case VCDIFF.parseVCDIFF requestedPatch of
           Left slapError -> assertFailureT ("parse: " <> renderSlapError slapError)
           Right (Parsed parsed _parseWarnings) -> case parsed of
             PatchCoreOnly _windows -> pure ()
             otherFlavor -> assertFailure ("parsed flavor: " ++ show otherFlavor)
       (Left createError, _) -> assertFailureT ("compression-requested create: " <> renderSlapError createError)
       (_, Left createError) -> assertFailureT ("compression-omitted create: " <> renderSlapError createError)

-- | A parsed xdelta3 patch offers its declared compressor for inheritance: the extraction
-- carries it like any other metadata (FGK excepted — only what slap can encode with is
-- offered), so a DJW-compressed patch converts back to DJW unless the user says otherwise.
xdelta3DeclaredCompressorInheritsOnConvert :: Assertion
xdelta3DeclaredCompressorInheritsOnConvert = do
  let (source, target) = repetitiveCoverPair
  case createXDelta3 IncludeVerification (CompressSectionsWith djwSectionCompressor) defaultXDelta3WindowSize Nothing
         (InputFileContents source) (OutputFileContents target) of
    Left createError -> assertFailureT ("create: " <> renderSlapError createError)
    Right (CreateResult patchBytes _) ->
      case parseSome noDialectsRequested SlapText.EncodingUtf8 patchBytes of
        Left slapError -> assertFailureT ("parseSome: " <> renderSlapError slapError)
        Right somePatch ->
          assertEqual "compressor offered for inheritance"
            (Just SecondaryDJW)
            (requestedSecondaryCompressor (patchExtractedMeta somePatch))

-- | An application header created with the patch comes back byte-identical,
-- and is enough by itself to make the patch parse as xdelta3.
xdelta3AppHeaderRoundTrips :: Assertion
xdelta3AppHeaderRoundTrips =
  let headerBytes = ByteString8.pack "made with slap"
  in case createXDelta3 OmitVerification EmitSectionsPlain defaultXDelta3WindowSize (Just headerBytes)
            (InputFileContents (ByteString.replicate 64 0x11))
            (OutputFileContents (ByteString.replicate 64 0x22)) of
       Left createError -> assertFailureT ("create: " <> renderSlapError createError)
       Right (CreateResult patchBytes _) -> case VCDIFF.parseVCDIFF patchBytes of
         Left slapError -> assertFailureT ("parse: " <> renderSlapError slapError)
         Right (Parsed parsed _parseWarnings) -> case parsed of
           PatchXDelta3 header _windows ->
             assertEqual "application header" (Just headerBytes) (xdelta3AppHeader header)
           otherFlavor -> assertFailure ("parsed flavor: " ++ show otherFlavor)

-- | A parsed xdelta3 patch offers its application header for inheritance,
-- and surfaces it as the metadata @info --extract-metadata@ writes.
xdelta3AppHeaderOfferedForInheritance :: Assertion
xdelta3AppHeaderOfferedForInheritance =
  let headerBytes = ByteString8.pack "dm4y-output.gbc//dm4y-input.gbc/"
  in case createXDelta3 OmitVerification EmitSectionsPlain defaultXDelta3WindowSize (Just headerBytes)
            (InputFileContents (ByteString.replicate 64 0x11))
            (OutputFileContents (ByteString.replicate 64 0x22)) of
       Left createError -> assertFailureT ("create: " <> renderSlapError createError)
       Right (CreateResult patchBytes _) ->
         case parseSome noDialectsRequested SlapText.EncodingUtf8 patchBytes of
           Left slapError -> assertFailureT ("parseSome: " <> renderSlapError slapError)
           Right somePatch -> do
             assertEqual "offered for inheritance"
               (Just headerBytes) (requestedEmbeddedBlob (patchExtractedMeta somePatch))
             assertEqual "surfaced as metadata"
               (Just headerBytes) (patchMetadata somePatch)

-- | The application header survives the convert merge, in all three directions: xdelta3 to itself, BPS to xdelta3, xdelta3 to BPS.
xdelta3AppHeaderCarriesAcrossConvert :: Assertion
xdelta3AppHeaderCarriesAcrossConvert = do
    xdelta3Patch <- patchBytesFrom (createXDelta3 OmitVerification EmitSectionsPlain defaultXDelta3WindowSize (Just blob) source target)
    bpsPatch     <- patchBytesFrom (createBPS source target (BPSMetadata blob))
    assertCarries "xdelta3 to xdelta3" xdelta3Patch (CreateDifferential CreateXDelta3)
    assertCarries "BPS to xdelta3"     bpsPatch     (CreateDifferential CreateXDelta3)
    assertCarries "xdelta3 to BPS"     xdelta3Patch (CreateDifferential CreateBPS)
  where
    blob   = ByteString8.pack "<crossing-metadata/>"
    source = InputFileContents  (ByteString.replicate 64 0x11)
    target = OutputFileContents (ByteString.replicate 64 0x22)

    patchBytesFrom (Left createError)                  = assertFailureT ("create: " <> renderSlapError createError)
    patchBytesFrom (Right (CreateResult patchBytes _)) = pure patchBytes

    -- Parse the source patch, merge its extracted metadata under an empty CLI request
    -- (the merge @slap convert@ runs), re-create in the target format, and read the bytes back out.
    assertCarries direction patchBytes targetFormat =
      case parseSome noDialectsRequested SlapText.EncodingUtf8 patchBytes of
        Left slapError -> assertFailureT (Text.pack direction <> ": parseSome: " <> renderSlapError slapError)
        Right somePatch ->
          case createPatch targetFormat Nothing source target
                 (mergeRequestedMetadata noMetadataRequested (patchExtractedMeta somePatch))
                 Nothing noConstraintsRequested noDialectsRequested of
            Left slapError -> assertFailureT (Text.pack direction <> ": create: " <> renderSlapError slapError)
            Right (CreateResult convertedBytes _) ->
              case parseSome noDialectsRequested SlapText.EncodingUtf8 convertedBytes of
                Left slapError -> assertFailureT (Text.pack direction <> ": reparse: " <> renderSlapError slapError)
                Right converted -> assertEqual direction (Just blob) (patchMetadata converted)

-- | The empty application header, end to end.
-- Creating with a present-but-empty header emits the bit and a varint 0; the exact wire is pinned, since the bit is the whole difference.
-- Parsing back raises the note. The metadata seam reads it as no metadata, so a convert emits no bit.
xdelta3EmptyAppHeader :: Assertion
xdelta3EmptyAppHeader =
  let target = ByteString.pack [0x41, 0x42]
      expected = ByteString.pack
        [ 0xD6, 0xC3, 0xC4, 0x00              -- magic, version
        , 0x04, 0x00                          -- header indicator (VCD_APPHEADER), header length 0
        , 0x00, 0x08                          -- Win_Indicator (none), delta-encoding length
        , 0x02, 0x00, 0x02, 0x01, 0x00        -- target size, Delta_Indicator, three section lengths
        , 0x41, 0x42                          -- data section
        , 0x03 ]                              -- instruction section: ADD(2)'s opcode
  in case createXDelta3 OmitVerification EmitSectionsPlain defaultXDelta3WindowSize (Just ByteString.empty)
            (InputFileContents ByteString.empty) (OutputFileContents target) of
       Left createError -> assertFailureT ("create: " <> renderSlapError createError)
       Right (CreateResult patchBytes@(PatchFileContents wireBytes) _) -> do
         assertEqual "exact wire bytes" expected wireBytes
         case VCDIFF.parseVCDIFF patchBytes of
           Left slapError -> assertFailureT ("parse: " <> renderSlapError slapError)
           Right (Parsed parsed parseWarnings) -> do
             assertBool "the empty declaration is noted"
               (VCDIFFEmptyApplicationHeader `elem` parseWarnings)
             assertEqual "declared-but-empty survives the parse"
               (Just ByteString.empty) (vcdiffAppHeader parsed)
         case parseSome noDialectsRequested SlapText.EncodingUtf8 patchBytes of
           Left slapError -> assertFailureT ("parseSome: " <> renderSlapError slapError)
           Right somePatch -> do
             assertEqual "read as no metadata"
               Nothing (requestedEmbeddedBlob (patchExtractedMeta somePatch))
             case createPatch (CreateDifferential CreateXDelta3) Nothing
                    (InputFileContents ByteString.empty) (OutputFileContents target)
                    (mergeRequestedMetadata noMetadataRequested (patchExtractedMeta somePatch))
                    Nothing noConstraintsRequested noDialectsRequested of
               Left slapError -> assertFailureT ("convert create: " <> renderSlapError slapError)
               Right (CreateResult convertedBytes _) -> case VCDIFF.parseVCDIFF convertedBytes of
                 Left slapError -> assertFailureT ("parse converted: " <> renderSlapError slapError)
                 Right (Parsed converted _parseWarnings) ->
                   assertEqual "no header bit after convert"
                     Nothing (vcdiffAppHeader converted)

-- | Selecting FGK is a real request slap understands — the token names a catalog entry —
-- and declines by name: slap decodes FGK-compressed patches and does not yet write them.
-- A different refusal from an unknown token (the CLI reader's) and from a format that
-- consumes no compressor selection at all (the accepted-metadata rejection's).
xdelta3FGKSelectionDeclinedByName :: Assertion
xdelta3FGKSelectionDeclinedByName =
  case xdelta3CompressionEmission noMetadataRequested { requestedSecondaryCompressor = Just SecondaryFGK } of
    Left (XDelta3CompressorEncodingUnsupported FGK) -> pure ()
    Left otherError -> assertFailureT ("expected the FGK decline, got: " <> renderSlapError otherError)
    Right _emission -> assertFailure "expected the FGK selection to be declined"

-- | The compressor-id catalog and its inverse agree: every compressor's declared id
-- resolves back to the compressor itself.
xdelta3CompressorIdsRoundTripThroughTheCatalog :: Assertion
xdelta3CompressorIdsRoundTripThroughTheCatalog =
  mapM_ (\compressor ->
          assertEqual (show compressor)
            (Just compressor)
            (secondaryCompressorCatalog (secondaryCompressorId compressor)))
        [SecondaryDJW, SecondaryLZMA, SecondaryFGK]

-- | The matcher's addressable-range wall, held at its exact boundary with no bytes allocated:
-- 'rejectUnaddressablePair' judges sizes, so files at 'maxBound' fit in two 'Int's here.
-- A pair whose augmented string is exactly 'maxBound' long passes; one byte more is refused;
-- and two 'maxBound' files — whose sum would wrap if the check ran in 'Int' — are refused too,
-- pinning that the judgment runs in 'Integer'.
vcdiffUnaddressablePairRefused :: Assertion
vcdiffUnaddressablePairRefused = do
  let judge sourceBytes targetBytes =
        rejectUnaddressablePair (SourceFileSize (FileSize sourceBytes))
                                (TargetFileSize (FileSize targetBytes))
  assertEqual "an augmented string of exactly maxBound bytes passes"
    (Right ()) (judge (maxBound - 2) 0)
  case judge (maxBound - 1) 0 of
    Left (VCDIFFPairExceedsAddressableRange _ _ _) -> pure ()
    other -> assertFailure ("expected the addressable-range refusal, got " ++ show other)
  case judge maxBound maxBound of
    Left (VCDIFFPairExceedsAddressableRange _ _ _) -> pure ()
    other -> assertFailure ("expected the addressable-range refusal, got " ++ show other)

-- | The windowed sibling of 'prop_vcdiff': sliced into deliberately tiny windows, an RFC create
-- still parses and applies back to the target exactly, whichever arm each window settled on.
prop_windowedRFC :: Property
prop_windowedRFC = forAll genPair $ \(source, target) ->
  case createRFCVCDIFF (SlicedIntoWindows sixtyFourByteWindows) (InputFileContents source) (OutputFileContents target) of
    Left createError -> counterexample ("create: " ++ Text.unpack (renderSlapError createError)) $ property False
    Right (CreateResult patch _) -> case VCDIFF.parseVCDIFF patch of
      Left slapError -> counterexample ("parse: " ++ Text.unpack (renderSlapError slapError)) $ property False
      Right (Parsed parsed _parseWarnings) ->
        VCDIFF.applyVCDIFF parsed (InputFileContents source) === Right (OutputFileContents target)

-- | The constructed case the target arm exists for: a repeated block over an unrelated source.
-- Sliced at the block size, window 0 carries the block itself (nothing is settled below its base,
-- so VCD_TARGET cannot mark it), every later window wins by copying earlier output,
-- and the patch earns 'PatchRFC' — the VCD_TARGET windows are what eject the bytes from the core shape.
-- slap's own emission parses with no advisories, and the whole thing applies back exactly.
windowedRFCTargetArmWins :: Assertion
windowedRFCTargetArmWins = do
  let block  = pseudoRandomBytes 0xb10c 4096
      target = ByteString.concat (replicate 8 block)
      source = pseudoRandomBytes 0x50fa 4096
      blockSizedWindows = case emissionWindowSizeOfBytes 4096 of
        Just windowSize -> windowSize
        Nothing         -> error "four KiB is positive"
  case createRFCVCDIFF (SlicedIntoWindows blockSizedWindows) (InputFileContents source) (OutputFileContents target) of
    Left createError -> assertFailureT ("create: " <> renderSlapError createError)
    Right (CreateResult patch _) -> case VCDIFF.parseVCDIFF patch of
      Left slapError -> assertFailureT ("parse: " <> renderSlapError slapError)
      Right (Parsed parsed advisories) -> do
        assertEqual "slap's own emission parses clean" [] advisories
        case parsed of
          PatchRFC header windows -> do
            assertEqual "no custom code table rode along" (RFCHeader Nothing) header
            case toList windows of
              [] -> assertFailure "expected eight windows, got none"
              firstWindow : laterWindows -> do
                assertEqual "window 0 is self-contained"
                  Nothing (windowSourceSegment firstWindow)
                assertEqual "every later window draws on the produced target"
                  (replicate 7 (Just FromProducedTarget))
                  (map (fmap sourceSegmentOrigin . windowSourceSegment) laterWindows)
          _ -> assertFailure "expected the RFC flavor (VCD_TARGET windows present)"
        assertEqual "the windowed VCD_TARGET patch applies back exactly"
          (Right (OutputFileContents target))
          (VCDIFF.applyVCDIFF parsed (InputFileContents source))

-- | On a small pair with no long self-repeats every window settles on its source arm, no custom table
-- can amortize over a mere eight windows (the gate declines), and the windowed RFC emission is then
-- byte-identical to the plain xdelta3 one (verification and compression omitted):
-- same matcher, same tightening, same packer, and no extension bytes on either side.
-- The equality also witnesses the tie rule in the compete (the source arm takes every tie),
-- and that a windowed RFC patch which reached for no RFC feature stays exactly as xdelta3-readable as ever.
windowedRFCSourceArmMatchesXDelta3 :: Assertion
windowedRFCSourceArmMatchesXDelta3 = do
  let source = pseudoRandomBytes 0x77e5 512
      target = ByteString.pack
        [ if index == 0 then byte `Bits.xor` 0x5a else byte
        | (index, byte) <- zip [0 :: Int ..] (ByteString.unpack source) ]
      rfcResult = createRFCVCDIFF (SlicedIntoWindows sixtyFourByteWindows)
                    (InputFileContents source) (OutputFileContents target)
      xdelta3Result = createXDelta3 OmitVerification EmitSectionsPlain sixtyFourByteWindows Nothing
                        (InputFileContents source) (OutputFileContents target)
  case (rfcResult, xdelta3Result) of
    (Right (CreateResult (PatchFileContents rfcBytes) _), Right (CreateResult (PatchFileContents xdelta3Bytes) _)) ->
      assertEqual "source-armed windowed RFC equals the plain xdelta3 emission" xdelta3Bytes rfcBytes
    _ -> assertFailure "both creates succeed on an ordinary pair"

-- | The amortization case: 512 source-lockstep windows, each a COPY whose size the default table
-- can only spell with a coded-size varint. Pooled across windows the repeated COPY(64) shape earns
-- its mint — the table ships once in the header and drops a varint per window — so the windowed
-- patch undercuts the plain xdelta3 emission (which has no table to reach for),
-- carries VCD_CODETABLE, and still applies back exactly.
windowedRFCCustomTableAmortizes :: Assertion
windowedRFCCustomTableAmortizes = do
  let source = pseudoRandomBytes 0x7ab1 32768
      target = ByteString.pack
        [ if index `mod` 4096 == 0 then byte `Bits.xor` 0x5a else byte
        | (index, byte) <- zip [0 :: Int ..] (ByteString.unpack source) ]
      rfcResult = createRFCVCDIFF (SlicedIntoWindows sixtyFourByteWindows)
                    (InputFileContents source) (OutputFileContents target)
      xdelta3Result = createXDelta3 OmitVerification EmitSectionsPlain sixtyFourByteWindows Nothing
                        (InputFileContents source) (OutputFileContents target)
  case (rfcResult, xdelta3Result) of
    (Right (CreateResult rfcPatch@(PatchFileContents rfcBytes) _), Right (CreateResult (PatchFileContents xdelta3Bytes) _)) -> do
      assertBool "the pooled table pays: windowed RFC undercuts the table-less xdelta3 emission"
        (ByteString.length rfcBytes < ByteString.length xdelta3Bytes)
      case VCDIFF.parseVCDIFF rfcPatch of
        Left slapError -> assertFailureT ("parse: " <> renderSlapError slapError)
        Right (Parsed parsed _parseWarnings) -> do
          case parsed of
            PatchRFC header _ -> case rfcCustomCodeTable header of
              Just _  -> pure ()
              Nothing -> assertFailure "expected the custom code table in the RFC header"
            _ -> assertFailure "expected PatchRFC (the custom table is the RFC signal here)"
          assertEqual "the amortized patch applies back exactly"
            (Right (OutputFileContents target))
            (VCDIFF.applyVCDIFF parsed (InputFileContents source))
    _ -> assertFailure "both creates succeed on an ordinary pair"

-- | An empty target under windowing: one empty window, applied back to the empty file.
windowedRFCEmptyTarget :: Assertion
windowedRFCEmptyTarget = do
  let source = pseudoRandomBytes 0xe0 64
  case createRFCVCDIFF (SlicedIntoWindows sixtyFourByteWindows) (InputFileContents source) (OutputFileContents ByteString.empty) of
    Left createError -> assertFailureT ("create: " <> renderSlapError createError)
    Right (CreateResult patch _) -> case VCDIFF.parseVCDIFF patch of
      Left slapError -> assertFailureT ("parse: " <> renderSlapError slapError)
      Right (Parsed parsed _parseWarnings) -> do
        assertEqual "one window" 1 (length (toList (patchWindows parsed)))
        assertEqual "applies back to the empty target"
          (Right (OutputFileContents ByteString.empty))
          (VCDIFF.applyVCDIFF parsed (InputFileContents source))

-- | The rematch flips a window the designed table favors. The two arms below encode
-- to the same size under the default table — six fixed-size opcodes, three one-byte
-- operands, fifteen literal bytes each — and only the runner-up repeats its
-- (ADD 5, COPY 7) pair often enough to earn a minted opcode, so the judge finds it
-- strictly smaller; 'recompeteArmsUnderCandidateTable' has the judging story.
armRematchFlipsUnderMintedTable :: Assertion
armRematchFlipsUnderMintedTable =
  case recompeteArmsUnderCandidateTable defaultAddressCacheConfig [rematchCompete] of
    Just [rematchWinner] ->
      assertEqual "the target arm earns the window" FromProducedTarget (chosenOrigin rematchWinner)
    Just rematched ->
      assertFailureT ("one compete in, " <> Text.pack (show (length rematched)) <> " arms out")
    Nothing -> assertFailureT "expected the minted table to flip the compete"
  where
    rematchCompete = WindowArmCompete
      { competeWinner   = rematchArm FromSourceFile     variedPairsCover
      , competeRunnerUp = rematchArm FromProducedTarget repeatedPairsCover
      }

-- | The stand-pat control: both arms carry the varied shapes, the pooled mints help
-- them equally, and the rematch answers 'Nothing' — the settled arms stand.
armRematchStandsPatWithoutAdvantage :: Assertion
armRematchStandsPatWithoutAdvantage =
  assertEqual "no flip" Nothing
    (fmap (map chosenOrigin)
          (recompeteArmsUnderCandidateTable defaultAddressCacheConfig [standPatCompete]))
  where
    standPatCompete = WindowArmCompete
      { competeWinner   = rematchArm FromSourceFile     variedPairsCover
      , competeRunnerUp = rematchArm FromProducedTarget variedPairsCover
      }

-- | An arm over the shared 36-byte window slice for the rematch cases.
-- The default-table bytes go unread by the judge, so the field carries empty bytes.
rematchArm :: SegmentOrigin -> Cover -> ChosenWindowArm
rematchArm armOrigin armCover = ChosenWindowArm
  { chosenOrigin            = armOrigin
  , chosenExternalLength    = Length 64
  , chosenSlice             = ByteString.pack [0 .. 35]
  , chosenCover             = armCover
  , chosenDefaultTableBytes = ByteString.empty
  }

-- | Three (ADD 5, COPY 7) pairs, every copy at external address 0: the repeated
-- shape a designed table mints a combined opcode for.
repeatedPairsCover :: Cover
repeatedPairsCover = Cover
  [ CoverLiteral (Offset 0)  (Length 5), CoverCopy (Length 7) (Offset 0)
  , CoverLiteral (Offset 12) (Length 5), CoverCopy (Length 7) (Offset 0)
  , CoverLiteral (Offset 24) (Length 5), CoverCopy (Length 7) (Offset 0)
  ]

-- | The same wire budget spent on pairs whose sizes never repeat, so no shape
-- reaches the mint threshold on its own.
variedPairsCover :: Cover
variedPairsCover = Cover
  [ CoverLiteral (Offset 0)  (Length 5), CoverCopy (Length 7) (Offset 0)
  , CoverLiteral (Offset 12) (Length 6), CoverCopy (Length 8) (Offset 15)
  , CoverLiteral (Offset 26) (Length 4), CoverCopy (Length 6) (Offset 40)
  ]

-- prop_vcdiffIgnoresSource is gone as of 02b. In the floor it was a
-- tripwire: source-independence held only because the encoder read
-- nothing of the source, and its own comment said it would fall when
-- source-aware diffing arrived. The matcher now reads the source, so
-- the property is false by design — this note is the record that the
-- floor's deliberate blindness has ended.

-- | A real diff — the target is the source with a small middle edit —
-- round-trips through 'createRFCVCDIFF' AND emits fewer bytes than the
-- all-literal floor for the same pair. The size drop is the proof the
-- source was actually used; a round-trip alone would pass on a floor
-- cover too.
vcdiffRealDiffShrinks :: Assertion
vcdiffRealDiffShrinks =
  let source = ByteString.pack [0 .. 63]
      target = ByteString.take 32 source
            <> ByteString.pack [0xFF, 0xFE]
            <> ByteString.drop 34 source
  in case createRFCVCDIFF OneWholeTargetWindow (InputFileContents source) (OutputFileContents target) of
       Left createError -> assertFailureT ("create: " <> renderSlapError createError)
       Right (CreateResult matchedPatch@(PatchFileContents matchedBytes) _) -> do
         case VCDIFF.parseVCDIFF matchedPatch of
           Left slapError -> assertFailureT ("parse: " <> renderSlapError slapError)
           Right (Parsed parsed _parseWarnings) ->
             assertEqual "real diff round-trips"
               (Right (OutputFileContents target))
               (VCDIFF.applyVCDIFF parsed (InputFileContents source))
         let CreateResult (PatchFileContents floorBytes) _ =
               createFromCover (InputFileContents source) (OutputFileContents target)
                               (Cover [CoverLiteral (Offset 0) (byteLength target)])
         assertBool "matcher patch is smaller than the all-literal floor"
           (ByteString.length matchedBytes < ByteString.length floorBytes)

-- | A pair the matcher covers with several segments of both kinds —
-- a source-region COPY, a literal over the changed middle, and a second source-region COPY, each copied run long enough to be worth its address.
-- Round-tripping proves the three parallel arrays marshal and unmarshal in order, not just for a single segment.
vcdiffMatcherMultipleCopies :: Assertion
vcdiffMatcherMultipleCopies =
  let source = ByteString.pack (map (fromIntegral . fromEnum) "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
      target = ByteString.pack (map (fromIntegral . fromEnum) "ABCDEFGHIJKLM??nopqrstuvwxyz")
      segments = coverSegments (vcdiffCover (InputFileContents source) (OutputFileContents target))
      isCopy    segment = case segment of CoverCopy{}    -> True; CoverLiteral{} -> False
      isLiteral segment = case segment of CoverLiteral{} -> True; CoverCopy{}    -> False
  in do
    assertBool "cover has multiple segments"            (length segments > 1)
    assertBool "cover has both a copy and a literal"
      (any isCopy segments && any isLiteral segments)
    case createRFCVCDIFF OneWholeTargetWindow (InputFileContents source) (OutputFileContents target) of
      Left createError -> assertFailureT ("create: " <> renderSlapError createError)
      Right (CreateResult patch _) -> case VCDIFF.parseVCDIFF patch of
        Left slapError -> assertFailureT ("parse: " <> renderSlapError slapError)
        Right (Parsed parsed _parseWarnings) ->
          assertEqual "multi-segment cover round-trips"
            (Right (OutputFileContents target))
            (VCDIFF.applyVCDIFF parsed (InputFileContents source))

-- | The matcher's output pinned against a hand-computed cover, independent of round-trip —
-- a behavioural reference, not only a does-it-apply check.
-- Over target "ABCDEFGHZZ" against source "ABCDEFGH" the matcher takes the whole eight-byte source match,
-- then the trailing "ZZ" (no earlier occurrence) as a literal.
vcdiffMatcherAgreesWithHandBuiltCover :: Assertion
vcdiffMatcherAgreesWithHandBuiltCover =
  let source = ByteString.pack (map (fromIntegral . fromEnum) "ABCDEFGH")
      target = ByteString.pack (map (fromIntegral . fromEnum) "ABCDEFGHZZ")
  in assertEqual "matcher cover matches the hand-built greedy cover"
       (Cover [ CoverCopy (Length 8) (Offset 0)
              , CoverLiteral (Offset 8) (Length 2) ])
       (vcdiffCover (InputFileContents source) (OutputFileContents target))

-- | A match-free pair (no run of at least the minimum match in common)
-- drives the live path to the all-literal cover, so 'createRFCVCDIFF'
-- emits the floor's exact bytes — the floor is still reached, just no
-- longer hard-coded. Shown by equality with 'createFromCover' on the
-- explicit all-literal cover.
vcdiffFloorReachableThroughMatcher :: Assertion
vcdiffFloorReachableThroughMatcher =
  let source = ByteString.pack [0x01, 0x02, 0x03]
      target = ByteString.pack [0x10, 0x11, 0x12, 0x13]
      CreateResult (PatchFileContents floorBytes) _ =
        createFromCover (InputFileContents source) (OutputFileContents target)
                        (Cover [CoverLiteral (Offset 0) (byteLength target)])
  in case createRFCVCDIFF OneWholeTargetWindow (InputFileContents source) (OutputFileContents target) of
       Left createError -> assertFailureT ("create: " <> renderSlapError createError)
       Right (CreateResult (PatchFileContents liveBytes) _) ->
         assertEqual "live path falls back to the floor bytes" floorBytes liveBytes

-- | The emitter's shape on an all-literal cover, asserted on the parsed
-- result: a flavorless 'PatchCoreOnly' (it reaches for no RFC- or
-- xdelta3-specific feature), exactly one window, that window
-- self-contained (no source segment), and its sole instruction a single
-- ADD carrying the whole target. Driven through 'createFromCover' so it
-- tests the emitter, not whatever the matcher happens to find.
vcdiffFloorStructure :: Assertion
vcdiffFloorStructure =
  let target = ByteString.pack [0x41, 0x42, 0x43, 0x44]
      allLiteralCover = Cover [CoverLiteral (Offset 0) (byteLength target)]
  in case createFromCover (InputFileContents ByteString.empty) (OutputFileContents target) allLiteralCover of
       CreateResult patch _ -> case VCDIFF.parseVCDIFF patch of
         Left slapError -> assertFailureT ("parse: " <> renderSlapError slapError)
         Right (Parsed parsed _parseWarnings) -> do
           case parsed of
             PatchCoreOnly _ -> pure ()
             _               -> assertFailure "expected PatchCoreOnly"
           case toList (patchWindows parsed) of
             [window] -> do
               assertEqual "window is self-contained" Nothing (windowSourceSegment window)
               case toList (windowInstructions window) of
                 [Add literal] -> assertEqual "ADD carries the whole target" target literal
                 other         -> assertFailure ("expected a single ADD, got " ++ show other)
             other    -> assertFailure ("expected exactly one window, got " ++ show (length other))

-- | The exact bytes for @target = "AB"@ through an all-literal cover,
-- derived by hand from the wire layout rather than from the encoder, so
-- a varint-endianness or section-ordering bug a round-trip could hide
-- (create and apply sharing a symmetric mistake) is caught here. Magic,
-- version 00, Hdr_Indicator 00; window: Win_Indicator 00,
-- delta-encoding-length 08, target size 02, Delta_Indicator 00, A 02,
-- I 01, C 00, data @41 42@, inst @03@ (ADD fixed-size-2, default index 3
-- — the size rides in the opcode, so no size varint trails), no addr.
-- Driven through 'createFromCover' so it pins the emitter, not the
-- matcher's incidental behaviour on this input.
vcdiffExactWireBytes :: Assertion
vcdiffExactWireBytes =
  let target = ByteString.pack [0x41, 0x42]
      allLiteralCover = Cover [CoverLiteral (Offset 0) (byteLength target)]
      expected = ByteString.pack
        [0xD6, 0xC3, 0xC4, 0x00, 0x00, 0x00, 0x08, 0x02, 0x00, 0x02, 0x01, 0x00, 0x41, 0x42, 0x03]
  in case createFromCover (InputFileContents ByteString.empty) (OutputFileContents target) allLiteralCover of
       CreateResult (PatchFileContents patch) _ ->
         assertEqual "exact wire bytes" expected patch

-- | Create a patch from a hand-built cover, parse it, apply it to the
-- source, and assert the result is the target. The shared body of the
-- cover round-trip cases below.
assertCoverRoundTrips :: ByteString.ByteString -> ByteString.ByteString -> Cover -> Assertion
assertCoverRoundTrips source target coverPlan =
  case createFromCover (InputFileContents source) (OutputFileContents target) coverPlan of
    CreateResult patchContents _ -> case VCDIFF.parseVCDIFF patchContents of
      Left slapError -> assertFailureT ("parse: " <> renderSlapError slapError)
      Right (Parsed parsed _parseWarnings) ->
        assertEqual "cover round-trip"
          (Right (OutputFileContents target))
          (VCDIFF.applyVCDIFF parsed (InputFileContents source))

-- | The load-bearing new path: a COPY that resolves into the source
-- segment @S@. The target reuses a verbatim stretch of the source
-- ("WORLD" out of "HELLOWORLD") and ends with a one-byte literal.
vcdiffSourceCopyRoundTrips :: Assertion
vcdiffSourceCopyRoundTrips =
  let source = ByteString.pack (map (fromIntegral . fromEnum) "HELLOWORLD")
      target = ByteString.pack (map (fromIntegral . fromEnum) "WORLD!")
      coverPlan = Cover
        [ CoverCopy (Length 5) (Offset 5)       -- source[5..10) = "WORLD"
        , CoverLiteral (Offset 5) (Length 1) ]  -- target[5] = "!"
  in assertCoverRoundTrips source target coverPlan

-- | A COPY addressing the produced-target region of @U@ (offset ≥ the
-- source length): the target repeats an earlier stretch of itself, so
-- the copy reads bytes this window already wrote, not the source. The
-- source ("XY") is still declared as the segment but never read.
vcdiffTargetCopyRoundTrips :: Assertion
vcdiffTargetCopyRoundTrips =
  let source = ByteString.pack (map (fromIntegral . fromEnum) "XY")
      target = ByteString.pack (map (fromIntegral . fromEnum) "ABAB")
      coverPlan = Cover
        [ CoverLiteral (Offset 0) (Length 2)    -- target[0..2) = "AB"
        , CoverCopy (Length 2) (Offset 2) ]     -- U offset 2 = produced-target[0..2) = "AB"
  in assertCoverRoundTrips source target coverPlan

-- | A literal that is one byte repeated becomes a 'Run', not an 'Add' —
-- asserted on the parsed instruction — and round-trips.
vcdiffRunRoundTrips :: Assertion
vcdiffRunRoundTrips =
  let source = ByteString.empty
      target = ByteString.replicate 4 0x41    -- "AAAA"
      coverPlan = Cover [CoverLiteral (Offset 0) (Length 4)]
  in case createFromCover (InputFileContents source) (OutputFileContents target) coverPlan of
       CreateResult patchContents _ -> case VCDIFF.parseVCDIFF patchContents of
         Left slapError -> assertFailureT ("parse: " <> renderSlapError slapError)
         Right (Parsed parsed _parseWarnings) -> do
           case toList (patchWindows parsed) of
             [window] -> case toList (windowInstructions window) of
               [Run (Length 4) 0x41] -> pure ()
               other                 -> assertFailure ("expected a single RUN, got " ++ show other)
             other -> assertFailure ("expected exactly one window, got " ++ show (length other))
           assertEqual "RUN round-trip"
             (Right (OutputFileContents target))
             (VCDIFF.applyVCDIFF parsed (InputFileContents source))

-- | The exact bytes for a cover whose sole instruction is a COPY of the
-- whole source, derived by hand from the layout — the VCD_SOURCE
-- indicator, the two segment varints, the index-20 fixed-size-4 opcode,
-- and the SELF-mode address in the address section. Pins the copying-window
-- shape the way 'vcdiffExactWireBytes' pins the all-ADD floor, catching
-- a segment-varint-order or address-section misroute a round-trip could
-- hide.
vcdiffCopyExactWireBytes :: Assertion
vcdiffCopyExactWireBytes =
  let source   = ByteString.pack [0x41, 0x42, 0x43, 0x44]   -- ABCD
      target   = source
      coverPlan = Cover [CoverCopy (Length 4) (Offset 0)]
      expected = ByteString.pack
        [ 0xD6, 0xC3, 0xC4   -- magic
        , 0x00               -- version
        , 0x00               -- Hdr_Indicator
        , 0x01               -- Win_Indicator: VCD_SOURCE
        , 0x04               -- source-segment length
        , 0x00               -- source-segment position
        , 0x07               -- delta-encoding length
        , 0x04               -- target window size
        , 0x00               -- Delta_Indicator
        , 0x00               -- data-section length
        , 0x01               -- instruction-section length
        , 0x01               -- address-section length
        , 0x14               -- inst: COPY mode-0 fixed-size-4 (default index 20)
        , 0x00 ]             -- addr: SELF address 0
  in case createFromCover (InputFileContents source) (OutputFileContents target) coverPlan of
       CreateResult (PatchFileContents patch) _ ->
         assertEqual "exact wire bytes (COPY)" expected patch

-- | SAME is a single byte. A COPY whose address already sits in its
-- same-slot — the same address recorded then copied again is the
-- simplest case — selects a same-mode opcode and emits its address as
-- one byte, where SELF would spend two for an address past 0x7F.
-- Asserted at the selection seam, the encoder's inverse of the decode
-- the round-trips exercise.
vcdiffSameModeIsOneByte :: Assertion
vcdiffSameModeIsOneByte =
  let address  = Offset 200          -- past 0x7F, so a SELF varint is two bytes
      here     = Offset 500          -- any write head past the address
      primed   = recordAddress (freshAddressCache defaultAddressCacheConfig) address
      selected = selectCopyAddressMode primed here address
  in do
       assertEqual "same-mode opcode (block 0)" 6 (selectedAddressMode selected)
       case selectedAddressOperand selected of
         AddressSameByte (SameSlotByte byte) -> assertEqual "single same-slot byte" 200 byte
         other -> assertFailure ("expected a one-byte same operand, got " ++ show other)

-- | The address section shrinks below a SELF-only encoding. Three copies
-- of one source region, each at the same offset past 0x7F, would cost a
-- two-byte SELF varint apiece under the 02c encoder (six bytes); the
-- cache modes spend one byte each (a HERE then two SAMEs, three bytes).
-- Its byte count — read back out of the emitted patch — dropping below
-- the SELF-only sum is the proof the cheaper modes engaged, where the
-- round-trip (also asserted) would pass a SELF-only encoder just as well.
vcdiffAddressModesShrinkTheAddressSection :: Assertion
vcdiffAddressModesShrinkTheAddressSection =
  let source    = ByteString.pack [ fromIntegral (i `mod` 251) | i <- [0 .. 299 :: Int] ]
      region    = ByteString.take 10 (ByteString.drop 200 source)
      lit1      = ByteString.pack [0xF0, 0xF1]
      lit2      = ByteString.pack [0xF2, 0xF3]
      target    = region <> lit1 <> region <> lit2 <> region
      coverPlan = Cover
        [ CoverCopy    (Length 10) (Offset 200)
        , CoverLiteral (Offset 10) (Length 2)
        , CoverCopy    (Length 10) (Offset 200)
        , CoverLiteral (Offset 22) (Length 2)
        , CoverCopy    (Length 10) (Offset 200) ]
      copyOffsets          = [ n | CoverCopy _ (Offset n) <- coverSegments coverPlan ]
      selfOnlyAddressBytes = sum [ minimalVcdiffVarintLength (fromIntegral n) | n <- copyOffsets ]
      patch = case createFromCover (InputFileContents source) (OutputFileContents target) coverPlan of
                CreateResult (PatchFileContents bytes) _ -> bytes
  in do
       assertCoverRoundTrips source target coverPlan
       assertBool "the address section is shorter than a SELF-only encoding"
         (addressSectionLength patch < selfOnlyAddressBytes)

-- | The three section byte-slices — data, instructions, addresses — of a
-- single-window VCDIFF patch, the shape the encoder emits: walk the fixed
-- header and the window framing to the sections and cut each to its
-- declared length. Test-local, and it assumes that one-window
-- default-table shape.
windowSections :: ByteString.ByteString
               -> (ByteString.ByteString, ByteString.ByteString, ByteString.ByteString)
windowSections patch =
  ( slice sectionsStart dataLen
  , slice (sectionsStart + dataLen) instLen
  , slice (sectionsStart + dataLen + instLen) addrLen )
  where
    readVarint offset = case getVcdiffVarint offset patch of
      Right (VarintResult value consumed) -> (fromIntegral value, offset + consumed)
      Left _ -> error "windowSections: malformed varint in patch framing"
    skipVarint       = snd . readVarint
    slice offset len = ByteString.take len (ByteString.drop offset patch)
    afterHeader  = 5                              -- magic(3) + version(1) + Hdr_Indicator(1)
    winIndicator = ByteString.index patch afterHeader
    afterWin     = afterHeader + 1
    afterSegment = if winIndicator Bits..&. 0x03 /= 0  -- a copy-source bit: two segment varints follow
                     then skipVarint (skipVarint afterWin)
                     else afterWin
    afterTarget             = skipVarint (skipVarint afterSegment)  -- delta-encoding length, then target size
    (dataLen, afterDataLen) = readVarint (afterTarget + 1)          -- Delta_Indicator(1), then data length
    (instLen, afterInstLen) = readVarint afterDataLen               -- instruction-section length
    (addrLen, afterAddrLen) = readVarint afterInstLen               -- address-section length
    sectionsStart           = afterAddrLen

-- | The byte length of a single-window patch's address section, a
-- projection of 'windowSections'.
addressSectionLength :: ByteString.ByteString -> Int
addressSectionLength patch = let (_, _, addr) = windowSections patch in ByteString.length addr

-- | The number of target bytes one instruction produces — its ADD/RUN/
-- COPY size — as the 'Length' a coded-size opcode would spell in a
-- trailing size varint. Test-local, for sizing a coded-only baseline.
instructionOutputLength :: VCDIFFInstruction -> Length
instructionOutputLength (Add literal)       = byteLength literal
instructionOutputLength (Run runLength _)   = runLength
instructionOutputLength (Copy copyLength _) = copyLength

-- | A small ADD immediately followed by a size-4 COPY is one combined
-- opcode for the two, not two singles: the instruction section is exactly
-- the one combined byte (index 163 = ADD(1)+COPY(4) mode 0, the COPY's
-- cheapest mode here being SELF), with no size varints trailing. The
-- ADD's literal still rides the data section and the COPY's operand the
-- address section. Round-trips.
vcdiffCombinedAddCopyIsOneOpcode :: Assertion
vcdiffCombinedAddCopyIsOneOpcode =
  let source = ByteString.pack (map (fromIntegral . fromEnum) "ABCD")
      target = ByteString.pack (map (fromIntegral . fromEnum) "ZABCD")
      coverPlan = Cover
        [ CoverLiteral (Offset 0) (Length 1)   -- "Z" -> ADD(1)
        , CoverCopy (Length 4) (Offset 0) ]    -- source[0..4) = "ABCD", SELF mode 0
      CreateResult (PatchFileContents patch) _ =
        createFromCover (InputFileContents source) (OutputFileContents target) coverPlan
      (dataSec, instSec, addrSec) = windowSections patch
  in do
       assertEqual "one combined opcode for the ADD+COPY pair"
         (ByteString.pack [0xA3]) instSec       -- index 163 = ADD(1)+COPY(4) mode 0
       assertEqual "data section carries the ADD's literal"
         (ByteString.pack [0x5A]) dataSec       -- "Z"
       assertEqual "address section carries the COPY's SELF operand"
         (ByteString.pack [0x00]) addrSec
       assertCoverRoundTrips source target coverPlan

-- | The mirror: a size-4 COPY immediately followed by a one-byte ADD is
-- one combined opcode (index 247 = COPY(4)+ADD(1) mode 0), the COPY's
-- operand in the address section and the ADD's literal in the data
-- section, no size varints. Round-trips.
vcdiffCombinedCopyAddIsOneOpcode :: Assertion
vcdiffCombinedCopyAddIsOneOpcode =
  let source = ByteString.pack (map (fromIntegral . fromEnum) "ABCD")
      target = ByteString.pack (map (fromIntegral . fromEnum) "ABCDZ")
      coverPlan = Cover
        [ CoverCopy (Length 4) (Offset 0)      -- source[0..4) = "ABCD", SELF mode 0
        , CoverLiteral (Offset 4) (Length 1) ] -- "Z" -> ADD(1)
      CreateResult (PatchFileContents patch) _ =
        createFromCover (InputFileContents source) (OutputFileContents target) coverPlan
      (dataSec, instSec, addrSec) = windowSections patch
  in do
       assertEqual "one combined opcode for the COPY+ADD pair"
         (ByteString.pack [0xF7]) instSec       -- index 247 = COPY(4)+ADD(1) mode 0
       assertEqual "data section carries the ADD's literal"
         (ByteString.pack [0x5A]) dataSec       -- "Z"
       assertEqual "address section carries the COPY's SELF operand"
         (ByteString.pack [0x00]) addrSec
       assertCoverRoundTrips source target coverPlan

-- | A lone three-byte non-repeated ADD with no copy beside it takes the
-- fixed-size single opcode (index 4 = ADD size 3) and emits no trailing
-- size varint — the instruction section is the one opcode byte. Round-trips.
vcdiffFixedSizeAddDropsVarint :: Assertion
vcdiffFixedSizeAddDropsVarint =
  let target = ByteString.pack (map (fromIntegral . fromEnum) "XYZ")  -- ADD, length 3, not repeated
      coverPlan = Cover [CoverLiteral (Offset 0) (Length 3)]
      CreateResult (PatchFileContents patch) _ =
        createFromCover (InputFileContents ByteString.empty) (OutputFileContents target) coverPlan
      (dataSec, instSec, _addrSec) = windowSections patch
  in do
       assertEqual "fixed-size ADD opcode, no size varint trailing"
         (ByteString.pack [0x04]) instSec       -- index 4 = ADD size 3
       assertEqual "data section carries the literal" target dataSec
       assertCoverRoundTrips ByteString.empty target coverPlan

-- | The fallback guard: an ADD too large to combine or to name a
-- fixed-size entry (length 20, above the table's 1–17 inline ADD range)
-- beside a COPY too large for a fixed entry (length 20, above 4–18) emit
-- as two separate coded-size singles — ADD coded (index 1) then a size
-- varint, COPY mode-0 coded (index 19) then a size varint — with no
-- combine forced and no fixed entry misapplied. Round-trips.
vcdiffOversizeFallsBackToCoded :: Assertion
vcdiffOversizeFallsBackToCoded =
  let source  = ByteString.pack [0 .. 39]
      literal = ByteString.pack [100 .. 119]            -- 20 distinct bytes -> ADD, too big to combine
      target  = literal <> ByteString.take 20 source    -- then a 20-byte COPY of source[0..20)
      coverPlan = Cover
        [ CoverLiteral (Offset 0) (Length 20)
        , CoverCopy (Length 20) (Offset 0) ]
      CreateResult (PatchFileContents patch) _ =
        createFromCover (InputFileContents source) (OutputFileContents target) coverPlan
      (_dataSec, instSec, _addrSec) = windowSections patch
  in do
       assertEqual "two separate coded-size singles (ADD then COPY mode 0), no combine"
         (ByteString.pack [0x01, 0x14, 0x13, 0x14]) instSec
       assertCoverRoundTrips source target coverPlan

-- | The whole layer's point: across three ADD(1)+COPY(4) pairs the dense
-- instruction section is shorter than a coded-size-only encoding of the
-- same instructions (one opcode plus a size varint each). The byte count
-- dropping below that baseline is the proof the dense entries engaged,
-- where a round-trip alone would pass a coded-only encoder too.
vcdiffDenseShrinksInstructionSection :: Assertion
vcdiffDenseShrinksInstructionSection =
  let source = ByteString.pack [0 .. 49]
      target = ByteString.pack
        [ 0xF0, 0, 1, 2, 3, 0xF1, 10, 11, 12, 13, 0xF2, 20, 21, 22, 23 ]
      coverPlan = Cover
        [ CoverLiteral (Offset 0)  (Length 1), CoverCopy (Length 4) (Offset 0)
        , CoverLiteral (Offset 5)  (Length 1), CoverCopy (Length 4) (Offset 10)
        , CoverLiteral (Offset 10) (Length 1), CoverCopy (Length 4) (Offset 20) ]
      CreateResult (PatchFileContents patch) _ =
        createFromCover (InputFileContents source) (OutputFileContents target) coverPlan
      (_dataSec, instSec, _addrSec) = windowSections patch
      -- The instruction section a coded-size-only encoder would emit for
      -- the same instructions: one opcode plus a size varint each.
      codedOnlyBytes = sum
        [ 1 + minimalVcdiffVarintLength (fromIntegral n)
        | instruction <- coverToInstructions target coverPlan
        , let Length n = instructionOutputLength instruction ]
  in do
       assertBool "the instruction section is shorter than a coded-size-only encoding"
         (ByteString.length instSec < codedOnlyBytes)
       assertCoverRoundTrips source target coverPlan

-- | The encode/decode inverse round-trips at the address-cache seam,
-- across address regimes the matcher-bounded 'prop_vcdiff' (capped at
-- 16-byte inputs) never reaches: multi-byte addresses and the
-- same-cache's 768-slot aliasing. For a cache primed with prior
-- addresses clustered at and just below the target — so SAME and NEAR
-- fire, not only SELF — the mode and operand 'selectCopyAddressMode'
-- chooses decode back through 'decodeCopyAddress' to the same address.
-- The lockstep guarantee at its narrowest, fastest point: any drift in
-- the band arithmetic or the cache state sends a NEAR or SAME address
-- elsewhere and fails here.
prop_vcdiffAddressModeRoundTrips :: Word.Word16 -> [Word.Word16] -> Word.Word16 -> Property
prop_vcdiffAddressModeRoundTrips addressRaw recentSteps hereBump =
  counterexample ("selected mode " ++ show (selectedAddressMode selected)) $
    case decodeCopyAddress cache here (selectedAddressMode selected) operandBytes (Offset 0) of
      Right reading -> copyAddressDecoded reading === address
      Left failure  -> counterexample ("decode failed: " ++ show failure) (property False)
  where
    addressInt   = fromIntegral addressRaw :: Int
    address      = Offset addressInt
    -- Recorded addresses at and just below the target, so a same-slot
    -- holds it (SAME) and near slots hold small-forward-delta neighbours
    -- (NEAR), across whatever multi-byte base address was generated.
    priorOffsets = [ Offset (max 0 (addressInt - fromIntegral (step `mod` 16))) | step <- recentSteps ]
    cache        = foldl recordAddress (freshAddressCache defaultAddressCacheConfig) priorOffsets
    here         = Offset (addressInt + fromIntegral hereBump + 1)
    selected     = selectCopyAddressMode cache here address
    operandBytes = case selectedAddressOperand selected of
      AddressVarint value -> LazyByteString.toStrict (toLazyByteString (putVcdiffVarint value))
      AddressSameByte (SameSlotByte byte) -> ByteString.singleton byte

-- | A COPY whose read overruns the write head — the run-length / overlap
-- case the decoder expands byte by byte ('ExpandForward'). The target
-- repeats a two-byte stretch of itself three times; the copy reads four
-- bytes starting two before the head, so each freshly written byte feeds
-- the read. This is the most intricate apply branch and the other cover
-- cases never reach it (their copies stop at the head, not past it).
vcdiffOverlapCopyRoundTrips :: Assertion
vcdiffOverlapCopyRoundTrips =
  let source = ByteString.pack (map (fromIntegral . fromEnum) "XY")
      target = ByteString.pack (map (fromIntegral . fromEnum) "ABABAB")
      coverPlan = Cover
        [ CoverLiteral (Offset 0) (Length 2)    -- target[0..2) = "AB"
        , CoverCopy (Length 4) (Offset 2) ]     -- reads produced "AB", overruns, expands to "ABAB"
  in assertCoverRoundTrips source target coverPlan

-- | One window mixing every instruction kind — a non-repeated literal
-- (ADD), a repeated literal (RUN), a source-region COPY, and a
-- produced-target COPY — so the three section streams interleave and the
-- address stream carries two independent SELF addresses. The strongest
-- check that 'layoutSections' keeps the streams in step.
vcdiffInterleavedRoundTrips :: Assertion
vcdiffInterleavedRoundTrips =
  let source = ByteString.pack (map (fromIntegral . fromEnum) "HELLO")
      target = ByteString.pack (map (fromIntegral . fromEnum) "XYZZHEXY")
      coverPlan = Cover
        [ CoverLiteral (Offset 0) (Length 2)    -- "XY" -> ADD (not repeated)
        , CoverLiteral (Offset 2) (Length 2)    -- "ZZ" -> RUN (repeated, length 2)
        , CoverCopy (Length 2) (Offset 0)       -- U offset 0 = source[0..2) = "HE"
        , CoverCopy (Length 2) (Offset 5) ]     -- U offset 5 = produced-target[0..2) = "XY"
  in assertCoverRoundTrips source target coverPlan

-- | Instruction selection pinned directly on 'coverToInstructions', across the RUN/ADD boundary.
-- A one-byte literal and a two-byte repeat both stay ADD, a three-byte repeat is the smallest RUN, a two-byte non-repeat stays ADD, and a copy passes through to COPY.
vcdiffInstructionSelection :: Assertion
vcdiffInstructionSelection =
  let target = ByteString.pack [0x41, 0x42, 0x42, 0x43, 0x43, 0x43, 0x44, 0x45]   -- "A" "BB" "CCC" "DE"
      coverPlan = Cover
        [ CoverLiteral (Offset 0) (Length 1)   -- "A"   -> Add (length 1, not "repeated")
        , CoverLiteral (Offset 1) (Length 2)   -- "BB"  -> Add (a two-byte repeat is below the boundary)
        , CoverLiteral (Offset 3) (Length 3)   -- "CCC" -> Run 3 (the smallest RUN)
        , CoverLiteral (Offset 6) (Length 2)   -- "DE"  -> Add (length 2, not repeated)
        , CoverCopy (Length 4) (Offset 7) ]    -- passes through unchanged
  in assertEqual "cover instruction selection"
       [ Add (ByteString.pack [0x41])
       , Add (ByteString.pack [0x42, 0x42])
       , Run (Length 3) 0x43
       , Add (ByteString.pack [0x44, 0x45])
       , Copy (Length 4) (Offset 7) ]
       (coverToInstructions target coverPlan)

-- | Every defined mode byte round-trips: 'classifyAddressMode' then 'modeFamilyToByte' is the identity over @[0, modeCeiling)@.
vcdiffAddressModeByteRoundTrip :: Assertion
vcdiffAddressModeByteRoundTrip =
  mapM_ roundTripsAt [0 .. modeCeiling config - 1]
  where
    config = defaultAddressCacheConfig
    roundTripsAt mode =
      let modeByte = fromIntegral mode
      in assertEqual ("mode byte " ++ show mode)
           (Just modeByte)
           (modeFamilyToByte config <$> classifyAddressMode config modeByte)

-- | A lopsided (source, target, cover) for the custom-table cases: @n@
-- repetitions of a five-byte literal then a four-byte copy of the source
-- head, so the resolved stream is @n@ ADD(5)+COPY(4) pairs — a shape the
-- default table has no combined opcode for, its ADD+COPY rows stopping at
-- ADD size 4. A large @n@ earns a custom table that pays its inner delta
-- back; a small @n@ earns one the gate declines.
lopsidedCustomTableCase :: Int -> (ByteString.ByteString, ByteString.ByteString, Cover)
lopsidedCustomTableCase repetitions =
  (source, target, Cover (concatMap segmentsAt [0 .. repetitions - 1]))
  where
    source       = ByteString.pack [0 .. 63]
    copiedHead   = ByteString.take 4 source                       -- source[0..4)
    literalAt i  = ByteString.pack [0xF0, 0xF1, 0xF2, 0xF3, fromIntegral (i `mod` 256)]
    unitAt i     = literalAt i <> copiedHead                      -- five-byte ADD, four-byte COPY
    target       = ByteString.concat (map unitAt [0 .. repetitions - 1])
    segmentsAt i = [ CoverLiteral (Offset (9 * i)) (Length 5)
                   , CoverCopy    (Length 4) (Offset 0) ]

-- | The designed table only ever mints entries the format can carry:
-- 'deserializeCodeTable' rejects malformed images, so a designed table that
-- survives a serialize/deserialize round-trip unchanged is wire-valid. Not
-- a tautology — it is the check that the design mints nothing the
-- 1536-byte image cannot hold.
vcdiffDesignedTableIsWireValid :: Assertion
vcdiffDesignedTableIsWireValid =
  let (source, target, coverPlan) = lopsidedCustomTableCase 16
      resolved = resolveInstructionAddresses defaultAddressCacheConfig
                   (Offset (ByteString.length source))
                   (coverToInstructions target coverPlan)
  in case designCandidateTable resolved of
       Nothing       -> assertFailure "expected a candidate table for a lopsided stream"
       Just designed ->
         assertEqual "the designed table deserializes from its own image unchanged"
           (Right designed)
           (deserializeCodeTable (serializeCodeTable designed))

-- | The load-bearing one: a lopsided pair the candidate table improves,
-- emitted with the custom-table consideration, parsed and applied back to
-- the target. It exercises the whole recursion — the inner delta parsed
-- with custom tables forbidden, applied to the default image, read back
-- into the table the window decodes against — and confirms the patch
-- declares VCD_CODETABLE and parses as an RFC-arc patch carrying a table.
-- A round-trip that reaches the target also proves the inner delta carried
-- no nested table, surviving the forbidden-policy decode.
vcdiffCustomTableRoundTrips :: Assertion
vcdiffCustomTableRoundTrips =
  let (source, target, coverPlan) = lopsidedCustomTableCase 150
      CreateResult (PatchFileContents patch) _ =
        createConsideringCustomTable (InputFileContents source) (OutputFileContents target) coverPlan
  in do
       assertBool "the custom-table patch sets Hdr_Indicator VCD_CODETABLE"
         (Bits.testBit (ByteString.index patch 4) 1)
       case VCDIFF.parseVCDIFF (PatchFileContents patch) of
         Left slapError -> assertFailureT ("parse: " <> renderSlapError slapError)
         Right (Parsed parsed _parseWarnings) -> do
           case parsed of
             PatchRFC header _ -> case rfcCustomCodeTable header of
               Just _  -> pure ()
               Nothing -> assertFailure "expected a custom code table in the parsed RFC header"
             _ -> assertFailure "expected PatchRFC for a custom-table patch"
           assertEqual "custom-table patch round-trips"
             (Right (OutputFileContents target))
             (VCDIFF.applyVCDIFF parsed (InputFileContents source))

-- | On the same lopsided pair, the custom-table patch is strictly smaller
-- than the one the default-only core produces for the identical cover. The
-- saving is the combined opcodes the default lacked, net of the inner
-- delta the table cost to ship.
vcdiffCustomTableBeatsDefault :: Assertion
vcdiffCustomTableBeatsDefault =
  let (source, target, coverPlan) = lopsidedCustomTableCase 150
      CreateResult (PatchFileContents customBytes) _ =
        createConsideringCustomTable (InputFileContents source) (OutputFileContents target) coverPlan
      CreateResult (PatchFileContents defaultBytes) _ =
        createFromCover (InputFileContents source) (OutputFileContents target) coverPlan
  in assertBool "the custom-table patch is strictly smaller than the default-only patch"
       (ByteString.length customBytes < ByteString.length defaultBytes)

-- | The gate declines a table that would not pay. On a barely-lopsided pair
-- a candidate table /is/ designed — so it is the gate, not a missing
-- candidate, doing the declining — but its two saved opcodes cannot cover
-- the inner delta, so the custom-considering emission falls back to the
-- default bytes exactly: VCD_CODETABLE clear, byte-identical to the
-- default-only core.
vcdiffCustomTableGateHolds :: Assertion
vcdiffCustomTableGateHolds =
  let (source, target, coverPlan) = lopsidedCustomTableCase 2
      resolved = resolveInstructionAddresses defaultAddressCacheConfig
                   (Offset (ByteString.length source))
                   (coverToInstructions target coverPlan)
      CreateResult (PatchFileContents consideredBytes) _ =
        createConsideringCustomTable (InputFileContents source) (OutputFileContents target) coverPlan
      CreateResult (PatchFileContents defaultBytes) _ =
        createFromCover (InputFileContents source) (OutputFileContents target) coverPlan
  in do
       case designCandidateTable resolved of
         Just _  -> pure ()
         Nothing -> assertFailure "expected a candidate to be designed, so the gate is what declines it"
       assertEqual "the gate falls back to the default bytes exactly" defaultBytes consideredBytes
       assertBool "no custom code table: Hdr_Indicator VCD_CODETABLE clear"
         (not (Bits.testBit (ByteString.index consideredBytes 4) 1))

-- | A (source, target, cover) whose copies interleave five source regions
-- round-robin, each region advancing a few bytes per round. With the default
-- four near slots the five-stream round-robin evicts each region before its
-- next use, so every copy spells its (two-byte) address out in full; a fifth
-- near slot holds all five regions across a round, turning each repeat into a
-- one-byte NEAR delta. So the address section shrinks under a grown cache,
-- and the grow lands on exactly five near slots. The regions sit past offset
-- 128 so a full address costs two bytes and the saving is real.
interleavedCacheCase :: Int -> (ByteString.ByteString, ByteString.ByteString, Cover)
interleavedCacheCase rounds = (source, target, Cover segments)
  where
    source        = ByteString.pack [ fromIntegral (i `mod` 256) | i <- [0 .. 1199 :: Int] ]
    bases         = [200, 400, 600, 800, 1000] :: [Int]
    step          = 4 :: Int
    copyLen       = 4 :: Int
    addressAt base r = base + r * step
    sliceAt  base r  = ByteString.take copyLen (ByteString.drop (addressAt base r) source)
    segments = [ CoverCopy (Length copyLen) (Offset (addressAt base r))
               | r <- [0 .. rounds - 1], base <- bases ]
    target   = ByteString.concat
                 [ sliceAt base r | r <- [0 .. rounds - 1], base <- bases ]

-- | The @s_near@ a custom-table patch declares, read from the code-table
-- data: past the magic, version, and Hdr_Indicator sits the code-table-data
-- length varint, and the first data byte after it is @s_near@.
declaredNearSlots :: ByteString.ByteString -> Int
declaredNearSlots patch = case getVcdiffVarint codeTableDataLengthOffset patch of
  Right (VarintResult _ consumed) ->
    fromIntegral (ByteString.index patch (codeTableDataLengthOffset + consumed))
  Left _ -> error "declaredNearSlots: patch carries no code-table data"
  where
    codeTableDataLengthOffset = 5   -- magic (3) + version (1) + Hdr_Indicator (1)

-- | The load-bearing cache test: a pair whose locality outruns four near
-- slots ships a patch declaring a grown geometry, and parse → apply
-- reconstructs the target. The round-trip is the proof the declared geometry
-- is carried and read as one — under a wrong-sized cache the NEAR addresses
-- would decode elsewhere and the target would not match.
vcdiffGrownCacheRoundTrips :: Assertion
vcdiffGrownCacheRoundTrips =
  let (source, target, coverPlan) = interleavedCacheCase 12
      CreateResult (PatchFileContents patch) _ =
        createConsideringCustomTable (InputFileContents source) (OutputFileContents target) coverPlan
  in do
    assertBool "ships a custom code table" (Bits.testBit (ByteString.index patch 4) 1)
    assertBool "declares a grown near cache (s_near > 4)" (declaredNearSlots patch > 4)
    case VCDIFF.parseVCDIFF (PatchFileContents patch) of
      Left slapError -> assertFailureT ("parse: " <> renderSlapError slapError)
      Right (Parsed parsed _parseWarnings) ->
        assertEqual "grown-cache patch round-trips"
          (Right (OutputFileContents target))
          (VCDIFF.applyVCDIFF parsed (InputFileContents source))

-- | On the same pair, the grown-cache patch is strictly smaller than the
-- one the default geometry produces for the identical cover — the address
-- section shrank by more than the custom table cost to ship.
vcdiffGrownCacheBeatsDefault :: Assertion
vcdiffGrownCacheBeatsDefault =
  let (source, target, coverPlan) = interleavedCacheCase 12
      CreateResult (PatchFileContents grownBytes) _ =
        createConsideringCustomTable (InputFileContents source) (OutputFileContents target) coverPlan
      CreateResult (PatchFileContents defaultBytes) _ =
        createFromCover (InputFileContents source) (OutputFileContents target) coverPlan
  in assertBool "the grown-cache patch is smaller than the default-geometry patch"
       (ByteString.length grownBytes < ByteString.length defaultBytes)

-- | The grown geometry is something a user can see: it survives parse into
-- the 'CustomCodeTable' (so the declared near-cache size is on the patch, not
-- just in its bytes), and @info@\/@explain@ surface it as an "address cache"
-- line. Only a custom table can vary the geometry, so this is the RFC-arc
-- case; xdelta3 and core-only patches always run the default and show no such
-- line.
vcdiffGrownCacheGeometryVisible :: Assertion
vcdiffGrownCacheGeometryVisible =
  let (source, target, coverPlan) = interleavedCacheCase 12
      CreateResult (PatchFileContents patch) _ =
        createConsideringCustomTable (InputFileContents source) (OutputFileContents target) coverPlan
  in case VCDIFF.parseVCDIFF (PatchFileContents patch) of
       Left slapError -> assertFailureT ("parse: " <> renderSlapError slapError)
       Right (Parsed parsed _parseWarnings) -> case parsed of
         PatchRFC header _ -> case rfcCustomCodeTable header of
           Nothing -> assertFailure "expected a custom code table carrying the cache geometry"
           Just customTable -> do
             assertBool "the parsed custom table exposes a grown near cache"
               (unNearSlotCount (nearSlotCount (customCodeTableCacheConfig customTable)) > 4)
             assertBool "info/explain surfaces an address-cache line"
               (any (\(InfoLine infoLabel _) -> infoLabel == "address cache")
                    (vcdiffMeta parsed))
         _ -> assertFailure "expected PatchRFC for a grown-cache patch"

-- | The grow stops where a larger cache stops paying: a pair whose copies
-- already encode in a single byte under the default geometry earns no grow,
-- so the considering emission ships the default bytes exactly — no custom
-- table, no inflated cache.
vcdiffCacheNotInflatedWhenDefaultHolds :: Assertion
vcdiffCacheNotInflatedWhenDefaultHolds =
  let source    = ByteString.pack [0 .. 63]
      coverPlan = Cover [ CoverCopy (Length 4) (Offset 0)
                        , CoverCopy (Length 4) (Offset 8)
                        , CoverCopy (Length 4) (Offset 16) ]
      target    = ByteString.concat
                    [ ByteString.take 4 (ByteString.drop off source) | off <- [0, 8, 16] ]
      CreateResult (PatchFileContents consideredBytes) _ =
        createConsideringCustomTable (InputFileContents source) (OutputFileContents target) coverPlan
      CreateResult (PatchFileContents defaultBytes) _ =
        createFromCover (InputFileContents source) (OutputFileContents target) coverPlan
  in do
       assertEqual "no custom table when the default cache suffices" defaultBytes consideredBytes
       assertBool "no custom code table: Hdr_Indicator VCD_CODETABLE clear"
         (not (Bits.testBit (ByteString.index consideredBytes 4) 1))

-- | A target of many distinct twenty-byte literals — a size the default
-- table has no fixed-size ADD for, so each spells out a size varint. The
-- minted single drops that varint, so the custom-table patch is strictly
-- smaller than the default and still round-trips.
vcdiffOddSizeSingleBeatsDefault :: Assertion
vcdiffOddSizeSingleBeatsDefault =
  let (source, target, coverPlan) = oddSizeSingleCase
      CreateResult (PatchFileContents customBytes) _ =
        createConsideringCustomTable (InputFileContents source) (OutputFileContents target) coverPlan
      CreateResult (PatchFileContents defaultBytes) _ =
        createFromCover (InputFileContents source) (OutputFileContents target) coverPlan
  in do
    assertBool "the odd-size-single patch is smaller than the default"
      (ByteString.length customBytes < ByteString.length defaultBytes)
    assertBool "ships a custom code table" (Bits.testBit (ByteString.index customBytes 4) 1)
    case VCDIFF.parseVCDIFF (PatchFileContents customBytes) of
      Left slapError -> assertFailureT ("parse: " <> renderSlapError slapError)
      Right (Parsed parsed _parseWarnings) ->
        assertEqual "odd-size-single patch round-trips"
          (Right (OutputFileContents target))
          (VCDIFF.applyVCDIFF parsed (InputFileContents source))

-- | The designed table for that pair carries a fixed-size single opcode for
-- the repeated twenty-byte ADD. The packer prefers a fixed-size entry over
-- the coded form, so a minted single is a used single — the size saving in
-- the test above is that preference taking effect.
vcdiffOddSizeSingleIsMinted :: Assertion
vcdiffOddSizeSingleIsMinted =
  let (_source, target, coverPlan) = oddSizeSingleCase
      resolved = resolveInstructionAddresses defaultAddressCacheConfig (Offset 0)
                   (coverToInstructions target coverPlan)
      addTwentySingle = Table.CodeTableEntry
                          (Table.Add (Table.SizeIs (Table.FixedInstructionSize 20))) Table.Noop
  in case designCandidateTable resolved of
       Nothing       -> assertFailure "expected a candidate table minting the repeated odd-size ADD"
       Just designed ->
         assertBool "the designed table carries a fixed-size single opcode for ADD(20)"
           (any ((== addTwentySingle) . snd) (Table.codeTableAssocs designed))

-- | A self-contained target of @count@ distinct twenty-byte literals (each a
-- non-repeating run, so an ADD not a RUN), with an all-literal cover and no
-- source. The ADD(20) shape repeats @count@ times — enough to earn a minted
-- fixed-size single whose varint saving clears the inner-delta cost.
oddSizeSingleCase :: (ByteString.ByteString, ByteString.ByteString, Cover)
oddSizeSingleCase = (ByteString.empty, target, Cover segments)
  where
    count       = 64 :: Int
    literalSize = 20 :: Int
    literalAt i = ByteString.pack [ fromIntegral ((i + j) `mod` 256) | j <- [0 .. literalSize - 1] ]
    target      = ByteString.concat (map literalAt [0 .. count - 1])
    segments    = [ CoverLiteral (Offset (literalSize * i)) (Length literalSize)
                  | i <- [0 .. count - 1] ]

prop_ips :: Property
prop_ips = forAll genPair $ \(source, target) ->
  case createPatch (CreateDirect CreateIPS) Nothing (InputFileContents source) (OutputFileContents target) noMetadataRequested Nothing noConstraintsRequested noDialectsRequested of
    Left slapError -> counterexample ("create: " ++ Text.unpack (renderSlapError slapError)) $ property False
    Right (CreateResult patch _) -> case IPS.parseIPS patch of
      Left slapError -> counterexample ("parse: " ++ Text.unpack (renderSlapError slapError)) $ property False
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
    Left slapError -> counterexample ("create: " ++ Text.unpack (renderSlapError slapError)) $ property False
    Right (CreateResult patch _) -> case IPS.parseIPS patch of
      Left slapError -> counterexample ("parse: " ++ Text.unpack (renderSlapError slapError)) $ property False
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
         counterexample ("unexpected error: " ++ Text.unpack (renderSlapError other)) $
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
         assertFailureT ("create: " <> renderSlapError slapError)
       Right (CreateResult patch _) -> case IPS.parseIPS patch of
         Left slapError ->
           assertFailureT ("parse: " <> renderSlapError slapError)
         Right (Parsed (IPSParseCleanIPS ipsPatch) _) ->
           case IPS.applyIPS (InputFileContents source) ipsPatch of
             Right outcome ->
               assertEqual "round-trip"
                 (OutputFileContents target) (outcomeValue outcome)
             Left slapError ->
               assertFailureT ("apply: " <> renderSlapError slapError)
         Right (Parsed (IPSParseCleanEBP _) _) ->
           assertFailure "unexpectedly parsed as EBP"
         Right (Parsed (IPSParseTruncated _ _) _) ->
           assertFailure "unexpectedly parsed as truncated"

-- | A record boundary can land exactly on the EOF sentinel offset
-- mid-diff, so the byte at @sentinel - 1@ is the last byte of the
-- preceding record's payload — a changed target byte, not an
-- unchanged source byte. The sentinel-collision fix shifts the
-- colliding record back one and prepends a byte; that prepended byte
-- is written last (wire order, later wins) over the preceding
-- record's tail, so it must be the byte the output is meant to hold
-- there. Here a varying, never-zero region spanning the sentinel
-- splits at a 0xFFFF chunk boundary that lands on it, putting a
-- changed byte at @sentinel - 1@; the patch must still round-trip,
-- and IPS has no checksum to catch it if it doesn't.
ipsSentinelCollisionMidDiffRoundTrips :: Assertion
ipsSentinelCollisionMidDiffRoundTrips =
  let sentinel     = 0x454F46
      regionStart  = sentinel - 0xFFFF   -- a 0xFFFF chunk boundary lands on the sentinel
      regionEnd    = sentinel + 0x10
      totalLength  = regionEnd
      source       = ByteString.replicate totalLength 0x00
      regionByteAt i = fromIntegral (0x01 + (i `mod` 0x7F))  -- varying, never zero
      target = ByteString.replicate regionStart 0x00
            <> ByteString.pack [regionByteAt i | i <- [regionStart .. regionEnd - 1]]
  in case createPatch (CreateDirect CreateIPS) Nothing
                      (InputFileContents source) (OutputFileContents target)
                      noMetadataRequested Nothing
                      noConstraintsRequested noDialectsRequested of
       Left slapError ->
         assertFailureT ("create: " <> renderSlapError slapError)
       Right (CreateResult patch _) -> case IPS.parseIPS patch of
         Left slapError ->
           assertFailureT ("parse: " <> renderSlapError slapError)
         Right (Parsed (IPSParseCleanIPS ipsPatch) _) ->
           case IPS.applyIPS (InputFileContents source) ipsPatch of
             Right outcome ->
               assertEqual "round-trip across a sentinel-aligned record boundary"
                 (OutputFileContents target) (outcomeValue outcome)
             Left slapError ->
               assertFailureT ("apply: " <> renderSlapError slapError)
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
    Left createError -> counterexample ("create: " ++ Text.unpack (renderSlapError createError)) $ property False
    Right (CreateResult patch _) -> case GDIFF.parseGDIFF patch of
      Left slapError -> counterexample ("parse: " ++ Text.unpack (renderSlapError slapError)) $ property False
      Right (Parsed parsed _parseWarnings) ->
        case GDIFF.applyGDIFF parsed (InputFileContents source) of
          Left applyError       -> counterexample ("apply: " ++ Text.unpack (renderSlapError applyError)) $ property False
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
      []                  -> unLength requestedLength === 0
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
        counterexample (Text.unpack (renderSlapError parseError)) (property False)
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
    Left createError -> counterexample ("create: " ++ Text.unpack (renderSlapError createError)) $ property False
    Right (CreateResult patch _) -> case APSGBA.parseAPSGBA patch of
      Left slapError -> counterexample ("parse: " ++ Text.unpack (renderSlapError slapError)) $ property False
      Right (Parsed parsed _parseWarnings) ->
        APSGBA.applyAPSGBA parsed (InputFileContents source) === Right (OutputFileContents target)

----------------------------------------------------------------------------
-- IPS32 / EBP: no truncation marker, target must be >= source
----------------------------------------------------------------------------

prop_ips32 :: Property
prop_ips32 = forAll genPairNoShrink $ \(source, target) ->
  case createPatch (CreateDirect CreateIPS32) Nothing (InputFileContents source) (OutputFileContents target) noMetadataRequested Nothing noConstraintsRequested noDialectsRequested of
    Left slapError -> counterexample ("create: " ++ Text.unpack (renderSlapError slapError)) $ property False
    Right (CreateResult patch _) -> case IPS.parseIPS patch of
      Left slapError -> counterexample ("parse: " ++ Text.unpack (renderSlapError slapError)) $ property False
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
    Left slapError -> counterexample ("create: " ++ Text.unpack (renderSlapError slapError)) $ property False
    Right (CreateResult patch _) -> case IPS.parseIPS patch of
      Left slapError -> counterexample ("parse: " ++ Text.unpack (renderSlapError slapError)) $ property False
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
prop_ppf1 = forAll genSameSizePair $ \(source, target) ->
  forAll (elements [PPF1OriginPC, PPF1OriginAmiga]) $ \origin ->
    let dialects = noDialectsRequested { requestedPPF1Origin = origin }
    in case createPatch (CreateDirect CreatePPF1) Nothing (InputFileContents source) (OutputFileContents target) noMetadataRequested Nothing noConstraintsRequested dialects of
         Left slapError -> counterexample ("create: " ++ Text.unpack (renderSlapError slapError)) $ property False
         Right (CreateResult patch _) -> case PPF1.parsePPF1 origin SlapText.EncodingUtf8 patch of
            Left slapError -> counterexample ("parse: " ++ Text.unpack (renderSlapError slapError)) $ property False
            Right (Parsed parsed _parseWarnings) -> PPF1.applyPPF1 parsed (InputFileContents source) === Right (noAdvisories (OutputFileContents target))

-- | PPF2 needs the source ROM to be at least 'ppf2ValidationOffset +
-- ppf2ValidationSize' = 0x9720 bytes for the validation block. Use a
-- generator that always produces sources past that threshold.
prop_ppf2 :: Property
prop_ppf2 = forAll genPPF2SizedPair $ \(source, target) ->
  case createPatch (CreateDirect CreatePPF2) Nothing (InputFileContents source) (OutputFileContents target) noMetadataRequested Nothing noConstraintsRequested noDialectsRequested of
    Left slapError -> counterexample ("create: " ++ Text.unpack (renderSlapError slapError)) $ property False
    Right (CreateResult patch _) -> case PPF2.parsePPF2 SlapText.EncodingUtf8 patch of
       Left slapError -> counterexample ("parse: " ++ Text.unpack (renderSlapError slapError)) $ property False
       Right (Parsed parsed _parseWarnings) -> PPF2.applyPPF2 parsed (InputFileContents source) === Right (noAdvisories (OutputFileContents target))
  where
    -- 0x9720 is the absolute minimum; bump to 0xA000 so QuickCheck-shrunk
    -- examples still fit, with a few KB of records-target headroom. This
    -- property stays same-size for a clean 'noAdvisories' assertion; the
    -- growth path (which emits a note) is pinned by 'ppf2GrowthRoundTrip'.
    minimumPPF2Source = 0xA000
    genPPF2SizedPair = do
      sourceLen <- choose (minimumPPF2Source, minimumPPF2Source + 8192)
      src <- ByteString.pack <$> vectorOf sourceLen arbitrary
      tgt <- ByteString.pack <$> vectorOf sourceLen arbitrary
      pure (src, tgt)

-- | PPF2 permits a growing target (its source-size header is an advisory
-- identity check, not an integrity rule). The source must clear the
-- 0x9720 validation-block threshold; the target grows past it. Apply
-- reproduces the target and emits the grow note (a note for PPF2, since
-- growth is within its accepted behavior). 'prop_ppf2' stays same-size
-- to keep its 'noAdvisories' assertion clean, so this pins the grow path.
ppf2GrowthRoundTrip :: Assertion
ppf2GrowthRoundTrip =
  case createPatch (CreateDirect CreatePPF2) Nothing (InputFileContents source) (OutputFileContents target) noMetadataRequested Nothing noConstraintsRequested noDialectsRequested of
    Left slapError -> assertFailure ("create: " ++ Text.unpack (renderSlapError slapError))
    Right (CreateResult patch _) -> case PPF2.parsePPF2 SlapText.EncodingUtf8 patch of
      Left slapError -> assertFailure ("parse: " ++ Text.unpack (renderSlapError slapError))
      Right (Parsed parsed _parseWarnings) -> case PPF2.applyPPF2 parsed (InputFileContents source) of
        Left slapError -> assertFailure ("apply: " ++ Text.unpack (renderSlapError slapError))
        Right (Outcome out advisories) -> do
          assertEqual "PPF2 grow output reproduces the target" (OutputFileContents target) out
          assertBool "PPF2 grow emits the grow advisory" (any isGrowNote advisories)
  where
    source = ByteString.pack (replicate 0xA000 0x41)
    target = source <> ByteString.pack (replicate 0x10 0x42)
    isGrowNote PPFApplyGrewPastSource{} = True
    isGrowNote _                        = False

-- | The validation block occupies @[0x9320, 0x9320 + 1024)@, so a
-- source of exactly @0x9320 + 1024 = 0x9720@ bytes ends right at the
-- block's end and can supply it whole. The extraction gate must
-- accept this exact-fit source; rejecting it (the prior strict-@>@
-- bug) contradicts the SourceTooSmallForPPF2Validation error's own
-- stated minimum, which is exactly @0x9720@.
ppf2ExactFitValidationSourceRoundTrips :: Assertion
ppf2ExactFitValidationSourceRoundTrips =
  let exactFit = 0x9320 + 1024   -- ppf2ValidationOffset + ppf2ValidationSize
      source   = ByteString.replicate exactFit 0x41
      target   = ByteString.take 0x100 source
              <> ByteString.singleton 0x42
              <> ByteString.drop 0x101 source
  in case createPatch (CreateDirect CreatePPF2) Nothing
                      (InputFileContents source) (OutputFileContents target)
                      noMetadataRequested Nothing noConstraintsRequested noDialectsRequested of
       Left slapError ->
         assertFailureT ("create: " <> renderSlapError slapError)
       Right (CreateResult patch _) -> case PPF2.parsePPF2 SlapText.EncodingUtf8 patch of
         Left slapError ->
           assertFailureT ("parse: " <> renderSlapError slapError)
         Right (Parsed parsed _parseWarnings) ->
           assertEqual "exact-fit validation source round-trips"
             (Right (noAdvisories (OutputFileContents target)))
             (PPF2.applyPPF2 parsed (InputFileContents source))

-- | One byte short of the exact fit, the source genuinely cannot
-- supply the full block, and create refuses with the structured error
-- — the boundary the fix preserves.
ppf2OneByteShortValidationSourceRejected :: Assertion
ppf2OneByteShortValidationSourceRejected =
  let oneShort = 0x9320 + 1024 - 1
      source   = ByteString.replicate oneShort 0x41
      target   = ByteString.take 0x100 source
              <> ByteString.singleton 0x42
              <> ByteString.drop 0x101 source
  in case createPatch (CreateDirect CreatePPF2) Nothing
                      (InputFileContents source) (OutputFileContents target)
                      noMetadataRequested Nothing noConstraintsRequested noDialectsRequested of
       Left (SourceTooSmallForPPF2Validation _ _ _) -> pure ()
       Left other ->
         assertFailureT ("expected SourceTooSmallForPPF2Validation, got: " <> renderSlapError other)
       Right _ ->
         assertFailure "expected refusal for a source one byte short of the validation block"

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
prop_ppf3 = forAll genSameSizePair $ \(source, target) ->
  case createPatch (CreateDirect CreatePPF3) Nothing (InputFileContents source) (OutputFileContents target) noMetadataRequested Nothing noConstraintsRequested noDialectsRequested of
    Left slapError -> counterexample ("create: " ++ Text.unpack (renderSlapError slapError)) $ property False
    Right (CreateResult patch _) -> case PPF3.parsePPF3 SlapText.EncodingUtf8 patch of
       Left slapError -> counterexample ("parse: " ++ Text.unpack (renderSlapError slapError)) $ property False
       Right (Parsed parsed _parseWarnings) -> PPF3.applyPPF3 parsed (InputFileContents source) === Right (noAdvisories (OutputFileContents target))

-- | PPF4 supports growth (via its Append phase) but not shrinkage, so
-- the generator stays at @target >= source@ — exercising both the
-- same-size (Replace-only) path and the growing (Replace + Append) path,
-- including the straddling-hunk split at the source boundary.
prop_ppf4 :: Property
prop_ppf4 = forAll genPairNoShrink $ \(source, target) ->
  case createPatch (CreateDirect CreatePPF4) Nothing (InputFileContents source) (OutputFileContents target) noMetadataRequested Nothing noConstraintsRequested noDialectsRequested of
    Left slapError -> counterexample ("create: " ++ Text.unpack (renderSlapError slapError)) $ property False
    Right (CreateResult patch _) -> case PPF4.parsePPF4 SlapText.EncodingUtf8 patch of
       Left slapError -> counterexample ("parse: " ++ Text.unpack (renderSlapError slapError)) $ property False
       Right (Parsed parsed _parseWarnings) -> PPF4.applyPPF4 parsed (InputFileContents source) === Right (OutputFileContents target)

-- | Deterministic regression for the straddling-hunk split. The change
-- from "AAAABBBB" to "BBBB" runs to the source's last byte and the four
-- "CCCC" bytes extend past it, so 'Slap.Binary.diffHunks' merges them
-- into one hunk spanning [4, 12) that straddles the 8-byte source
-- boundary. 'partitionPPF4Phases' must cut that hunk: [4, 8) is a
-- Replace, [8, 12) an Append. A partition that classified the whole
-- straddling hunk by its start offset would emit a Replace that grows
-- the file, and apply would reject it. 'prop_ppf4' only hits this case
-- when a random pair happens to differ at the boundary; this pins it.
ppf4StraddleRoundTrip :: Assertion
ppf4StraddleRoundTrip =
  let source = ByteString.pack (replicate 8 0x41)                       -- AAAAAAAA
      target = ByteString.pack (replicate 4 0x41 ++ replicate 4 0x42    -- AAAABBBB
                                                  ++ replicate 4 0x43)   -- CCCC (grown)
  in case createPatch (CreateDirect CreatePPF4) Nothing (InputFileContents source) (OutputFileContents target) noMetadataRequested Nothing noConstraintsRequested noDialectsRequested of
       Left slapError -> assertFailure ("create: " ++ Text.unpack (renderSlapError slapError))
       Right (CreateResult patch _) -> case PPF4.parsePPF4 SlapText.EncodingUtf8 patch of
         Left slapError -> assertFailure ("parse: " ++ Text.unpack (renderSlapError slapError))
         Right (Parsed parsed _parseWarnings) ->
           assertEqual "straddle round-trip"
             (Right (OutputFileContents target))
             (PPF4.applyPPF4 parsed (InputFileContents source))

-- | The wire bytes of an IPS patch carrying one real write and one
-- zero-count RLE record at a far offset: a 1-byte copy at offset 0,
-- then the zero-count record at 0x100000.
ipsZeroCountRlePatchBytes :: PatchFileContents
ipsZeroCountRlePatchBytes = PatchFileContents (ByteString.concat
  [ ipsMagicBytes
  , ByteString.pack [0x00, 0x00, 0x00,  0x00, 0x01,  0x42]
  , ByteString.pack [0x10, 0x00, 0x00,  0x00, 0x00,  0x00, 0x00,  0x00]
  , ipsEOFMarkerBytes
  ])

-- | A zero-count RLE record is the no-op the parse ruling says it is
-- (docs/ips/questions.md): it writes nothing, so it also sizes
-- nothing — the output stays source-sized even when the record's
-- offset sits past every real write.
ipsZeroCountRleSizesNothing :: Assertion
ipsZeroCountRleSizesNothing =
  let source = ByteString.pack [0x41, 0x41, 0x41, 0x41]
  in case IPS.parseIPS ipsZeroCountRlePatchBytes of
       Left slapError -> assertFailure ("parse: " ++ Text.unpack (renderSlapError slapError))
       Right (Parsed (IPSParseCleanIPS ipsPatch) _parseWarnings) ->
         assertEqual "no-op record must not grow the output"
           (Right (OutputFileContents (ByteString.pack [0x42, 0x41, 0x41, 0x41])))
           (fmap outcomeValue (IPS.applyIPS (InputFileContents source) ipsPatch))
       Right _ -> assertFailure "expected a clean StandardIPS parse"

-- | A parsed zero-count RLE record must not survive into a converted
-- patch's wire bytes: it expands to no write, and emitting it as a
-- size-0 record would collide with the RLE sentinel and desync every
-- record after it. The converted patch re-parses cleanly and applies
-- identically.
ipsZeroCountRleConvertRoundTrips :: Assertion
ipsZeroCountRleConvertRoundTrips =
  let source = ByteString.pack [0x41, 0x41, 0x41, 0x41]
      expected = OutputFileContents (ByteString.pack [0x42, 0x41, 0x41, 0x41])
  in case parseSome noDialectsRequested SlapText.EncodingUtf8 ipsZeroCountRlePatchBytes of
       Left slapError -> assertFailure ("parseSome: " ++ Text.unpack (renderSlapError slapError))
       Right somePatch -> case patchKind somePatch of
         Direct (Just contents) ->
           case convertDirect contents (CreateDirect CreateIPS) noMetadataRequested noConstraintsRequested noDialectsRequested of
             Left slapError -> assertFailure ("convert: " ++ Text.unpack (renderSlapError slapError))
             Right (CreateResult convertedPatch _) -> case IPS.parseIPS convertedPatch of
               Left slapError -> assertFailure ("re-parse: " ++ Text.unpack (renderSlapError slapError))
               Right (Parsed (IPSParseCleanIPS reparsed) _parseWarnings) ->
                 assertEqual "converted patch applies identically"
                   (Right expected)
                   (fmap outcomeValue (IPS.applyIPS (InputFileContents source) reparsed))
               Right _ -> assertFailure "expected the converted patch to re-parse as clean StandardIPS"
         _ -> assertFailure "expected a Direct patch kind with contents"

-- | A shrinking pair whose target is too large for the truncation
-- marker to name must refuse: the post-EOF marker spells the final
-- size in the same 24-bit width as record offsets, and masking the
-- size to fit would emit a patch that applies to a wrongly-sized
-- file in a format with no checksum to notice.
ipsTruncationPastMarkerReachRefused :: Assertion
ipsTruncationPastMarkerReachRefused =
  let source = ByteString.replicate (0x1000000 + 64) 0x41
      target = ByteString.replicate (0x1000000 + 32) 0x41
  in case createPatch (CreateDirect CreateIPS) Nothing (InputFileContents source) (OutputFileContents target) noMetadataRequested Nothing noConstraintsRequested noDialectsRequested of
       Left (UnencodeablePair LabelIPS (TruncationTargetUnrepresentable _ _)) -> pure ()
       Left other -> assertFailure
         ("expected the marker-range refusal, got: " ++ Text.unpack (renderSlapError other))
       Right _ -> assertFailure
         "IPS emitted a truncation marker for a size past its 24-bit reach"

-- | The boundary of the refusal: a shrinking pair whose target sits
-- exactly at the marker's maximum (0xFFFFFF) still encodes, and the
-- patch round-trips to the declared size.
ipsTruncationAtMarkerMaximumRoundTrips :: Assertion
ipsTruncationAtMarkerMaximumRoundTrips =
  let source = ByteString.replicate (0x1000000 + 64) 0x41
      target = ByteString.replicate 0xFFFFFF 0x41
  in case createPatch (CreateDirect CreateIPS) Nothing (InputFileContents source) (OutputFileContents target) noMetadataRequested Nothing noConstraintsRequested noDialectsRequested of
       Left slapError -> assertFailure ("create: " ++ Text.unpack (renderSlapError slapError))
       Right (CreateResult patch _) -> case IPS.parseIPS patch of
         Left slapError -> assertFailure ("parse: " ++ Text.unpack (renderSlapError slapError))
         Right (Parsed (IPSParseCleanIPS ipsPatch) _parseWarnings) ->
           assertEqual "round-trip at the marker's maximum"
             (Right (OutputFileContents target))
             (fmap outcomeValue (IPS.applyIPS (InputFileContents source) ipsPatch))
         Right _ -> assertFailure "expected a clean StandardIPS parse"

-- | A format that can't represent shrinkage must refuse a shrinking
-- (target shorter than source) create, with the shrink reason and its
-- own label — not silently emit a patch that produces a source-sized
-- output on apply. Shared by the NINJA1 and PMSR cases; both formats
-- only write at offsets and have no truncate/output-size mechanism.
assertShrinkRefused :: DirectCreate -> FormatLabel -> Assertion
assertShrinkRefused format expectedLabel =
  let source = ByteString.pack (replicate 16 0x41)
      target = ByteString.pack (replicate 8 0x41)
  in case createPatch (CreateDirect format) Nothing (InputFileContents source) (OutputFileContents target) noMetadataRequested Nothing noConstraintsRequested noDialectsRequested of
       Left (UnencodeablePair refusedLabel (TargetShrinksBelowSource _ _))
         | refusedLabel == expectedLabel -> pure ()
       Left other -> assertFailure
         ("expected a shrink refusal for " ++ show expectedLabel ++ ", got: "
          ++ Text.unpack (renderSlapError other))
       Right _ -> assertFailure
         (show expectedLabel ++ " produced a patch for a shrinking pair instead of refusing")

prop_pmsr :: Property
prop_pmsr = forAll genPairNoShrink $ \(source, target) ->
  case createPatch (CreateDirect CreatePMSR) Nothing (InputFileContents source) (OutputFileContents target) noMetadataRequested Nothing noConstraintsRequested noDialectsRequested of
    Left slapError -> counterexample ("create: " ++ Text.unpack (renderSlapError slapError)) $ property False
    Right (CreateResult patch _) -> case PMSR.parsePMSR patch of
       Left slapError -> counterexample ("parse: " ++ Text.unpack (renderSlapError slapError)) $ property False
       Right (Parsed parsed _parseWarnings) ->
         PMSR.applyPMSR parsed (InputFileContents source) === Right (OutputFileContents target)

prop_ninja1 :: Property
prop_ninja1 = forAll genPairNoShrink $ \(source, target) ->
  case createPatch (CreateDirect CreateNINJA1) Nothing (InputFileContents source) (OutputFileContents target) noMetadataRequested Nothing noConstraintsRequested noDialectsRequested of
    Left slapError -> counterexample ("create: " ++ Text.unpack (renderSlapError slapError)) $ property False
    Right (CreateResult patch _) -> case NINJA1.parseNINJA1 patch of
       Left slapError -> counterexample ("parse: " ++ Text.unpack (renderSlapError slapError)) $ property False
       Right (Parsed parsed _parseWarnings) ->
         NINJA1.applyNINJA1 parsed (InputFileContents source) === Right (OutputFileContents target)

prop_ninja1Hashes :: Property
prop_ninja1Hashes = forAll genNonEmptyByteString $ \source ->
  case createPatch (CreateDirect CreateNINJA1) Nothing (InputFileContents source) (OutputFileContents source) noMetadataRequested Nothing noConstraintsRequested noDialectsRequested of
    Left slapError -> counterexample ("create: " ++ Text.unpack (renderSlapError slapError)) $ property False
    Right (CreateResult patch _) -> case NINJA1.parseNINJA1 patch of
       Left slapError -> counterexample ("parse: " ++ Text.unpack (renderSlapError slapError)) $ property False
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
    Left slapError -> counterexample ("create: " ++ Text.unpack (renderSlapError slapError)) $ property False
    Right (CreateResult patch _) -> case NINJA1.parseNINJA1 patch of
      Left slapError -> counterexample ("parse: " ++ Text.unpack (renderSlapError slapError)) $ property False
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
         counterexample ("unexpected error: " ++ Text.unpack (renderSlapError other)) $
           property False
       Right _ ->
         counterexample "expected Left SentinelCollisionUnfixable, got Right" $
           property False

prop_ninja1FooterRequired :: Property
prop_ninja1FooterRequired = forAll genPairNoShrink $ \(source, target) ->
  case createPatch (CreateDirect CreateNINJA1) Nothing (InputFileContents source) (OutputFileContents target) noMetadataRequested Nothing noConstraintsRequested noDialectsRequested of
    Left slapError -> counterexample ("create: " ++ Text.unpack (renderSlapError slapError)) $ property False
    Right (CreateResult (PatchFileContents bytes) _) ->
      case NINJA1.parseNINJA1 (PatchFileContents (ByteString.dropEnd 4 bytes)) of
        Left NINJA1BinaryMissingEOFFooter -> property True
        Left other -> counterexample ("expected footer refusal, got: " ++ Text.unpack (renderSlapError other)) $ property False
        Right _   -> counterexample "expected Left NINJA1BinaryMissingEOFFooter, got Right" $ property False

-- DPS: differential, no truncation
prop_dps :: Property
prop_dps = forAll genPairNoShrink $ \(source, target) ->
  case createDPS (InputFileContents source) (OutputFileContents target)
         (DPS.DPSCreateMetadata
            { DPS.dpsCreateMetadataName    = SlapText.EncodedText SlapText.EncodingUtf8 Text.empty
            , DPS.dpsCreateMetadataAuthor  = SlapText.EncodedText SlapText.EncodingUtf8 Text.empty
            , DPS.dpsCreateMetadataVersion = SlapText.EncodedText SlapText.EncodingUtf8 Text.empty
            })
         DPS.DPSStable of
    Left createError -> counterexample ("create: " ++ Text.unpack (renderSlapError createError)) $ property False
    Right (CreateResult patch _) -> case DPS.parseDPS SlapText.EncodingUtf8 patch of
      Left slapError -> counterexample ("parse: " ++ Text.unpack (renderSlapError slapError)) $ property False
      Right (Parsed parsed _parseWarnings) -> DPS.applyDPS parsed (InputFileContents source) === Right (OutputFileContents target)

prop_ninja2 :: Property
prop_ninja2 = forAll genPair $ \(source, target) ->
  case createNINJA2 (InputFileContents source) (OutputFileContents target) emptyNINJA2Metadata of
    Left createError -> counterexample ("create: " ++ Text.unpack (renderSlapError createError)) $ property False
    Right (CreateResult patch _) -> case NINJA2.parseNINJA2 SlapText.EncodingUtf8 patch of
      Left slapError -> counterexample ("parse: " ++ Text.unpack (renderSlapError slapError)) $ property False
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
    Left createError -> counterexample ("create: " ++ Text.unpack (renderSlapError createError)) $ property False
    Right (CreateResult patch _) -> case NINJA2.parseNINJA2 SlapText.EncodingUtf8 patch of
      Left slapError -> counterexample ("parse: " ++ Text.unpack (renderSlapError slapError)) $ property False
      Right (Parsed parsed _parseWarnings) ->
        NINJA2.applyNINJA2 parsed (InputFileContents source) === Right (OutputFileContents target)

prop_ninja2Hashes :: Property
prop_ninja2Hashes = forAll genPair $ \(source, target) ->
  case createNINJA2 (InputFileContents source) (OutputFileContents target) emptyNINJA2Metadata of
    Left createError -> counterexample ("create: " ++ Text.unpack (renderSlapError createError)) $ property False
    Right (CreateResult patch _) -> case NINJA2.parseNINJA2 SlapText.EncodingUtf8 patch of
      Left slapError -> counterexample ("parse: " ++ Text.unpack (renderSlapError slapError)) $ property False
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
    Left createError -> assertFailureT ("create: " <> renderSlapError createError)
    Right (CreateResult (PatchFileContents bytes) _) -> do
      assertEqual "OPEN_NEW_FILE opcode at 0x800"  0x01 (ByteString.index bytes 0x800)
      assertEqual "FILE_N_MUL single-file sentinel at 0x801" 0x00 (ByteString.index bytes 0x801)
      assertEqual "ROM type byte at 0x802 (raw default)"     0x00 (ByteString.index bytes 0x802)

-- | Both PATCH_ENC values the NINJA2 spec defines must survive a
-- create-then-parse trip intact: the byte the encoder writes at offset
-- 6 must round-trip through the parser back into the same
-- 'TextMode' constructor it was created with. Empty source and
-- target keep the test focused on the header byte the property is
-- about; the round-trip body is exercised exhaustively by 'prop_ninja2'.
ninja2EncodingRoundTrips :: NINJA2.TextMode -> Assertion
ninja2EncodingRoundTrips textMode =
  let metadata = emptyNINJA2Metadata { NINJA2.ninja2CreateTextMode = textMode }
  in case createNINJA2 (InputFileContents ByteString.empty) (OutputFileContents ByteString.empty) metadata of
       Left createError -> assertFailureT ("create: " <> renderSlapError createError)
       Right (CreateResult patch _) -> case NINJA2.parseNINJA2 SlapText.EncodingUtf8 patch of
         Left slapError -> assertFailureT ("parse: " <> renderSlapError slapError)
         Right (Parsed parsed _parseWarnings) ->
           assertEqual "PATCH_ENC round-trip" textMode (NINJA2.ninja2TextMode parsed)

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
      descriptionText         = Text.pack (asciiPrefix ++ [fourByteCodepoint])
      descriptionEncoded      = SlapText.EncodedText SlapText.EncodingUtf8 descriptionText
      expectedOriginalLength  = Length (asciiPrefixLength + 4)
      expectedStoredLength    = Length asciiPrefixLength
      metadata                = emptyNINJA2Metadata
        { NINJA2.ninja2CreateMetadataDescription = Just descriptionEncoded
        , NINJA2.ninja2CreateTextMode           = NINJA2.TextModeUTF8
        }
  in case createNINJA2 (InputFileContents ByteString.empty) (OutputFileContents ByteString.empty) metadata of
       Left createError -> assertFailureT ("create: " <> renderSlapError createError)
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
         case NINJA2.parseNINJA2 SlapText.EncodingUtf8 patch of
           Left slapError -> assertFailureT ("parse: " <> renderSlapError slapError)
           Right (Parsed parsed _) -> case NINJA2.ninja2Description (NINJA2.ninja2Header parsed) of
             Nothing -> assertFailure "parsed description was Nothing; expected the truncated bytes"
             Just storedEncoded ->
               let storedBytes = TextEncoding.encodeUtf8
                                   (SlapText.encodedTextContent storedEncoded)
               in assertEqual "parsed-back stored byte count matches the warning"
                    (byteLength storedBytes) reportedTruncated

-- | UTF-8 (mode 1) NINJA2 patches with non-ASCII text in the metadata
-- round-trip byte-faithfully: the wire bytes are well-defined Unicode,
-- and slap's parse path decodes them back to the same 'Text'. Pins
-- the typed encode\/decode pipeline through 'encodeTextBounded' \/
-- 'decodeTextLenient' end-to-end on a real codepoint payload, not
-- just the ASCII-only fixtures that 'prop_ninja2' exercises.
ninja2Mode1Utf8NonAsciiTitleRoundTrips :: Assertion
ninja2Mode1Utf8NonAsciiTitleRoundTrips =
  let titleText = Text.pack "\x65E5\x672C\x8A9E"   -- "Japanese language"
      titleEncoded = SlapText.EncodedText SlapText.EncodingUtf8 titleText
      metadata = emptyNINJA2Metadata
        { NINJA2.ninja2CreateMetadataTitle    = Just titleEncoded
        , NINJA2.ninja2CreateTextMode         = NINJA2.TextModeUTF8
        }
  in case createNINJA2 (InputFileContents ByteString.empty)
                       (OutputFileContents ByteString.empty) metadata of
       Left createError -> assertFailureT ("create: " <> renderSlapError createError)
       Right (CreateResult patch _) -> case NINJA2.parseNINJA2 SlapText.EncodingUtf8 patch of
         Left slapError -> assertFailureT ("parse: " <> renderSlapError slapError)
         Right (Parsed parsed _) ->
           case NINJA2.ninja2Title (NINJA2.ninja2Header parsed) of
             Nothing -> assertFailure "parsed title was Nothing"
             Just parsedTitle -> do
               assertEqual "title tag is EncodingUtf8"
                 SlapText.EncodingUtf8 (SlapText.encodedTextEncoding parsedTitle)
               assertEqual "title text round-trips"
                 titleText (SlapText.encodedTextContent parsedTitle)

-- | A mode-1 (UTF-8) NINJA2 patch decoded by 'parseNINJA2' tags each
-- non-empty metadata field's 'EncodedText' with 'EncodingUtf8',
-- because the wire byte at offset 6 declares UTF-8. The tag is the
-- typed signal downstream conversion sites read instead of consulting
-- a side-channel.
ninja2ParseTagsMode1FieldsAsUtf8 :: Assertion
ninja2ParseTagsMode1FieldsAsUtf8 = do
  parsed <- createAndParseNINJA2 SlapText.EncodingUtf8 NINJA2.TextModeUTF8
  case NINJA2.ninja2Title (NINJA2.ninja2Header parsed) of
    Nothing -> assertFailure "parsed title was Nothing"
    Just titled -> assertEqual "mode-1 title tag is UTF-8"
      SlapText.EncodingUtf8 (SlapText.encodedTextEncoding titled)

-- | A mode-0 (undeclared) NINJA2 patch decoded by 'parseNINJA2' tags
-- each non-empty metadata field's 'EncodedText' with the chosen
-- metadata encoding, not a fixed one: the wire declined to declare an
-- encoding, so the reader's @--metadata-encoding@ choice decides.
-- Counterpart to 'ninja2ParseTagsMode1FieldsAsUtf8', where the wire's
-- UTF-8 declaration overrides the choice.
ninja2ParseTagsMode0FieldsUnderChosenEncoding :: Assertion
ninja2ParseTagsMode0FieldsUnderChosenEncoding =
  case SlapText.resolveEncodingName (Text.pack "ISO-8859-1") of
    Left _ -> assertFailure "ISO-8859-1 should resolve in the encoding library"
    Right chosen -> do
      parsed <- createAndParseNINJA2 (SlapText.EncodingNamed chosen) NINJA2.TextModeUndeclared
      case NINJA2.ninja2Title (NINJA2.ninja2Header parsed) of
        Nothing -> assertFailure "parsed title was Nothing"
        Just titled -> assertEqual "mode-0 title tag is the chosen encoding"
          (SlapText.EncodingNamed chosen) (SlapText.encodedTextEncoding titled)

-- | Helper for the parse-tag tests: create a NINJA2 patch with an
-- ASCII title under the given wire 'TextMode', parse it back under the
-- given metadata encoding, and return the parsed patch. ASCII is
-- representable everywhere, so the create side (always UTF-8) never
-- substitutes or truncates and the resulting wire bytes are stable.
createAndParseNINJA2 :: SlapText.EncodingName -> NINJA2.TextMode -> IO NINJA2.NINJA2Patch
createAndParseNINJA2 metadataEncoding textMode =
  let titleEncoded = SlapText.EncodedText SlapText.EncodingUtf8 (Text.pack "demo")
      metadata = emptyNINJA2Metadata
        { NINJA2.ninja2CreateMetadataTitle    = Just titleEncoded
        , NINJA2.ninja2CreateTextMode         = textMode
        }
  in case createNINJA2 (InputFileContents ByteString.empty)
                       (OutputFileContents ByteString.empty) metadata of
       Left createError -> assertFailureT ("create: " <> renderSlapError createError)
                          >> error "unreachable"
       Right (CreateResult patch _) -> case NINJA2.parseNINJA2 metadataEncoding patch of
         Left slapError -> assertFailureT ("parse: " <> renderSlapError slapError)
                          >> error "unreachable"
         Right (Parsed parsed _) -> pure parsed

-- | Convert-path detection: a CLI @--ninja2-text-mode undeclared@
-- selects @PATCH_ENC=0@ for the output. The CLI flag is the only
-- input that moves PATCH_ENC off the UTF-8 default — slap no longer
-- inherits a text mode from any source field's encoding.
ninja2DetectionCliSelectsTextMode :: Assertion
ninja2DetectionCliSelectsTextMode =
  assertCreatedNINJA2PatchEnc
    "expected PATCH_ENC=0 (CLI --ninja2-text-mode undeclared selected)"
    (metadataWithTitleTag SlapText.EncodingUtf8 (Just NINJA2.TextModeUndeclared))
    0

-- | Convert-path detection: with no CLI @--ninja2-text-mode@ flag, the
-- encoder defaults to @PATCH_ENC=1@ (UTF-8 is the portable choice, and
-- the field bytes are written UTF-8 regardless).
ninja2DetectionDefaultsToUtf8 :: Assertion
ninja2DetectionDefaultsToUtf8 =
  assertCreatedNINJA2PatchEnc
    "expected PATCH_ENC=1 (UTF-8 default with no CLI flag)"
    noMetadataRequested
    1

-- | Build a 'RequestedPatchMetadata' carrying a title with the given
-- 'EncodingName' tag plus an optional CLI @--ninja2-text-mode@ choice.
-- The title text is ASCII so the create side never substitutes
-- under any encoding the test exercises.
metadataWithTitleTag
  :: SlapText.EncodingName
  -> Maybe NINJA2.TextMode
  -> RequestedPatchMetadata
metadataWithTitleTag tag cliTextMode = noMetadataRequested
  { requestedTitle    = Just (SlapText.EncodedText tag (Text.pack "demo"))
  , requestedTextMode = cliTextMode
  }

-- | Drive the differential @CreateNINJA2@ arm of 'createPatch' with
-- the given metadata, parse the output's byte at offset 6, and
-- assert it matches the expected @PATCH_ENC@ wire value. Empty
-- source\/target keep the test focused on the header byte.
assertCreatedNINJA2PatchEnc
  :: String
  -> RequestedPatchMetadata
  -> Word.Word8
  -> Assertion
assertCreatedNINJA2PatchEnc messagePrefix metadata expectedByte =
  case createPatch (CreateDifferential CreateNINJA2) Nothing
                   (InputFileContents ByteString.empty)
                   (OutputFileContents ByteString.empty)
                   metadata Nothing
                   noConstraintsRequested noDialectsRequested of
    Left createError -> assertFailureT ("create: " <> renderSlapError createError)
    Right (CreateResult (PatchFileContents bytes) _) ->
      assertEqual messagePrefix expectedByte (ByteString.index bytes 6)

----------------------------------------------------------------------------
-- PPF1/2/3 description text-encoding round-trip and truncation
----------------------------------------------------------------------------

-- | A non-ASCII codepoint payload that takes 9 UTF-8 bytes and fits
-- comfortably inside the 50-byte PPF description field. The encode and
-- decode both go through UTF-8 (slap writes UTF-8 and the test reads
-- back under the default UTF-8 metadata encoding), so it round-trips
-- byte-for-byte.
ppfNonAsciiDescriptionText :: Text.Text
ppfNonAsciiDescriptionText = Text.pack "\x65E5\x672C\x8A9E"  -- "Japanese language"

-- | An overflow probe: 47 ASCII bytes plus a 4-byte UTF-8 codepoint
-- (🎮, U+1F3AE) — encoded length 51, one byte past the 50-byte cap.
-- 'encodeTextBounded' drops the 4-byte codepoint whole and keeps the
-- 47-byte prefix, rather than cutting at a raw byte boundary mid-
-- codepoint.
ppfTruncationProbeText :: Text.Text
ppfTruncationProbeText = Text.pack (replicate 47 'a' ++ ['\x1F3AE'])

ppfTruncationProbeExpectedOriginal :: Length
ppfTruncationProbeExpectedOriginal = Length 51

ppfTruncationProbeExpectedTruncated :: Length
ppfTruncationProbeExpectedTruncated = Length 47

-- | A non-ASCII description round-trips byte-faithfully when re-encoding
-- the parsed-back text as UTF-8 produces wire bytes identical to the
-- original encode. Slap parses the description with
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
    Left slapError -> assertFailureT (Text.pack formatName <> " parse: " <> renderSlapError slapError)
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
  let descriptionTyped = SlapText.EncodedText SlapText.EncodingUtf8 ppfNonAsciiDescriptionText
      patchResult      = PPF1.encodePPF1 PPF1OriginPC [] descriptionTyped
  in ppfDescriptionRoundTripsByteFaithfully patchResult
       (PPF1.parsePPF1 PPF1OriginPC SlapText.EncodingUtf8)
       PPF1.ppf1Description
       (PPF1.encodePPF1 PPF1OriginPC [])
       "PPF1"

ppf1DescriptionCodepointAwareTruncation :: Assertion
ppf1DescriptionCodepointAwareTruncation =
  let descriptionTyped = SlapText.EncodedText SlapText.EncodingUtf8 ppfTruncationProbeText
      CreateResult _ advisories =
        PPF1.encodePPF1 PPF1OriginPC [] descriptionTyped
  in assertPPFDescriptionTruncationWarning LabelPPF1 advisories

ppf2DescriptionUtf8RoundTrip :: Assertion
ppf2DescriptionUtf8RoundTrip =
  let descriptionTyped = SlapText.EncodedText SlapText.EncodingUtf8 ppfNonAsciiDescriptionText
      sourceSize       = case narrowPPF2SourceSize (FileSize 0x9720) of
        Right size -> size
        Left  err  -> error ("narrowPPF2SourceSize: " ++ Text.unpack (renderSlapError err))
      validation       = PPF2.PPF2ValidationBlock (ByteString.replicate 1024 0)
      patchResult      = PPF2.encodePPF2 [] descriptionTyped sourceSize validation
      reEncodePPF2 d   = PPF2.encodePPF2 [] d sourceSize validation
  in ppfDescriptionRoundTripsByteFaithfully patchResult
       (PPF2.parsePPF2 SlapText.EncodingUtf8)
       PPF2.ppf2Description
       reEncodePPF2
       "PPF2"

ppf2DescriptionCodepointAwareTruncation :: Assertion
ppf2DescriptionCodepointAwareTruncation =
  let descriptionTyped = SlapText.EncodedText SlapText.EncodingUtf8 ppfTruncationProbeText
      sourceSize       = case narrowPPF2SourceSize (FileSize 0x9720) of
        Right size -> size
        Left  err  -> error ("narrowPPF2SourceSize: " ++ Text.unpack (renderSlapError err))
      validation       = PPF2.PPF2ValidationBlock (ByteString.replicate 1024 0)
      CreateResult _ advisories =
        PPF2.encodePPF2 [] descriptionTyped sourceSize validation
  in assertPPFDescriptionTruncationWarning LabelPPF2 advisories

ppf3DescriptionUtf8RoundTrip :: Assertion
ppf3DescriptionUtf8RoundTrip =
  let descriptionTyped = SlapText.EncodedText SlapText.EncodingUtf8 ppfNonAsciiDescriptionText
      patchResult      = PPF3.encodePPF3 [] descriptionTyped Nothing Nothing BIN
      reEncodePPF3 d   = PPF3.encodePPF3 [] d Nothing Nothing BIN
  in ppfDescriptionRoundTripsByteFaithfully patchResult
       (PPF3.parsePPF3 SlapText.EncodingUtf8)
       PPF3.ppf3Description
       reEncodePPF3
       "PPF3"

ppf3DescriptionCodepointAwareTruncation :: Assertion
ppf3DescriptionCodepointAwareTruncation =
  let descriptionTyped = SlapText.EncodedText SlapText.EncodingUtf8 ppfTruncationProbeText
      CreateResult _ advisories =
        PPF3.encodePPF3 [] descriptionTyped Nothing Nothing BIN
  in assertPPFDescriptionTruncationWarning LabelPPF3 advisories

-- | A FILE_ID.DIZ body that round-trips byte-faithfully: the typed
-- text encodes to identical UTF-8 bytes whether read by parse or
-- rewritten by create, so the trailer wraps and unwraps cleanly with
-- the format's wire-level marker/length frame.
ppfFileIdDizSampleText :: Text.Text
ppfFileIdDizSampleText = Text.pack "slap sample FILE_ID.DIZ\nline two\n"

ppf2FileIdDizRoundTrip :: Assertion
ppf2FileIdDizRoundTrip =
  let descriptionTyped = SlapText.EncodedText SlapText.EncodingUtf8 Text.empty
      sourceSize       = case narrowPPF2SourceSize (FileSize 0x9720) of
        Right size -> size
        Left  err  -> error ("narrowPPF2SourceSize: " ++ Text.unpack (renderSlapError err))
      validation       = PPF2.PPF2ValidationBlock (ByteString.replicate 1024 0)
      fileIdText       = SlapText.EncodedText SlapText.EncodingUtf8 ppfFileIdDizSampleText
      fileId = case narrowPPF2FileId fileIdText of
        Right value -> value
        Left  err   -> error ("narrowPPF2FileId: " ++ Text.unpack (renderSlapError err))
      CreateResult patchBytes _ =
        PPF2.encodePPF2 [] descriptionTyped sourceSize validation
      (trailerBytes, _trailerAdv) = PPF2.encodeFileIdDiz fileId
      stitched = PatchFileContents (unPatchFileContents patchBytes <> trailerBytes)
  in case PPF2.parsePPF2 SlapText.EncodingUtf8 stitched of
       Left slapError -> assertFailureT ("PPF2 parse: " <> renderSlapError slapError)
       Right (Parsed parsed _) -> case PPF2.ppf2FileId parsed of
         Nothing  -> assertFailure "PPF2 parsed file_id.diz was Nothing; expected trailer"
         Just fid ->
           assertEqual "PPF2 parsed file_id.diz content matches the original"
             ppfFileIdDizSampleText
             (SlapText.encodedTextContent (PPF2.unPPF2FileId fid))

ppf3FileIdDizRoundTrip :: Assertion
ppf3FileIdDizRoundTrip =
  let descriptionTyped = SlapText.EncodedText SlapText.EncodingUtf8 Text.empty
      fileIdText       = SlapText.EncodedText SlapText.EncodingUtf8 ppfFileIdDizSampleText
      fileId = case narrowPPF3FileId fileIdText of
        Right value -> value
        Left  err   -> error ("narrowPPF3FileId: " ++ Text.unpack (renderSlapError err))
      CreateResult patchBytes _ =
        PPF3.encodePPF3 [] descriptionTyped Nothing Nothing BIN
      (trailerBytes, _trailerAdv) = PPF3.encodeFileIdDiz fileId
      stitched = PatchFileContents (unPatchFileContents patchBytes <> trailerBytes)
  in case PPF3.parsePPF3 SlapText.EncodingUtf8 stitched of
       Left slapError -> assertFailureT ("PPF3 parse: " <> renderSlapError slapError)
       Right (Parsed parsed _) -> case PPF3.ppf3FileId parsed of
         Nothing  -> assertFailure "PPF3 parsed file_id.diz was Nothing; expected trailer"
         Just fid ->
           assertEqual "PPF3 parsed file_id.diz content matches the original"
             ppfFileIdDizSampleText
             (SlapText.encodedTextContent (PPF3.unPPF3FileId fid))

-- APS-N64: pure direct, no truncation
prop_apsN64 :: Property
prop_apsN64 = forAll genPairNoShrink $ \(source, target) ->
  case createPatch (CreateDirect CreateAPSN64) Nothing (InputFileContents source) (OutputFileContents target) noMetadataRequested Nothing noConstraintsRequested noDialectsRequested of
    Left slapError -> counterexample ("create: " ++ Text.unpack (renderSlapError slapError)) $ property False
    Right (CreateResult patch _) -> case APSN64.parseAPSN64 SlapText.EncodingUtf8 patch of
       Left slapError -> counterexample ("parse: " ++ Text.unpack (renderSlapError slapError)) $ property False
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
       Left createError -> counterexample ("create: " ++ Text.unpack (renderSlapError createError)) $ property False
       Right (CreateResult patch _) ->
         counterexample ("patch size: " ++ show (ByteString.length (unPatchFileContents patch))
                          ++ " (block: " ++ show blockSize ++ ")") $
         conjoin
           [ case BPS.parseBPS patch of
               Left slapError -> counterexample ("parse: " ++ Text.unpack (renderSlapError slapError)) $ property False
               Right (Parsed parsed _parseWarnings) -> BPS.applyBPS parsed (InputFileContents source) === Right (OutputFileContents target)
           , property (ByteString.length (unPatchFileContents patch) < 1024)
           ]

-- | Patch size should not regress: a random diff with the rolling-hash
-- algorithm must produce patches no larger than a pure-literal encoding
-- (TargetRead for every byte), which costs targetLen + small overhead.
prop_bpsNoSizeRegression :: Property
prop_bpsNoSizeRegression = forAll genPair $ \(source, target) ->
  case createBPS (InputFileContents source) (OutputFileContents target) (BPSMetadata ByteString.empty) of
    Left createError -> counterexample ("create: " ++ Text.unpack (renderSlapError createError)) $ property False
    Right (CreateResult patch _) ->
      let maxPatchSize = ByteString.length target + 100
          patchSize = ByteString.length (unPatchFileContents patch)
      in counterexample ("patch size: " ++ show patchSize
                          ++ ", max: " ++ show maxPatchSize) $
         patchSize <= maxPatchSize

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
  let asLocale = SlapText.EncodedText SlapText.EncodingUtf8
  in case resolveXDelta1FileNames (Just (asLocale "source")) (Just (asLocale "target"))
                                  "ignored-source-path" "ignored-target-path" of
       Right resolved -> resolved
       Left err -> error ("xdelta1FixtureNames: " ++ Text.unpack (renderSlapError err))

prop_xdelta1RoundTrips :: Property
prop_xdelta1RoundTrips =
  forAll genPair $ \(sourceBytes, targetBytes) ->
  forAll genCompression $ \compression ->
  case createXDelta1 IncludeVerification compression xdelta1FixtureNames (InputFileContents sourceBytes) (OutputFileContents targetBytes) of
    Left createError -> counterexample ("create: " ++ Text.unpack (renderSlapError createError)) (property False)
    Right (CreateResult patch _) -> case XDelta1.parseXDelta1 SlapText.EncodingUtf8 patch of
      Left parseError -> counterexample ("parse: " ++ Text.unpack (renderSlapError parseError)) (property False)
      Right (Parsed parsed _) -> case XDelta1.applyXDelta1 parsed (InputFileContents sourceBytes) of
        Left applyError    -> counterexample ("apply: " ++ Text.unpack (renderSlapError applyError)) (property False)
        Right outputBytes  -> outputBytes === OutputFileContents targetBytes

-- | The compression posture round-trips: a patch created under each 'CompressionInclusion'
-- parses back to the matching wire-level 'XDelta1PatchCompression'.
prop_xdelta1CompressionPostureRoundTrips :: Property
prop_xdelta1CompressionPostureRoundTrips =
  forAll genPair $ \(sourceBytes, targetBytes) ->
  forAll genCompression $ \compression ->
  case createXDelta1 IncludeVerification compression xdelta1FixtureNames (InputFileContents sourceBytes) (OutputFileContents targetBytes) of
    Left createError -> counterexample ("create: " ++ Text.unpack (renderSlapError createError)) (property False)
    Right (CreateResult patch _) -> case XDelta1.parseXDelta1 SlapText.EncodingUtf8 patch of
      Left parseError -> counterexample ("parse: " ++ Text.unpack (renderSlapError parseError)) (property False)
      Right (Parsed parsed _) ->
        let expectedPosture = case compression of
              IncludeCompression -> CompressedPatch
              OmitCompression    -> UncompressedPatch
        in XDelta1.xdelta1PatchCompression parsed === expectedPosture

-- | A parsed xdelta1 patch offers its wire postures for inheritance: verification and
-- compression are explicit flag bits, so both states carry — an opted-out, uncompressed
-- source converts to an opted-out, uncompressed patch unless the user says otherwise.
xdelta1PosturesInheritOnConvert :: Assertion
xdelta1PosturesInheritOnConvert =
  case createXDelta1 OmitVerification OmitCompression xdelta1FixtureNames
         (InputFileContents (ByteString.replicate 64 0x11))
         (OutputFileContents (ByteString.replicate 64 0x22)) of
    Left createError -> assertFailureT ("create: " <> renderSlapError createError)
    Right (CreateResult patchBytes _) ->
      case parseSome noDialectsRequested SlapText.EncodingUtf8 patchBytes of
        Left slapError -> assertFailureT ("parseSome: " <> renderSlapError slapError)
        Right somePatch -> do
          assertEqual "verification posture offered"
            (Just OmitVerification) (requestedVerificationInclusion (patchExtractedMeta somePatch))
          assertEqual "compression posture offered"
            (Just OmitCompression) (requestedPatchCompression (patchExtractedMeta somePatch))

prop_xdelta1CreateProducesVerifyPosture :: Property
prop_xdelta1CreateProducesVerifyPosture =
  forAll genPair $ \(sourceBytes, targetBytes) ->
  forAll genCompression $ \compression ->
  case createXDelta1 IncludeVerification compression xdelta1FixtureNames (InputFileContents sourceBytes) (OutputFileContents targetBytes) of
    Left createError -> counterexample ("create: " ++ Text.unpack (renderSlapError createError)) (property False)
    Right (CreateResult patch _) -> case XDelta1.parseXDelta1 SlapText.EncodingUtf8 patch of
      Left parseError -> counterexample ("parse: " ++ Text.unpack (renderSlapError parseError)) (property False)
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
    Left createError -> counterexample ("create: " ++ Text.unpack (renderSlapError createError)) (property False)
    Right (CreateResult patch _) -> case XDelta1.parseXDelta1 SlapText.EncodingUtf8 patch of
      Left parseError -> counterexample ("parse: " ++ Text.unpack (renderSlapError parseError)) (property False)
      Right (Parsed parsed warnings) ->
        let postureCheck = XDelta1.xdelta1Verification parsed === XDelta1.CreatorOptedOutOfVerification
            warningCheck = counterexample
              ("expected VerificationOptedOutByCreator warning, got: " ++ show warnings)
              (any isOptedOutByCreatorWarning warnings)
            applyCheck = case XDelta1.applyXDelta1 parsed (InputFileContents sourceBytes) of
              Left applyError    -> counterexample ("apply: " ++ Text.unpack (renderSlapError applyError)) (property False)
              Right outputBytes  -> outputBytes === OutputFileContents targetBytes
        in postureCheck .&&. warningCheck .&&. applyCheck
  where
    isOptedOutByCreatorWarning warning = case warning of
      VerificationOptedOutByCreator _ -> True
      _ -> False

genCompression :: Gen CompressionInclusion
genCompression = elements [IncludeCompression, OmitCompression]

xdelta1EmptyTarget :: Assertion
xdelta1EmptyTarget = xdelta1RoundTripCase "hello world" ByteString.empty

xdelta1SingleByteTarget :: Assertion
xdelta1SingleByteTarget = xdelta1RoundTripCase "hello world" (ByteString.singleton 0x42)

xdelta1TargetEqualsSource :: Assertion
xdelta1TargetEqualsSource = xdelta1RoundTripCase payload payload
  where payload = "the source and target are identical"

xdelta1RoundTripCase :: ByteString.ByteString -> ByteString.ByteString -> Assertion
xdelta1RoundTripCase sourceBytes targetBytes =
  case createXDelta1 IncludeVerification IncludeCompression xdelta1FixtureNames (InputFileContents sourceBytes) (OutputFileContents targetBytes) of
    Left createError -> assertFailureT ("create: " <> renderSlapError createError)
    Right (CreateResult patch _) -> case XDelta1.parseXDelta1 SlapText.EncodingUtf8 patch of
      Left parseError -> assertFailureT ("parse: " <> renderSlapError parseError)
      Right (Parsed parsed _) -> case XDelta1.applyXDelta1 parsed (InputFileContents sourceBytes) of
        Left applyError -> assertFailureT ("apply: " <> renderSlapError applyError)
        Right outputBytes -> assertEqual "round-trip target" (OutputFileContents targetBytes) outputBytes

-- | The wire bit for @FLAG_NO_VERIFY@ is bit 0 of the first 32-bit
-- header word, which lives at file offset 8..11 (after the 8-byte
-- magic). Big-endian: bit 0 is the lowest-order bit of byte 11.
xdelta1NoVerifySetsFlagBit :: Assertion
xdelta1NoVerifySetsFlagBit =
  case createXDelta1 OmitVerification IncludeCompression xdelta1FixtureNames (InputFileContents "abcdef") (OutputFileContents "ghijkl") of
    Left createError -> assertFailureT ("create: " <> renderSlapError createError)
    Right (CreateResult (PatchFileContents patchBytes) _) -> do
      assertBool ("patch must be at least 12 bytes, got " ++ show (ByteString.length patchBytes))
        (ByteString.length patchBytes >= 12)
      let flagsLowByte = ByteString.index patchBytes 11
      assertBool ("FLAG_NO_VERIFY (bit 0) should be set; flags low byte = " ++ show flagsLowByte)
        (flagsLowByte `Bits.testBit` 0)

xdelta1IncludeVerifyClearsFlagBit :: Assertion
xdelta1IncludeVerifyClearsFlagBit =
  case createXDelta1 IncludeVerification IncludeCompression xdelta1FixtureNames (InputFileContents "abcdef") (OutputFileContents "ghijkl") of
    Left createError -> assertFailureT ("create: " <> renderSlapError createError)
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
  case createXDelta1 IncludeVerification OmitCompression
                     xdelta1FixtureNames
                     (InputFileContents "abcdef")
                     (OutputFileContents "ghijkl") of
    Left createError -> assertFailureT ("create: " <> renderSlapError createError)
    Right (CreateResult (PatchFileContents patchBytes) _) ->
      let totalLength    = ByteString.length patchBytes
          controlOffset  = fromIntegral (getWord32BE (totalLength - 12) patchBytes) :: Int
          corruptedBytes = ByteString.concat
            [ ByteString.take controlOffset patchBytes
            , ByteString.singleton 0xFF        -- flip high byte of type tag
            , ByteString.drop (controlOffset + 1) patchBytes
            ]
      in case XDelta1.parseXDelta1 SlapText.EncodingUtf8 (PatchFileContents corruptedBytes) of
        Right _ -> assertFailure
          "expected parser to reject corrupted control type tag; parse succeeded"
        Left parseError ->
          let rendered = Text.unpack (renderSlapError parseError)
          in assertBool
               ("rejection should name the type tag (got: " ++ rendered ++ ")")
               (   "type tag"        `isInfixOf` rendered
                || "ST_XdeltaControl" `isInfixOf` rendered)
