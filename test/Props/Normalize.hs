{-# LANGUAGE OverloadedStrings #-}

-- | Properties and pinned examples for "Slap.Normalize", the NINJA formats' ROM-image canonicalization. Three strands:
--
--   * The pure byte transforms — the N64 pair swap, the SMD block deinterleave, the Game Doctor chart reordering —
--     checked against test-local inverses, so each is pinned to the layout it claims to undo rather than to its own implementation.
--   * Each platform procedure's dispositions: what strips, what restores, what is taken as-is with which advisory.
--   * The full round trip — create from headered dumps, parse, normalize, apply, restore — the property the whole feature exists for.
--     NINJA2 restores the header; NINJA1 is forward-only and must not.
module Props.Normalize (normalizeTests) where

import Slap.Normalize (SourceNormalization(..), RestoreDiscipline(..),
                       NormalizationConfirmation(..),
                       NormalizedSource(..), normalizeApplySource,
                       CanonicalizedImage(..), canonicalizeRomImage,
                       RestoreStep(..), StrippedHeader(..),
                       restoreStrippedContent,
                       sharesNormalizationLayout,
                       deinterleaveByChart, evenOddInterleaveChart,
                       snesGD3Chart20Mbit, snesGD3Chart24Mbit, snesGD3Chart48Mbit,
                       rebuildUNIFContainer, UNIFRebuildMismatch(..))
import Slap.Status (SlapError, SlapAdvisory(..), NormalizationStep(..),
                    SNESInterleaveLayout(..), NormalizedImageRole(..),
                    NormalizationSkipReason(..), Outcome(..),
                    CreateResult(..), renderSlapError)
import Slap.PlatformType (PlatformType(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.FileContents (InputFileContents(..), OutputFileContents(..))
import Slap.SomePatch (SomePatch(..), ApplyStrategy(..), Verification(..), parseSome)
import Slap.Convert (CreateFormat(..), DirectCreate(..), RequestedPatchMetadata(..),
                     noMetadataRequested, noConstraintsRequested, noDialectsRequested,
                     createPatch)
import Slap.Create (createNINJA2)
import Slap.NINJA2.Types (NINJA2CreateMetadata(..), TextMode(..))
import Slap.Binary (md5, swapAdjacentBytePairs, deinterleaveSMDBlock)
import Slap.Text (EncodingName(EncodingUtf8))

import Props.Helpers (assertFailureT)

import Data.Array (bounds, elems)
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.List (sort)
import Data.Word (Word8)

import Test.Tasty
import Test.Tasty.HUnit
import Test.Tasty.QuickCheck

normalizeTests :: TestTree
normalizeTests = testGroup "Normalize"
  [ pairSwapTests
  , smdBlockTests
  , gd3ChartTests
  , evenOddChartTests
  , nesTests
  , unifTests
  , snesTests
  , sizeProbedHeaderTests
  , n64Tests
  , segaTests
  , siblingLayoutTests
  , createApplyRestoreTests
  ]

----------------------------------------------------------------------------
-- Pure transforms
----------------------------------------------------------------------------

genEvenLengthBytes :: Gen ByteString
genEvenLengthBytes = do
  pairCount <- chooseInt (0, 512)
  ByteString.pack <$> vectorOf (2 * pairCount) arbitrary

pairSwapTests :: TestTree
pairSwapTests = testGroup "swapAdjacentBytePairs"
  [ testCase "1234 becomes 2143" $
      swapAdjacentBytePairs (ByteString.pack [1, 2, 3, 4]) @?= ByteString.pack [2, 1, 4, 3]
  , testProperty "is its own inverse" $
      forAll genEvenLengthBytes $ \bytes ->
        swapAdjacentBytePairs (swapAdjacentBytePairs bytes) === bytes
  ]

-- | The SMD layout 'deinterleaveSMDBlock' claims to undo: a block's first half holds the clean bytes' even positions, its second half the odd ones.
interleaveIntoSMDBlock :: ByteString -> ByteString
interleaveIntoSMDBlock clean =
  evenPositions <> oddPositions
  where
    evenPositions = ByteString.pack [ByteString.index clean position | position <- [0, 2 .. ByteString.length clean - 1]]
    oddPositions  = ByteString.pack [ByteString.index clean position | position <- [1, 3 .. ByteString.length clean - 1]]

smdBlockTests :: TestTree
smdBlockTests = testGroup "deinterleaveSMDBlock"
  [ testProperty "undoes the SMD half-split" $
      forAll genEvenLengthBytes $ \clean ->
        deinterleaveSMDBlock (interleaveIntoSMDBlock clean) === clean
  ]

-- | A 32 KiB bank whose every byte is its own bank number, so a reordering mistake shows in any single byte.
numberedBank :: Int -> ByteString
numberedBank bankNumber = ByteString.replicate 0x8000 (fromIntegral bankNumber :: Word8)

gd3ChartTests :: TestTree
gd3ChartTests = testGroup "Game Doctor charts"
  [ testGroup "each chart is a permutation"
      [ testCase name $ sort (elems chart) @?= [low .. high]
      | (name, chart) <- namedCharts
      , let (low, high) = bounds chart
      ]
  , testGroup "deinterleaveByChart places every input bank at its chart position"
      [ testCase name $
          let (low, high) = bounds chart
              chartEntries = elems chart
              -- The interleaved image the copier wrote: input bank j holds the clean bank the chart sends position j to.
              interleaved = ByteString.concat [numberedBank destination | destination <- chartEntries]
              expected    = ByteString.concat [numberedBank bank | bank <- [low .. high]]
          in deinterleaveByChart chart interleaved @?= expected
      | (name, chart) <- namedCharts
      ]
  ]
  where
    namedCharts =
      [ ("20 Mbit", snesGD3Chart20Mbit)
      , ("24 Mbit", snesGD3Chart24Mbit)
      , ("48 Mbit", snesGD3Chart48Mbit)
      ]

-- | The reference even/odd deinterleave, hand-rolled from @sfam_read@'s fall-through loop:
-- for chunk @i@ in @[0, half)@, append chunk @i + half@ then chunk @i@.
-- The equivalence property pins 'evenOddInterleaveChart', run through 'deinterleaveByChart', against this.
referenceEvenOddShuffle :: ByteString -> ByteString
referenceEvenOddShuffle image =
  ByteString.concat
    (concat [[bankAt (position + halfCount), bankAt position] | position <- [0 .. halfCount - 1]])
  where
    bankCount = ByteString.length image `div` 0x8000
    halfCount = bankCount `div` 2
    bankAt position = ByteString.take 0x8000 (ByteString.drop (position * 0x8000) image)

evenOddChartTests :: TestTree
evenOddChartTests = testGroup "even/odd interleave chart"
  [ testCase "eight banks: odd output positions first, then even" $
      elems (evenOddInterleaveChart 8) @?= [1, 3, 5, 7, 0, 2, 4, 6]
  , testGroup "each chart is a permutation of its bank range"
      [ testCase (show bankCount ++ " banks") $
          sort (elems (evenOddInterleaveChart bankCount)) @?= [0 .. bankCount - 1]
      | bankCount <- [2, 4, 8, 80, 96, 192]
      ]
  , testProperty "deinterleaveByChart reproduces the reference even/odd shuffle" $
      forAll (chooseInt (1, 40)) $ \halfCount ->
        let bankCount = 2 * halfCount
            image     = ByteString.concat [numberedBank bank | bank <- [0 .. bankCount - 1]]
        in deinterleaveByChart (evenOddInterleaveChart bankCount) image === referenceEvenOddShuffle image
  ]

----------------------------------------------------------------------------
-- Per-platform procedure fixtures
----------------------------------------------------------------------------

-- | Canonicalize as the NINJA2 apply path would, for fixture assertions.
canonicalizeAsNINJA2Input :: PlatformType -> ByteString -> CanonicalizedImage
canonicalizeAsNINJA2Input = canonicalizeRomImage LabelNINJA2 NormalizedApplyInput

performedSteps :: CanonicalizedImage -> [NormalizationStep]
performedSteps canonical =
  [step | RomImageNormalized _ _ _ step <- canonicalImageAdvisories canonical]

skipReasons :: CanonicalizedImage -> [NormalizationSkipReason]
skipReasons canonical =
  [reason | RomImageNormalizationSkipped _ _ _ reason <- canonicalImageAdvisories canonical]

shapeUnrecognizedCount :: CanonicalizedImage -> Int
shapeUnrecognizedCount canonical =
  length [() | RomImageShapeUnrecognized{} <- canonicalImageAdvisories canonical]

nesTests :: TestTree
nesTests = testGroup "NES"
  [ testCase "iNES: 16-byte header strips and is kept for restore" $ do
      let header = "NES\x1A" <> ByteString.replicate 12 0xEE
          body   = ByteString.replicate 0x100 0x42
          canonical = canonicalizeAsNINJA2Input PlatformNES (header <> body)
      canonicalImageBytes canonical @?= body
      performedSteps canonical @?= [StrippedINESHeader]
      case canonicalImageRestore canonical of
        RestoreHeaderPrefix (StrippedHeader kept) -> kept @?= header
        _ -> assertFailure "expected a header prefix to restore"
  , testCase "FFE: the 0xAA 0xBB marker at offset 8 strips 512 bytes" $ do
      let header = ByteString.replicate 8 0 <> ByteString.pack [0xAA, 0xBB] <> ByteString.replicate (0x200 - 10) 0
          body   = ByteString.replicate 0x80 0x51
          canonical = canonicalizeAsNINJA2Input PlatformNES (header <> body)
      canonicalImageBytes canonical @?= body
      performedSteps canonical @?= [StrippedFFEHeader]
  , testCase "no known signature: taken as-is with the shape warning" $ do
      let image = ByteString.replicate 0x40 0x33
          canonical = canonicalizeAsNINJA2Input PlatformNES image
      canonicalImageBytes canonical @?= image
      shapeUnrecognizedCount canonical @?= 1
  ]

----------------------------------------------------------------------------
-- UNIF
----------------------------------------------------------------------------

unifChunk :: ByteString -> ByteString -> ByteString
unifChunk chunkId payload =
  chunkId <> littleEndianWord32 (ByteString.length payload) <> payload
  where
    littleEndianWord32 value = ByteString.pack
      [ fromIntegral (value `mod` 0x100)
      , fromIntegral ((value `div` 0x100) `mod` 0x100)
      , fromIntegral ((value `div` 0x10000) `mod` 0x100)
      , fromIntegral ((value `div` 0x1000000) `mod` 0x100)
      ]

-- | A small synthetic UNIF container: 32-byte file header, a mapper chunk the merge must skip, one PRG and one CHR chunk, and a trailing non-ROM chunk.
syntheticUNIF :: ByteString -> ByteString -> ByteString
syntheticUNIF prgPayload chrPayload =
  "UNIF" <> ByteString.replicate 28 0
    <> unifChunk "MAPR" "some-mapper-board"
    <> unifChunk "PRG0" prgPayload
    <> unifChunk "CHR0" chrPayload
    <> unifChunk "BATR" "\x01"

unifTests :: TestTree
unifTests = testGroup "UNIF"
  [ testCase "merge concatenates PRG and CHR payloads in order" $ do
      let prgPayload = ByteString.replicate 0x20 0xAA
          chrPayload = ByteString.replicate 0x10 0xBB
          canonical  = canonicalizeAsNINJA2Input PlatformNES (syntheticUNIF prgPayload chrPayload)
      canonicalImageBytes canonical @?= prgPayload <> chrPayload
      performedSteps canonical @?= [MergedUNIFChunks]
  , testCase "rebuild reinserts same-size patched data, framing intact" $ do
      let prgPayload = ByteString.replicate 0x20 0xAA
          chrPayload = ByteString.replicate 0x10 0xBB
          container  = syntheticUNIF prgPayload chrPayload
          patchedPRG = ByteString.replicate 0x20 0x11
          patchedCHR = ByteString.replicate 0x10 0x22
      case rebuildUNIFContainer container (patchedPRG <> patchedCHR) of
        Left _ -> assertFailure "rebuild refused a same-size reinsert"
        Right rebuilt -> rebuilt @?= syntheticUNIF patchedPRG patchedCHR
  , testCase "rebuild refuses resized data with both byte counts" $ do
      let container = syntheticUNIF (ByteString.replicate 0x20 0xAA) (ByteString.replicate 0x10 0xBB)
      case rebuildUNIFContainer container (ByteString.replicate 0x31 0x11) of
        Left (UNIFRebuildMismatch _ _) -> pure ()
        Right _ -> assertFailure "rebuild accepted resized data"
  , testCase "a chunk declaring bytes past the end skips the merge" $ do
      let truncated = "UNIF" <> ByteString.replicate 28 0
                        <> "PRG0" <> ByteString.pack [0xFF, 0, 0, 0]  -- declares 255 bytes
                        <> ByteString.replicate 4 0x77                -- holds 4
          canonical = canonicalizeAsNINJA2Input PlatformNES truncated
      canonicalImageBytes canonical @?= truncated
      skipReasons canonical @?= [UNIFChunkTableTruncated]
  ]

----------------------------------------------------------------------------
-- SNES
----------------------------------------------------------------------------

-- | A LoROM-shaped bank pair: the internal header's checksum pair at 0x7FDC sums to 0xFFFF and the ROM-state byte at 0x7FD5 is even.
loROMBody :: ByteString
loROMBody = snesBodyWithProbe 0x00 2

-- | An interleaved-HiROM-shaped body of the given bank count: same checksum pair, ROM-state byte odd.
interleavedHiROMBody :: Int -> ByteString
interleavedHiROMBody = snesBodyWithProbe 0x01

-- | Banks of distinct fill bytes with the 0x7FDC-area probe bytes planted: ROM state, then (inverse, checksum) = (0x1234, 0xEDCB), little-endian.
snesBodyWithProbe :: Word8 -> Int -> ByteString
snesBodyWithProbe romstateByte bankCount =
  plantBytes 0x7FD5 (ByteString.singleton romstateByte)
    (plantBytes 0x7FDC (ByteString.pack [0x34, 0x12, 0xCB, 0xED])
      (ByteString.concat [numberedBank bank | bank <- [1 .. bankCount]]))

plantBytes :: Int -> ByteString -> ByteString -> ByteString
plantBytes position replacement image =
  ByteString.take position image
    <> replacement
    <> ByteString.drop (position + ByteString.length replacement) image

snesTests :: TestTree
snesTests = testGroup "SNES"
  [ testCase "a copier header strips and is not kept" $ do
      let image = ByteString.replicate 0x200 0x99 <> loROMBody
          canonical = canonicalizeAsNINJA2Input PlatformSNES image
      canonicalImageBytes canonical @?= loROMBody
      performedSteps canonical @?= [StrippedSNESCopierHeader]
      case canonicalImageRestore canonical of
        NothingToRestore -> pure ()
        _ -> assertFailure "a plain copier header must not restore"
  , testCase "an NSRT header strips and is kept for restore" $ do
      let header = plantBytes 0x1E8 "NSRT" (ByteString.replicate 0x200 0x99)
          canonical = canonicalizeAsNINJA2Input PlatformSNES (header <> loROMBody)
      canonicalImageBytes canonical @?= loROMBody
      performedSteps canonical @?= [StrippedNSRTHeader]
      case canonicalImageRestore canonical of
        RestoreHeaderPrefix (StrippedHeader kept) -> kept @?= header
        _ -> assertFailure "expected the NSRT header kept for restore"
  , testCase "an interleaved HiROM swaps its even/odd bank halves" $ do
      let body = interleavedHiROMBody 4
          bankAt position = ByteString.take 0x8000 (ByteString.drop (position * 0x8000) body)
          canonical = canonicalizeAsNINJA2Input PlatformSNES body
      canonicalImageBytes canonical
        @?= ByteString.concat [bankAt 2, bankAt 0, bankAt 3, bankAt 1]
      performedSteps canonical @?= [DeinterleavedSNESHiROM EvenOddHalvesLayout]
  , testCase "no checksum pair anywhere: taken as-is with the shape warning" $ do
      let image = ByteString.concat [numberedBank bank | bank <- [1 .. 2]]
          canonical = canonicalizeAsNINJA2Input PlatformSNES image
      canonicalImageBytes canonical @?= image
      shapeUnrecognizedCount canonical @?= 1
  , testCase "ForwardOnly discipline drops the NSRT restore" $ do
      let header = plantBytes 0x1E8 "NSRT" (ByteString.replicate 0x200 0x99)
          normalization = SourceNormalization
            { normalizationFormat       = LabelNINJA1
            , normalizationPlatform     = PlatformSNES
            , normalizationDiscipline   = ForwardOnly
            , normalizationConfirmation = ConfirmableBySourceChecksum
            }
          normalized = normalizeApplySource (Just normalization) (InputFileContents (header <> loROMBody))
      unInputFileContents (normalizedSourceBytes normalized) @?= loROMBody
      case normalizedSourceRestore normalized of
        NothingToRestore -> pure ()
        _ -> assertFailure "ForwardOnly must not carry a restore step"
  ]

----------------------------------------------------------------------------
-- Game Boy and PC-Engine
----------------------------------------------------------------------------

sizeProbedHeaderTests :: TestTree
sizeProbedHeaderTests = testGroup "size-probed headers"
  [ testCase "Game Boy: off-bank size strips 512 bytes, dropped" $ do
      let body  = ByteString.replicate 0x8000 0x42
          canonical = canonicalizeAsNINJA2Input PlatformGB (ByteString.replicate 0x200 0x77 <> body)
      canonicalImageBytes canonical @?= body
      performedSteps canonical @?= [StrippedSmartCardHeader]
  , testCase "Game Boy: bank-aligned size passes through untouched" $ do
      let image = ByteString.replicate 0x8000 0x42
          canonical = canonicalizeAsNINJA2Input PlatformGB image
      canonicalImageBytes canonical @?= image
      canonicalImageAdvisories canonical @?= []
  , testCase "PC-Engine: off-unit size strips 512 bytes" $ do
      let body = ByteString.replicate 0x2000 0x24
          canonical = canonicalizeAsNINJA2Input PlatformPCEngine (ByteString.replicate 0x200 0x77 <> body)
      canonicalImageBytes canonical @?= body
      performedSteps canonical @?= [StrippedMagicSuperGriffinHeader]
  , testCase "Lynx: the LYNX header strips and is kept for restore" $ do
      let header = "LYNX" <> ByteString.replicate 0x3C 0x10
          body   = ByteString.replicate 0x100 0x64
          canonical = canonicalizeAsNINJA2Input PlatformLynx (header <> body)
      canonicalImageBytes canonical @?= body
      performedSteps canonical @?= [StrippedLynxHeader]
      case canonicalImageRestore canonical of
        RestoreHeaderPrefix (StrippedHeader kept) -> kept @?= header
        _ -> assertFailure "expected the LYNX header kept for restore"
  , testCase "Lynx: an unsignatured image passes through with no remark" $ do
      let image = ByteString.replicate 0x100 0x64
          canonical = canonicalizeAsNINJA2Input PlatformLynx image
      canonicalImageBytes canonical @?= image
      canonicalImageAdvisories canonical @?= []
  ]

----------------------------------------------------------------------------
-- N64
----------------------------------------------------------------------------

n64Tests :: TestTree
n64Tests = testGroup "N64"
  [ testCase "native order passes through untouched" $ do
      let image = ByteString.pack [0x80, 0x37, 0x12, 0x40] <> ByteString.pack [1, 2, 3, 4]
          canonical = canonicalizeAsNINJA2Input PlatformN64 image
      canonicalImageBytes canonical @?= image
      canonicalImageAdvisories canonical @?= []
  , testCase "byteswapped order swaps every pair" $ do
      let canonical = canonicalizeAsNINJA2Input PlatformN64
                        (ByteString.pack [0x37, 0x80, 0x40, 0x12] <> ByteString.pack [2, 1, 4, 3])
      canonicalImageBytes canonical
        @?= ByteString.pack [0x80, 0x37, 0x12, 0x40] <> ByteString.pack [1, 2, 3, 4]
      performedSteps canonical @?= [ByteswappedN64Image]
  , testCase "unknown magic: taken as-is with the shape warning" $ do
      let image = ByteString.replicate 8 0x55
          canonical = canonicalizeAsNINJA2Input PlatformN64 image
      canonicalImageBytes canonical @?= image
      shapeUnrecognizedCount canonical @?= 1
  ]

----------------------------------------------------------------------------
-- Sega
----------------------------------------------------------------------------

segaTests :: TestTree
segaTests = testGroup "Sega"
  [ testCase "Genesis: a SEGA signature at 0x100 means already canonical" $ do
      let image = plantBytes 0x100 "SEGA" (ByteString.replicate 0x8000 0x21)
          canonical = canonicalizeAsNINJA2Input PlatformGenesis image
      canonicalImageBytes canonical @?= image
      canonicalImageAdvisories canonical @?= []
  , testCase "Genesis: an SMD image strips its header and deinterleaves" $ do
      let cleanBlock = ByteString.pack (map fromIntegral [0 :: Int .. 0x3FFF])
          image = ByteString.replicate 8 0 <> ByteString.pack [0xAA, 0xBB]
                    <> ByteString.replicate (0x200 - 10) 0
                    <> interleaveIntoSMDBlock cleanBlock
          canonical = canonicalizeAsNINJA2Input PlatformGenesis image
      canonicalImageBytes canonical @?= cleanBlock
      performedSteps canonical @?= [DeinterleavedSMDImage]
  , testCase "SMS: an SMD body of fractional blocks skips with its reason" $ do
      let image = ByteString.replicate 8 0 <> ByteString.pack [0xAA, 0xBB]
                    <> ByteString.replicate (0x200 - 10) 0
                    <> ByteString.replicate 0x123 0x66
          canonical = canonicalizeAsNINJA2Input PlatformSMS image
      canonicalImageBytes canonical @?= image
      skipReasons canonical @?= [SMDBlocksNotWhole]
  , testCase "SMS: neither signature is the shape warning" $ do
      let image = ByteString.replicate 0x9000 0x13
          canonical = canonicalizeAsNINJA2Input PlatformSMS image
      canonicalImageBytes canonical @?= image
      shapeUnrecognizedCount canonical @?= 1
  ]

----------------------------------------------------------------------------
-- Sibling layouts
----------------------------------------------------------------------------

siblingLayoutTests :: TestTree
siblingLayoutTests = testGroup "sharesNormalizationLayout"
  [ testCase "SMS and Game Gear share, both ways" $ do
      sharesNormalizationLayout PlatformSMS PlatformGameGear @?= True
      sharesNormalizationLayout PlatformGameGear PlatformSMS @?= True
  , testCase "every platform shares with itself" $
      sharesNormalizationLayout PlatformSNES PlatformSNES @?= True
  , testCase "a cross-platform pair does not share" $
      sharesNormalizationLayout PlatformSNES PlatformGameGear @?= False
  ]

----------------------------------------------------------------------------
-- The full round trip
----------------------------------------------------------------------------

-- | Run the apply pipeline the way @app/Main.hs@ does — normalize, apply, restore — against a parsed patch.
applyThroughNormalization :: SomePatch -> ByteString -> IO (Either SlapError ByteString)
applyThroughNormalization somePatch handedBytes = do
  let normalized = normalizeApplySource (patchSourceNormalization somePatch) (InputFileContents handedBytes)
  applied <- runApply (patchApply somePatch) (normalizedSourceBytes normalized)
  pure $ case applied of
    Left applyError -> Left applyError
    Right outcome ->
      let (OutputFileContents restored, _restoreAdvisories) =
            restoreStrippedContent (patchFormat somePatch)
                                   (normalizedSourceRestore normalized)
                                   (outcomeValue outcome)
      in Right restored

createApplyRestoreTests :: TestTree
createApplyRestoreTests = testGroup "create → parse → apply → restore"
  [ testCase "NINJA2/NES: a headered pair round-trips, header restored" $ do
      let header   = "NES\x1A" <> ByteString.replicate 12 0xEE
          body     = ByteString.pack (map fromIntegral [0 :: Int .. 0x3FF])
          patched  = plantBytes 0x100 "patched!" body
          original = header <> body
          modified = header <> patched
      patchBytes <- either (assertFailureT . renderSlapError) (pure . resultBytes)
        (createNINJA2 (InputFileContents original) (OutputFileContents modified) nesCreateMetadata)
      somePatch <- either (assertFailureT . renderSlapError) pure
        (parseSome noDialectsRequested EncodingUtf8 patchBytes)
      -- The stored source MD5 describes the clean body, not the handed file.
      verifySourceMD5 (patchVerification somePatch) @?= Just (md5 body)
      applied <- applyThroughNormalization somePatch original
      either (assertFailureT . renderSlapError) (@?= modified) applied
  , testCase "NINJA1/GB: forward-only apply emits the clean patched body" $ do
      let header   = ByteString.replicate 0x200 0x77
          body     = ByteString.replicate 0x8000 0x42
          patched  = plantBytes 0x30 "patched!" body
          original = header <> body
          modified = header <> patched
          ninja1Meta = noMetadataRequested { requestedRomType = Just PlatformGB }
      patchBytes <- either (assertFailureT . renderSlapError) (pure . resultBytes)
        (createPatch (CreateDirect CreateNINJA1) Nothing
                     (InputFileContents original) (OutputFileContents modified)
                     ninja1Meta Nothing noConstraintsRequested noDialectsRequested)
      somePatch <- either (assertFailureT . renderSlapError) pure
        (parseSome noDialectsRequested EncodingUtf8 patchBytes)
      applied <- applyThroughNormalization somePatch original
      either (assertFailureT . renderSlapError) (@?= patched) applied
  ]
  where
    nesCreateMetadata = NINJA2CreateMetadata
      { ninja2CreateMetadataAuthor      = Nothing
      , ninja2CreateMetadataVersion     = Nothing
      , ninja2CreateMetadataTitle       = Nothing
      , ninja2CreateMetadataGenre       = Nothing
      , ninja2CreateMetadataLanguage    = Nothing
      , ninja2CreateMetadataDate        = Nothing
      , ninja2CreateMetadataWebsite     = Nothing
      , ninja2CreateMetadataDescription = Nothing
      , ninja2CreateTextMode            = TextModeUTF8
      , ninja2CreateMetadataPlatform    = Just PlatformNES
      }
