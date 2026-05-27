{-# LANGUAGE OverloadedStrings #-}

-- | Per-warning coverage for parse-time structural-warning channels
-- across the IPS family and APSN64. Each test constructs a minimal
-- format-specific patch that triggers exactly one parse-time warning
-- and asserts both that parsing succeeds and that the returned
-- warning list contains only the expected warning with the expected
-- field values. Patches are hand-assembled as 'ByteString' literals
-- rather than going through slap's create path, because slap's
-- encoder would never produce any of these structures — the whole
-- point of the warnings is to flag input patches that arrived from
-- elsewhere.
module Props.ParseWarnings (parseWarningsTests) where

import Props.Helpers (assertFailureT)

import qualified Slap.APSN64.Parse as APSN64
import qualified Slap.APSN64.Types as APSN64
import qualified Slap.IPS.Parse as IPS
import qualified Slap.PPF1.Parse as PPF1
import Slap.PPF1.Types (PPF1Origin(..))
import Slap.FieldName (FieldName(..))
import Slap.Status (Parsed(..), SlapAdvisory(..), OverlapCount(..),
                   renderSlapError)
import Slap.FileContents (PatchFileContents(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.Measure (actionAtPosition, Length(..), SubstitutionCount(..))

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.Word (Word8)

import Test.Tasty
import Test.Tasty.HUnit (Assertion, assertEqual, testCase)

parseWarningsTests :: TestTree
parseWarningsTests = testGroup "ParseWarnings"
  [ testCase "zero-count RLE record is accepted with warning"
      zeroCountRLEEmitsWarning
  , testCase "overlapping records emit pair warning"
      overlappingRecordsEmitWarning
  , testCase "unsorted records emit a single warning"
      unsortedRecordsEmitOneWarning
  , testCase "IPS32 trailing bytes are dropped with warning"
      ips32TrailingBytesEmitWarning
  , testCase "truncated IPS32 reports NoEOFMarker keyed to LabelIPS32"
      truncatedIPS32NoEOFMarkerCarriesVariantLabel
  , testCase "APS-N64 type-1 with recognized country byte parses cleanly"
      apsN64RecognizedCountryEmitsNoWarning
  , testCase "APS-N64 type-1 region-free (0x00) country parses as a named value without warning"
      apsN64RegionFreeCountryParsesNamed
  , testCase "APS-N64 type-1 with an unrecognized country byte preserves it without warning"
      apsN64UnrecognizedCountryPreservedWithoutWarning
  , testCase "APS-N64 type-0 (Simple) carries no country field and no country warning"
      apsN64SimplePatchHasNoCountryWarning
  , testCase "PPF1 description with bytes that do not decode under the locale surfaces a substitution advisory"
      ppf1DescriptionDecodeSubstitutionEmitsAdvisory
  ]

----------------------------------------------------------------------------
-- Patch-building helpers
----------------------------------------------------------------------------

-- | Magic bytes for a 'StandardIPS' patch.
standardIPSMagic :: ByteString
standardIPSMagic = ByteString.pack [0x50, 0x41, 0x54, 0x43, 0x48]  -- "PATCH"

-- | Trailer bytes that close a 'StandardIPS' record stream.
standardIPSTrailer :: ByteString
standardIPSTrailer = ByteString.pack [0x45, 0x4F, 0x46]  -- "EOF"

-- | Magic bytes for an 'IPS32' patch.
ips32Magic :: ByteString
ips32Magic = ByteString.pack [0x49, 0x50, 0x53, 0x33, 0x32]  -- "IPS32"

-- | Trailer bytes that close an 'IPS32' record stream.
ips32Trailer :: ByteString
ips32Trailer = ByteString.pack [0x45, 0x45, 0x4F, 0x46]  -- "EEOF"

-- | Encode an 'Int' as a 24-bit big-endian offset, the 'StandardIPS'
-- wire format's record-offset field.
word24BE :: Int -> ByteString
word24BE value = ByteString.pack
  [ fromIntegral ((value `div` 0x10000) `mod` 0x100)
  , fromIntegral ((value `div` 0x100)   `mod` 0x100)
  , fromIntegral (value                 `mod` 0x100)
  ]

-- | Encode an 'Int' as a 32-bit big-endian offset, the 'IPS32'
-- wire format's record-offset field.
word32BE :: Int -> ByteString
word32BE value = ByteString.pack
  [ fromIntegral ((value `div` 0x1000000) `mod` 0x100)
  , fromIntegral ((value `div` 0x10000)   `mod` 0x100)
  , fromIntegral ((value `div` 0x100)     `mod` 0x100)
  , fromIntegral (value                   `mod` 0x100)
  ]

-- | Encode an 'Int' as a 16-bit big-endian value, the IPS-family
-- record-size field.
word16BE :: Int -> ByteString
word16BE value = ByteString.pack
  [ fromIntegral ((value `div` 0x100) `mod` 0x100)
  , fromIntegral (value               `mod` 0x100)
  ]

-- | Build a 'StandardIPS' copy record: 24-bit offset, 16-bit size,
-- payload of exactly that many bytes.
copyRecord :: Int -> ByteString -> ByteString
copyRecord recordOffset recordPayload =
     word24BE recordOffset
  <> word16BE (ByteString.length recordPayload)
  <> recordPayload

-- | Build an 'IPS32' copy record: 32-bit offset, 16-bit size,
-- payload of exactly that many bytes. Mirrors 'copyRecord', with
-- the wider offset field the 'IPS32' variant requires.
ips32CopyRecord :: Int -> ByteString -> ByteString
ips32CopyRecord recordOffset recordPayload =
     word32BE recordOffset
  <> word16BE (ByteString.length recordPayload)
  <> recordPayload

-- | Build a 'StandardIPS' RLE record: 24-bit offset, a zero-valued
-- 16-bit size field (the RLE sentinel), a 16-bit run length, and a
-- one-byte fill value.
rleRecord :: Int -> Int -> Word8 -> ByteString
rleRecord recordOffset runLength fillByte =
     word24BE recordOffset
  <> word16BE 0
  <> word16BE runLength
  <> ByteString.singleton fillByte

----------------------------------------------------------------------------
-- Individual warning tests
----------------------------------------------------------------------------

-- | A single RLE record whose run-length field is zero. The parser
-- must accept the record as a no-op and surface exactly one
-- 'ZeroCountRLERecord' warning naming its wire position.
zeroCountRLEEmitsWarning :: Assertion
zeroCountRLEEmitsWarning =
  let patchBytes = standardIPSMagic
                <> rleRecord 0x000100 0 0xAA
                <> standardIPSTrailer
  in assertParseWarnings patchBytes
       [ZeroCountRLERecord LabelIPS (actionAtPosition 0)]

-- | Two copy records whose write regions intersect: record 0 writes
-- 10 bytes at offset 0; record 1 writes 10 bytes at offset 5. The
-- pair triggers a single 'OverlappingRecords' warning carrying the
-- count of intersecting pairs (one); no other warning applies (the
-- offsets are in ascending wire order, and neither record is an RLE
-- run).
overlappingRecordsEmitWarning :: Assertion
overlappingRecordsEmitWarning =
  let firstPayload  = ByteString.replicate 10 0x11
      secondPayload = ByteString.replicate 10 0x22
      patchBytes    = standardIPSMagic
                   <> copyRecord 0 firstPayload
                   <> copyRecord 5 secondPayload
                   <> standardIPSTrailer
  in assertParseWarnings patchBytes
       [OverlappingRecords LabelIPS (OverlapCount 1)]

-- | Two copy records whose offsets run in descending wire order:
-- record 0 at offset 20, record 1 at offset 10. Their 5-byte
-- payloads don't overlap — [20,25) and [10,15) are disjoint — so
-- only the 'UnsortedRecords' warning fires, naming the later
-- record whose offset dropped below its predecessor's.
unsortedRecordsEmitOneWarning :: Assertion
unsortedRecordsEmitOneWarning =
  let firstPayload  = ByteString.replicate 5 0x33
      secondPayload = ByteString.replicate 5 0x44
      patchBytes    = standardIPSMagic
                   <> copyRecord 20 firstPayload
                   <> copyRecord 10 secondPayload
                   <> standardIPSTrailer
  in assertParseWarnings patchBytes
       [UnsortedRecords LabelIPS (actionAtPosition 1)]

-- | A minimal 'IPS32' patch — magic, no records, the @"EEOF"@
-- trailer, and five arbitrary trailing bytes. The parser must
-- accept the patch, drop the trailing slice, and surface exactly
-- one 'IPS32TrailingBytes' warning carrying the dropped byte
-- count.
ips32TrailingBytesEmitWarning :: Assertion
ips32TrailingBytesEmitWarning =
  let trailingGarbage = ByteString.replicate 5 0x55
      patchBytes      = ips32Magic
                     <> ips32Trailer
                     <> trailingGarbage
  in assertParseWarnings patchBytes
       [IPS32TrailingBytes LabelIPS32 (Length 5)]

-- | A truncated 'IPS32' patch: magic plus one well-formed copy
-- record and no @"EEOF"@ trailer at all. The parser surfaces the
-- decoded record as 'IPSParseTruncated' and the warning channel
-- must carry 'NoEOFMarker' keyed to 'LabelIPS32' — not 'LabelIPS',
-- which would be a hardcoded-label bug rather than a correct
-- variant-aware label. A single record triggers neither the overlap
-- nor the unsorted detection pass, so the expected warning list
-- has exactly one entry.
truncatedIPS32NoEOFMarkerCarriesVariantLabel :: Assertion
truncatedIPS32NoEOFMarkerCarriesVariantLabel =
  let onlyRecordPayload = ByteString.replicate 4 0x66
      patchBytes        = ips32Magic
                       <> ips32CopyRecord 0x00000010 onlyRecordPayload
  in assertParseWarnings patchBytes
       [NoEOFMarker LabelIPS32]

----------------------------------------------------------------------------
-- Shared assertion
----------------------------------------------------------------------------

-- | Run 'IPS.parseIPS' on the given bytes, assert the parse
-- succeeds, and assert the surfaced warning list equals the
-- expected list exactly. The parsed value is intentionally not
-- inspected — each test's invariant is on the warning channel, and
-- the parse-succeeds gate is enough to confirm the record walk
-- reached the end of the input.
assertParseWarnings :: ByteString -> [SlapAdvisory] -> Assertion
assertParseWarnings patchBytes expectedWarnings =
  case IPS.parseIPS (PatchFileContents patchBytes) of
    Left slapError ->
      assertFailureT ("parse failed: " <> renderSlapError slapError)
    Right (Parsed _parseResult actualWarnings) ->
      assertEqual "surfaced warnings" expectedWarnings actualWarnings

----------------------------------------------------------------------------
-- APS-N64 country byte
----------------------------------------------------------------------------

-- | APS-N64 magic: the literal ASCII bytes @"APS10"@.
apsN64Magic :: ByteString
apsN64Magic = ByteString.pack [0x41, 0x50, 0x53, 0x31, 0x30]

-- | The APS-N64 description field is exactly 50 bytes wide; tests
-- that don't care about its contents pad with NULs.
apsN64NullDescription :: ByteString
apsN64NullDescription = ByteString.replicate 50 0x00

-- | Encode an 'Int' as a 32-bit little-endian value, the APS-N64
-- destination-size field's wire shape.
word32LE :: Int -> ByteString
word32LE value = ByteString.pack
  [ fromIntegral ( value                  `mod` 0x100)
  , fromIntegral ((value `div` 0x100)     `mod` 0x100)
  , fromIntegral ((value `div` 0x10000)   `mod` 0x100)
  , fromIntegral ((value `div` 0x1000000) `mod` 0x100)
  ]

-- | Build a record-free APS-N64 type-1 (N64-specific) patch carrying
-- a chosen country byte. The other type-1 fields are filled with
-- placeholder bytes whose values don't matter for the country test.
apsN64Type1Patch :: Word8 -> ByteString
apsN64Type1Patch countryByte =
     apsN64Magic
  <> ByteString.singleton 0x01                    -- patch type 1 (N64-specific)
  <> ByteString.singleton 0x00                    -- encoding method (default)
  <> apsN64NullDescription                        -- description
  <> ByteString.singleton 0x01                    -- image format (Z64)
  <> ByteString.pack [0x53, 0x4D]                 -- cart ID
  <> ByteString.singleton countryByte             -- country byte (under test)
  <> ByteString.replicate 8 0x00                  -- CIC checksum pair
  <> ByteString.replicate 5 0x00                  -- header padding (bytes 69-73)
  <> word32LE 0                                   -- destination size

-- | Build a record-free APS-N64 type-0 (Simple) patch. Type-0 has
-- no country byte at all, which is the structural property under
-- test.
apsN64Type0Patch :: ByteString
apsN64Type0Patch =
     apsN64Magic
  <> ByteString.singleton 0x00                    -- patch type 0 (Simple)
  <> ByteString.singleton 0x00                    -- encoding method (default)
  <> apsN64NullDescription                        -- description
  <> word32LE 0                                   -- destination size

-- | Run 'APSN64.parseAPSN64' on the given bytes, assert the parse
-- succeeds, and yield the parsed header plus its surfaced warnings
-- to the caller for further structural assertions.
withParsedAPSN64 :: ByteString -> (APSN64.APSN64Header -> [SlapAdvisory] -> Assertion) -> Assertion
withParsedAPSN64 patchBytes inspect =
  case APSN64.parseAPSN64 (PatchFileContents patchBytes) of
    Left slapError ->
      assertFailureT ("parse failed: " <> renderSlapError slapError)
    Right (Parsed (APSN64.APSN64Patch header _records) actualWarnings) ->
      inspect header actualWarnings

apsN64RecognizedCountryEmitsNoWarning :: Assertion
apsN64RecognizedCountryEmitsNoWarning =
  withParsedAPSN64 (apsN64Type1Patch 0x4A) $ \header actualWarnings -> do
    assertEqual "country field" (Just APSN64.APSN64CountryJapan) (APSN64.apsN64Country header)
    assertEqual "surfaced warnings" [] actualWarnings

apsN64RegionFreeCountryParsesNamed :: Assertion
apsN64RegionFreeCountryParsesNamed =
  withParsedAPSN64 (apsN64Type1Patch 0x00) $ \header actualWarnings -> do
    assertEqual "country field" (Just APSN64.APSN64CountryRegionFree) (APSN64.apsN64Country header)
    assertEqual "surfaced warnings" [] actualWarnings

apsN64UnrecognizedCountryPreservedWithoutWarning :: Assertion
apsN64UnrecognizedCountryPreservedWithoutWarning =
  withParsedAPSN64 (apsN64Type1Patch 0xFF) $ \header actualWarnings -> do
    assertEqual "country field" (Just (APSN64.APSN64CountryUnrecognized 0xFF)) (APSN64.apsN64Country header)
    assertEqual "surfaced warnings" [] actualWarnings

apsN64SimplePatchHasNoCountryWarning :: Assertion
apsN64SimplePatchHasNoCountryWarning =
  withParsedAPSN64 apsN64Type0Patch $ \header actualWarnings -> do
    assertEqual "country field" Nothing (APSN64.apsN64Country header)
    assertEqual "surfaced warnings" [] actualWarnings

----------------------------------------------------------------------------
-- PPF description: parse-time decode substitution advisory
----------------------------------------------------------------------------

-- | A minimal PPF1 patch whose 50-byte description contains a byte
-- sequence that does not decode under a UTF-8 locale: an isolated
-- @0x80@ continuation byte, surrounded by ASCII padding. The patch
-- carries no records, just the header — enough to exercise the
-- description-decode pathway and the resulting advisory channel.
ppf1PatchWithInvalidDescriptionByte :: ByteString
ppf1PatchWithInvalidDescriptionByte =
  let invalidByte    = 0x80
      paddingByte    = 0x20  -- ASCII space; PPF1's reference pad byte
      descriptionBytes = ByteString.replicate 24 paddingByte
                      <> ByteString.singleton invalidByte
                      <> ByteString.replicate 25 paddingByte
  in ByteString.pack [0x50, 0x50, 0x46, 0x31, 0x30, 0x00]  -- "PPF10" + encoding byte 0x00
     <> descriptionBytes

-- | When the description bytes don't decode cleanly under the
-- process locale, slap leniently substitutes 'U+FFFD' for each
-- offending sequence and surfaces a single
-- 'FieldDecodedSubstituted' advisory naming the format, the field,
-- and the substitution count. This test asserts that exact shape on
-- a hand-built PPF1 patch whose description holds one undecodable
-- byte.
--
-- The test is locale-sensitive: a non-UTF-8 process locale (e.g.
-- ISO-8859-1) would decode @0x80@ to a single defined codepoint
-- rather than substituting, and the assertion would not match.
-- Slap's CI host uses UTF-8 by default, so this assertion is
-- meaningful in the environments the test suite normally runs in.
ppf1DescriptionDecodeSubstitutionEmitsAdvisory :: Assertion
ppf1DescriptionDecodeSubstitutionEmitsAdvisory =
  case PPF1.parsePPF1 PPF1OriginPC
         (PatchFileContents ppf1PatchWithInvalidDescriptionByte) of
    Left slapError -> assertFailureT ("parse failed: " <> renderSlapError slapError)
    Right (Parsed _ advisories) ->
      assertEqual "surfaced advisories"
        [FieldDecodedSubstituted LabelPPF1 FieldDescription
           (SubstitutionCount 1)]
        advisories
