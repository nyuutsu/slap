-- | Per-warning coverage for the IPS parser's structural-warning
-- channel. Each test constructs a minimal IPS-family patch that
-- triggers exactly one of the four parse-time warnings and asserts
-- both that parsing succeeds and that the returned warning list
-- contains only the expected warning with the expected field
-- values. Patches are hand-assembled as 'ByteString' literals
-- rather than going through slap's create path, because slap's
-- encoder would never produce any of these structures — the whole
-- point of the warnings is to flag input patches that arrived
-- from elsewhere.
module Props.ParseWarnings (parseWarningsTests) where

import qualified Slap.IPS.Parse as IPS
import Slap.Error (Parsed(..), SlapWarning(..), renderSlapError)
import Slap.FileContents (PatchFileContents(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.Measure (ActionIndex(..), Length(..))

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.Word (Word8)

import Test.Tasty
import Test.Tasty.HUnit (Assertion, assertEqual, assertFailure, testCase)

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
       [ZeroCountRLERecord LabelIPS (ActionIndex 0)]

-- | Two copy records whose write regions intersect: record 0 writes
-- 10 bytes at offset 0; record 1 writes 10 bytes at offset 5. The
-- pair triggers a single 'OverlappingRecords' warning with the
-- @(earlier, later)@ tuple @(0, 1)@; no other warning applies (the
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
       [OverlappingRecords LabelIPS (ActionIndex 0) (ActionIndex 1)]

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
       [UnsortedRecords LabelIPS (ActionIndex 1)]

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

----------------------------------------------------------------------------
-- Shared assertion
----------------------------------------------------------------------------

-- | Run 'IPS.parseIPS' on the given bytes, assert the parse
-- succeeds, and assert the surfaced warning list equals the
-- expected list exactly. The parsed value is intentionally not
-- inspected — each test's invariant is on the warning channel, and
-- the parse-succeeds gate is enough to confirm the record walk
-- reached the end of the input.
assertParseWarnings :: ByteString -> [SlapWarning] -> Assertion
assertParseWarnings patchBytes expectedWarnings =
  case IPS.parseIPS (PatchFileContents patchBytes) of
    Left slapError ->
      assertFailure ("parse failed: " ++ renderSlapError slapError)
    Right (Parsed _parseResult actualWarnings) ->
      assertEqual "surfaced warnings" expectedWarnings actualWarnings
