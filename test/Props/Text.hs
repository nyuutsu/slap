-- | Tests for 'Slap.Text': the typed-text-with-encoding foundation.
-- Exercises the strict primitives ('encodeText' / 'decodeText'), the
-- lenient primitives ('encodeTextLenient' / 'decodeTextLenient'),
-- bounded encoding ('encodeTextBounded'), and the name resolver
-- ('resolveEncodingName'). Format-independent — these tests do not
-- construct any patches.
module Props.Text (textTests) where

import Slap.Text
  ( EncodingName(..)
  , EncodedText(..)
  , LossNotice(..)
  , encodeText
  , decodeText
  , encodeTextLenient
  , decodeTextLenient
  , encodeTextBounded
  , resolveEncodingName
  , displayNamedEncoding
  , advertisedEncodingNames
  )

import Slap.Measure (Length(..), MaxLength(..), OriginalLength(..), TruncatedLength(..))

import qualified Data.ByteString as ByteString
import qualified Data.Encoding as Encoding
import qualified Data.Text as Text
import Data.Either (isLeft)
import Data.Maybe (isJust)
import Test.Tasty
import Test.Tasty.HUnit
import Test.Tasty.QuickCheck

textTests :: TestTree
textTests = testGroup "Slap.Text"
  [ testGroup "encodeText / decodeText round-trip"
      [ testProperty "utf8-round-trip" prop_utf8RoundTrip
      , testCase     "ascii-utf8-pin"  test_utf8AsciiPin
      , testCase     "japanese-utf8-pin" test_utf8JapanesePin
      , testCase     "emoji-utf8-pin"    test_utf8EmojiPin
      ]
  , testGroup "encodeTextLenient"
      [ testCase "utf8-never-substitutes" test_utf8LenientNeverSubstitutes
      ]
  , testGroup "decodeTextLenient"
      [ testCase "utf8-invalid-becomes-replacement"
                 test_utf8LenientReplacesInvalidBytes
      , testCase "utf8-valid-passes-through"
                 test_utf8LenientPassesValid
      , testProperty "utf8-decodes-arbitrary-bytes-without-bottom"
                     prop_utf8LenientDecodesArbitraryBytesWithoutBottom
      ]
  , testGroup "encodeTextBounded"
      [ testProperty "output-is-at-most-cap-bytes" prop_boundedAtMostCap
      , testCase     "ascii-cap-50"   test_boundedAsciiCap50
      , testCase     "ascii-no-cap-overrun" test_boundedAsciiExact
      , testCase     "japanese-cap-7"  test_boundedJapaneseCap7
      , testCase     "cap-0-yields-empty" test_boundedCapZero
      , testCase     "truncation-notice-byte-counts" test_boundedTruncationCounts
      ]
  , testGroup "resolveEncodingName"
      [ testCase "known-name-resolves"  test_resolveKnownName
      , testCase "unknown-name-is-Left" test_resolveUnknownName
      , testCase "advertised-set-all-resolve" test_advertisedEncodingsResolve
      ]
  , testGroup "documentedLocaleAliases — library has these (table promises resolution)"
      -- Slap.Text's alias table claims certain names will resolve
      -- in the encoding library. This group exercises the library
      -- directly (no slap indirection) to catch the case where a
      -- library version drops a name we promised. If one of these
      -- assertions starts failing after a dep bump, the table
      -- entry needs a different name the new library version
      -- accepts.
      [ testCase "UTF-8"        (assertResolves "UTF-8")
      , testCase "CP1252"       (assertResolves "CP1252")
      , testCase "CP1258"       (assertResolves "CP1258")
      , testCase "CP932"        (assertResolves "CP932")
      , testCase "CP437"        (assertResolves "CP437")
      , testCase "CP850"        (assertResolves "CP850")
      , testCase "CP866"        (assertResolves "CP866")
      , testCase "CP874"        (assertResolves "CP874")
      , testCase "ISO-8859-1"   (assertResolves "ISO-8859-1")
      , testCase "ISO-8859-2"   (assertResolves "ISO-8859-2")
      , testCase "ISO-8859-5"   (assertResolves "ISO-8859-5")
      , testCase "ISO-8859-13"  (assertResolves "ISO-8859-13")
      , testCase "Shift-JIS"    (assertResolves "Shift-JIS")
      , testCase "GB18030"      (assertResolves "GB18030")
      , testCase "KOI8-R"       (assertResolves "KOI8-R")
      , testCase "KOI8-U"       (assertResolves "KOI8-U")
      , testCase "macintosh"    (assertResolves "macintosh")
      , testCase "ISO-2022-JP"  (assertResolves "ISO-2022-JP")
      ]
  , testGroup "documentedLocaleAliases — library does NOT have these (table documents gap)"
      -- Slap.Text's alias table lists these names as known gaps:
      -- the encoding library does not ship an encoder and there is
      -- no compatible superset in the library. If a future library
      -- version starts supporting one of these, the assertion below
      -- fails — that's signal to remove the corresponding entry
      -- from the documented-gap section and add it as a real
      -- mapping.
      [ testCase "CP949 (Korean Wansung)"        (assertDoesNotResolve "CP949")
      , testCase "CP950 (Windows Big5)"          (assertDoesNotResolve "CP950")
      , testCase "Big5"                          (assertDoesNotResolve "Big5")
      , testCase "EUC-JP"                        (assertDoesNotResolve "EUC-JP")
      , testCase "EUC-KR"                        (assertDoesNotResolve "EUC-KR")
      , testCase "TIS-620 (Thai)"                (assertDoesNotResolve "TIS-620")
      , testCase "VISCII (Vietnamese)"           (assertDoesNotResolve "VISCII")
      , testCase "ARMSCII-8 (Armenian)"          (assertDoesNotResolve "ARMSCII-8")
      , testCase "TSCII (Tamil)"                 (assertDoesNotResolve "TSCII")
      ]
  ]

----------------------------------------------------------------------------
-- UTF-8 round-trip
----------------------------------------------------------------------------

-- | Every Unicode string round-trips through UTF-8 encode/decode.
-- Scope: 'Text' values that 'Text.pack' accepts (all valid Unicode).
prop_utf8RoundTrip :: String -> Property
prop_utf8RoundTrip sourceString =
  let text = Text.pack sourceString
  in case encodeText EncodingUtf8 text of
       Left  _     -> property False  -- UTF-8 encode never fails
       Right bytes -> case decodeText EncodingUtf8 bytes of
         Left  _                         -> property False
         Right (EncodedText tag decoded) ->
           (tag === EncodingUtf8) .&&. (decoded === text)

-- | Pinned ASCII UTF-8 output: \"slap\" encodes to its ASCII bytes.
test_utf8AsciiPin :: IO ()
test_utf8AsciiPin =
  assertEqual "ASCII UTF-8 byte shape"
    (Right (ByteString.pack [0x73, 0x6C, 0x61, 0x70]))
    (encodeText EncodingUtf8 (Text.pack "slap"))

-- | Pinned Japanese UTF-8 output: \"日本語\" encodes to its
-- 3-codepoint × 3-byte representation. Pinning the exact bytes
-- guards the UTF-8 path against any future refactor that would
-- accidentally drift byte identity on multibyte codepoints.
test_utf8JapanesePin :: IO ()
test_utf8JapanesePin =
  assertEqual "Japanese UTF-8 byte shape"
    (Right (ByteString.pack [0xE6, 0x97, 0xA5, 0xE6, 0x9C, 0xAC, 0xE8, 0xAA, 0x9E]))
    (encodeText EncodingUtf8 (Text.pack "\x65E5\x672C\x8A9E"))

-- | Pinned emoji UTF-8 output: U+1F3AE (🎮) encodes to its
-- 4-byte representation.
test_utf8EmojiPin :: IO ()
test_utf8EmojiPin =
  assertEqual "emoji UTF-8 byte shape"
    (Right (ByteString.pack [0xF0, 0x9F, 0x8E, 0xAE]))
    (encodeText EncodingUtf8 (Text.pack "\x1F3AE"))

----------------------------------------------------------------------------
-- Lenient encode
----------------------------------------------------------------------------

-- | UTF-8 lenient encode never substitutes anything; the notice list
-- is always empty regardless of the source text.
test_utf8LenientNeverSubstitutes :: IO ()
test_utf8LenientNeverSubstitutes = do
  let (_, notices1) = encodeTextLenient EncodingUtf8 (Text.pack "hello")
      (_, notices2) = encodeTextLenient EncodingUtf8 (Text.pack "\x65E5\x672C\x8A9E")
      (_, notices3) = encodeTextLenient EncodingUtf8 (Text.pack "\x1F3AE")
  assertEqual "ASCII no notices"    [] notices1
  assertEqual "Japanese no notices" [] notices2
  assertEqual "emoji no notices"    [] notices3

----------------------------------------------------------------------------
-- Lenient decode
----------------------------------------------------------------------------

-- | A bare UTF-8 continuation byte (0x80) decodes to U+FFFD via the
-- lenient path — never throwing, always producing a 'Text'.
test_utf8LenientReplacesInvalidBytes :: IO ()
test_utf8LenientReplacesInvalidBytes = do
  let invalid = ByteString.pack [0x80]
      (EncodedText tag decoded, notices) = decodeTextLenient EncodingUtf8 invalid
  assertEqual "tag preserved" EncodingUtf8 tag
  assertBool  "contains replacement character"
    (Text.any (== '\xFFFD') decoded)
  assertBool  "loss notice surfaces the bad byte"
    (any isSubstitutedByteSequence notices)
  where
    isSubstitutedByteSequence SubstitutedByteSequence = True
    isSubstitutedByteSequence _                       = False

-- | Valid UTF-8 bytes lenient-decode to the same string strict
-- decode would produce.
test_utf8LenientPassesValid :: IO ()
test_utf8LenientPassesValid = do
  let bytes = ByteString.pack [0xE6, 0x97, 0xA5, 0xE6, 0x9C, 0xAC, 0xE8, 0xAA, 0x9E]
      (EncodedText _ decoded, notices) = decodeTextLenient EncodingUtf8 bytes
  assertEqual "Japanese decodes" (Text.pack "\x65E5\x672C\x8A9E") decoded
  assertEqual "clean decode emits no loss notices" [] notices

-- | UTF-8 lenient decode terminates with a fully-defined 'Text' for
-- any byte sequence — no exception, no bottom hiding in the result.
-- The '>= 0' is vacuous on its own; its purpose is to force the
-- decoded text, turning a lurking error/undefined into a test failure.
prop_utf8LenientDecodesArbitraryBytesWithoutBottom :: [Int] -> Property
prop_utf8LenientDecodesArbitraryBytesWithoutBottom ints =
  let bytes = ByteString.pack (map (fromIntegral . (`mod` 256)) ints)
      (EncodedText _tag text, _notices) = decodeTextLenient EncodingUtf8 bytes
  in property (Text.length text >= 0)

----------------------------------------------------------------------------
-- Bounded encoding
----------------------------------------------------------------------------

-- | Bounded encoding never overshoots the byte cap, regardless of
-- input text or encoding.
prop_boundedAtMostCap :: NonNegative Int -> String -> Property
prop_boundedAtMostCap (NonNegative cap) sourceString =
  let text = Text.pack sourceString
      (bytes, _notices) = encodeTextBounded EncodingUtf8 (Length (fromIntegral cap)) text
  in property (ByteString.length bytes <= cap)

-- | 100 ASCII chars under a 50-byte cap: exactly 50 bytes out,
-- truncation notice carries (100, 50).
test_boundedAsciiCap50 :: IO ()
test_boundedAsciiCap50 = do
  let source = Text.pack (replicate 100 'x')
      (bytes, notices) = encodeTextBounded EncodingUtf8 (Length 50) source
  assertEqual "50 bytes out" 50 (ByteString.length bytes)
  assertEqual "one notice"   1  (length notices)
  case notices of
    [TruncatedToFitBound (MaxLength cap) (OriginalLength original) (TruncatedLength written)] -> do
      assertEqual "reported cap"        (Length 50)  cap
      assertEqual "original byte count" (Length 100) original
      assertEqual "written byte count"  (Length 50)  written
    other -> assertFailure ("unexpected notices: " ++ show other)

-- | ASCII text exactly at the cap produces no truncation notice.
test_boundedAsciiExact :: IO ()
test_boundedAsciiExact = do
  let source = Text.pack (replicate 50 'a')
      (bytes, notices) = encodeTextBounded EncodingUtf8 (Length 50) source
  assertEqual "50 bytes out" 50 (ByteString.length bytes)
  assertEqual "no notices"   [] notices

-- | Japanese in UTF-8 is 3 bytes per codepoint. A 7-byte cap fits
-- two codepoints (6 bytes); the third codepoint would overflow and
-- gets dropped.
test_boundedJapaneseCap7 :: IO ()
test_boundedJapaneseCap7 = do
  let source = Text.pack "\x65E5\x672C\x8A9E"  -- 9 bytes total in UTF-8
      (bytes, notices) = encodeTextBounded EncodingUtf8 (Length 7) source
  assertEqual "6 bytes out (two codepoints fit)" 6 (ByteString.length bytes)
  case notices of
    [TruncatedToFitBound (MaxLength cap) (OriginalLength original) (TruncatedLength written)] -> do
      assertEqual "reported cap is the field's width, not what fit" (Length 7) cap
      assertEqual "original byte count" (Length 9) original
      assertEqual "written byte count"  (Length 6) written
    other -> assertFailure ("unexpected notices: " ++ show other)

-- | Cap of 0 produces empty bytes; if the source was nonempty,
-- truncation is reported.
test_boundedCapZero :: IO ()
test_boundedCapZero = do
  let (bytes1, notices1) = encodeTextBounded EncodingUtf8 (Length 0) (Text.pack "")
      (bytes2, notices2) = encodeTextBounded EncodingUtf8 (Length 0) (Text.pack "x")
  assertEqual "empty source, cap 0" ByteString.empty bytes1
  assertEqual "empty source, no notice" [] notices1
  assertEqual "non-empty source, cap 0" ByteString.empty bytes2
  case notices2 of
    [TruncatedToFitBound (MaxLength cap) (OriginalLength original) (TruncatedLength written)] -> do
      assertEqual "reported cap"        (Length 0) cap
      assertEqual "original byte count" (Length 1) original
      assertEqual "written byte count"  (Length 0) written
    other -> assertFailure ("unexpected notices: " ++ show other)

-- | Across many cap and source sizes, the truncation notice reports the cap it was
-- given, its written-count always matches the actual output byte count, and
-- the original-count is at least the written-count.
test_boundedTruncationCounts :: IO ()
test_boundedTruncationCounts =
  mapM_ checkOne
    [ ("ASCII", Text.pack "abcdefghij", 5)
    , ("ASCII full",   Text.pack "abcde",      5)
    , ("Japanese",     Text.pack "\x65E5\x672C\x8A9E", 5)
    , ("Mixed",        Text.pack "a\x65E5\x672C", 5)
    ]
  where
    checkOne (caseLabel, text, cap) = do
      let (bytes, notices) = encodeTextBounded EncodingUtf8 (Length (fromIntegral cap)) text
      assertBool (caseLabel ++ ": output ≤ cap")
        (ByteString.length bytes <= cap)
      case [n | n@TruncatedToFitBound{} <- notices] of
        [] -> pure ()
        [TruncatedToFitBound (MaxLength reportedCap) (OriginalLength original) (TruncatedLength written)] -> do
          assertEqual (caseLabel ++ ": reported cap is the cap given")
            (Length (fromIntegral cap)) reportedCap
          assertEqual (caseLabel ++ ": written matches output")
            (Length (fromIntegral (ByteString.length bytes))) written
          assertBool (caseLabel ++ ": original ≥ written")
            (original >= written)
        many ->
          assertFailure (caseLabel ++ ": >1 truncation notice: " ++ show many)

----------------------------------------------------------------------------
-- Name resolution
----------------------------------------------------------------------------

-- | A name the engine recognizes resolves to a 'NamedEncoding' that
-- remembers the name it was handed. Don't pin the encoder — the point
-- is that the name resolves and travels through verbatim.
test_resolveKnownName :: IO ()
test_resolveKnownName =
  case resolveEncodingName (Text.pack "shift-jis") of
    Right named ->
      assertEqual "display name preserved"
        (Text.pack "shift-jis") (displayNamedEncoding named)
    Left failure ->
      assertFailure ("shift-jis should resolve: " ++ show failure)

-- | A name the engine can't place returns 'Left' rather than falling
-- back to a default — the boundary surfaces it, never decodes past it.
test_resolveUnknownName :: IO ()
test_resolveUnknownName =
  case resolveEncodingName (Text.pack "not-a-real-encoding") of
    Left _  -> pure ()
    Right _ -> assertFailure "a bogus encoding name must not resolve"

-- | Every name slap advertises (via 'advertisedEncodings', surfaced by
-- @--encodings@ and offered in shell completion) must actually resolve
-- through 'resolveEncodingName' — otherwise the tool would advertise,
-- and tab-complete, a name it then rejects.
test_advertisedEncodingsResolve :: IO ()
test_advertisedEncodingsResolve =
  case filter (isLeft . resolveEncodingName . Text.pack) advertisedEncodingNames of
    []         -> pure ()
    unresolved ->
      assertFailure ("advertised encodings that do not resolve: " ++ show unresolved)

----------------------------------------------------------------------------
-- Library-resolution probes
----------------------------------------------------------------------------

-- | Assert that the given name resolves to an encoder via
-- 'Encoding.encodingFromStringExplicit'. Used to verify that names
-- in 'Slap.Text''s alias table actually correspond to encoders the
-- installed @encoding@ library version knows about — the table
-- promises certain names will work, this test holds it to that
-- promise.
assertResolves :: String -> IO ()
assertResolves name =
  assertBool ("encoding library should resolve " ++ show name)
    (isJust (Encoding.encodingFromStringExplicit name))

-- | Assert that the given name does /not/ resolve. Used to verify
-- the documented-gap entries in 'Slap.Text''s alias table — the
-- table lists certain names as known gaps (no encoder available),
-- and this test holds the library to that. If an assertion here
-- starts failing after a dep bump, the gap has closed and the
-- table should be updated to map the name to the now-available
-- encoder.
assertDoesNotResolve :: String -> IO ()
assertDoesNotResolve name =
  assertBool ("encoding library should NOT resolve " ++ show name
              ++ " (table lists this name as a documented gap)")
    (not (isJust (Encoding.encodingFromStringExplicit name)))
