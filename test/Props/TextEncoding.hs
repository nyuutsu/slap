-- | Tests for 'Slap.TextEncoding': UTF-8 and locale encoding, byte-level
-- truncation, bounded-width field encoding. Format-independent — these
-- tests do not construct any patches.
module Props.TextEncoding (textEncodingTests) where

import Slap.TextEncoding (truncateUtf8, isValidUtf8,
                          encodeUtf8Field, decodeUtf8Field,
                          encodeLocaleField, decodeLocaleField,
                          encodeBoundedUtf8, encodeBoundedLocale,
                          truncateLocale, BoundedResult(..))

import qualified Data.ByteString as ByteString
import Data.Maybe (isJust)
import qualified Data.Text as Text
import qualified Data.Text.Encoding as Text
import Test.Tasty
import Test.Tasty.HUnit
import Test.Tasty.QuickCheck

textEncodingTests :: TestTree
textEncodingTests = testGroup "TextEncoding"
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
  , testGroup "encodeUtf8Field byte-shape"
      [ testCase "ASCII"            test_encodeUtf8FieldAscii
      , testCase "Japanese 日本語"   test_encodeUtf8FieldJapanese
      , testCase "emoji 🎮"          test_encodeUtf8FieldEmoji
      ]
  , testGroup "decodeLocaleField is lenient"
      [ testCase "invalid byte sequence does not throw"
          test_decodeLocaleFieldInvalid
      , testCase "all-ASCII bytes decode identically regardless of locale rule"
          test_decodeLocaleFieldAscii
      ]
  ]

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
  let gamepadBytes = encodeUtf8Field "\x1F3AE"     -- F0 9F 8E AE = 4 bytes
      prefixedBytes = encodeUtf8Field "a\x1F3AE"   -- 61 F0 9F 8E AE = 5 bytes
  assertEqual "budget 3 -> empty"   ByteString.empty (truncateUtf8 3 gamepadBytes)
  assertEqual "budget 4 -> gamepad" gamepadBytes (truncateUtf8 4 gamepadBytes)
  assertEqual "a+ budget 4 -> a"    (encodeUtf8Field "a") (truncateUtf8 4 prefixedBytes)
  assertEqual "a+ budget 5 -> full" prefixedBytes (truncateUtf8 5 prefixedBytes)

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
  let localeEncoded = encodeLocaleField "\xE9"  -- "é"
      truncatedOneByte = truncateLocale 1 localeEncoded
  assertEqual "truncateLocale is byte-level" 1 (ByteString.length truncatedOneByte)

-- isValidUtf8 unit cases

test_isValidUtf8Ascii :: IO ()
test_isValidUtf8Ascii =
  assertBool "valid ASCII" (isValidUtf8 (encodeUtf8Field "hello"))

test_isValidUtf8Multibyte :: IO ()
test_isValidUtf8Multibyte =
  assertBool "valid multibyte" (isValidUtf8 (encodeUtf8Field "Andr\xE9"))

test_isValidUtf8Truncated :: IO ()
test_isValidUtf8Truncated =
  assertBool "truncated multibyte is invalid"
    (not (isValidUtf8 (ByteString.take 1 (encodeUtf8Field "\xE9"))))

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

-- encodeUtf8Field byte-shape pins
--
-- 'encodeUtf8Field' is the wire encoder NINJA2 mode-1 fields (and
-- every other UTF-8 field in slap) go through. The point of mode 1
-- is that its bytes are independent of the encoder process's locale
-- — pinning them to fixed sequences here gives a regression net for
-- any future refactor that accidentally routes mode-1 emission
-- through a locale-aware path.

test_encodeUtf8FieldAscii :: IO ()
test_encodeUtf8FieldAscii =
  assertEqual "ASCII roundtrips byte-for-byte"
    (ByteString.pack [0x73, 0x6c, 0x61, 0x70])
    (encodeUtf8Field "slap")

test_encodeUtf8FieldJapanese :: IO ()
test_encodeUtf8FieldJapanese =
  -- 日 = U+65E5 = e6 97 a5
  -- 本 = U+672C = e6 9c ac
  -- 語 = U+8A9E = e8 aa 9e
  assertEqual "Japanese encodes as fixed UTF-8"
    (ByteString.pack [0xe6, 0x97, 0xa5, 0xe6, 0x9c, 0xac, 0xe8, 0xaa, 0x9e])
    (encodeUtf8Field "\x65E5\x672C\x8A9E")

test_encodeUtf8FieldEmoji :: IO ()
test_encodeUtf8FieldEmoji =
  -- 🎮 = U+1F3AE = f0 9f 8e ae
  assertEqual "supplementary plane encodes as 4-byte UTF-8"
    (ByteString.pack [0xf0, 0x9f, 0x8e, 0xae])
    (encodeUtf8Field "\x1F3AE")

-- decodeLocaleField lenience
--
-- Before the @\/\/TRANSLIT@ fix, 'decodeLocaleField' threw an
-- IOException whenever the input bytes weren't well-formed in the
-- process's locale encoding — which is the everyday case for a
-- foreign-locale NINJA2 mode-0 metadata field viewed under a
-- mismatched reader. The new behavior is to substitute U+FFFD for
-- unrepresentable input, matching every other modern Unicode
-- pipeline. These tests pin the new behavior so a future regression
-- to strict decoding fires loudly.
--
-- The exact mojibake we get back depends on the test runner's
-- locale, so the assertions check shape (no exception, output
-- length is reasonable) rather than exact characters.

test_decodeLocaleFieldInvalid :: IO ()
test_decodeLocaleFieldInvalid = do
  -- A byte sequence that is invalid in basically every encoding:
  -- bare 0xFE, bare 0xFF (forbidden in UTF-8; not standard 2-byte
  -- lead in EUC-JP either) followed by a few stray continuation
  -- bytes. The strict decoder used to throw on this; the lenient
  -- one returns *some* String — we just assert it terminated.
  let invalidBytes = ByteString.pack [0xfe, 0xff, 0x80, 0x80]
      result = decodeLocaleField invalidBytes
  assertBool "decode returns a finite, non-bottom String"
    (length result >= 0)

test_decodeLocaleFieldAscii :: IO ()
test_decodeLocaleFieldAscii = do
  -- Pure-ASCII bytes are valid in every reasonable locale codec, so
  -- they should decode to the same characters whether the codec is
  -- UTF-8, EUC-JP, ISO-8859-1, etc. This test pins the
  -- lenient-decode path's identity behavior on the ASCII subset and
  -- doubles as proof that the //TRANSLIT routing didn't break the
  -- happy path.
  let asciiBytes = ByteString.pack [0x73, 0x6c, 0x61, 0x70]
  assertEqual "ASCII bytes decode to ASCII chars"
    "slap" (decodeLocaleField asciiBytes)
