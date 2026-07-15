-- | Properties for the BPS metadata glance: the content 'Slap.BPS.Describe.bpsEmbeddedContent' shows for the blob,
-- the safe-display escape 'Slap.Display.Primitives.renderEscapingNonPrintable',
-- and the conformance remark 'Slap.BPS.Describe.bpsMetadataNotes' — measured against UTF-8, which the spec recommends but does not require.
-- So the content is always shown, and only the oddity remarked.
module Props.BPSMetadata (bpsMetadataTests) where

import Slap.BPS.Types (BPSPatch(..), BPSMetadata(..))
import Slap.BPS.Describe (bpsEmbeddedContent, bpsMetadataNotes)
import Slap.Display.EmbeddedContent (EmbeddedContent(..), EmbeddedField(..), EmbeddedWireBytes(..))
import Slap.Display.Primitives (renderEscapingNonPrintable)
import Slap.Text (EncodingName(EncodingUtf8), encodedTextContent)
import Slap.Status (SlapAdvisory(..), BPSMetadataDivergence(..))
import Slap.FormatLabel (FormatLabel(LabelBPS))
import Slap.Checksum (CRC32(..))
import Slap.Measure (FileSize(..), Length(..), SubstitutionCount(..))

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.Char (isPrint)
import qualified Data.Text as Text
import qualified Data.Text.Encoding as TextEncoding
import qualified Data.Vector as Vector
import Test.Tasty
import Test.Tasty.HUnit
import Test.Tasty.QuickCheck

bpsMetadataTests :: TestTree
bpsMetadataTests = testGroup "BPS metadata"
  [ testGroup "bpsEmbeddedContent"
      [ testCase "empty-blob-is-absent"          test_fieldEmpty
      , testCase "ascii-reads-clean"             test_fieldAscii
      , testCase "multibyte-reads-clean"         test_fieldMultibyte
      , testCase "non-utf8-substitutes-but-keeps-bytes" test_fieldNonUtf8
      , testProperty "reading-does-not-bottom-on-arbitrary-bytes"
          prop_fieldDoesNotBottomOnArbitraryBytes
      ]
  , testGroup "renderEscapingNonPrintable"
      [ testCase "printable-ascii-passes-through" test_renderAsciiPasses
      , testCase "emoji-passes-through"           test_renderEmojiPasses
      , testCase "newline-escapes"                test_renderNewline
      , testCase "nul-escapes"                    test_renderNul
      , testCase "esc-escapes"                    test_renderEsc
      , testCase "bidi-override-escapes"          test_renderBidiOverride
      , testProperty "output-is-all-printable"    prop_renderAllPrintable
      , testProperty "identity-on-printable-text" prop_renderIdentityOnPrintable
      ]
  , testGroup "bpsMetadataNotes"
      [ testCase "absent-field-is-silent"        test_noteAbsentSilent
      , testCase "plain-text-is-silent"          test_notePlainSilent
      , testCase "multiline-xml-is-silent"       test_noteMultilineXMLSilent
      , testCase "embedded-nul-notes-non-text"   test_noteEmbeddedNul
      , testCase "non-utf8-notes-the-count"      test_noteNonUtf8Count
      ]
  ]

----------------------------------------------------------------------------
-- Helpers
----------------------------------------------------------------------------

-- | A 'BPSMetadata' from a Haskell 'String', encoded UTF-8.
utf8Meta :: String -> BPSMetadata
utf8Meta = BPSMetadata . TextEncoding.encodeUtf8 . Text.pack

-- | A 'BPSPatch' carrying the given metadata bytes and nothing else of interest —
-- empty action stream, zero sizes and CRCs. Enough to exercise the metadata field and its remark,
-- which read only that field.
bpsPatchWithMetadata :: ByteString -> BPSPatch
bpsPatchWithMetadata metadataBytes = BPSPatch
  { bpsSourceSize = FileSize 0
  , bpsTargetSize = FileSize 0
  , bpsMetadata   = BPSMetadata metadataBytes
  , bpsActions    = Vector.empty
  , bpsSourceCRC  = CRC32 0
  , bpsTargetCRC  = CRC32 0
  , bpsPatchCRC   = CRC32 0
  }

-- | The embedded field slap shows for a blob, read under UTF-8.
fieldOf :: ByteString -> EmbeddedField
fieldOf bytes = case bpsEmbeddedContent EncodingUtf8 (bpsPatchWithMetadata bytes) of
  [content] -> embeddedField content
  other     -> error ("expected one embedded row, got " ++ show other)

-- | The remark the blob earns, measured against UTF-8.
notesOf :: ByteString -> [SlapAdvisory]
notesOf bytes = bpsMetadataNotes LabelBPS (bpsPatchWithMetadata bytes)

----------------------------------------------------------------------------
-- bpsEmbeddedContent
----------------------------------------------------------------------------

test_fieldEmpty :: IO ()
test_fieldEmpty =
  assertEqual "empty blob is absent" FieldAbsent (fieldOf ByteString.empty)

test_fieldAscii :: IO ()
test_fieldAscii = case fieldOf (TextEncoding.encodeUtf8 (Text.pack "hello")) of
  FieldContent _ reading (SubstitutionCount substituted) -> do
    assertEqual "reading is the text" (Text.pack "hello") (encodedTextContent reading)
    assertEqual "nothing substituted" 0 substituted
  other -> assertFailure ("expected FieldContent, got " ++ show other)

test_fieldMultibyte :: IO ()
test_fieldMultibyte = case fieldOf (unBPSMetadata (utf8Meta "\x65E5\x672C\x8A9E")) of
  FieldContent _ reading (SubstitutionCount substituted) -> do
    assertEqual "reading is the multibyte text" (Text.pack "\x65E5\x672C\x8A9E") (encodedTextContent reading)
    assertEqual "nothing substituted" 0 substituted
  other -> assertFailure ("expected FieldContent, got " ++ show other)

-- | Bytes that are not UTF-8 are shown, not hidden: the reading substitutes U+FFFD and the count says how many,
-- but the wire bytes ride through byte-exact for extraction.
test_fieldNonUtf8 :: IO ()
test_fieldNonUtf8 = case fieldOf (ByteString.pack [0x80, 0xFE, 0xFF]) of
  FieldContent (EmbeddedWireBytes bytes) _ (SubstitutionCount substituted) -> do
    assertBool "the reading substituted" (substituted > 0)
    assertEqual "the wire bytes are kept" (ByteString.pack [0x80, 0xFE, 0xFF]) bytes
  other -> assertFailure ("expected FieldContent, got " ++ show other)

-- | The decode terminates with a fully-defined field for any byte sequence — no exception, no bottom in the carried reading.
-- The arms are vacuous as assertions; their job is to force the result so a lurking bottom fails.
prop_fieldDoesNotBottomOnArbitraryBytes :: [Int] -> Bool
prop_fieldDoesNotBottomOnArbitraryBytes ints =
  let bytes = ByteString.pack (map (fromIntegral . (`mod` 256)) ints)
  in case fieldOf bytes of
       FieldAbsent                          -> ByteString.null bytes
       FieldEmpty                           -> True
       FieldContent _ reading (SubstitutionCount n) -> Text.length (encodedTextContent reading) >= 0 && n >= 0

----------------------------------------------------------------------------
-- renderEscapingNonPrintable
----------------------------------------------------------------------------

test_renderAsciiPasses :: IO ()
test_renderAsciiPasses =
  assertEqual "printable ascii unchanged"
    (Text.pack "<?xml version=\"1.0\"?>")
    (renderEscapingNonPrintable (Text.pack "<?xml version=\"1.0\"?>"))

test_renderEmojiPasses :: IO ()
test_renderEmojiPasses =
  assertEqual "emoji is printable, passes through"
    (Text.pack "\x1F3AE")
    (renderEscapingNonPrintable (Text.pack "\x1F3AE"))

test_renderNewline :: IO ()
test_renderNewline =
  assertEqual "newline escapes to uppercase token"
    (Text.pack "a<U+000A>b")
    (renderEscapingNonPrintable (Text.pack "a\nb"))

test_renderNul :: IO ()
test_renderNul =
  assertEqual "NUL escapes"
    (Text.pack "<U+0000>")
    (renderEscapingNonPrintable (Text.pack "\NUL"))

test_renderEsc :: IO ()
test_renderEsc =
  assertEqual "ESC escapes (the terminal-injection introducer)"
    (Text.pack "<U+001B>")
    (renderEscapingNonPrintable (Text.pack "\ESC"))

test_renderBidiOverride :: IO ()
test_renderBidiOverride =
  assertEqual "bidi override (U+202E) escapes, not passed raw"
    (Text.pack "<U+202E>")
    (renderEscapingNonPrintable (Text.pack "\x202E"))

-- | The load-bearing safety invariant: the rendered output is entirely
-- printable. Every codepoint in the result is either a passed-through
-- printable input character or part of an all-ASCII @\<U+XXXX\>@ token,
-- so nothing a terminal would act on survives.
prop_renderAllPrintable :: String -> Bool
prop_renderAllPrintable source =
  Text.all isPrint (renderEscapingNonPrintable (Text.pack source))

-- | Text that is already entirely printable passes through untouched.
prop_renderIdentityOnPrintable :: String -> Property
prop_renderIdentityOnPrintable source =
  let printableOnly = Text.filter isPrint (Text.pack source)
  in renderEscapingNonPrintable printableOnly === printableOnly

----------------------------------------------------------------------------
-- bpsMetadataNotes
----------------------------------------------------------------------------

test_noteAbsentSilent :: IO ()
test_noteAbsentSilent =
  assertEqual "absent metadata raises no note" [] (notesOf ByteString.empty)

test_notePlainSilent :: IO ()
test_notePlainSilent =
  assertEqual "plain UTF-8 text raises no note" []
    (notesOf (TextEncoding.encodeUtf8 (Text.pack "Cozy Sunday patch")))

-- | A pretty-printed XML blob is full of newlines and tabs, which are
-- control characters but also whitespace. The note keys off
-- non-whitespace controls precisely so the spec-recommended multi-line
-- XML — the form the field is meant to hold — stays silent; this pins
-- that the whitespace controls do not trip it.
test_noteMultilineXMLSilent :: IO ()
test_noteMultilineXMLSilent =
  assertEqual "multi-line XML (newlines, tabs) raises no note" []
    (notesOf (TextEncoding.encodeUtf8 (Text.pack
       "<?xml version=\"1.0\"?>\n<patch>\n\t<name>x</name>\n</patch>\n")))

test_noteEmbeddedNul :: IO ()
test_noteEmbeddedNul =
  assertEqual "a clean reading with an embedded NUL notes a non-text control"
    [BPSMetadataNonConformant LabelBPS MetadataDecodedButNonText (Length 9)]
    (notesOf (TextEncoding.encodeUtf8 (Text.pack "text\NULmore")))

test_noteNonUtf8Count :: IO ()
test_noteNonUtf8Count =
  assertEqual "non-UTF-8 bytes note the substitution count"
    [BPSMetadataNonConformant LabelBPS (MetadataBytesSubstituted (SubstitutionCount 3)) (Length 3)]
    (notesOf (ByteString.pack [0x80, 0xFE, 0xFF]))
