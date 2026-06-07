-- | Properties for the BPS metadata glance: the pure classifier
-- 'Slap.BPS.Types.classifyBPSMetadata' (is the blob absent, valid
-- UTF-8, or not UTF-8 at all), the safe-display primitive
-- 'Slap.Display.Primitives.renderEscapingNonPrintable' (printable
-- codepoints pass, everything else escapes to a visible token), and
-- the remark projection 'Slap.BPS.Describe.bpsMetadataNotes' (a
-- note for the two divergent shapes, silence for the spec-recommended
-- text). The BPS spec recommends UTF-8 XML in the metadata field but
-- permits "literally anything", so these are the three honest answers
-- and the remark that names the oddity.
module Props.BPSMetadata (bpsMetadataTests) where

import Slap.BPS.Types (BPSPatch(..), BPSMetadata(..),
                       BPSMetadataShape(..), classifyBPSMetadata)
import Slap.BPS.Describe (bpsMetadataNotes)
import Slap.Display.Primitives (renderEscapingNonPrintable)
import Slap.Status (SlapAdvisory(..), BPSMetadataDivergence(..))
import Slap.FormatLabel (FormatLabel(LabelBPS))
import Slap.Checksum (CRC32(..))
import Slap.Measure (FileSize(..), Length(..))

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
  [ testGroup "classifyBPSMetadata"
      [ testCase "empty-blob-is-absent" test_classifyEmpty
      , testCase "ascii-text-is-utf8"   test_classifyAscii
      , testCase "multibyte-text-is-utf8" test_classifyMultibyte
      , testCase "embedded-nul-is-still-utf8" test_classifyControlIsUTF8
      , testCase "lone-continuation-byte-is-not-utf8" test_classifyLoneContinuation
      , testCase "stray-high-byte-is-not-utf8" test_classifyHighByte
      , testProperty "classification-does-not-bottom-on-arbitrary-bytes"
          prop_classifyDoesNotBottomOnArbitraryBytes
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
      , testCase "invalid-utf8-notes-not-utf8"   test_noteInvalidUTF8
      ]
  ]

----------------------------------------------------------------------------
-- Helpers
----------------------------------------------------------------------------

-- | A 'BPSMetadata' from a Haskell 'String', encoded UTF-8.
utf8Meta :: String -> BPSMetadata
utf8Meta = BPSMetadata . TextEncoding.encodeUtf8 . Text.pack

-- | A 'BPSPatch' carrying the given metadata bytes and nothing else of
-- interest — empty action stream, zero sizes and CRCs. Enough to
-- exercise 'bpsMetadataNotes', which reads only the metadata field.
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

----------------------------------------------------------------------------
-- classifyBPSMetadata
----------------------------------------------------------------------------

test_classifyEmpty :: IO ()
test_classifyEmpty =
  assertEqual "empty blob" MetadataAbsent
    (classifyBPSMetadata (BPSMetadata ByteString.empty))

test_classifyAscii :: IO ()
test_classifyAscii =
  assertEqual "ascii text" (MetadataUTF8Text (Text.pack "hello"))
    (classifyBPSMetadata (utf8Meta "hello"))

test_classifyMultibyte :: IO ()
test_classifyMultibyte =
  assertEqual "japanese text" (MetadataUTF8Text (Text.pack "\x65E5\x672C\x8A9E"))
    (classifyBPSMetadata (utf8Meta "\x65E5\x672C\x8A9E"))

-- | A NUL byte is valid UTF-8, so a blob carrying one classifies as
-- 'MetadataUTF8Text' — the classifier answers only "is this UTF-8",
-- not "is this text"; the text-versus-binary judgment is
-- 'bpsMetadataNotes''s job.
test_classifyControlIsUTF8 :: IO ()
test_classifyControlIsUTF8 =
  assertEqual "embedded NUL is valid UTF-8"
    (MetadataUTF8Text (Text.pack "a\NULb"))
    (classifyBPSMetadata (BPSMetadata (ByteString.pack [0x61, 0x00, 0x62])))

test_classifyLoneContinuation :: IO ()
test_classifyLoneContinuation =
  assertEqual "lone continuation byte" MetadataNotUTF8
    (classifyBPSMetadata (BPSMetadata (ByteString.pack [0x80])))

test_classifyHighByte :: IO ()
test_classifyHighByte =
  assertEqual "stray 0xFF" MetadataNotUTF8
    (classifyBPSMetadata (BPSMetadata (ByteString.pack [0xFF])))

-- | Classification terminates with a fully-defined result for any byte
-- sequence: every input lands in one of the three arms with no
-- exception and no bottom in the carried text. The 'True' arms and the
-- '>= 0' are vacuous as assertions; their job is to force the result
-- so a lurking error/undefined surfaces as a failure.
prop_classifyDoesNotBottomOnArbitraryBytes :: [Int] -> Bool
prop_classifyDoesNotBottomOnArbitraryBytes ints =
  let bytes = ByteString.pack (map (fromIntegral . (`mod` 256)) ints)
  in case classifyBPSMetadata (BPSMetadata bytes) of
       MetadataAbsent       -> True
       MetadataUTF8Text txt -> Text.length txt >= 0
       MetadataNotUTF8      -> True

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
  assertEqual "absent metadata raises no note" []
    (bpsMetadataNotes (bpsPatchWithMetadata ByteString.empty))

test_notePlainSilent :: IO ()
test_notePlainSilent =
  assertEqual "plain UTF-8 text raises no note" []
    (bpsMetadataNotes (bpsPatchWithMetadata
       (TextEncoding.encodeUtf8 (Text.pack "Cozy Sunday patch"))))

-- | A pretty-printed XML blob is full of newlines and tabs, which are
-- control characters but also whitespace. The note keys off
-- non-whitespace controls precisely so the spec-recommended multi-line
-- XML — the form the field is meant to hold — stays silent; this pins
-- that the whitespace controls do not trip it.
test_noteMultilineXMLSilent :: IO ()
test_noteMultilineXMLSilent =
  assertEqual "multi-line XML (newlines, tabs) raises no note" []
    (bpsMetadataNotes (bpsPatchWithMetadata
       (TextEncoding.encodeUtf8 (Text.pack
          "<?xml version=\"1.0\"?>\n<patch>\n\t<name>x</name>\n</patch>\n"))))

test_noteEmbeddedNul :: IO ()
test_noteEmbeddedNul =
  assertEqual "valid UTF-8 with an embedded NUL notes a non-text control"
    [BPSMetadataNonConformant LabelBPS MetadataIsValidUTF8ButNonText (Length 9)]
    (bpsMetadataNotes (bpsPatchWithMetadata
       (TextEncoding.encodeUtf8 (Text.pack "text\NULmore"))))

test_noteInvalidUTF8 :: IO ()
test_noteInvalidUTF8 =
  assertEqual "non-UTF-8 bytes note the not-UTF-8 divergence"
    [BPSMetadataNonConformant LabelBPS MetadataIsNotUTF8 (Length 3)]
    (bpsMetadataNotes (bpsPatchWithMetadata (ByteString.pack [0x80, 0xFE, 0xFF])))
