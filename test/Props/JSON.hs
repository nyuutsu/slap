{-# LANGUAGE OverloadedStrings #-}
-- | Tests for slap's EBP-metadata JSON layer. The bulk exercises
-- 'Slap.JSON', the aeson-backed parser: things the previous
-- hand-rolled scanner got wrong (escaped Unicode, nested objects,
-- non-string siblings, malformed input), plus the case-insensitive
-- lookup that real-world EBP producers depend on. A final group
-- covers the build/parse round-trip through
-- 'Slap.IPS.Create.buildEBPMetadataJSON' — the other half of slap's
-- JSON surface — with non-ASCII content, since that's where the
-- type-level UTF-8 contract earns its keep.
module Props.JSON (jsonTests) where

import Slap.JSON
  ( EBPMetadataView(..)
  , parseEBPMetadata
  )
import qualified Slap.IPS.Create as IPS
import Slap.IPS.Types (EBPMetadataFields(..))
import Slap.Text (EncodedText(..), EncodingName(..))

import Data.ByteString (ByteString)
import qualified Data.Text as Text
import Test.Tasty
import Test.Tasty.HUnit

-- | Wrap a literal for an EBP metadata field. JSON values come out
-- of @aeson@ tagged 'EncodingUtf8', so test expectations carry the
-- same tag — the helper keeps the test bodies focused on the value
-- and not on the wrapping ceremony.
asUtf8 :: String -> EncodedText
asUtf8 = EncodedText EncodingUtf8 . Text.pack

jsonTests :: TestTree
jsonTests = testGroup "Slap.JSON"
  [ testGroup "EBPatcher-style (lowercase keys)"
      [ testCase "all four fields extracted"
          test_lowercaseAllFour
      , testCase "empty-string values preserved as Just \"\""
          test_lowercaseEmptyStringPreserved
      ]
  , testGroup "RomPatcher.js-style (capitalised keys)"
      [ testCase "Title/Author/Description match lowercase lookup"
          test_capitalisedKeysMatched
      , testCase "missing fields tolerated (writer skips empties)"
          test_capitalisedSomeFieldsMissing
      ]
  , testGroup "Spec corners the scanner mishandled"
      [ testCase "escaped Unicode \\u00e9 decodes to é"
          test_escapedUnicode
      , testCase "nested object value does not abort top-level scan"
          test_nestedObjectSibling
      , testCase "numeric / boolean / null siblings are skipped, not crashed on"
          test_nonStringSiblings
      ]
  , testGroup "Honest failure on bad input"
      [ testCase "malformed JSON returns Nothing"
          test_malformedReturnsNothing
      , testCase "JSON array (non-object root) returns Nothing"
          test_arrayRootReturnsNothing
      , testCase "empty input returns Nothing"
          test_emptyReturnsNothing
      ]
  , testGroup "Build/parse round-trip"
      [ testCase "non-ASCII title survives buildEBPMetadataJSON \\u2192 parseEBPMetadata"
          test_nonAsciiRoundTrip
      ]
  ]

----------------------------------------------------------------------------
-- EBPatcher-style
----------------------------------------------------------------------------

test_lowercaseAllFour :: Assertion
test_lowercaseAllFour =
  parseEBPMetadata
    "{\"patcher\":\"slap\",\"title\":\"FE6\",\"author\":\"nyuu\",\"description\":\"hi\"}"
    @?= Just EBPMetadataView
          { ebpMetadataViewTitle       = Just (asUtf8 "FE6")
          , ebpMetadataViewAuthor      = Just (asUtf8 "nyuu")
          , ebpMetadataViewDescription = Just (asUtf8 "hi")
          , ebpMetadataViewPatcher     = Just (asUtf8 "slap")
          }

test_lowercaseEmptyStringPreserved :: Assertion
test_lowercaseEmptyStringPreserved =
  -- This is the shape the dm4y fixture in test/data/ uses: a patch
  -- that slap itself produced with no metadata, every field empty.
  parseEBPMetadata
    "{\"patcher\":\"slap\",\"title\":\"\",\"author\":\"\",\"description\":\"\"}"
    @?= Just EBPMetadataView
          { ebpMetadataViewTitle       = Just (asUtf8 "")
          , ebpMetadataViewAuthor      = Just (asUtf8 "")
          , ebpMetadataViewDescription = Just (asUtf8 "")
          , ebpMetadataViewPatcher     = Just (asUtf8 "slap")
          }

----------------------------------------------------------------------------
-- RomPatcher.js-style
----------------------------------------------------------------------------

test_capitalisedKeysMatched :: Assertion
test_capitalisedKeysMatched =
  parseEBPMetadata
    "{\"Title\":\"FE6\",\"Author\":\"nyuu\",\"Description\":\"hi\",\"patcher\":\"romp.js\"}"
    @?= Just EBPMetadataView
          { ebpMetadataViewTitle       = Just (asUtf8 "FE6")
          , ebpMetadataViewAuthor      = Just (asUtf8 "nyuu")
          , ebpMetadataViewDescription = Just (asUtf8 "hi")
          , ebpMetadataViewPatcher     = Just (asUtf8 "romp.js")
          }

test_capitalisedSomeFieldsMissing :: Assertion
test_capitalisedSomeFieldsMissing =
  -- RomPatcher.js's writer skips empty fields entirely. A patch
  -- where the user left author and description blank arrives with
  -- only Title and patcher present; the missing fields land as
  -- Nothing rather than as some sentinel "" or a parse failure.
  parseEBPMetadata
    "{\"Title\":\"FE6\",\"patcher\":\"romp.js\"}"
    @?= Just EBPMetadataView
          { ebpMetadataViewTitle       = Just (asUtf8 "FE6")
          , ebpMetadataViewAuthor      = Nothing
          , ebpMetadataViewDescription = Nothing
          , ebpMetadataViewPatcher     = Just (asUtf8 "romp.js")
          }

----------------------------------------------------------------------------
-- Spec corners the scanner mishandled
----------------------------------------------------------------------------

test_escapedUnicode :: Assertion
test_escapedUnicode =
  -- The previous scanner stripped the backslash and emitted the
  -- literal four characters @u00e9@. aeson decodes the escape
  -- sequence to U+00E9 (é), which is what the file actually means.
  let blob :: ByteString
      blob = "{\"title\":\"caf\\u00e9\"}"
  in case parseEBPMetadata blob of
       Just view -> ebpMetadataViewTitle view @?= Just (asUtf8 "caf\233")
       Nothing   -> assertFailure "expected valid JSON to parse"

test_nestedObjectSibling :: Assertion
test_nestedObjectSibling =
  -- The previous scanner gave up the moment it saw a nested @{@,
  -- losing every field that appeared after one. aeson sees through
  -- the nesting and the top-level title is still extractable.
  let blob :: ByteString
      blob = "{\"extra\":{\"deep\":\"value\"},\"title\":\"FE6\"}"
  in case parseEBPMetadata blob of
       Just view -> ebpMetadataViewTitle view @?= Just (asUtf8 "FE6")
       Nothing   -> assertFailure "expected valid JSON to parse"

test_nonStringSiblings :: Assertion
test_nonStringSiblings =
  -- Numbers, booleans, nulls sitting at the top level alongside the
  -- four EBP fields. The previous scanner skipped them quietly;
  -- aeson parses them honestly and we then drop them at extraction
  -- because they aren't strings. The four EBP fields still land.
  let blob :: ByteString
      blob = "{\"version\":2,\"verified\":true,\"checksum\":null,\
             \\"title\":\"FE6\",\"author\":\"nyuu\"}"
  in case parseEBPMetadata blob of
       Just view -> do
         ebpMetadataViewTitle  view @?= Just (asUtf8 "FE6")
         ebpMetadataViewAuthor view @?= Just (asUtf8 "nyuu")
       Nothing -> assertFailure "expected valid JSON to parse"

----------------------------------------------------------------------------
-- Honest failure on bad input
----------------------------------------------------------------------------

test_malformedReturnsNothing :: Assertion
test_malformedReturnsNothing =
  parseEBPMetadata "{ not actually json" @?= Nothing

test_arrayRootReturnsNothing :: Assertion
test_arrayRootReturnsNothing =
  -- Valid JSON, but not an object. There's no EBP metadata to
  -- extract here so the honest answer is Nothing.
  parseEBPMetadata "[\"title\",\"FE6\"]" @?= Nothing

test_emptyReturnsNothing :: Assertion
test_emptyReturnsNothing =
  parseEBPMetadata "" @?= Nothing

----------------------------------------------------------------------------
-- Build/parse round-trip
----------------------------------------------------------------------------

test_nonAsciiRoundTrip :: Assertion
test_nonAsciiRoundTrip =
  -- A Japanese title and a Cyrillic author and description. The
  -- builder emits via aeson, which escapes nothing that isn't
  -- mandated by RFC 8259 — non-ASCII codepoints land verbatim as
  -- UTF-8 in the output bytes. The parser pulls them back as
  -- EncodingUtf8-tagged 'EncodedText'. Equality on EncodedText then
  -- includes tag equality, which catches a regression where the
  -- builder lost provenance (e.g. by re-encoding via latin1).
  let fields = EBPMetadataFields
        { ebpMetadataTitle       = asUtf8 "\12486\12473\12488\12497\12483\12481"
        , ebpMetadataAuthor      = asUtf8 "\1085\1102\1091"
        , ebpMetadataDescription = asUtf8 "\26085\26412\35486\12486\12473\12488"
        }
      blob = IPS.buildEBPMetadataJSON fields
  in case parseEBPMetadata blob of
       Nothing   -> assertFailure "buildEBPMetadataJSON produced JSON parseEBPMetadata could not read"
       Just view -> do
         ebpMetadataViewTitle       view @?= Just (ebpMetadataTitle       fields)
         ebpMetadataViewAuthor      view @?= Just (ebpMetadataAuthor      fields)
         ebpMetadataViewDescription view @?= Just (ebpMetadataDescription fields)
         ebpMetadataViewPatcher     view @?= Just (asUtf8 "slap")
