{-# LANGUAGE OverloadedStrings #-}
-- | Tests for slap's EBP-metadata JSON layer. The bulk exercises
-- 'Slap.JSON.parseEBPMetadata', the aeson-backed parser: things the
-- previous hand-rolled scanner got wrong (escaped Unicode, nested
-- objects, non-string siblings, malformed input), plus the
-- case-insensitive lookup that real-world EBP producers depend on.
-- A final group covers the build/parse round-trip through
-- 'Slap.IPS.Create.buildEBPMetadataJSON' — the other half of slap's
-- JSON surface — with non-ASCII content, since that's where the
-- type-level UTF-8 contract earns its keep.
--
-- Under the parse-finishes-its-job restructure, 'parseEBPMetadata'
-- returns @(EBPMetadata, [SlapAdvisory])@: the four-field record
-- on the value side, the advisory channel on the diagnostic side.
-- A malformed input surfaces the all-'Nothing' record paired with
-- @['EBPMetadataMalformed' 'LabelEBP']@.
module Props.JSON (jsonTests) where

import Slap.JSON (parseEBPMetadata)
import qualified Slap.IPS.Create as IPS
import Slap.IPS.Types (EBPMetadata(..), emptyEBPMetadata)
import Slap.FormatLabel (FormatLabel(..))
import Slap.Status (SlapAdvisory(..))
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
      [ testCase "malformed JSON yields all-Nothing + EBPMetadataMalformed"
          test_malformedReturnsAdvisory
      , testCase "JSON array (non-object root) yields all-Nothing + EBPMetadataMalformed"
          test_arrayRootReturnsAdvisory
      , testCase "empty input yields all-Nothing + EBPMetadataMalformed"
          test_emptyReturnsAdvisory
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
    @?= ( EBPMetadata
            { ebpMetadataTitle       = Just (asUtf8 "FE6")
            , ebpMetadataAuthor      = Just (asUtf8 "nyuu")
            , ebpMetadataDescription = Just (asUtf8 "hi")
            , ebpMetadataPatcher     = Just (asUtf8 "slap")
            }
        , []
        )

test_lowercaseEmptyStringPreserved :: Assertion
test_lowercaseEmptyStringPreserved =
  -- This is the shape the dm4y fixture in test/data/ uses: a patch
  -- that slap itself produced with no metadata, every field empty.
  parseEBPMetadata
    "{\"patcher\":\"slap\",\"title\":\"\",\"author\":\"\",\"description\":\"\"}"
    @?= ( EBPMetadata
            { ebpMetadataTitle       = Just (asUtf8 "")
            , ebpMetadataAuthor      = Just (asUtf8 "")
            , ebpMetadataDescription = Just (asUtf8 "")
            , ebpMetadataPatcher     = Just (asUtf8 "slap")
            }
        , []
        )

----------------------------------------------------------------------------
-- RomPatcher.js-style
----------------------------------------------------------------------------

test_capitalisedKeysMatched :: Assertion
test_capitalisedKeysMatched =
  parseEBPMetadata
    "{\"Title\":\"FE6\",\"Author\":\"nyuu\",\"Description\":\"hi\",\"patcher\":\"romp.js\"}"
    @?= ( EBPMetadata
            { ebpMetadataTitle       = Just (asUtf8 "FE6")
            , ebpMetadataAuthor      = Just (asUtf8 "nyuu")
            , ebpMetadataDescription = Just (asUtf8 "hi")
            , ebpMetadataPatcher     = Just (asUtf8 "romp.js")
            }
        , []
        )

test_capitalisedSomeFieldsMissing :: Assertion
test_capitalisedSomeFieldsMissing =
  -- RomPatcher.js's writer skips empty fields entirely. A patch
  -- where the user left author and description blank arrives with
  -- only Title and patcher present; the missing fields land as
  -- Nothing rather than as some sentinel "" or a parse failure.
  parseEBPMetadata
    "{\"Title\":\"FE6\",\"patcher\":\"romp.js\"}"
    @?= ( EBPMetadata
            { ebpMetadataTitle       = Just (asUtf8 "FE6")
            , ebpMetadataAuthor      = Nothing
            , ebpMetadataDescription = Nothing
            , ebpMetadataPatcher     = Just (asUtf8 "romp.js")
            }
        , []
        )

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
      (metadata, advisories) = parseEBPMetadata blob
  in do
    advisories @?= []
    ebpMetadataTitle metadata @?= Just (asUtf8 "caf\233")

test_nestedObjectSibling :: Assertion
test_nestedObjectSibling =
  -- The previous scanner gave up the moment it saw a nested @{@,
  -- losing every field that appeared after one. aeson sees through
  -- the nesting and the top-level title is still extractable.
  let blob :: ByteString
      blob = "{\"extra\":{\"deep\":\"value\"},\"title\":\"FE6\"}"
      (metadata, advisories) = parseEBPMetadata blob
  in do
    advisories @?= []
    ebpMetadataTitle metadata @?= Just (asUtf8 "FE6")

test_nonStringSiblings :: Assertion
test_nonStringSiblings =
  -- Numbers, booleans, nulls sitting at the top level alongside the
  -- four EBP fields. The previous scanner skipped them quietly;
  -- aeson parses them honestly and we then drop them at extraction
  -- because they aren't strings. The four EBP fields still land.
  let blob :: ByteString
      blob = "{\"version\":2,\"verified\":true,\"checksum\":null,\
             \\"title\":\"FE6\",\"author\":\"nyuu\"}"
      (metadata, advisories) = parseEBPMetadata blob
  in do
    advisories                 @?= []
    ebpMetadataTitle  metadata @?= Just (asUtf8 "FE6")
    ebpMetadataAuthor metadata @?= Just (asUtf8 "nyuu")

----------------------------------------------------------------------------
-- Honest failure on bad input
----------------------------------------------------------------------------

test_malformedReturnsAdvisory :: Assertion
test_malformedReturnsAdvisory =
  parseEBPMetadata "{ not actually json"
    @?= (emptyEBPMetadata, [EBPMetadataMalformed LabelEBP])

test_arrayRootReturnsAdvisory :: Assertion
test_arrayRootReturnsAdvisory =
  -- Valid JSON, but not an object. There's no EBP metadata to
  -- extract here so the honest answer is the empty record plus the
  -- malformed-trailer advisory.
  parseEBPMetadata "[\"title\",\"FE6\"]"
    @?= (emptyEBPMetadata, [EBPMetadataMalformed LabelEBP])

test_emptyReturnsAdvisory :: Assertion
test_emptyReturnsAdvisory =
  parseEBPMetadata ""
    @?= (emptyEBPMetadata, [EBPMetadataMalformed LabelEBP])

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
  let metadata = EBPMetadata
        { ebpMetadataTitle       = Just (asUtf8 "\12486\12473\12488\12497\12483\12481")
        , ebpMetadataAuthor      = Just (asUtf8 "\1085\1102\1091")
        , ebpMetadataDescription = Just (asUtf8 "\26085\26412\35486\12486\12473\12488")
        , ebpMetadataPatcher     = Just (asUtf8 "slap")
        }
      blob = IPS.buildEBPMetadataJSON metadata
      (parsed, advisories) = parseEBPMetadata blob
  in do
    advisories @?= []
    ebpMetadataTitle       parsed @?= ebpMetadataTitle       metadata
    ebpMetadataAuthor      parsed @?= ebpMetadataAuthor      metadata
    ebpMetadataDescription parsed @?= ebpMetadataDescription metadata
    ebpMetadataPatcher     parsed @?= Just (asUtf8 "slap")
