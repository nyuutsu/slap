{-# LANGUAGE OverloadedStrings #-}
-- | The EBP metadata blob, both directions: 'parseEBPMetadata' across the shapes real producers emit
-- (case-insensitive keys, escaped Unicode, nested and non-string siblings, malformed input),
-- and the build/parse round-trip through 'buildEBPMetadataJSON' with non-ASCII content,
-- where the type-level UTF-8 contract earns its keep.
module Props.EBPMetadata (ebpMetadataTests) where

import Slap.IPS.EBPMetadata (buildEBPMetadataJSON, parseEBPMetadata)
import Slap.IPS.Types (EBPMetadata(..), emptyEBPMetadata)
import Slap.FormatLabel (FormatLabel(..))
import Slap.Status (SlapAdvisory(..))
import Slap.Text (EncodedText(..), EncodingName(..))

import Data.ByteString (ByteString)
import qualified Data.Text as Text
import Test.Tasty
import Test.Tasty.HUnit

-- | Wrap a literal for an EBP metadata field: JSON values come out of aeson tagged 'EncodingUtf8', so expectations carry the same tag.
asUtf8 :: String -> EncodedText
asUtf8 = EncodedText EncodingUtf8 . Text.pack

ebpMetadataTests :: TestTree
ebpMetadataTests = testGroup "EBP metadata"
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
  , testGroup "Spec corners"
      [ testCase "escaped Unicode \\u00e9 decodes to é"
          test_escapedUnicode
      , testCase "nested object value does not abort top-level scan"
          test_nestedObjectSibling
      , testCase "numeric / boolean / null siblings are skipped, not crashed on"
          test_nonStringSiblings
      ]
  , testGroup "Malformed input"
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
  -- RomPatcher.js's writer skips empty fields entirely, so blank author and description never reach the wire;
  -- the missing fields land as 'Nothing', not a sentinel @""@ or a parse failure.
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
-- Spec corners
----------------------------------------------------------------------------

test_escapedUnicode :: Assertion
test_escapedUnicode =
  let blob :: ByteString
      blob = "{\"title\":\"caf\\u00e9\"}"
      (metadata, advisories) = parseEBPMetadata blob
  in do
    advisories @?= []
    ebpMetadataTitle metadata @?= Just (asUtf8 "caf\233")

test_nestedObjectSibling :: Assertion
test_nestedObjectSibling =
  let blob :: ByteString
      blob = "{\"extra\":{\"deep\":\"value\"},\"title\":\"FE6\"}"
      (metadata, advisories) = parseEBPMetadata blob
  in do
    advisories @?= []
    ebpMetadataTitle metadata @?= Just (asUtf8 "FE6")

test_nonStringSiblings :: Assertion
test_nonStringSiblings =
  let blob :: ByteString
      blob = "{\"version\":2,\"verified\":true,\"checksum\":null,\
             \\"title\":\"FE6\",\"author\":\"nyuu\"}"
      (metadata, advisories) = parseEBPMetadata blob
  in do
    advisories                 @?= []
    ebpMetadataTitle  metadata @?= Just (asUtf8 "FE6")
    ebpMetadataAuthor metadata @?= Just (asUtf8 "nyuu")

----------------------------------------------------------------------------
-- Malformed input
----------------------------------------------------------------------------

test_malformedReturnsAdvisory :: Assertion
test_malformedReturnsAdvisory =
  parseEBPMetadata "{ not actually json"
    @?= (emptyEBPMetadata, [EBPMetadataMalformed LabelEBP])

test_arrayRootReturnsAdvisory :: Assertion
test_arrayRootReturnsAdvisory =
  -- Valid JSON is still not EBP metadata unless its root is an object.
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
  -- aeson escapes nothing RFC 8259 doesn't mandate, so the Japanese and Cyrillic codepoints land verbatim as UTF-8,
  -- and the parser pulls them back as 'EncodingUtf8'-tagged 'EncodedText' — equality includes the tag,
  -- catching a builder that lost provenance (say, by re-encoding via latin1).
  let metadata = EBPMetadata
        { ebpMetadataTitle       = Just (asUtf8 "\12486\12473\12488\12497\12483\12481")
        , ebpMetadataAuthor      = Just (asUtf8 "\1085\1102\1091")
        , ebpMetadataDescription = Just (asUtf8 "\26085\26412\35486\12486\12473\12488")
        , ebpMetadataPatcher     = Just (asUtf8 "slap")
        }
      blob = buildEBPMetadataJSON metadata
      (parsed, advisories) = parseEBPMetadata blob
  in do
    advisories @?= []
    ebpMetadataTitle       parsed @?= ebpMetadataTitle       metadata
    ebpMetadataAuthor      parsed @?= ebpMetadataAuthor      metadata
    ebpMetadataDescription parsed @?= ebpMetadataDescription metadata
    ebpMetadataPatcher     parsed @?= Just (asUtf8 "slap")
