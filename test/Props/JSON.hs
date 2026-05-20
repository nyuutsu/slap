{-# LANGUAGE OverloadedStrings #-}
-- | Tests for 'Slap.JSON': the aeson-backed parser for EBP
-- metadata blobs. Exercises the things the previous hand-rolled
-- scanner got wrong (escaped Unicode, nested objects, non-string
-- siblings, malformed input), plus the case-insensitive lookup
-- that real-world EBP producers depend on.
module Props.JSON (jsonTests) where

import Slap.JSON
  ( EBPMetadataView(..)
  , parseEBPMetadata
  )

import Data.ByteString (ByteString)
import Test.Tasty
import Test.Tasty.HUnit

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
  ]

----------------------------------------------------------------------------
-- EBPatcher-style
----------------------------------------------------------------------------

test_lowercaseAllFour :: Assertion
test_lowercaseAllFour =
  parseEBPMetadata
    "{\"patcher\":\"slap\",\"title\":\"FE6\",\"author\":\"nyuu\",\"description\":\"hi\"}"
    @?= Just EBPMetadataView
          { ebpMetadataViewTitle       = Just "FE6"
          , ebpMetadataViewAuthor      = Just "nyuu"
          , ebpMetadataViewDescription = Just "hi"
          , ebpMetadataViewPatcher     = Just "slap"
          }

test_lowercaseEmptyStringPreserved :: Assertion
test_lowercaseEmptyStringPreserved =
  -- This is the shape the dm4y fixture in test/data/ uses: a patch
  -- that slap itself produced with no metadata, every field empty.
  parseEBPMetadata
    "{\"patcher\":\"slap\",\"title\":\"\",\"author\":\"\",\"description\":\"\"}"
    @?= Just EBPMetadataView
          { ebpMetadataViewTitle       = Just ""
          , ebpMetadataViewAuthor      = Just ""
          , ebpMetadataViewDescription = Just ""
          , ebpMetadataViewPatcher     = Just "slap"
          }

----------------------------------------------------------------------------
-- RomPatcher.js-style
----------------------------------------------------------------------------

test_capitalisedKeysMatched :: Assertion
test_capitalisedKeysMatched =
  parseEBPMetadata
    "{\"Title\":\"FE6\",\"Author\":\"nyuu\",\"Description\":\"hi\",\"patcher\":\"romp.js\"}"
    @?= Just EBPMetadataView
          { ebpMetadataViewTitle       = Just "FE6"
          , ebpMetadataViewAuthor      = Just "nyuu"
          , ebpMetadataViewDescription = Just "hi"
          , ebpMetadataViewPatcher     = Just "romp.js"
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
          { ebpMetadataViewTitle       = Just "FE6"
          , ebpMetadataViewAuthor      = Nothing
          , ebpMetadataViewDescription = Nothing
          , ebpMetadataViewPatcher     = Just "romp.js"
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
       Just view -> ebpMetadataViewTitle view @?= Just "caf\233"
       Nothing   -> assertFailure "expected valid JSON to parse"

test_nestedObjectSibling :: Assertion
test_nestedObjectSibling =
  -- The previous scanner gave up the moment it saw a nested @{@,
  -- losing every field that appeared after one. aeson sees through
  -- the nesting and the top-level title is still extractable.
  let blob :: ByteString
      blob = "{\"extra\":{\"deep\":\"value\"},\"title\":\"FE6\"}"
  in case parseEBPMetadata blob of
       Just view -> ebpMetadataViewTitle view @?= Just "FE6"
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
         ebpMetadataViewTitle  view @?= Just "FE6"
         ebpMetadataViewAuthor view @?= Just "nyuu"
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
