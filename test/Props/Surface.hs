{-# LANGUAGE OverloadedStrings #-}

-- | The metadata-field surface: flag tokens and control kinds.
module Props.Surface (surfaceTests) where

import Slap.MetadataField (DroppableField, MetadataField, TypedTextField,
                           dropFlagName, metadataFieldFlagName, typedTextFlagName, requestFlagName)
import Slap.Surface (MetadataFieldKind(..), metadataFieldKind, romTypeTokens)
import Slap.Convert (metadataRequests, noMetadataRequested,
                     RequestedPatchMetadata(..), EmbeddedBlobContents(..), EmbeddedBlobRequest(..))

import Data.Char (isUpper)
import Data.List (nub)
import qualified Data.Set as Set
import Test.Tasty
import Test.Tasty.HUnit

surfaceTests :: TestTree
surfaceTests = testGroup "Surface"
  [ testCase "every field's flag is its own" test_flagNamesDistinct
  , testCase "choice vocabularies are non-empty, lowercase, and duplicate-free" test_choiceVocabularies
  , testCase "the rom-type vocabulary carries all nineteen platforms" test_romTypeCensus
  , testCase "the embedded-blob request names the flag it arrived on" test_embeddedBlobRequestFlag
  ]

allMetadataFields :: [MetadataField]
allMetadataFields = [minBound .. maxBound]

test_flagNamesDistinct :: IO ()
test_flagNamesDistinct =
  assertEqual "distinct flag names" (length allFlagNames) (Set.size (Set.fromList allFlagNames))
  where
    allFlagNames = map metadataFieldFlagName allMetadataFields
                ++ map dropFlagName      [minBound .. maxBound :: DroppableField]
                ++ map typedTextFlagName [minBound .. maxBound :: TypedTextField]

test_choiceVocabularies :: IO ()
test_choiceVocabularies = sequence_
  [ do assertBool (show field <> ": non-empty") (not (null tokens))
       assertEqual (show field <> ": duplicate-free") (length tokens) (length (nub tokens))
       assertBool (show field <> ": lowercase") (all (all (not . isUpper)) tokens)
  | field <- allMetadataFields
  , ChoiceField tokens <- [metadataFieldKind field]
  ]

test_romTypeCensus :: IO ()
test_romTypeCensus = do
  assertEqual "tokens" 19 (length romTypeTokens)
  assertEqual "distinct platforms" 19 (length (nub (map snd romTypeTokens)))

-- | The engine's own request derivation ('metadataRequests', the source-inheriting path a frontend uses)
-- must name a typed-text blob by its own flag, so a refusal answers with the flag the user typed rather than @--metadata@.
test_embeddedBlobRequestFlag :: IO ()
test_embeddedBlobRequestFlag = do
  assertEqual "typed text names --metadata-text"
    ["metadata-text"] (flagsFor (SetEmbeddedTypedText "x"))
  assertEqual "a file blob names --metadata"
    ["metadata"] (flagsFor (SetEmbeddedBlob (EmbeddedBlobContents "x")))
  where
    flagsFor blobRequest =
      map requestFlagName (metadataRequests noMetadataRequested { requestedEmbeddedBlob = blobRequest })
