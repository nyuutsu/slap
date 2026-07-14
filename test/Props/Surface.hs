-- | The metadata-field surface: flag tokens and control kinds.
module Props.Surface (surfaceTests) where

import Slap.MetadataField (DroppableField, MetadataField, dropFlagName, metadataFieldFlagName)
import Slap.Surface (MetadataFieldKind(..), metadataFieldKind, romTypeTokens)

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
  ]

allMetadataFields :: [MetadataField]
allMetadataFields = [minBound .. maxBound]

test_flagNamesDistinct :: IO ()
test_flagNamesDistinct =
  assertEqual "distinct flag names" (length allFlagNames) (Set.size (Set.fromList allFlagNames))
  where
    allFlagNames = map metadataFieldFlagName allMetadataFields
                ++ map dropFlagName [minBound .. maxBound :: DroppableField]

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
