-- | Undo property: for formats that support undo data,
--
-- > undo(apply(patch, src)) == src
--
-- UPS undo is the special case of self-inversion (applying the same
-- XOR patch twice recovers the original). PPF3 undo stores original
-- bytes explicitly.
module Props.Undo (undoTests) where

import qualified Slap.UPS.Apply as UPS
import qualified Slap.UPS.Parse as UPS
import qualified Slap.PPF3.Apply as PPF3
import qualified Slap.PPF3.Parse as PPF3

import Slap.Error (CreateResult(..), Parsed(..), renderSlapError)
import Slap.FileContents (InputFileContents(..), OutputFileContents(..))
import Slap.Convert (CreateFormat(..), DirectCreate(..), RequestedPatchMetadata(..),
                     UndoInclusion(..), noMetadataRequested, noConstraintsRequested)
import Slap.Create (createUPS, createPatch)

import qualified Data.ByteString as ByteString
import Test.Tasty
import Test.Tasty.QuickCheck

import Props.Helpers

undoTests :: TestTree
undoTests = testGroup "Undo"
  [ testProperty "UPS"  prop_upsUndo
  , testProperty "PPF3" prop_ppf3Undo
  ]

-- | UPS XOR is symmetric: applying the same patch to the target yields
-- the source.  Only holds for same-size inputs (different sizes lose
-- information in the size field).
prop_upsUndo :: Property
prop_upsUndo = forAll genSameSizePair $ \(source, target) ->
  case createUPS (InputFileContents source) (OutputFileContents target) of
    Left _createError -> property True
    Right (CreateResult patch _) ->
      case UPS.parseUPS patch of
        Left parseError ->
          counterexample ("parse: " ++ renderSlapError parseError) $ property False
        Right (Parsed parsed _parseWarnings) ->
          (UPS.applyUPS parsed (InputFileContents source) >>= \(OutputFileContents intermediate) -> UPS.applyUPS parsed (InputFileContents intermediate)) === Right (OutputFileContents source)

-- | PPF3 with undo data: apply then undo recovers the original.
-- Same-size pairs only — PPF3 undo writes back original bytes but can't
-- truncate the file, so growth is irreversible.
prop_ppf3Undo :: Property
prop_ppf3Undo = forAll genSameSizePair $ \(source, target) -> not (ByteString.null source) ==>
  case createPatch (CreateDirect CreatePPF3) (InputFileContents source) (OutputFileContents target) (noMetadataRequested { requestedUndoInclusion = Just IncludeUndoData }) Nothing noConstraintsRequested of
    Left _ -> discard
    Right (CreateResult patch _) -> case PPF3.parsePPF3 patch of
      Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
      Right (Parsed parsed _parseWarnings) ->
        case PPF3.applyPPF3 parsed (InputFileContents source) of
          Left err -> counterexample ("apply failed: " ++ show err) $ property False
          Right applied ->
            PPF3.undoPPF3 parsed applied === Right (InputFileContents source)
