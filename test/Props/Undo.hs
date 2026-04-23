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
import qualified Slap.PPF.Parse as PPF
import qualified Slap.PPF.Apply as PPF

import Slap.Error (CreateResult(..), Parsed(..), renderSlapError)
import Slap.FileContents (SourceFileContents(..), TargetFileContents(..))
import Slap.Convert (CreateFormat(..), DirectCreate(..), RequestedPatchMetadata(..),
                     UndoInclusion(..), noMetadataRequested)
import Slap.Create (createUPS, createFromMemory)

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
  case createUPS (SourceFileContents source) (TargetFileContents target) of
    Left _createError -> property True
    Right (CreateResult patch _) ->
      case UPS.parseUPS patch of
        Left parseError ->
          counterexample ("parse: " ++ renderSlapError parseError) $ property False
        Right (Parsed parsed _parseWarnings) ->
          (UPS.applyUPS parsed (SourceFileContents source) >>= \(TargetFileContents intermediate) -> UPS.applyUPS parsed (SourceFileContents intermediate)) === Right (TargetFileContents source)

-- | PPF3 with undo data: apply then undo recovers the original.
-- Same-size pairs only — PPF3 undo writes back original bytes but can't
-- truncate the file, so growth is irreversible.
prop_ppf3Undo :: Property
prop_ppf3Undo = forAll genSameSizePair $ \(source, target) -> not (ByteString.null source) ==>
  case createFromMemory (CreateDirect CreatePPF3) (SourceFileContents source) (TargetFileContents target) (noMetadataRequested { requestedUndoInclusion = Just IncludeUndoData }) Nothing of
    Left _ -> discard
    Right (CreateResult patch _) -> case PPF.parsePatch patch of
      Left slapError -> counterexample ("parse: " ++ renderSlapError slapError) $ property False
      Right (Parsed parsed _parseWarnings) ->
        case PPF.applyPatchMemory parsed (SourceFileContents source) of
          Left err -> counterexample ("apply failed: " ++ show err) $ property False
          Right applied ->
            PPF.undoPatchMemory parsed applied === Right (SourceFileContents source)
