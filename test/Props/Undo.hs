-- | Undo property: for formats that support undo data,
--
-- > undo(apply(patch, src)) == src
--
-- UPS undo relies on XOR's self-inverse property: walking the same
-- block stream against the target with a source-sized output buffer
-- reconstructs the source. PPF3 undo stores original bytes
-- explicitly.
module Props.Undo (undoTests) where

import qualified Slap.UPS.Apply as UPS
import qualified Slap.UPS.Parse as UPS
import qualified Slap.PPF3.Apply as PPF3
import qualified Slap.PPF3.Parse as PPF3

import Slap.Status (CreateResult(..), Parsed(..), Outcome(..), renderSlapError)
import Slap.FileContents (InputFileContents(..), OutputFileContents(..))
import Slap.Convert (CreateFormat(..), DirectCreate(..), RequestedPatchMetadata(..),
                     UndoInclusion(..), noMetadataRequested, noConstraintsRequested, noDialectsRequested)
import Slap.Create (createUPS, createPatch)

import qualified Data.ByteString as ByteString
import Test.Tasty
import Test.Tasty.QuickCheck

import Props.Helpers
import qualified Data.Text as Text

undoTests :: TestTree
undoTests = testGroup "Undo"
  [ testProperty "UPS"  prop_upsUndo
  , testProperty "PPF3" prop_ppf3Undo
  ]

-- | UPS XOR is symmetric: applying the patch forward to source
-- yields target, and the dedicated 'undoUPS' (which walks the same
-- block stream but sizes the output buffer to 'upsSourceSize'
-- instead of 'upsTargetSize') takes that target back to the source.
-- Holds for arbitrary pairs, including size changes — the size each
-- direction produces is the one declared in the patch's header.
-- The same-size-only restriction this property used to carry was an
-- artefact of slap's old undo path, which reapplied 'applyUPS' and
-- so always produced a target-sized buffer regardless of direction.
prop_upsUndo :: Property
prop_upsUndo = forAll genPair $ \(source, target) ->
  case createUPS (InputFileContents source) (OutputFileContents target) of
    Left _createError -> property True
    Right (CreateResult patch _) ->
      case UPS.parseUPS patch of
        Left parseError ->
          counterexample ("parse: " ++ Text.unpack (renderSlapError parseError)) $ property False
        Right (Parsed parsed _parseWarnings) ->
          case UPS.applyUPS parsed (InputFileContents source) of
            Left applyError ->
              counterexample ("apply: " ++ Text.unpack (renderSlapError applyError)) $ property False
            Right (Outcome intermediate _applyWarnings) ->
              fmap outcomeValue (UPS.undoUPS parsed intermediate)
                === Right (InputFileContents source)

-- | PPF3 with undo data: apply then undo recovers the original.
-- Same-size pairs only — PPF3 undo writes back original bytes but can't
-- truncate the file, so growth is irreversible.
prop_ppf3Undo :: Property
prop_ppf3Undo = forAll genSameSizePair $ \(source, target) -> not (ByteString.null source) ==>
  case createPatch (CreateDirect CreatePPF3) Nothing (InputFileContents source) (OutputFileContents target) (noMetadataRequested { requestedUndoInclusion = Just IncludeUndoData }) Nothing noConstraintsRequested noDialectsRequested of
    Left _ -> discard
    Right (CreateResult patch _) -> case PPF3.parsePPF3 patch of
      Left slapError -> counterexample ("parse: " ++ Text.unpack (renderSlapError slapError)) $ property False
      Right (Parsed parsed _parseWarnings) ->
        case PPF3.applyPPF3 parsed (InputFileContents source) of
          Left err -> counterexample ("apply failed: " ++ show err) $ property False
          Right (Outcome applied _advisories) ->
            PPF3.undoPPF3 parsed applied === Right (InputFileContents source)
