-- | The undo property, for every patch that can run in reverse:
--
-- > undo(apply(patch, src)) == src
module Props.Undo (undoTests) where

import qualified Slap.UPS.Apply as UPS
import qualified Slap.UPS.Parse as UPS
import qualified Slap.PPF3.Apply as PPF3
import qualified Slap.PPF3.Parse as PPF3
import qualified Slap.NINJA2.Apply as NINJA2
import qualified Slap.NINJA2.Parse as NINJA2
import qualified Slap.NINJA2.Types as NINJA2

import Slap.SomePatch (parseSome, patchUndo, undoAnswerFor, UndoAnswer(..))
import Slap.Status (CreateResult(..), Parsed(..), Outcome(..), renderSlapError)
import Slap.Text (EncodingName(EncodingUtf8))
import Slap.FileContents (InputFileContents(..), OutputFileContents(..), PatchFileContents(..))
import Slap.Convert (CreateFormat(..), DirectCreate(..), DifferentialCreate(..), RequestedPatchMetadata(..),
                     UndoInclusion(..), noMetadataRequested, noConstraintsRequested, noDialectsRequested)
import Slap.Create (createUPS, createPatch)

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Test.Tasty
import Test.Tasty.QuickCheck

import Props.Helpers
import qualified Data.Text as Text

undoTests :: TestTree
undoTests = testGroup "Undo"
  [ testProperty "UPS"  prop_upsUndo
  , testProperty "PPF3" prop_ppf3Undo
  , testProperty "NINJA2 same size"      (prop_ninja2Undo genSameSizePair  PatchIsItsOwnReverse)
  , testProperty "NINJA2 grows or stays" (prop_ninja2Undo genPairNoShrink  PatchIsItsOwnReverse)
  , testProperty "NINJA2 shrinks"        (prop_ninja2Undo genShrinkingPair PatchCarriesUndoData)
  , testProperty "NINJA2 append-mode shrink" prop_ninja2AppendModeShrink
  ]

-- | Holds for arbitrary pairs, including size changes: each direction produces the size the patch's header declares for it.
prop_upsUndo :: Property
prop_upsUndo = forAll genUPSEncodeablePair $ \(source, target) ->
  case createUPS (InputFileContents source) (OutputFileContents target) of
    Left createError ->
      counterexample ("create on encodeable pair: "
                       ++ Text.unpack (renderSlapError createError)) $ property False
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

prop_ninja2Undo :: Gen (ByteString, ByteString) -> UndoAnswer -> Property
prop_ninja2Undo genNINJA2Pair expectedAnswer = forAll genNINJA2Pair $ \(source, target) ->
  case createPatch (CreateDifferential CreateNINJA2) Nothing
                   (InputFileContents source) (OutputFileContents target)
                   noMetadataRequested Nothing noConstraintsRequested noDialectsRequested of
    Left createError ->
      counterexample ("create: " ++ Text.unpack (renderSlapError createError)) $ property False
    Right (CreateResult patch _) ->
      let answerSpoken = case parseSome noDialectsRequested EncodingUtf8 patch of
            Left parseError ->
              counterexample ("parseSome: " ++ Text.unpack (renderSlapError parseError)) $ property False
            Right parsed -> undoAnswerFor (patchUndo parsed) === expectedAnswer
          sourceRestored = case NINJA2.parseNINJA2 EncodingUtf8 patch of
            Left parseError ->
              counterexample ("parse: " ++ Text.unpack (renderSlapError parseError)) $ property False
            Right (Parsed parsed _parseWarnings) ->
              case NINJA2.applyNINJA2 parsed (InputFileContents source) of
                Left applyError ->
                  counterexample ("apply: " ++ Text.unpack (renderSlapError applyError)) $ property False
                Right applied ->
                  NINJA2.undoNINJA2 parsed applied === Right (InputFileContents source)
      in answerSpoken .&&. sourceRestored

-- | The one shrink that cannot peel: its overflow is marked append, so the tail the shrink cut off is not in the patch.
-- slap's own create never writes one, so the wire is built by hand.
appendModeShrinkWire :: ByteString
appendModeShrinkWire =
     NINJA2.ninja2MagicBytes
  <> ByteString.pack [0]           -- PATCH_ENC: encoding undeclared
  <> ByteString.replicate 2041 0   -- the fixed header's text fields, all empty
  <> ByteString.pack
       [ 0x01                      -- OPEN_NEW_FILE
       , 0x00                      -- file name, zero length
       , 0x00                      -- rom type: raw
       , 0x01, 0x04                -- source size 4
       , 0x01, 0x02                -- target size 2
       ]
  <> ByteString.replicate 32 0     -- source and target MD5s, both absent
  <> ByteString.pack
       [ 0x41                      -- overflow mode: append
       , 0x01, 0x01                -- overflow length 1
       , 0xAB                      -- the overflow byte
       , 0x00                      -- END
       ]

prop_ninja2AppendModeShrink :: Property
prop_ninja2AppendModeShrink = once $
  case parseSome noDialectsRequested EncodingUtf8 (PatchFileContents appendModeShrinkWire) of
    Left parseError ->
      counterexample ("parse: " ++ Text.unpack (renderSlapError parseError)) $ property False
    Right parsed -> undoAnswerFor (patchUndo parsed) === AuthorOmittedUndoData

-- | Same-size pairs, the only pairs PPF3 encodes.
prop_ppf3Undo :: Property
prop_ppf3Undo = forAll genSameSizePair $ \(source, target) -> not (ByteString.null source) ==>
  case createPatch (CreateDirect CreatePPF3) Nothing
                   (InputFileContents source) (OutputFileContents target)
                   (noMetadataRequested { requestedUndoInclusion = Just IncludeUndoData })
                   Nothing noConstraintsRequested noDialectsRequested of
    Left _ -> discard
    Right (CreateResult patch _) -> case PPF3.parsePPF3 EncodingUtf8 patch of
      Left slapError -> counterexample ("parse: " ++ Text.unpack (renderSlapError slapError)) $ property False
      Right (Parsed parsed _parseWarnings) ->
        case PPF3.applyPPF3 parsed (InputFileContents source) of
          Left err -> counterexample ("apply failed: " ++ show err) $ property False
          Right (Outcome applied _advisories) ->
            PPF3.undoPPF3 parsed applied === Right (InputFileContents source)
