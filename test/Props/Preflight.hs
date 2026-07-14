{-# LANGUAGE OverloadedStrings #-}

-- | The pre-run pipeline: 'reframeInput' carries out the header directive with its narrating note,
-- the header rescue judges every arrangement through the weighing apply enforces —
-- width-sharing consoles surface together, and a checkless patch confirms nothing —
-- the checks answer without acting, and 'prepareApplySource' carries out the one proven fix.
module Props.Preflight (preflightTests) where

import Slap.Preflight (HeaderRescueCandidate(..), headerRescueCandidates, reframeInput,
                       SourceReport(..), checkApply, checkUndo,
                       PreparedApplySource(..), prepareApplySource)
import Slap.Convert (CreateFormat(..), DifferentialCreate(..), DirectCreate(..),
                     noMetadataRequested, noConstraintsRequested, noDialectsRequested, createPatch)
import Slap.Verify (DeclaredCheckKind(..), VerificationPolicy(..), VerificationVerdict(..), verdictOnWeighing)
import Slap.FileContents (InputFileContents(..), OutputFileContents(..))
import Slap.Header (ConsoleHeader(..), HeaderAdjustment(..), InputHeaderDirective(..))
import Slap.SomePatch (SomePatch, parseSome)
import Slap.Status (SlapError(..), SlapAdvisory(..), Outcome(..), CreateResult(..), renderSlapError)
import Slap.Text (EncodingName(EncodingUtf8))

import Props.Helpers (assertFailureT)

import Data.Bits (xor)
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.List.NonEmpty as NonEmpty

import Test.Tasty
import Test.Tasty.HUnit

-- | Create a patch and parse it back, so the rescue is exercised over a real 'SomePatch'.
parsedPatchFrom :: CreateFormat -> ByteString -> ByteString -> IO SomePatch
parsedPatchFrom format sourceBytes targetBytes =
  case createPatch format Nothing (InputFileContents sourceBytes) (OutputFileContents targetBytes)
         noMetadataRequested Nothing noConstraintsRequested noDialectsRequested of
    Left createError -> assertFailureT ("create: " <> renderSlapError createError)
    Right (CreateResult patchBytes _advisories) ->
      case parseSome noDialectsRequested EncodingUtf8 patchBytes of
        Left parseError -> assertFailureT ("parse: " <> renderSlapError parseError)
        Right parsed    -> pure parsed

bareSource :: ByteString
bareSource = ByteString.pack (concat (replicate 8 [0 .. 255]))

bareTarget :: ByteString
bareTarget = ByteString.map (`xor` 0x5A) bareSource

-- | Long enough to reach past PPF3's BIN validation block (1024 bytes at 0x9320), so the created patch carries it.
-- Aperiodic on purpose: a byte sequence whose period divides a header width would validate at shifted offsets too,
-- and the rescue would truthfully report the extra arrangements.
validationReachingSource :: ByteString
validationReachingSource = ByteString.pack [fromIntegral ((index * 131 + 7) `mod` 251) | index <- [0 .. 40959 :: Int]]

validationReachingTarget :: ByteString
validationReachingTarget =
  ByteString.take 40000 validationReachingSource <> "Z" <> ByteString.drop 40001 validationReachingSource

-- | The four consoles that share the 512-byte header width, in declaration order.
sharedWidth512 :: [ConsoleHeader]
sharedWidth512 = [FrontFarEastHeader, GameBoyHeader, SNESHeader, PCEngineHeader]

preflightTests :: TestTree
preflightTests = testGroup "Preflight"
  [ testCase "a headered copy is rescued by taking the header off" $ do
      parsed <- parsedPatchFrom (CreateDifferential CreateUPS) bareSource bareTarget
      let headeredCopy = ByteString.replicate 512 0x00 <> bareSource
      case headerRescueCandidates parsed headeredCopy of
        [HeaderRescueCandidate HeaderComesOff consoles heldKinds] -> do
          NonEmpty.toList consoles @?= sharedWidth512
          NonEmpty.toList heldKinds @?= [DeclaredFileSize, DeclaredCRC32]
        other -> assertFailure ("expected one comes-off find, got " ++ show other)

  , testCase "a bare copy is rescued by putting the header on" $ do
      parsed <- parsedPatchFrom (CreateDifferential CreateUPS)
                  (ByteString.replicate 512 0x00 <> bareSource)
                  (ByteString.replicate 512 0x00 <> bareTarget)
      case headerRescueCandidates parsed bareSource of
        [HeaderRescueCandidate HeaderGoesOn consoles _heldKinds] ->
          NonEmpty.toList consoles @?= sharedWidth512
        other -> assertFailure ("expected one goes-on find, got " ++ show other)

  , testCase "an advisory-only patch confirms nothing vacuously" $ do
      parsed <- parsedPatchFrom (CreateDirect CreatePPF3) validationReachingSource validationReachingTarget
      headerRescueCandidates parsed (ByteString.replicate (ByteString.length validationReachingSource) 0xEE)
        @?= []

  , testCase "an advisory-only patch still earns a real find" $ do
      parsed <- parsedPatchFrom (CreateDirect CreatePPF3) validationReachingSource validationReachingTarget
      case headerRescueCandidates parsed (ByteString.replicate 512 0x00 <> validationReachingSource) of
        [HeaderRescueCandidate HeaderComesOff consoles heldKinds] -> do
          NonEmpty.toList consoles @?= sharedWidth512
          NonEmpty.toList heldKinds @?= [DeclaredValidationBlock]
        other -> assertFailure ("expected one comes-off find, got " ++ show other)

  , testCase "an unrelated file gets no false hope" $ do
      parsed <- parsedPatchFrom (CreateDifferential CreateUPS) bareSource bareTarget
      headerRescueCandidates parsed (ByteString.replicate 2048 0xEE) @?= []

  , testCase "a checkless patch confirms nothing" $ do
      let alteredSameLength = ByteString.take 100 bareSource <> "XYZ" <> ByteString.drop 103 bareSource
      parsed <- parsedPatchFrom (CreateDirect CreateIPS) bareSource alteredSameLength
      headerRescueCandidates parsed (ByteString.replicate 512 0x00 <> bareSource) @?= []

  , testCase "reframe narrates, and refuses removal from a too-short input" $ do
      let added = reframeInput (AddHeader SNESHeader) "bare"
      outcomeAdvisories added @?= [InputHeaderAdded SNESHeader]
      outcomeValue added @?= Right (ByteString.replicate 512 0x00 <> "bare")
      case outcomeValue (reframeInput (RemoveHeader SNESHeader) "tiny") of
        Left (HeaderRemovalExceedsInput _ _) -> pure ()
        other -> assertFailure ("expected the removal refusal, got " ++ show other)

  , testCase "checkApply answers a match with the kinds it rests on" $ do
      parsed <- parsedPatchFrom (CreateDifferential CreateUPS) bareSource bareTarget
      case checkApply parsed TakeInputAsIs bareSource of
        Right (SourceReport (VerdictMatches heldKinds) []) ->
          NonEmpty.toList heldKinds @?= [DeclaredFileSize, DeclaredCRC32]
        other -> assertFailure ("expected a bare match, got " ++ show other)

  , testCase "checkApply reports the differ and the find together" $ do
      parsed <- parsedPatchFrom (CreateDifferential CreateUPS) bareSource bareTarget
      case checkApply parsed TakeInputAsIs (ByteString.replicate 512 0x00 <> bareSource) of
        Right (SourceReport (VerdictDiffers _) [HeaderRescueCandidate HeaderComesOff _ _]) -> pure ()
        other -> assertFailure ("expected a differ with one comes-off find, got " ++ show other)

  , testCase "checkApply under a typed directive answers for the reframed form, and never searches" $ do
      parsed <- parsedPatchFrom (CreateDifferential CreateUPS) bareSource bareTarget
      case checkApply parsed (RemoveHeader SNESHeader) (ByteString.replicate 512 0x00 <> bareSource) of
        Right (SourceReport (VerdictMatches _) []) -> pure ()
        other -> assertFailure ("expected a match under the directive, got " ++ show other)
      case checkApply parsed (RemoveHeader SNESHeader) (ByteString.replicate 2048 0xEE) of
        Right (SourceReport (VerdictDiffers _) rescue) -> rescue @?= []
        other -> assertFailure ("expected an unsearched differ, got " ++ show other)

  , testCase "prepareApplySource carries out the only find and narrates it" $ do
      parsed <- parsedPatchFrom (CreateDifferential CreateUPS) bareSource bareTarget
      case prepareApplySource EnforceVerification parsed TakeInputAsIs (ByteString.replicate 512 0x00 <> bareSource) of
        Left preparationError -> assertFailureT (renderSlapError preparationError)
        Right prepared -> do
          preparedFramedInput prepared @?= bareSource
          case verdictOnWeighing (preparedWeighing prepared) of
            VerdictMatches _ -> pure ()
            other -> assertFailure ("the reframed form should match, got " ++ show other)
          case preparedAdvisories prepared of
            [InputReframedToMatchPatch HeaderComesOff consoles heldKinds] -> do
              NonEmpty.toList consoles @?= sharedWidth512
              NonEmpty.toList heldKinds @?= [DeclaredFileSize, DeclaredCRC32]
            other -> assertFailure ("expected the fix's own narration, got " ++ show other)
          case sourceVerdict (preparedReport prepared) of
            VerdictDiffers _ -> pure ()
            other -> assertFailure ("the report should keep speaking about the handed bytes, got " ++ show other)

  , testCase "prepareApplySource under --no-verify leaves the input alone" $ do
      parsed <- parsedPatchFrom (CreateDifferential CreateUPS) bareSource bareTarget
      let headeredCopy = ByteString.replicate 512 0x00 <> bareSource
      case prepareApplySource SkipVerification parsed TakeInputAsIs headeredCopy of
        Left preparationError -> assertFailureT (renderSlapError preparationError)
        Right prepared -> do
          preparedFramedInput prepared @?= headeredCopy
          preparedAdvisories prepared @?= []

  , testCase "prepareApplySource with empty hands changes nothing" $ do
      parsed <- parsedPatchFrom (CreateDifferential CreateUPS) bareSource bareTarget
      let unrelated = ByteString.replicate 2048 0xEE
      case prepareApplySource EnforceVerification parsed TakeInputAsIs unrelated of
        Left preparationError -> assertFailureT (renderSlapError preparationError)
        Right prepared -> do
          preparedFramedInput prepared @?= unrelated
          sourceRescue (preparedReport prepared) @?= []

  , testCase "prepareApplySource under a typed directive keeps the plain note" $ do
      parsed <- parsedPatchFrom (CreateDifferential CreateUPS) bareSource bareTarget
      case prepareApplySource EnforceVerification parsed (RemoveHeader SNESHeader) (ByteString.replicate 512 0x00 <> bareSource) of
        Left preparationError -> assertFailureT (renderSlapError preparationError)
        Right prepared -> preparedAdvisories prepared @?= [InputHeaderRemoved SNESHeader]

  , testCase "checkUndo weighs the handed file crosswise" $ do
      parsed <- parsedPatchFrom (CreateDifferential CreateUPS) bareSource bareTarget
      case checkUndo parsed bareTarget of
        VerdictMatches _ -> pure ()
        other -> assertFailure ("the true target should match, got " ++ show other)
      case checkUndo parsed bareSource of
        VerdictDiffers _ -> pure ()
        other -> assertFailure ("the source handed to undo should differ, got " ++ show other)
  ]
