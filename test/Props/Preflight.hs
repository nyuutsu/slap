{-# LANGUAGE OverloadedStrings #-}

-- | The pre-apply pipeline: 'reframeInput' carries out the header directive with its narrating note,
-- and the header rescue judges every arrangement through the weighing apply enforces —
-- width-sharing consoles surface together, and a checkless patch confirms nothing.
module Props.Preflight (preflightTests) where

import Slap.Preflight (HeaderRescueCandidate(..), headerRescueCandidates, reframeInput)
import Slap.Convert (CreateFormat(..), DifferentialCreate(..), DirectCreate(..),
                     noMetadataRequested, noConstraintsRequested, noDialectsRequested, createPatch)
import Slap.Verify (DeclaredCheckKind(..))
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
  ]
