{-# LANGUAGE OverloadedStrings #-}

-- | The verification weighing: enforcement ('verifySource' / 'verifyTarget') and the policy-free verdict
-- ('verdictOnSource' / 'verdictOnTarget') are projections of one pass over the declared checks.
-- Pins the three-way verdict split — matches / differs / nothing-declared — and its lockstep with enforcement:
-- a fatal-class refusal implies a differing verdict, while an advisory-only disagreement differs without refusing.
-- Also pins 'renderVerificationReport', the sentences the verdicts earn on the happy path.
module Props.Verify (verifyTests) where

import Slap.Verify (Verification(..), VerificationPolicy(..), VerificationVerdict(..),
                    DeclaredCheckKind(..), noVerification, SourcePreHash(..),
                    ValidationBlock(..), FileSizeCheck(..), WindowCheck(..),
                    verifySource, verifyTarget, verdictOnSource, verdictOnTarget)
import Slap.Binary (md5, sha1)
import Slap.Checksum (ExpectedCRC32(..), ActualCRC32(..))
import Slap.Display.Info (InputSideVerdict(..), OutputSideVerdict(..), renderVerificationReport)
import Slap.FFI (crc32, adler32)
import Slap.FileContents (InputFileContents(..), OutputFileContents(..))
import Slap.Measure (Offset(..), byteFileSize, byteLength)
import Slap.Status (SlapAdvisory(..), SlapError(..), Outcome(..))
import qualified Slap.NINJA1.Create as NINJA1

import Props.Helpers (genNonEmptyByteString)

import Data.Bits (xor)
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.Either (isRight)
import Data.List.NonEmpty (NonEmpty(..))

import Test.Tasty
import Test.Tasty.HUnit
import Test.Tasty.QuickCheck

-- | A source declaration computed from the file's own bytes, so it must hold against them.
declaredFromOwnFacts :: ByteString -> Verification
declaredFromOwnFacts bytes = noVerification
  { verifySourceCRC32 = Just (crc32 bytes)
  , verifySourceMD5   = Just (md5 bytes)
  , verifySourceSHA1  = Just (sha1 bytes)
  , verifyFileSize    = Just (RequiredSize (byteFileSize bytes))
  }

flipByteAt :: Int -> ByteString -> ByteString
flipByteAt flipIndex bytes = ByteString.concat
  [ ByteString.take flipIndex bytes
  , ByteString.singleton (ByteString.index bytes flipIndex `xor` 0xFF)
  , ByteString.drop (flipIndex + 1) bytes
  ]

verifyTests :: TestTree
verifyTests = testGroup "Verify"
  [ testCase "nothing declared is uncheckable, not a pass" $ do
      verdictOnSource noVerification (InputFileContents "any bytes at all") @?= VerdictUncheckable
      verdictOnTarget noVerification (OutputFileContents "any bytes at all") @?= VerdictUncheckable

  , testProperty "a file matches the checks computed from its own bytes" $
      forAll genNonEmptyByteString $ \originalBytes ->
        let verification = declaredFromOwnFacts originalBytes
            enforced = verifySource EnforceVerification verification (InputFileContents originalBytes)
        in verdictOnSource verification (InputFileContents originalBytes)
             === VerdictMatches (DeclaredFileSize :| [DeclaredCRC32, DeclaredMD5, DeclaredSHA1])
           .&&. property (isRight (outcomeValue enforced))
           .&&. outcomeAdvisories enforced === []

  , testProperty "one flipped byte: the verdict differs and enforcement refuses" $
      forAll genNonEmptyByteString $ \originalBytes ->
        forAll (choose (0, ByteString.length originalBytes - 1)) $ \flipIndex ->
          let verification = declaredFromOwnFacts originalBytes
              alteredBytes = InputFileContents (flipByteAt flipIndex originalBytes)
              differs = case verdictOnSource verification alteredBytes of
                VerdictDiffers _ -> True
                _                -> False
              refused = case outcomeValue (verifySource EnforceVerification verification alteredBytes) of
                Left (VerificationFatal _) -> True
                _                          -> False
          in property differs .&&. property refused

  , testCase "a differing CRC32 carries the expected and actual values" $ do
      let originalBytes = "the original rom"
          alteredBytes  = "an unrelated rom"
          verification  = noVerification { verifySourceCRC32 = Just (crc32 originalBytes) }
      case verdictOnSource verification (InputFileContents alteredBytes) of
        VerdictDiffers (VerificationCRCMismatch _ expected actual :| []) -> do
          expected @?= ExpectedCRC32 (crc32 originalBytes)
          actual   @?= ActualCRC32 (crc32 alteredBytes)
        other -> assertFailure ("expected exactly one CRC mismatch, got " ++ show other)

  , testCase "an advisory-only disagreement differs without refusing" $ do
      let verification = noVerification { verifyPPFBlock = Just (ValidationBlock (Offset 0) "GOOD") }
          wrongBytes   = InputFileContents "EVIL bytes here"
          enforced     = verifySource EnforceVerification verification wrongBytes
      case verdictOnSource verification wrongBytes of
        VerdictDiffers (VerificationPPFBlockMismatch _ :| []) -> pure ()
        other -> assertFailure ("expected exactly one validation-block mismatch, got " ++ show other)
      outcomeValue enforced @?= Right ()
      outcomeAdvisories enforced @?= [VerificationPPFBlockMismatch (Offset 0)]

  , testCase "a held advisory-only check is a match, not uncheckable" $ do
      let verification = noVerification { verifyPPFBlock = Just (ValidationBlock (Offset 0) "well") }
      verdictOnSource verification (InputFileContents "well beyond the block")
        @?= VerdictMatches (DeclaredValidationBlock :| [])

  , testCase "held window checksums are a match, not uncheckable" $ do
      let producedBytes = "window contents here"
          windowCheck = WindowCheck (Offset 0) (byteLength producedBytes) (adler32 producedBytes)
          verification = noVerification { verifyWindowAdler32 = [windowCheck] }
      verdictOnTarget verification (OutputFileContents producedBytes)
        @?= VerdictMatches (DeclaredWindowAdler32 :| [])

  , testCase "a required size is enforced and an advisory size only warns" $ do
      let declaredRequired = noVerification { verifyFileSize = Just (RequiredSize (byteFileSize "four")) }
          declaredAdvisory = noVerification { verifyFileSize = Just (AdvisorySize (byteFileSize "four")) }
          wrongLengthBytes = InputFileContents "sixteen bytes!!!"
      case verdictOnSource declaredRequired wrongLengthBytes of
        VerdictDiffers (VerificationFileSizeMismatch {} :| []) -> pure ()
        other -> assertFailure ("expected one required-size mismatch, got " ++ show other)
      case outcomeValue (verifySource EnforceVerification declaredRequired wrongLengthBytes) of
        Left (VerificationFatal _) -> pure ()
        other -> assertFailure ("expected the required size to refuse, got " ++ show other)
      case verdictOnSource declaredAdvisory wrongLengthBytes of
        VerdictDiffers (VerificationFileSizeAdvisory {} :| []) -> pure ()
        other -> assertFailure ("expected one advisory-size mismatch, got " ++ show other)
      let enforcedAdvisory = verifySource EnforceVerification declaredAdvisory wrongLengthBytes
      outcomeValue enforcedAdvisory @?= Right ()
      case outcomeAdvisories enforcedAdvisory of
        [VerificationFileSizeAdvisory {}] -> pure ()
        other -> assertFailure ("expected the advisory size to ride as a warning, got " ++ show other)

  , testCase "the verdict hashes through the declared pre-hash" $ do
      -- Over NINJA1's 30 MiB sampling threshold, so a verdict that hashed the raw bytes would mismatch.
      let sourceBytes  = ByteString.replicate (0x1e00000 + 1) 0xAB
          verification = noVerification
            { verifySourcePreHash = HashNINJA1Sample
            , verifySourceCRC32   = Just (crc32 (NINJA1.ninja1HashInput sourceBytes))
            }
      verdictOnSource verification (InputFileContents sourceBytes)
        @?= VerdictMatches (DeclaredCRC32 :| [])

  , testCase "skip verification never refuses, and the mismatch still rides as a warning" $ do
      let verification = noVerification { verifySourceCRC32 = Just (crc32 "one rom") }
          skipped = verifySource SkipVerification verification (InputFileContents "two rom")
      outcomeValue skipped @?= Right ()
      case outcomeAdvisories skipped of
        [VerificationCRCMismatch {}] -> pure ()
        other -> assertFailure ("expected the CRC mismatch to ride as a warning, got " ++ show other)

  , testCase "the target side mirrors the source split" $ do
      let producedBytes = "the produced target"
          verification  = noVerification { verifyTargetCRC32 = Just (crc32 producedBytes) }
      verdictOnTarget verification (OutputFileContents producedBytes)
        @?= VerdictMatches (DeclaredCRC32 :| [])
      case verdictOnTarget verification (OutputFileContents "not that target") of
        VerdictDiffers _ -> pure ()
        other -> assertFailure ("expected a differing target verdict, got " ++ show other)
      case outcomeValue (verifyTarget EnforceVerification verification (OutputFileContents "not that target")) of
        Left (VerificationFatal _) -> pure ()
        other -> assertFailure ("expected enforcement to refuse the differing target, got " ++ show other)

  , testCase "the report names what each side's match rests on" $
      renderVerificationReport
        (InputSideVerdict (VerdictMatches (DeclaredCRC32 :| [])))
        (OutputSideVerdict (VerdictMatches (DeclaredCRC32 :| [DeclaredMD5, DeclaredSHA1])))
        @?= [ "input matches the patch's CRC"
            , "output matches the patch's CRC, MD5, and SHA1" ]

  , testCase "the report collapses when the patch declares nothing, and stays per-side otherwise" $ do
      renderVerificationReport (InputSideVerdict VerdictUncheckable) (OutputSideVerdict VerdictUncheckable)
        @?= ["the patch carries no checks, so nothing was compared"]
      renderVerificationReport
        (InputSideVerdict (VerdictMatches (DeclaredValidationBlock :| [])))
        (OutputSideVerdict VerdictUncheckable)
        @?= [ "input matches the patch's validation block"
            , "the patch carries no checks for the output" ]

  , testCase "a differing side stays out of the report; its warnings speak" $
      renderVerificationReport
        (InputSideVerdict (VerdictDiffers (VerificationPPFBlockMismatch (Offset 0) :| [])))
        (OutputSideVerdict (VerdictMatches (DeclaredCRC32 :| [])))
        @?= ["output matches the patch's CRC"]
  ]
