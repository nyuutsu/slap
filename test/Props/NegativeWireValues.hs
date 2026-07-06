{-# LANGUAGE OverloadedStrings #-}

-- | A hostile wire value — negative where a format expects
-- non-negative, or so large a summed bound would wrap — is malformed,
-- and slap answers it with a typed error that names the actual wall:
-- not the generic "writes past target" the bounds primitive would
-- otherwise return, and not the decompression failure a wrong slicing
-- would produce downstream.
--
-- 'Slap.Measure.fitsWithin' is already total (see 'Props.Measure'), so
-- a negative operand is *safe*: it answers "does not fit" and the write
-- never happens. The apply-time tests cover the layer above that — the
-- guards that turn "does not fit" into a precise message:
-- 'ApplyNegativeRecordOffset' for a NINJA2 record offset that decoded
-- negative from its packed integer, and 'ApplyNegativeControlLength'
-- for a bsdiff control instruction whose sign-magnitude add or copy
-- length came in negative. (bsdiff's seek delta in the same triple is
-- legitimately signed and is deliberately not caught.) The parse-time
-- tests cover the bsdiff header's sequential fit checks: two hostile
-- near-2^63 declared sizes would wrap a summed bound and slip through
-- as a decompression failure; sequential comparison keeps the verdict
-- a header verdict naming the block.
module Props.NegativeWireValues (negativeWireValuesTests) where

import Slap.BSDiff.Types (BSDiffPatch(..), BSDiffInstruction(..), bsdiffMagicBytes)
import Slap.BSDiff.Apply (applyBSDiff)
import Slap.BSDiff.Create (putSignMagnitude64)
import qualified Slap.BSDiff.Parse as BSDiff
import Slap.NINJA2.Types (NINJA2Patch(..), NINJA2Record(..))
import Slap.NINJA2.Apply (applyNINJA2)
import qualified Slap.NINJA2.Parse as NINJA2
import Slap.Create (createNINJA2)
import Slap.Status (SlapError(..), ApplyError(..), CreateResult(..),
                    BSDiffHeaderMalformation(..), Parsed(..), renderSlapError)
import Slap.FormatLabel (FormatLabel(..))
import Slap.Measure (Offset(..), Length(..), FileSize(..), Delta(..))
import Slap.FileContents (InputFileContents(..), OutputFileContents(..), PatchFileContents(..))
import qualified Slap.Text as SlapText

import Props.Helpers (emptyNINJA2Metadata, assertFailureT)

import qualified Data.ByteString as ByteString
import Data.ByteString.Builder (toLazyByteString, byteString)
import qualified Data.ByteString.Lazy as LazyByteString
import Data.Int (Int64)

import Test.Tasty
import Test.Tasty.HUnit

negativeWireValuesTests :: TestTree
negativeWireValuesTests = testGroup "hostile wire values are named, not mislabelled"
  [ testCase "bsdiff: a negative add length is refused as a negative control length"
      bsdiffNegativeAddLength
  , testCase "bsdiff: a negative copy length is refused as a negative control length"
      bsdiffNegativeCopyLength
  , testCase "bsdiff: a control size past the patch end is a header verdict"
      bsdiffControlOverrunNamed
  , testCase "bsdiff: hostile control and diff sizes cannot wrap past the guard"
      bsdiffHostileSizesCannotWrap
  , testCase "NINJA2: a negative record offset is refused as a negative record offset"
      ninja2NegativeRecordOffset
  ]

-- | A bsdiff patch whose single instruction declares an add region of
-- negative length. The apply must refuse with 'ApplyNegativeControlLength',
-- naming the malformed instruction, rather than summing the negative
-- length into a bounds verdict. The compressed-size fields and the
-- diff\/extra streams play no part in this rejection, so the patch is
-- built as a value directly — no bzip2 framing needed to reach the guard.
bsdiffNegativeAddLength :: Assertion
bsdiffNegativeAddLength =
  assertNegativeControlLength
    (bsdiffPatchWithInstruction (BSDiffInstruction (Length (-1)) (Length 0) (Delta 0)))

-- | As 'bsdiffNegativeAddLength', but the copy region carries the
-- negative length. The add region is a well-formed no-op, so the walk
-- reaches the copy-region guard.
bsdiffNegativeCopyLength :: Assertion
bsdiffNegativeCopyLength =
  assertNegativeControlLength
    (bsdiffPatchWithInstruction (BSDiffInstruction (Length 0) (Length (-1)) (Delta 0)))

-- | A bsdiff patch carrying exactly one control instruction, a positive
-- declared target size, and empty diff\/extra streams.
bsdiffPatchWithInstruction :: BSDiffInstruction -> BSDiffPatch
bsdiffPatchWithInstruction instruction = BSDiffPatch
  { bsdiffControlSize  = Length 0
  , bsdiffDiffSize     = Length 0
  , bsdiffExtraSize    = Length 0
  , bsdiffTargetSize   = FileSize 4
  , bsdiffInstructions = [instruction]
  , bsdiffDiffData     = ByteString.empty
  , bsdiffExtraData    = ByteString.empty
  }

-- | A 32-byte header and nothing else: the declared sizes are the
-- whole hostile payload.
bsdiffHeaderOnlyPatch :: Int64 -> Int64 -> PatchFileContents
bsdiffHeaderOnlyPatch declaredControlSize declaredDiffSize =
  PatchFileContents . LazyByteString.toStrict . toLazyByteString $
    byteString bsdiffMagicBytes
    <> putSignMagnitude64 declaredControlSize
    <> putSignMagnitude64 declaredDiffSize
    <> putSignMagnitude64 4  -- declared target size; never reached

-- | A control size past the empty body must be named as the control
-- block's overrun, before any slicing or decompression runs.
bsdiffControlOverrunNamed :: Assertion
bsdiffControlOverrunNamed =
  case BSDiff.parseBSDiff (bsdiffHeaderOnlyPatch 24 0) of
    Left (MalformedBSDiffHeader (BSDiffControlOverrunsPatch 24)) -> pure ()
    Left other -> assertFailureT
      ("expected a control-overrun header verdict, got: " <> renderSlapError other)
    Right _ -> assertFailure
      "expected parse to refuse the overrunning control size, but it succeeded"

-- | Two near-2^63 declared sizes drive a summed bound past the Int64
-- floor and back to positive — the shape that would slip a
-- subtraction-chain guard and explode later as a decompression
-- failure. The sequential checks name the first wall instead.
bsdiffHostileSizesCannotWrap :: Assertion
bsdiffHostileSizesCannotWrap =
  let nearCeiling = 0x7000000000000000
  in case BSDiff.parseBSDiff (bsdiffHeaderOnlyPatch nearCeiling nearCeiling) of
       Left (MalformedBSDiffHeader (BSDiffControlOverrunsPatch overrun)) ->
         assertEqual "overrun distance" nearCeiling overrun
       Left other -> assertFailureT
         ("expected a control-overrun header verdict, got: " <> renderSlapError other)
       Right _ -> assertFailure
         "expected parse to refuse the hostile sizes, but it succeeded"

assertNegativeControlLength :: BSDiffPatch -> Assertion
assertNegativeControlLength patch =
  case applyBSDiff patch (InputFileContents ByteString.empty) of
    Left (ApplyFailed LabelBSDiff (ApplyNegativeControlLength _ _)) -> pure ()
    Left other -> assertFailureT
      ("expected a negative-control-length error, got: " <> renderSlapError other)
    Right _ -> assertFailure
      "expected apply to refuse the negative control length, but it succeeded"

-- | A real NINJA2 patch (created from a one-byte difference, so it
-- carries a genuine header) with its record list replaced by a single
-- record whose offset is negative — the value a packed integer with its
-- top bit set decodes to. The apply must refuse with
-- 'ApplyNegativeRecordOffset', naming the offset, rather than reporting
-- a write past the target.
ninja2NegativeRecordOffset :: Assertion
ninja2NegativeRecordOffset =
  let source = ByteString.pack [0, 1, 2, 3, 4, 5, 6, 7]
      target = ByteString.pack [0, 1, 2, 3, 4, 5, 6, 9]
  in case createNINJA2 (InputFileContents source) (OutputFileContents target)
                       emptyNINJA2Metadata of
       Left err -> assertFailureT ("NINJA2 create failed: " <> renderSlapError err)
       Right (CreateResult patchBytes _) ->
         case NINJA2.parseNINJA2 SlapText.EncodingUtf8 patchBytes of
           Left err -> assertFailureT ("NINJA2 parse failed: " <> renderSlapError err)
           Right (Parsed parsedPatch _) ->
             let tamperedPatch = parsedPatch
                   { ninja2Records = [NINJA2Record (Offset (-1)) (ByteString.pack [0xAB])] }
             in case applyNINJA2 tamperedPatch (InputFileContents source) of
                  Left (ApplyFailed LabelNINJA2 (ApplyNegativeRecordOffset _ _)) -> pure ()
                  Left other -> assertFailureT
                    ("expected a negative-record-offset error, got: " <> renderSlapError other)
                  Right _ -> assertFailure
                    "expected apply to refuse the negative record offset, but it succeeded"
