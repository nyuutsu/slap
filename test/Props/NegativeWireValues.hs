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
--
-- A separate apply-time shape is the absolute write whose start already
-- sits past the target's end: an APSN64 record against its declared
-- destination, or a PPF3 undo run against the wrong modified file. The
-- forward-cursor refusal 'ApplyWritesPastTarget' would describe it as
-- remaining space — target size minus offset — but that subtraction
-- throws when the offset is the larger, so these sites carry offset and
-- size raw in 'ApplyAbsoluteWritePastTarget'. The tests force the whole
-- rendered message, because the field is lazy: the wrong constructor
-- would carry the throwing subtraction unforced and blow up only here.
module Props.NegativeWireValues (negativeWireValuesTests) where

import Slap.BSDiff.Types (BSDiffPatch(..), BSDiffInstruction(..), bsdiffMagicBytes)
import Slap.BSDiff.Apply (applyBSDiff)
import Slap.BSDiff.Create (putSignMagnitude64)
import qualified Slap.BSDiff.Parse as BSDiff
import Slap.NINJA2.Types (NINJA2Patch(..), NINJA2Record(..))
import Slap.NINJA2.Apply (applyNINJA2)
import qualified Slap.NINJA2.Parse as NINJA2
import Slap.APSN64.Types (APSN64Patch(..), APSN64Header(..), APSN64Record(..),
                          APSPatchType(..), apsN64DestinationSizeFromParsed)
import Slap.APSN64.Apply (applyAPSN64)
import Slap.PPF3.Types (PPF3Patch(..), PPF3Record(..), PPF3ImageType(..))
import Slap.PPF3.Apply (undoPPF3)
import Slap.Create (createNINJA2)
import Slap.Status (SlapError(..), ApplyError(..), CreateResult(..),
                    BSDiffHeaderMalformation(..), Parsed(..), renderSlapError)
import Control.Exception (evaluate)
import qualified Data.Text as Text
import Slap.FormatLabel (FormatLabel(..))
import Slap.Measure (Offset(..), Length(..), FileSize(..), Delta(..))
import Slap.FileContents (InputFileContents(..), OutputFileContents(..), PatchFileContents(..))
import qualified Slap.Text as SlapText

import Props.Helpers (emptyNINJA2Metadata, assertFailureT)

import qualified Data.ByteString as ByteString
import qualified Data.Vector as Vector
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
  , testCase "APSN64: a record starting past the destination renders, not crashes"
      apsn64AbsoluteWritePastTarget
  , testCase "PPF3 undo: a record starting past the modified file renders, not crashes"
      ppf3UndoAbsoluteWritePastTarget
  ]

-- | An APS-N64 patch whose destination is 10 bytes and whose single
-- record writes 5 bytes at offset 100 — the start alone is 90 past the
-- end. Apply must refuse with 'ApplyAbsoluteWritePastTarget'.
apsn64AbsoluteWritePastTarget :: Assertion
apsn64AbsoluteWritePastTarget =
  assertAbsoluteWritePastTarget "APSN64" $
    applyAPSN64 apsn64OutOfBoundsPatch (InputFileContents ByteString.empty)

apsn64OutOfBoundsPatch :: APSN64Patch
apsn64OutOfBoundsPatch = APSN64Patch header (Vector.singleton record)
  where
    header = APSN64Header
      { apsN64PatchType       = APSSimple
      , apsN64Description     = SlapText.EncodedText SlapText.EncodingUtf8 Text.empty
      , apsN64ImageFormat     = Nothing
      , apsN64CartId          = Nothing
      , apsN64Country         = Nothing
      , apsN64Crc             = Nothing
      , apsN64DestinationSize = apsN64DestinationSizeFromParsed 10
      }
    record = APSN64Normal (Offset 100) (ByteString.pack [1, 2, 3, 4, 5])

-- | A PPF3 patch carrying undo data whose one record's undo write lands
-- at offset 100, run against a 10-byte modified file: the everyday
-- undo-against-the-wrong-file mistake. Undo must refuse with
-- 'ApplyAbsoluteWritePastTarget'.
ppf3UndoAbsoluteWritePastTarget :: Assertion
ppf3UndoAbsoluteWritePastTarget =
  assertAbsoluteWritePastTarget "PPF3 undo" $
    undoPPF3 ppf3OutOfBoundsUndoPatch (OutputFileContents (ByteString.replicate 10 0x00))

ppf3OutOfBoundsUndoPatch :: PPF3Patch
ppf3OutOfBoundsUndoPatch = PPF3Patch
  { ppf3Description     = SlapText.EncodedText SlapText.EncodingUtf8 Text.empty
  , ppf3ImageType       = BIN
  , ppf3HasUndo         = True
  , ppf3ValidationBlock = Nothing
  , ppf3Records         = [PPF3Record (Offset 100) payload (Just payload)]
  , ppf3FileId          = Nothing
  }
  where
    payload = ByteString.pack [1, 2, 3, 4, 5]

-- | Match the absolute-write refusal and force the whole rendered
-- message. Forcing is the point: the pre-fix 'ApplyWritesPastTarget'
-- carried a throwing remaining-length subtraction that a lazy field
-- left unforced until render.
assertAbsoluteWritePastTarget :: Text.Text -> Either SlapError a -> Assertion
assertAbsoluteWritePastTarget label result =
  case result of
    Left err | isAbsoluteWritePastTarget err -> do
      rendered <- evaluate (renderSlapError err)
      _        <- evaluate (Text.length rendered)
      assertBool (Text.unpack label <> ": rendered refusal is empty")
                 (not (Text.null rendered))
    Left other -> assertFailureT
      (label <> ": expected an absolute-write-past-target refusal, got: "
             <> renderSlapError other)
    Right _ -> assertFailureT
      (label <> ": expected the out-of-bounds write to be refused, but it succeeded")

isAbsoluteWritePastTarget :: SlapError -> Bool
isAbsoluteWritePastTarget (ApplyFailed _ ApplyAbsoluteWritePastTarget{}) = True
isAbsoluteWritePastTarget (UndoFailed  _ ApplyAbsoluteWritePastTarget{}) = True
isAbsoluteWritePastTarget _                                              = False

-- | A bsdiff patch whose single instruction declares an add region of negative length.
-- Apply must refuse with 'ApplyNegativeControlLength', naming the malformed instruction, not fold the negative length into a bounds verdict.
-- The patch is built directly, no bzip2 framing — but its diff stream must cover the declared target size,
-- since the declared-size ceiling runs before the instruction walk and only a patch that clears it reaches this guard.
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

-- | A bsdiff patch with one control instruction, a positive target size, and a diff stream that covers it,
-- so the declared-size ceiling passes and the instruction walk is reached.
bsdiffPatchWithInstruction :: BSDiffInstruction -> BSDiffPatch
bsdiffPatchWithInstruction instruction = BSDiffPatch
  { bsdiffControlSize  = Length 0
  , bsdiffDiffSize     = Length 4
  , bsdiffExtraSize    = Length 0
  , bsdiffTargetSize   = FileSize 4
  , bsdiffInstructions = [instruction]
  , bsdiffDiffData     = ByteString.replicate 4 0x00
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
