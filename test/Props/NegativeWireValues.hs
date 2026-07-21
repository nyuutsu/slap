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
-- negative from its packed integer. A bsdiff instruction's sign-magnitude
-- add or copy length is answered a layer earlier, at parse, since a
-- length no region can have makes the whole patch malformed rather than
-- one action of it. (bsdiff's seek delta in the same triple is
-- legitimately signed and is deliberately not caught.) The parse-time
-- tests cover that refusal and the bsdiff header's sequential fit checks: two hostile
-- near-2^63 declared sizes would wrap a summed bound and slip through
-- as a decompression failure; sequential comparison keeps the verdict
-- a header verdict naming the block.
--
-- The absolute-write refusal 'ApplyAbsoluteWritePastTarget' carries its offset and size raw,
-- where 'ApplyWritesPastTarget' carries a remaining-length whose subtraction throws when the offset is the larger.
-- That is the APSN64 and PPF3-undo case; the field is lazy, so the tests force the whole rendered message, where the crash lived.
--
-- Two formats size their output by summing independent declared sizes — VCDIFF's windows laid end to end, GDIFF's commands —
-- where every other sizes by a single field or a max-fold, so these two alone can carry a running total past 'Int64'.
-- Both fold 'boundedWriteEnd' to refuse the overrun rather than wrap a short buffer the write walk would run past.
module Props.NegativeWireValues (negativeWireValuesTests) where

import Slap.BSDiff.Types (bsdiffMagicBytes)
import Slap.BSDiff.Create (putSignMagnitude64)
import Slap.Compression.Stream (bzip2Compress)
import qualified Slap.BSDiff.Parse as BSDiff
import Slap.NINJA2.Types (NINJA2Patch(..), NINJA2Record(..))
import Slap.NINJA2.Apply (applyNINJA2)
import qualified Slap.NINJA2.Parse as NINJA2
import Slap.APSN64.Types (APSN64Patch(..), APSN64Header(..), APSN64Record(..),
                          APSPatchType(..), apsN64DestinationSizeFromParsed)
import Slap.APSN64.Apply (applyAPSN64)
import Slap.PPF3.Types (PPF3Patch(..), PPF3Record(..), PPF3ImageType(..))
import Slap.PPF3.Apply (undoPPF3)
import Slap.VCDIFF.Types (VCDIFFPatch(..), Window(..))
import Slap.VCDIFF.Apply (applyVCDIFF)
import Slap.PMSR.Types (pmsrMagicBytes)
import qualified Slap.PMSR.Parse as PMSR
import Slap.Binary (putWord32BE)
import Slap.GDIFF.Types (GDiffCommand(..))
import Slap.GDIFF.Apply (validateCommands)
import Slap.Create (createNINJA2)
import Slap.Status (SlapError(..), ApplyError(..), CreateResult(..),
                    BSDiffHeaderMalformation(..), Parsed(..), renderSlapError, renderApplyError)
import Control.Exception (evaluate)
import qualified Data.Text as Text
import Slap.FormatLabel (FormatLabel(..))
import Slap.Measure (Offset(..), Length(..), FileSize(..), ParsedSizeValue(..))
import Slap.FileContents (InputFileContents(..), OutputFileContents(..), PatchFileContents(..))
import qualified Slap.Text as SlapText

import Props.Helpers (emptyNINJA2Metadata, assertFailureT)

import qualified Data.ByteString as ByteString
import qualified Data.Vector as Vector
import Data.ByteString.Builder (toLazyByteString, byteString)
import qualified Data.ByteString.Lazy as LazyByteString
import Data.Int (Int64)
import Data.Word (Word32)

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
  , testCase "PMSR: a record offset in the signed half of its field is refused at parse"
      pmsrNegativeRecordOffset
  , testCase "NINJA2: a negative record offset is refused as a negative record offset"
      ninja2NegativeRecordOffset
  , testCase "APSN64: a record starting past the destination renders, not crashes"
      apsn64AbsoluteWritePastTarget
  , testCase "PPF3 undo: a record starting past the modified file renders, not crashes"
      ppf3UndoAbsoluteWritePastTarget
  , testCase "VCDIFF: window target sizes summing past Int64 are refused, not wrapped"
      vcdiffSummedTargetSizeWraps
  , testCase "GDIFF: command outputs summing past Int64 are refused, not wrapped"
      gdiffSummedOutputExtentWraps
  ]

-- | Two windows each declaring 2^62 target bytes: laid end to end the total reaches 2^63, one past 'Int64',
-- where a bare sum wraps negative. The refusal lands in the size fold before any window is walked, so the bodies are left empty.
vcdiffSummedTargetSizeWraps :: Assertion
vcdiffSummedTargetSizeWraps =
  let hugeWindow = Window Nothing (FileSize 0x4000000000000000) Vector.empty
      patch      = PatchCoreOnly (Vector.fromList [hugeWindow, hugeWindow])
  in assertOutputExceedsAddressable "VCDIFF" $
       applyVCDIFF patch (InputFileContents ByteString.empty)

-- | Two COPY commands each reading 2^62 bytes from a source large enough that each read is in bounds alone,
-- so the walk clears the source-range check and reaches the output-extent fold, where the two sum past 'Int64'.
-- Driven through 'validateCommands' directly — through 'applyGDIFF' it would need a 2^63-byte source on disk.
gdiffSummedOutputExtentWraps :: Assertion
gdiffSummedOutputExtentWraps =
  case validateCommands sourceCoveringEachCopy [hugeCopy, hugeCopy] of
    Left ApplyOutputExceedsAddressableRange{} -> pure ()
    Left other -> assertFailureT
      ("GDIFF: expected an addressable-range refusal, got: " <> renderApplyError other)
    Right _ -> assertFailure
      "GDIFF: expected the summed output extent to be refused, but it succeeded"
  where
    hugeCopy               = GDiffCommandCopy { gdiffCopyOffset = Offset 0
                                              , gdiffCopyLength = Length 0x4000000000000000 }
    sourceCoveringEachCopy = FileSize maxBound

-- | As 'assertAbsoluteWritePastTarget', for the addressable-range refusal.
assertOutputExceedsAddressable :: Text.Text -> Either SlapError a -> Assertion
assertOutputExceedsAddressable label result =
  case result of
    Left err | isOutputExceedsAddressable err -> do
      rendered <- evaluate (renderSlapError err)
      _        <- evaluate (Text.length rendered)
      assertBool (Text.unpack label <> ": rendered refusal is empty")
                 (not (Text.null rendered))
    Left other -> assertFailureT
      (label <> ": expected an addressable-range refusal, got: " <> renderSlapError other)
    Right _ -> assertFailureT
      (label <> ": expected the summed extent to be refused, but it succeeded")

isOutputExceedsAddressable :: SlapError -> Bool
isOutputExceedsAddressable (ApplyFailed _ ApplyOutputExceedsAddressableRange{}) = True
isOutputExceedsAddressable _                                                    = False

-- | Destination 10 bytes, one record writing 5 bytes at offset 100 — the start alone sits 90 past the end.
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

-- | Undo data writing at offset 100 against a 10-byte modified file — the everyday
-- undo-against-the-wrong-file mistake.
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

-- | Match the refusal and force its whole rendered text.
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
-- Parse must refuse it by name, not leave it for a bounds verdict downstream to fold into "does not fit".
-- The patch carries real bzip2 framing, and its diff stream must cover the declared target size,
-- since the declared-size ceiling runs before the instruction walk and only a patch that clears it reaches this refusal.
bsdiffNegativeAddLength :: Assertion
bsdiffNegativeAddLength =
  assertNegativeInstructionLength (bsdiffPatchWithInstructionBytes (-1) 0 0)

-- | As 'bsdiffNegativeAddLength', but the copy region carries the
-- negative length. The add region is a well-formed no-op, so the walk
-- reaches the copy-region guard.
bsdiffNegativeCopyLength :: Assertion
bsdiffNegativeCopyLength =
  assertNegativeInstructionLength (bsdiffPatchWithInstructionBytes 0 (-1) 0)

-- | A bsdiff patch with one control instruction, a positive target size, and a diff stream that covers it,
-- so the declared-size ceiling passes and the instruction walk is reached.
-- | One bsdiff instruction, bzip2-framed as a whole patch, so the refusal is reached the way a real patch would reach it.
-- The diff stream covers the 4-byte declared target; the extra stream is empty.
bsdiffPatchWithInstructionBytes :: Int64 -> Int64 -> Int64 -> PatchFileContents
bsdiffPatchWithInstructionBytes addLength copyLength seekDelta =
  let instruction = toStrictBytes
        (putSignMagnitude64 addLength <> putSignMagnitude64 copyLength <> putSignMagnitude64 seekDelta)
      controlCompressed = bzip2Compress instruction
      diffCompressed    = bzip2Compress (ByteString.replicate 4 0x00)
      extraCompressed   = bzip2Compress ByteString.empty
      header = toStrictBytes
        (  byteString bsdiffMagicBytes
        <> putSignMagnitude64 (fromIntegral (ByteString.length controlCompressed))
        <> putSignMagnitude64 (fromIntegral (ByteString.length diffCompressed))
        <> putSignMagnitude64 4 )
  in PatchFileContents (header <> controlCompressed <> diffCompressed <> extraCompressed)
  where
    toStrictBytes = LazyByteString.toStrict . toLazyByteString

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

assertNegativeInstructionLength :: PatchFileContents -> Assertion
assertNegativeInstructionLength patchBytes =
  case BSDiff.parseBSDiff patchBytes of
    Left (NegativeRecordLength LabelBSDiff _ (ParsedSizeValue (-1))) -> pure ()
    Left other -> assertFailureT
      ("expected a negative-length verdict, got: " <> renderSlapError other)
    Right _ -> assertFailure
      "expected parse to refuse the negative instruction length, but it succeeded"

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

-- | Star Rod writes a PMSR offset with ByteBuffer.putInt, so the top bit of that four-byte field is a sign.
-- A patch setting it names a position no buffer has room for, and one Star Rod could neither write nor read back;
-- parse refuses it there rather than let the apply walk take it to a raw pointer.
pmsrNegativeRecordOffset :: Assertion
pmsrNegativeRecordOffset =
  case PMSR.parsePMSR (pmsrPatchWithOffset 0x80000000) of
    Left (NegativeRecordOffset LabelPMSR _ (Offset (-2147483648))) -> pure ()
    Left other -> assertFailureT
      ("expected a negative-record-offset verdict, got: " <> renderSlapError other)
    Right _ -> assertFailure
      "expected parse to refuse the signed-half offset, but it succeeded"

-- | One PMSR record carrying a single byte at the given offset, magic and count included.
pmsrPatchWithOffset :: Word32 -> PatchFileContents
pmsrPatchWithOffset wireOffset =
  PatchFileContents . LazyByteString.toStrict . toLazyByteString $
    byteString pmsrMagicBytes
    <> putWord32BE 1
    <> putWord32BE wireOffset
    <> putWord32BE 1
    <> byteString (ByteString.singleton 0xAA)
