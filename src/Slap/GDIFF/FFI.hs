-- | GDIFF differ binding to rusty-slap.
--
-- The Rust side (@rusty-slap/src/gdiff_diff.rs@) owns the source index and the target walk;
-- this module is the seam: it decodes the parallel-array command buffers back into a 'GDiffPatch' —
-- the same commands Parse produces, so create is encoding and nothing else.
-- The data segment is transport only — GDIFF's wire interleaves each DATA command's payload —
-- so the seam slices it into per-command payloads and no segment survives into the Haskell-side vocabulary.
--
-- The narrow Rust-side cause widens to 'SlapError' ('GDIFFDiffFailed') at this seam.
{-# LANGUAGE OverloadedStrings #-}

module Slap.GDIFF.FFI
  ( gdiffDiff
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.Text (Text)
import Data.Word (Word8)
import Foreign.C.Types (CSize(..), CInt(..))
import Foreign.Marshal.Alloc (alloca)
import Foreign.Ptr (Ptr)
import System.IO.Unsafe (unsafePerformIO)

import Slap.Display.Common (renderAsText)
import Slap.Display.Primitives (padHex)
import Slap.Status (SlapError(..), GDIFFDiffCause(..))
import Slap.FFI (readByteString, readText, withByteString, readWord64LE)
import Slap.FileContents (InputFileContents(..), OutputFileContents(..))
import Slap.Measure (Offset(..), Length(..))
import Slap.GDIFF.Types (GDiffPatch(..), GDiffCommand(..))

foreign import ccall unsafe "rusty_gdiff_diff"
  rustyGDiffDiff
    :: Ptr Word8 -> CSize -> Ptr Word8 -> CSize
    -> Ptr (Ptr Word8) -> Ptr CSize    -- command_kinds
    -> Ptr (Ptr Word8) -> Ptr CSize    -- command_source_offsets
    -> Ptr (Ptr Word8) -> Ptr CSize    -- command_lengths
    -> Ptr (Ptr Word8) -> Ptr CSize    -- data_segment
    -> Ptr (Ptr Word8) -> Ptr CSize    -- error_cause
    -> IO CInt

gdiffDiff
  :: InputFileContents
  -> OutputFileContents
  -> Either SlapError GDiffPatch
gdiffDiff (InputFileContents sourceBytes) (OutputFileContents targetBytes) =
  unsafePerformIO $
    withByteString sourceBytes $ \sourcePointer sourceLength ->
    withByteString targetBytes $ \targetPointer targetLength ->
    alloca $ \kindsAddressPointer          ->
    alloca $ \kindsLengthPointer           ->
    alloca $ \sourceOffsetsAddressPointer  ->
    alloca $ \sourceOffsetsLengthPointer   ->
    alloca $ \lengthsAddressPointer        ->
    alloca $ \lengthsLengthPointer         ->
    alloca $ \dataSegmentAddressPointer    ->
    alloca $ \dataSegmentLengthPointer     ->
    alloca $ \errorCauseAddressPointer     ->
    alloca $ \errorCauseLengthPointer      -> do
      returnCode <- rustyGDiffDiff
        sourcePointer sourceLength
        targetPointer targetLength
        kindsAddressPointer         kindsLengthPointer
        sourceOffsetsAddressPointer sourceOffsetsLengthPointer
        lengthsAddressPointer       lengthsLengthPointer
        dataSegmentAddressPointer   dataSegmentLengthPointer
        errorCauseAddressPointer    errorCauseLengthPointer
      if returnCode /= 0
        then do
          rustMessage <- readText errorCauseAddressPointer errorCauseLengthPointer
          pure $ Left (GDIFFDiffFailed (GDIFFDiffCause rustMessage))
        else do
          kindTagBytes      <- readByteString kindsAddressPointer         kindsLengthPointer
          sourceOffsetBytes <- readByteString sourceOffsetsAddressPointer sourceOffsetsLengthPointer
          lengthBytes       <- readByteString lengthsAddressPointer       lengthsLengthPointer
          dataSegmentBytes  <- readByteString dataSegmentAddressPointer   dataSegmentLengthPointer
          -- error_cause is the canonical null buffer on success;
          -- routing it through readByteString frees any allocation
          -- behind it, the same as every other out-pointer.
          _                 <- readByteString errorCauseAddressPointer    errorCauseLengthPointer
          pure (GDiffPatch <$> parseParallelCommands kindTagBytes sourceOffsetBytes lengthBytes dataSegmentBytes)

-- | Reconstruct '[GDiffCommand]' from the three parallel buffers the
-- Rust side surfaces (one byte per kind tag; eight LE bytes per
-- offset; eight LE bytes per length), slicing each DATA command's
-- payload out of the data segment.
-- Buffer-shape mismatches and unknown tag bytes register as typed failures ('GDIFFDiffFailed') rather than runtime exceptions.
parseParallelCommands
  :: ByteString
  -> ByteString
  -> ByteString
  -> ByteString
  -> Either SlapError [GDiffCommand]
parseParallelCommands kindTags commandOffsetBytes commandLengthBytes dataSegment = do
  requireBufferLength "command-source-offsets" commandOffsetBytes
  requireBufferLength "command-lengths"        commandLengthBytes
  traverse decodeOneCommand [0 .. commandCount - 1]
  where
    commandCount = ByteString.length kindTags

    requireBufferLength :: Text -> ByteString -> Either SlapError ()
    requireBufferLength bufferRole buffer
      | ByteString.length buffer == 8 * commandCount = Right ()
      | otherwise = Left $ ffiInvariantFailure $
          bufferRole <> " buffer is " <> renderAsText (ByteString.length buffer)
          <> " bytes, expected " <> renderAsText (8 * commandCount)
          <> " (8 LE bytes per command × " <> renderAsText commandCount <> " commands)"

    decodeOneCommand index = do
      let commandOffset = readWord64LE commandOffsetBytes (8 * index)
          commandLength = readWord64LE commandLengthBytes (8 * index)
      case ByteString.index kindTags index of
        0 -> GDiffCommandData <$> sliceDataPayload (fromIntegral commandOffset) (fromIntegral commandLength)
        1 -> Right (GDiffCommandCopy (Offset (fromIntegral commandOffset)) (Length (fromIntegral commandLength)))
        tagByte -> Left $ ffiInvariantFailure $
          "invalid command kind tag byte 0x" <> padHex 2 tagByte
          <> " (expected 0 = DATA or 1 = COPY)"

    -- A DATA command's offset points into the data segment; a slice
    -- past its end means the parallel buffers disagree with the
    -- segment they describe.
    sliceDataPayload segmentOffset payloadLength
      | segmentOffset + payloadLength <= ByteString.length dataSegment =
          Right (ByteString.take payloadLength (ByteString.drop segmentOffset dataSegment))
      | otherwise = Left $ ffiInvariantFailure $
          "DATA command slice [" <> renderAsText segmentOffset <> ", "
          <> renderAsText (segmentOffset + payloadLength)
          <> ") lies past the data segment's "
          <> renderAsText (ByteString.length dataSegment) <> " bytes"

ffiInvariantFailure :: Text -> SlapError
ffiInvariantFailure detail =
  GDIFFDiffFailed (GDIFFDiffCause ("FFI invariant violation: " <> detail))
