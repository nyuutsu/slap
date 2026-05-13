-- | xdelta1 differ binding to rusty-slap.
--
-- The Rust side ('rusty-slap/src/xdelta1_diff.rs') owns the rolling-
-- checksum index over source, the byte-by-byte target walk, and the
-- bidirectional match extension. This module is the seam: it
-- assembles the FFI call, decodes the parallel-array instruction
-- buffers back into a typed '[XDelta1Instruction]', and lifts the
-- narrow Rust-side cause into 'SlapError' via 'XDelta1DiffFailed'.
--
-- The FFI module has one downstream caller ('Slap.XDelta1.Create'),
-- so the narrower 'Slap.Error.XDelta1DiffCause' is wrapped here
-- rather than being threaded further out.
module Slap.XDelta1.FFI
  ( XDelta1DiffOutput(..)
  , xdelta1Diff
  ) where

import Data.Bits ((.|.), shiftL)
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Unsafe as UnsafeByteString
import Data.Word (Word8, Word64)
import Foreign.C.Types (CSize(..), CInt(..))
import Foreign.Marshal.Alloc (alloca)
import Foreign.Ptr (Ptr, castPtr)
import Foreign.Storable (peek)
import System.IO.Unsafe (unsafeDupablePerformIO)

import Slap.Display.Primitives (padHex)
import Slap.Error (SlapError(..), XDelta1DiffCause(..))
import Slap.FFI (readByteString, readString)
import Slap.FileContents (InputFileContents(..), OutputFileContents(..))
import Slap.Measure (Offset(..), FileSize(..))
import Slap.XDelta1.Types
    ( XDelta1Instruction(..)
    , XDelta1InstructionTarget(..)
    )

-- | The xdelta1 differ's output, marshaled out of Rust into typed
-- Haskell. Instruction order is emission order, preserved across the
-- FFI seam by parallel-array serialization (one Rust buffer per
-- instruction field) and zip3-style reconstruction on this side.
data XDelta1DiffOutput = XDelta1DiffOutput
  { xdelta1DiffInstructions             :: ![XDelta1Instruction]
  , xdelta1DiffDataSegment              :: !ByteString
  , xdelta1DiffDataSourceIsSequential   :: !Bool
  , xdelta1DiffFileSourceIsSequential   :: !Bool
  }
  deriving (Show, Eq)

foreign import ccall unsafe "rusty_xdelta1_diff"
  rustyXDelta1Diff
    :: Ptr Word8 -> CSize -> Ptr Word8 -> CSize
    -> Ptr (Ptr Word8) -> Ptr CSize    -- instruction_targets
    -> Ptr (Ptr Word8) -> Ptr CSize    -- instruction_source_offsets
    -> Ptr (Ptr Word8) -> Ptr CSize    -- instruction_lengths
    -> Ptr (Ptr Word8) -> Ptr CSize    -- data_segment
    -> Ptr Word8                       -- data_source_is_sequential
    -> Ptr Word8                       -- file_source_is_sequential
    -> Ptr (Ptr Word8) -> Ptr CSize    -- error_cause
    -> IO CInt

-- | Invoke the Rust xdelta1 differ. Marshals the parallel-array FFI
-- output back into typed Haskell; lifts the Rust-side cause into
-- 'SlapError' via 'XDelta1DiffFailed' at this seam.
xdelta1Diff
  :: InputFileContents
  -> OutputFileContents
  -> Either SlapError XDelta1DiffOutput
xdelta1Diff (InputFileContents sourceBytes) (OutputFileContents targetBytes) =
  unsafeDupablePerformIO $
    UnsafeByteString.unsafeUseAsCStringLen sourceBytes $ \(sourcePointer, sourceLength) ->
    UnsafeByteString.unsafeUseAsCStringLen targetBytes $ \(targetPointer, targetLength) ->
    alloca $ \targetsAddressPointer        ->
    alloca $ \targetsLengthPointer         ->
    alloca $ \sourceOffsetsAddressPointer  ->
    alloca $ \sourceOffsetsLengthPointer   ->
    alloca $ \lengthsAddressPointer        ->
    alloca $ \lengthsLengthPointer         ->
    alloca $ \dataSegmentAddressPointer    ->
    alloca $ \dataSegmentLengthPointer     ->
    alloca $ \dataSourceFlagPointer        ->
    alloca $ \fileSourceFlagPointer        ->
    alloca $ \errorCauseAddressPointer     ->
    alloca $ \errorCauseLengthPointer      -> do
      returnCode <- rustyXDelta1Diff
        (castPtr sourcePointer) (fromIntegral sourceLength)
        (castPtr targetPointer) (fromIntegral targetLength)
        targetsAddressPointer       targetsLengthPointer
        sourceOffsetsAddressPointer sourceOffsetsLengthPointer
        lengthsAddressPointer       lengthsLengthPointer
        dataSegmentAddressPointer   dataSegmentLengthPointer
        dataSourceFlagPointer
        fileSourceFlagPointer
        errorCauseAddressPointer    errorCauseLengthPointer
      if returnCode /= 0
        then do
          rustMessage <- readString errorCauseAddressPointer errorCauseLengthPointer
          pure $ Left (XDelta1DiffFailed (XDelta1DiffCause rustMessage))
        else do
          targetTagBytes      <- readByteString targetsAddressPointer       targetsLengthPointer
          sourceOffsetBytes   <- readByteString sourceOffsetsAddressPointer sourceOffsetsLengthPointer
          lengthBytes         <- readByteString lengthsAddressPointer       lengthsLengthPointer
          dataSegmentBytes    <- readByteString dataSegmentAddressPointer   dataSegmentLengthPointer
          dataSourceFlagByte  <- peek dataSourceFlagPointer
          fileSourceFlagByte  <- peek fileSourceFlagPointer
          -- The success path's error_cause is canonically the empty
          -- buffer (null pointer, zero length). Free defensively in
          -- case a future Rust-side change starts writing one.
          _                   <- readByteString errorCauseAddressPointer    errorCauseLengthPointer
          case parseParallelInstructions targetTagBytes sourceOffsetBytes lengthBytes of
            Left slapError ->
              pure (Left slapError)
            Right instructions ->
              pure $ Right XDelta1DiffOutput
                { xdelta1DiffInstructions           = instructions
                , xdelta1DiffDataSegment            = dataSegmentBytes
                , xdelta1DiffDataSourceIsSequential = dataSourceFlagByte /= 0
                , xdelta1DiffFileSourceIsSequential = fileSourceFlagByte /= 0
                }

-- | Reconstruct '[XDelta1Instruction]' from the three parallel
-- buffers the Rust side surfaces (one byte per target tag; eight LE
-- bytes per source offset; eight LE bytes per length). Buffer-shape
-- mismatches and unknown tag bytes register as typed failures
-- ('XDelta1DiffFailed') rather than runtime exceptions — Rust never
-- emits them, surfacing the impossible-case as a structured failure
-- is the slap discipline of "do not shut up".
parseParallelInstructions
  :: ByteString
  -> ByteString
  -> ByteString
  -> Either SlapError [XDelta1Instruction]
parseParallelInstructions targetTags sourceOffsetBytes lengthBytes
  | ByteString.length sourceOffsetBytes /= 8 * instructionCount =
      Left $ ffiInvariantFailure $
        "instruction-source-offsets buffer is " ++ show (ByteString.length sourceOffsetBytes)
        ++ " bytes, expected " ++ show (8 * instructionCount)
        ++ " (8 LE bytes per instruction × " ++ show instructionCount ++ " instructions)"
  | ByteString.length lengthBytes /= 8 * instructionCount =
      Left $ ffiInvariantFailure $
        "instruction-lengths buffer is " ++ show (ByteString.length lengthBytes)
        ++ " bytes, expected " ++ show (8 * instructionCount)
        ++ " (8 LE bytes per instruction × " ++ show instructionCount ++ " instructions)"
  | otherwise =
      traverse decodeOneInstruction [0 .. instructionCount - 1]
  where
    instructionCount = ByteString.length targetTags

    decodeOneInstruction index = do
      instructionTarget <- decodeTargetTag (ByteString.index targetTags index)
      let sourceOffset      = readWord64LE sourceOffsetBytes (8 * index)
          instructionLength = readWord64LE lengthBytes       (8 * index)
      pure XDelta1Instruction
        { xdelta1InstructionTarget = instructionTarget
        , xdelta1InstructionOffset = Offset   (fromIntegral sourceOffset)
        , xdelta1InstructionLength = FileSize (fromIntegral instructionLength)
        }

    decodeTargetTag tagByte = case tagByte of
      0 -> Right FromDataSource
      1 -> Right FromFileSource
      _ -> Left $ ffiInvariantFailure $
             "invalid instruction target tag byte 0x" ++ padHex 2 tagByte
             ++ " (expected 0 = data source or 1 = file source)"

ffiInvariantFailure :: String -> SlapError
ffiInvariantFailure detail =
  XDelta1DiffFailed (XDelta1DiffCause ("FFI invariant violation: " ++ detail))

readWord64LE :: ByteString -> Int -> Word64
readWord64LE buffer offset =
  let byteAt index = fromIntegral (ByteString.index buffer (offset + index)) :: Word64
  in       byteAt 0
    .|. (byteAt 1 `shiftL` 8)
    .|. (byteAt 2 `shiftL` 16)
    .|. (byteAt 3 `shiftL` 24)
    .|. (byteAt 4 `shiftL` 32)
    .|. (byteAt 5 `shiftL` 40)
    .|. (byteAt 6 `shiftL` 48)
    .|. (byteAt 7 `shiftL` 56)
