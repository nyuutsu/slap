-- | bsdiff differ binding to rusty-slap.
--
-- The Rust side ('rusty-slap/src/bsdiff_diff.rs') owns the source
-- index, the scan walk, and the region extension. This module is the
-- seam: it assembles the FFI call, decodes the parallel-array triple
-- buffers back into the '[BSDiffInstruction]' vocabulary the parse
-- side already speaks, and lifts the narrow Rust-side cause into
-- 'SlapError' via 'BSDiffDifferFailed'.
--
-- The FFI module has one downstream caller ('Slap.BSDiff.Create'),
-- so the narrower 'Slap.Status.BSDiffDifferCause' is wrapped here
-- rather than being threaded further out.
{-# LANGUAGE OverloadedStrings #-}

module Slap.BSDiff.FFI
  ( BSDiffDifferOutput(..)
  , bsdiffDiff
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.Text (Text)
import Data.Word (Word8)
import Foreign.C.Types (CSize(..), CInt(..))
import Foreign.Marshal.Alloc (alloca)
import Foreign.Ptr (Ptr)
import System.IO.Unsafe (unsafePerformIO)

import Slap.BSDiff.Types (BSDiffInstruction(..))
import Slap.Display.Common (renderAsText)
import Slap.FFI (readByteString, readText, withByteString, readWord64LE)
import Slap.FileContents (InputFileContents(..), OutputFileContents(..))
import Slap.Measure (Length(..), Delta(..))
import Slap.Status (SlapError(..), BSDiffDifferCause(..))

-- | The bsdiff differ's output, marshaled out of Rust into typed
-- Haskell: the control triples in emission order (preserved across
-- the seam by parallel-array serialization, one Rust buffer per
-- triple field) and the two still-uncompressed byte streams.
-- Everything from here to the wire — sign-magnitude fields, bzip2
-- sections, the 32-byte header — is 'Slap.BSDiff.Create's.
data BSDiffDifferOutput = BSDiffDifferOutput
  { bsdiffDifferInstructions :: ![BSDiffInstruction]
  , bsdiffDifferDiffStream   :: !ByteString
  , bsdiffDifferExtraStream  :: !ByteString
  }
  deriving (Show)

foreign import ccall unsafe "rusty_bsdiff_diff"
  rustyBSDiffDiff
    :: Ptr Word8 -> CSize -> Ptr Word8 -> CSize
    -> Ptr (Ptr Word8) -> Ptr CSize    -- add_lengths
    -> Ptr (Ptr Word8) -> Ptr CSize    -- copy_lengths
    -> Ptr (Ptr Word8) -> Ptr CSize    -- source_seeks
    -> Ptr (Ptr Word8) -> Ptr CSize    -- diff_stream
    -> Ptr (Ptr Word8) -> Ptr CSize    -- extra_stream
    -> Ptr (Ptr Word8) -> Ptr CSize    -- error_cause
    -> IO CInt

-- | Invoke the Rust bsdiff differ.
bsdiffDiff
  :: InputFileContents
  -> OutputFileContents
  -> Either SlapError BSDiffDifferOutput
bsdiffDiff (InputFileContents sourceBytes) (OutputFileContents targetBytes) =
  unsafePerformIO $
    withByteString sourceBytes $ \sourcePointer sourceLength ->
    withByteString targetBytes $ \targetPointer targetLength ->
    alloca $ \addLengthsAddressPointer   ->
    alloca $ \addLengthsLengthPointer    ->
    alloca $ \copyLengthsAddressPointer  ->
    alloca $ \copyLengthsLengthPointer   ->
    alloca $ \sourceSeeksAddressPointer  ->
    alloca $ \sourceSeeksLengthPointer   ->
    alloca $ \diffStreamAddressPointer   ->
    alloca $ \diffStreamLengthPointer    ->
    alloca $ \extraStreamAddressPointer  ->
    alloca $ \extraStreamLengthPointer   ->
    alloca $ \errorCauseAddressPointer   ->
    alloca $ \errorCauseLengthPointer    -> do
      returnCode <- rustyBSDiffDiff
        sourcePointer sourceLength
        targetPointer targetLength
        addLengthsAddressPointer  addLengthsLengthPointer
        copyLengthsAddressPointer copyLengthsLengthPointer
        sourceSeeksAddressPointer sourceSeeksLengthPointer
        diffStreamAddressPointer  diffStreamLengthPointer
        extraStreamAddressPointer extraStreamLengthPointer
        errorCauseAddressPointer  errorCauseLengthPointer
      if returnCode /= 0
        then do
          rustMessage <- readText errorCauseAddressPointer errorCauseLengthPointer
          pure $ Left (BSDiffDifferFailed (BSDiffDifferCause rustMessage))
        else do
          addLengthBytes   <- readByteString addLengthsAddressPointer  addLengthsLengthPointer
          copyLengthBytes  <- readByteString copyLengthsAddressPointer copyLengthsLengthPointer
          sourceSeekBytes  <- readByteString sourceSeeksAddressPointer sourceSeeksLengthPointer
          diffStreamBytes  <- readByteString diffStreamAddressPointer  diffStreamLengthPointer
          extraStreamBytes <- readByteString extraStreamAddressPointer extraStreamLengthPointer
          -- error_cause is the canonical null buffer on success;
          -- routing it through readByteString frees any allocation
          -- behind it, the same as every other out-pointer.
          _                <- readByteString errorCauseAddressPointer  errorCauseLengthPointer
          pure $ do
            instructions <- parseParallelTriples addLengthBytes copyLengthBytes sourceSeekBytes
            pure BSDiffDifferOutput
              { bsdiffDifferInstructions = instructions
              , bsdiffDifferDiffStream   = diffStreamBytes
              , bsdiffDifferExtraStream  = extraStreamBytes
              }

-- | Reconstruct '[BSDiffInstruction]' from the three parallel buffers
-- the Rust side surfaces (eight LE bytes per field per triple; the
-- seek's i64 crosses as its two's-complement bit pattern, which the
-- 'Word64' → 'Int' 'fromIntegral' reinterprets exactly).
-- Buffer-shape mismatches register as typed failures
-- ('BSDiffDifferFailed') rather than runtime exceptions.
parseParallelTriples
  :: ByteString
  -> ByteString
  -> ByteString
  -> Either SlapError [BSDiffInstruction]
parseParallelTriples addLengthBytes copyLengthBytes sourceSeekBytes = do
  requireWholeTriples
  requireBufferLength "copy-lengths" copyLengthBytes
  requireBufferLength "source-seeks" sourceSeekBytes
  Right (map decodeOneTriple [0 .. instructionCount - 1])
  where
    instructionCount = ByteString.length addLengthBytes `div` 8

    requireWholeTriples :: Either SlapError ()
    requireWholeTriples
      | ByteString.length addLengthBytes `mod` 8 == 0 = Right ()
      | otherwise = Left $ ffiInvariantFailure $
          "add-lengths buffer is " <> renderAsText (ByteString.length addLengthBytes)
          <> " bytes, not a multiple of 8"

    requireBufferLength :: Text -> ByteString -> Either SlapError ()
    requireBufferLength bufferRole buffer
      | ByteString.length buffer == 8 * instructionCount = Right ()
      | otherwise = Left $ ffiInvariantFailure $
          bufferRole <> " buffer is " <> renderAsText (ByteString.length buffer)
          <> " bytes, expected " <> renderAsText (8 * instructionCount)
          <> " (8 LE bytes per instruction × " <> renderAsText instructionCount <> " instructions)"

    decodeOneTriple index = BSDiffInstruction
      { controlAdd  = Length (fromIntegral (readWord64LE addLengthBytes  (8 * index)))
      , controlCopy = Length (fromIntegral (readWord64LE copyLengthBytes (8 * index)))
      , controlSeek = Delta  (fromIntegral (readWord64LE sourceSeekBytes (8 * index)))
      }

ffiInvariantFailure :: Text -> SlapError
ffiInvariantFailure detail =
  BSDiffDifferFailed (BSDiffDifferCause ("FFI invariant violation: " <> detail))
