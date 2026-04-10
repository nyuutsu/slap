module Slap.UPS.Apply
  ( applyUPS
  ) where

import Slap.UPS.Types (UPSPatch(..), UPSBlock(..), upsTerminatorByteLength)
import Slap.Error (SlapError(..), ApplyError(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.Measure (Offset(..), Length(..), FileSize(..),
                     ActionIndex(..),
                     RequestedLength(..), RemainingLength(..),
                     Cursor(..), fitsWithin, remainingFromOffset,
                     subtractLength, minLength,
                     firstAction, nextAction, plusOffset)
import Slap.FileContents (SourceFileContents(..), TargetFileContents(..))

import Control.Monad (when)
import Data.Bits (xor)
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.ByteString.Internal (create)
import Data.ByteString.Unsafe (unsafeIndex, unsafeUseAsCStringLen)
import Data.IORef (newIORef, readIORef, writeIORef)
import qualified Data.Vector as Vector
import Data.Word (Word8)
import Foreign.Marshal.Utils (copyBytes, fillBytes)
import Foreign.Ptr (Ptr, castPtr, plusPtr)
import Foreign.Storable (peekByteOff, pokeByteOff)
import System.IO.Unsafe (unsafePerformIO)

-- | Apply a parsed UPS patch to a source ByteString. Returns
-- 'Left' with a structured error if the patch is semantically
-- malformed (declared target size is negative, or a block's total
-- span exceeds target size). Source-shorter-than-target is legal
-- (spec-mandated zero-fill past source end) and is handled inline
-- by the helper functions, not as an error. The caller is still
-- responsible for CRC validation before calling.
applyUPS :: UPSPatch -> SourceFileContents -> Either SlapError TargetFileContents
applyUPS patch (SourceFileContents source)
  | unFileSize targetSize < 0 =
      Left (NegativeTargetSize LabelUPS targetSize)
  | unFileSize targetSize == 0 =
      Right (TargetFileContents ByteString.empty)
  | otherwise = unsafePerformIO $ do
      errorRef <- newIORef Nothing
      result <- create (unFileSize targetSize) $ \outputPointer ->
        unsafeUseAsCStringLen source $ \(sourcePointerCString, _) ->
          let sourcePointer = castPtr sourcePointerCString :: Ptr Word8
          in runApply outputPointer sourcePointer errorRef
      errorState <- readIORef errorRef
      pure $ case errorState of
        Just applyErr -> Left (ApplyFailed LabelUPS applyErr)
        Nothing       -> Right (TargetFileContents result)
  where
    targetSize     = upsTargetSize patch
    sourceSize     = FileSize (ByteString.length source)
    blocks         = upsBlocks patch
    blockStreamEnd = ActionIndex (Vector.length blocks)

    runApply outputPointer sourcePointer errorRef =
      let
        abort :: ApplyError -> IO ()
        abort applyErr = writeIORef errorRef (Just applyErr)

        -- | Copy bytes from source to output at the given position,
        -- zero-filling past source end (spec-mandated for source-
        -- shorter-than-target). The caller is responsible for ensuring
        -- the copy fits within target bounds — this helper does not
        -- clip to target.
        copySourceSlice :: Offset -> Length -> IO ()
        copySourceSlice outputPosition copyLength = do
          let availableInSource = remainingFromOffset outputPosition sourceSize
              inBoundsLength    = minLength copyLength availableInSource
              zeroFillLength    = subtractLength copyLength inBoundsLength
              zeroFillStart     = advance outputPosition inBoundsLength
          when (unLength inBoundsLength > 0) $
            copyBytes
              (plusOffset outputPointer outputPosition)
              (sourcePointer `plusPtr` unOffset outputPosition)
              (unLength inBoundsLength)
          when (unLength zeroFillLength > 0) $
            fillBytes
              (plusOffset outputPointer zeroFillStart)
              0
              (unLength zeroFillLength)

        -- | XOR source bytes with xorData, writing result to output.
        -- Past source end, source bytes are treated as 0x00 (so
        -- xorData bytes are written verbatim — x XOR 0 == x). The
        -- caller is responsible for ensuring the write fits within
        -- target bounds — this helper does not clip to target.
        --
        -- Two-phase loop: a tight in-bounds phase reads source via
        -- the raw pinned pointer and XORs against xorData; a tight
        -- zero-fill phase writes xorData verbatim. This mirrors
        -- copySourceSlice's split-phase structure and BPS's
        -- generalOverlapLoop hoisted-base-pointer style.
        xorSourceSlice :: Offset -> Length -> ByteString -> IO ()
        xorSourceSlice outputPosition xorDataLength xorData = do
          let availableInSource = remainingFromOffset outputPosition sourceSize
              inBoundsLength    = minLength xorDataLength availableInSource
              readBase          = sourcePointer `plusPtr` unOffset outputPosition
              writeBase         = plusOffset outputPointer outputPosition
              inBoundsBytes     = unLength inBoundsLength
              totalBytes        = unLength xorDataLength

              -- Phase 1: source is in bounds. Read source, XOR with
              -- xorData, poke result.
              inBoundsLoop !byteOffset
                | byteOffset >= inBoundsBytes = pure ()
                | otherwise = do
                    sourceByte <- peekByteOff readBase byteOffset :: IO Word8
                    let xorByte = unsafeIndex xorData byteOffset
                    pokeByteOff writeBase byteOffset
                      (sourceByte `xor` xorByte :: Word8)
                    inBoundsLoop (byteOffset + 1)

              -- Phase 2: source is past end. Source byte is virtually
              -- 0, so the result is just xorData[byteOffset].
              zeroFillLoop !byteOffset
                | byteOffset >= totalBytes = pure ()
                | otherwise = do
                    let xorByte = unsafeIndex xorData byteOffset
                    pokeByteOff writeBase byteOffset xorByte
                    zeroFillLoop (byteOffset + 1)
          inBoundsLoop 0
          zeroFillLoop inBoundsBytes

        applyBlockStream :: ActionIndex -> Offset -> IO ()
        applyBlockStream !blockIndex !outputPosition
          | blockIndex >= blockStreamEnd = do
              -- End of stream: tail copy from source to target,
              -- zero-filling past source end. No ApplyTargetUnderfilled
              -- check — the tail copy always fills target exactly.
              let tailLength = remainingFromOffset outputPosition targetSize
              copySourceSlice outputPosition tailLength
          | otherwise =
              handleBlock blockIndex outputPosition
                (Vector.unsafeIndex blocks (unActionIndex blockIndex))

        handleBlock :: ActionIndex -> Offset -> UPSBlock -> IO ()
        handleBlock blockIndex outputPosition (UPSBlock skipLen xorData) =
          let xorLen         = Length (ByteString.length xorData)
              totalBlockLen  = skipLen <> xorLen <> upsTerminatorByteLength
              skipStart      = outputPosition
              xorStart       = advance skipStart skipLen
              terminatorPos  = advance xorStart xorLen
              nextPosition   = advance terminatorPos upsTerminatorByteLength
              remainingSpace = remainingFromOffset outputPosition targetSize
          in if not (fitsWithin outputPosition totalBlockLen targetSize)
               then abort (ApplyWritesPastTarget blockIndex
                            (RequestedLength totalBlockLen)
                            (RemainingLength remainingSpace))
               else do
                 copySourceSlice skipStart skipLen
                 xorSourceSlice xorStart xorLen xorData
                 copySourceSlice terminatorPos upsTerminatorByteLength
                 applyBlockStream (nextAction blockIndex) nextPosition

      in applyBlockStream firstAction (Offset 0)
