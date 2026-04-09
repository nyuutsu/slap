module Slap.UPS.Apply
  ( applyUPS
  ) where

import Slap.UPS.Types (UPSPatch(..), UPSBlock(..))
import Slap.Error (SlapError(..), ApplyError(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.Measure (Offset(..), Length(..), FileSize(..), Delta(..),
                     ActionIndex(..),
                     RequestedLength(..), RemainingLength(..),
                     Cursor(..), fitsWithin, remainingFromOffset,
                     firstAction, nextAction, plusOffset)

import Control.Monad (when)
import Data.Bits (xor)
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.ByteString.Internal (create)
import Data.ByteString.Unsafe (unsafeUseAsCStringLen)
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
applyUPS :: UPSPatch -> ByteString -> Either SlapError ByteString
applyUPS patch source
  | unFileSize targetSize < 0 =
      Left (NegativeTargetSize LabelUPS targetSize)
  | unFileSize targetSize == 0 =
      Right ByteString.empty
  | otherwise = unsafePerformIO $ do
      errorRef <- newIORef Nothing
      result <- create (unFileSize targetSize) $ \outputPointer ->
        unsafeUseAsCStringLen source $ \(sourcePointerCString, _) ->
          let sourcePointer = castPtr sourcePointerCString :: Ptr Word8
          in runApply outputPointer sourcePointer errorRef
      errorState <- readIORef errorRef
      pure $ case errorState of
        Just applyErr -> Left (ApplyFailed LabelUPS applyErr)
        Nothing       -> Right result
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
        -- zero-filling past source end (spec-mandated for
        -- source-shorter-than-target). The caller is responsible for
        -- ensuring the copy fits within target bounds — this helper
        -- does not clip to target end.
        copySourceSlice :: Offset -> Length -> IO ()
        copySourceSlice outputPosition copyLength = do
          let startPos       = unOffset outputPosition
              sourceEnd      = unFileSize sourceSize
              requestedLen   = unLength copyLength
              inBoundsLength = max 0 (min requestedLen (sourceEnd - startPos))
              zeroFillLength = requestedLen - inBoundsLength
          when (inBoundsLength > 0) $
            copyBytes
              (plusOffset outputPointer outputPosition)
              (sourcePointer `plusPtr` startPos)
              inBoundsLength
          when (zeroFillLength > 0) $
            fillBytes
              (plusOffset outputPointer (Offset (startPos + inBoundsLength)))
              0
              zeroFillLength

        -- | XOR source bytes with xorBytes, writing result to output.
        -- Past source end, source bytes are treated as 0x00 (so
        -- xorBytes are written verbatim). The caller is responsible
        -- for ensuring the write fits within target bounds — this
        -- helper does not clip to target end.
        xorSourceSlice :: Offset -> ByteString -> IO ()
        xorSourceSlice outputPosition xorBytes = do
          let xorLength = ByteString.length xorBytes
              startPos  = unOffset outputPosition
              sourceEnd = unFileSize sourceSize
              innerLoop !byteOffset
                | byteOffset >= xorLength = pure ()
                | otherwise = do
                    let absolutePos = startPos + byteOffset
                        xorByte     = ByteString.index xorBytes byteOffset
                    sourceByte <-
                      if absolutePos < sourceEnd
                        then peekByteOff sourcePointer absolutePos :: IO Word8
                        else pure 0
                    pokeByteOff outputPointer absolutePos
                      (sourceByte `xor` xorByte :: Word8)
                    innerLoop (byteOffset + 1)
          innerLoop 0

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
        handleBlock blockIndex outputPosition (UPSBlock skipDelta xorBytes) =
          let skipLen        = Length (unDelta skipDelta)
              xorLen         = Length (ByteString.length xorBytes)
              terminatorLen  = Length 1
              totalBlockLen  = Length (unLength skipLen + unLength xorLen + 1)
              skipStart      = outputPosition
              xorStart       = advance skipStart skipLen
              terminatorPos  = advance xorStart xorLen
              nextPosition   = advance terminatorPos terminatorLen
              remainingSpace = remainingFromOffset outputPosition targetSize
          in if not (fitsWithin outputPosition totalBlockLen targetSize)
               then abort (ApplyWritesPastTarget blockIndex
                            (RequestedLength totalBlockLen)
                            (RemainingLength remainingSpace))
               else do
                 copySourceSlice skipStart skipLen
                 xorSourceSlice xorStart xorBytes
                 copySourceSlice terminatorPos terminatorLen
                 applyBlockStream (nextAction blockIndex) nextPosition

      in applyBlockStream firstAction (Offset 0)
