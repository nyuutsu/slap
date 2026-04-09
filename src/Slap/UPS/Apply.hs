module Slap.UPS.Apply
  ( applyUPS
  ) where

import Slap.UPS.Types (UPSPatch(..), UPSBlock(..))
import Slap.Error (SlapError(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.Measure (Offset(..), Length(..), FileSize(..), Delta(..),
                     ActionIndex(..),
                     Cursor(..), remainingFromOffset,
                     firstAction, nextAction, plusOffset)

import Control.Monad (when)
import Data.Bits (xor)
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.ByteString.Internal (create)
import Data.ByteString.Unsafe (unsafeUseAsCStringLen)
import qualified Data.Vector as Vector
import Data.Word (Word8)
import Foreign.Marshal.Utils (copyBytes, fillBytes)
import Foreign.Ptr (Ptr, castPtr, plusPtr)
import Foreign.Storable (peekByteOff, pokeByteOff)
import System.IO.Unsafe (unsafePerformIO)

-- | Apply a parsed UPS patch to a source ByteString. Returns
-- 'Left' with a structured error if the declared target size is
-- negative; otherwise always succeeds. Source-shorter-than-target
-- is legal (spec-mandated zero-fill past source end), and blocks
-- that extend past target size are clipped — this happens normally
-- in shrinking patches and when the last block's terminator falls
-- at exactly target size. The caller is still responsible for CRC
-- validation before calling.
applyUPS :: UPSPatch -> ByteString -> Either SlapError ByteString
applyUPS patch source
  | unFileSize targetSize < 0 =
      Left (NegativeTargetSize LabelUPS targetSize)
  | unFileSize targetSize == 0 =
      Right ByteString.empty
  | otherwise =
      Right $ unsafePerformIO $
        create (unFileSize targetSize) $ \outputPointer ->
          unsafeUseAsCStringLen source $ \(sourcePointerCString, _) ->
            let sourcePointer = castPtr sourcePointerCString :: Ptr Word8
            in runApply outputPointer sourcePointer
  where
    targetSize = upsTargetSize patch
    sourceSize = FileSize (ByteString.length source)
    targetEnd  = unFileSize targetSize
    sourceEnd  = unFileSize sourceSize
    blocks     = upsBlocks patch
    blockCount = ActionIndex (Vector.length blocks)

    runApply outputPointer sourcePointer =
      let
        -- | Copy bytes from source to output at the given position,
        -- zero-filling past source end (spec-mandated) and clipping
        -- to target end.
        copySourceSlice :: Offset -> Length -> IO ()
        copySourceSlice outputPosition copyLength = do
          let startPos       = unOffset outputPosition
              clippedLen     = max 0 (min (unLength copyLength) (targetEnd - startPos))
              inBoundsLength = max 0 (min clippedLen (sourceEnd - startPos))
              zeroFillLength = clippedLen - inBoundsLength
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
        -- xorBytes are written verbatim). Clipped to target end.
        xorSourceSlice :: Offset -> ByteString -> IO ()
        xorSourceSlice outputPosition xorBytes = do
          let startPos   = unOffset outputPosition
              clippedLen = max 0 (min (ByteString.length xorBytes) (targetEnd - startPos))
              innerLoop !byteOffset
                | byteOffset >= clippedLen = pure ()
                | otherwise = do
                    let absolutePos = startPos + byteOffset
                        xorByte    = ByteString.index xorBytes byteOffset
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
          | blockIndex >= blockCount = do
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
          let skipLen       = Length (unDelta skipDelta)
              xorLen        = Length (ByteString.length xorBytes)
              skipStart     = outputPosition
              xorStart      = advance skipStart skipLen
              terminatorPos = advance xorStart xorLen
              nextPosition  = advance terminatorPos (Length 1)
          in do
            copySourceSlice skipStart skipLen
            xorSourceSlice xorStart xorBytes
            copySourceSlice terminatorPos (Length 1)
            applyBlockStream (nextAction blockIndex) nextPosition

      in applyBlockStream firstAction (Offset 0)
