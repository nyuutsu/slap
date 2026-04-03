module Slap.BPS.Apply
  ( applyBPS
  ) where

import Slap.BPS.Types (BPSPatch(..), BPSAction(..))
import Slap.Binary (copyByteStringRange)
import Slap.Measure (Length(..), FileSize(..), Delta(..))

import Control.Monad (when)
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.ByteString.Internal (unsafeCreate)
import Data.Int (Int64)
import Data.Word (Word8)
import Foreign.Marshal.Utils (fillBytes)
import Foreign.Ptr (Ptr, plusPtr)
import Foreign.Storable (peekByteOff, pokeByteOff)

-- Caller validates checksums.
applyBPS :: BPSPatch -> ByteString -> ByteString
applyBPS patch source = unsafeCreate targetLength $ \outputPointer ->
  applyLoop outputPointer 0 0 0 (bpsActions patch)
  where
    targetLength = fromIntegral (unFileSize (bpsTargetSize patch))
    sourceLength = ByteString.length source

    applyLoop :: Ptr Word8 -> Int -> Int64 -> Int64 -> [BPSAction] -> IO ()
    applyLoop _             _              _              _              []           = pure ()
    applyLoop outputPointer outputPosition sourceRelative targetRelative (action:remaining) = case action of
      SourceRead actionLength -> do
        let copyLength = unLength actionLength
            count = min copyLength (targetLength - outputPosition)
            inBounds = max 0 (min count (sourceLength - outputPosition))
        copyByteStringRange outputPointer outputPosition source outputPosition inBounds
        when (inBounds < count) $
          fillBytes (outputPointer `plusPtr` (outputPosition + inBounds)) 0 (count - inBounds)
        applyLoop outputPointer (outputPosition + count) sourceRelative targetRelative remaining

      TargetRead payload -> do
        let count = min (ByteString.length payload) (targetLength - outputPosition)
        copyByteStringRange outputPointer outputPosition payload 0 count
        applyLoop outputPointer (outputPosition + count) sourceRelative targetRelative remaining

      SourceCopy actionLength actionDelta -> do
        let copyLength = unLength actionLength
            nextSourceRelative = sourceRelative + unDelta actionDelta
            sourceOffset  = fromIntegral nextSourceRelative :: Int
            count   = min copyLength (targetLength - outputPosition)
            -- Clamp to the portion that falls within the source ByteString
            leadingClipLength = max 0 (negate sourceOffset)
            safeSourceStart   = max 0 sourceOffset
            safeSourceLength  = max 0 (min (count - leadingClipLength) (sourceLength - safeSourceStart))
        -- Zero-fill any leading out-of-bounds bytes
        when (leadingClipLength > 0) $
          fillBytes (outputPointer `plusPtr` outputPosition) 0 (min leadingClipLength count)
        -- Bulk copy the in-bounds portion
        copyByteStringRange outputPointer (outputPosition + leadingClipLength) source safeSourceStart safeSourceLength
        -- Zero-fill any trailing out-of-bounds bytes
        let copied = leadingClipLength + safeSourceLength
        when (copied < count) $
          fillBytes (outputPointer `plusPtr` (outputPosition + copied)) 0 (count - copied)
        applyLoop outputPointer (outputPosition + count) (nextSourceRelative + fromIntegral count) targetRelative remaining

      TargetCopy actionLength actionDelta -> do
        let copyLength = unLength actionLength
            nextTargetRelative = targetRelative + unDelta actionDelta
            count   = min copyLength (targetLength - outputPosition)
            readOffset = fromIntegral nextTargetRelative
        -- Byte-by-byte: source region may overlap with destination
        mapM_ (\index -> do
          let readIndex = readOffset + index
          byte <- if readIndex >= 0 && readIndex < targetLength
               then peekByteOff outputPointer readIndex :: IO Word8
               else pure 0
          pokeByteOff outputPointer (outputPosition + index) byte) [0..count-1]
        applyLoop outputPointer (outputPosition + count) sourceRelative (nextTargetRelative + fromIntegral count) remaining
