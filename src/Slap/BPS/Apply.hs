module Slap.BPS.Apply
  ( applyBPS
  ) where

import Slap.BPS.Types (BPSPatch(..), BPSAction(..))
import Slap.Binary (copyByteStringRange)
import Slap.Measure (Length(..), FileSize(..), Delta(..))

import Control.Monad (when, forM_)
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.ByteString.Internal (unsafeCreate)
import qualified Data.Vector as Vector
import Data.Word (Word8)
import Foreign.Marshal.Utils (fillBytes)
import Foreign.Ptr (Ptr, plusPtr)
import Foreign.Storable (peekByteOff, pokeByteOff)

-- Caller validates checksums.
applyBPS :: BPSPatch -> ByteString -> ByteString
applyBPS patch source = unsafeCreate targetLength $ \outputPointer ->
  applyActionStream outputPointer 0 0 0 0
  where
    actions      = bpsActions patch
    actionCount  = Vector.length actions
    targetLength = unFileSize (bpsTargetSize patch)
    sourceLength = ByteString.length source

    -- Walk the action stream by index. Bang patterns on the four cursor
    -- variables are load-bearing: without them GHC builds up a chain of
    -- unevaluated @(+ 1)@ thunks across millions of actions and the
    -- whole point of moving off the lazy list collapses. 'unsafeIndex'
    -- is bounds-check-free; the loop guard guarantees the index is in
    -- range.
    applyActionStream
      :: Ptr Word8 -> Int -> Int -> Int -> Int -> IO ()
    applyActionStream outputPointer !actionIndex !outputPosition !sourceRelative !targetRelative
      | actionIndex >= actionCount = pure ()
      | otherwise = case Vector.unsafeIndex actions actionIndex of
          SourceRead actionLength -> do
            let copyLength = unLength actionLength
                count = min copyLength (targetLength - outputPosition)
                inBounds = max 0 (min count (sourceLength - outputPosition))
            copyByteStringRange outputPointer outputPosition source outputPosition inBounds
            when (inBounds < count) $
              fillBytes (outputPointer `plusPtr` (outputPosition + inBounds)) 0 (count - inBounds)
            applyActionStream outputPointer (actionIndex + 1) (outputPosition + count) sourceRelative targetRelative

          TargetRead payload -> do
            let count = min (ByteString.length payload) (targetLength - outputPosition)
            copyByteStringRange outputPointer outputPosition payload 0 count
            applyActionStream outputPointer (actionIndex + 1) (outputPosition + count) sourceRelative targetRelative

          SourceCopy actionLength actionDelta -> do
            let copyLength = unLength actionLength
                nextSourceRelative = sourceRelative + unDelta actionDelta
                sourceOffset  = nextSourceRelative
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
            applyActionStream outputPointer (actionIndex + 1) (outputPosition + count) (nextSourceRelative + count) targetRelative

          TargetCopy actionLength actionDelta -> do
            let copyLength = unLength actionLength
                nextTargetRelative = targetRelative + unDelta actionDelta
                count   = min copyLength (targetLength - outputPosition)
                readOffset = nextTargetRelative
            -- Byte-by-byte: source region may overlap with destination
            forM_ [0 .. count - 1] $ \byteOffset -> do
              let readIndex = readOffset + byteOffset
              byte <- if readIndex >= 0 && readIndex < targetLength
                        then peekByteOff outputPointer readIndex :: IO Word8
                        else pure 0
              pokeByteOff outputPointer (outputPosition + byteOffset) byte
            applyActionStream outputPointer (actionIndex + 1) (outputPosition + count) sourceRelative (nextTargetRelative + count)
