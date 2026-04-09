module Slap.BPS.Apply
  ( applyBPS
  ) where

import Slap.BPS.Types (BPSPatch(..), BPSAction(..))
import Slap.Measure (Offset(..), Length(..), FileSize(..),
                     SignedOffset(..), ActionIndex(..),
                     Cursor(..), clampToOffset, remainingFromOffset,
                     firstAction, nextAction, copyRegion)

import Control.Monad (when, forM_)
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.ByteString.Internal (unsafeCreate)
import qualified Data.Vector as Vector
import Data.Word (Word8)
import Foreign.Marshal.Utils (fillBytes)
import Foreign.Ptr (plusPtr)
import Foreign.Storable (peekByteOff, pokeByteOff)

-- Caller validates checksums.
applyBPS :: BPSPatch -> ByteString -> ByteString
applyBPS patch source = unsafeCreate (unFileSize targetSize) $ \outputPointer ->
    let
      actionAt index =
        Vector.unsafeIndex actions (unActionIndex index)

      -- Walk the action stream by index. Bang patterns on the four cursor
      -- variables are load-bearing: without them GHC builds up a chain of
      -- unevaluated @(+ 1)@ thunks across millions of actions and the
      -- whole point of moving off the lazy list collapses. 'unsafeIndex'
      -- is bounds-check-free; the loop guard guarantees the index is in
      -- range.
      applyActionStream
        :: ActionIndex -> Offset -> SignedOffset -> SignedOffset -> IO ()
      applyActionStream !actionIndex !outputPosition !sourceRelative !targetRelative
        | actionIndex >= actionStreamEnd = pure ()
        | otherwise = case actionAt actionIndex of
            SourceRead actionLength -> do
              let clampedLength = min actionLength (remainingFromOffset outputPosition targetSize)
                  sourceBoundsLength = min clampedLength (remainingFromOffset outputPosition sourceSize)
              copyRegion outputPointer outputPosition source outputPosition sourceBoundsLength
              when (sourceBoundsLength < clampedLength) $
                fillBytes (outputPointer `plusPtr` (unOffset outputPosition + unLength sourceBoundsLength))
                          0
                          (unLength clampedLength - unLength sourceBoundsLength)
              applyActionStream
                (nextAction actionIndex)
                (advance outputPosition clampedLength)
                sourceRelative
                targetRelative

            TargetRead payload -> do
              let payloadLength = Length (ByteString.length payload)
                  copyLength = min payloadLength (remainingFromOffset outputPosition targetSize)
              copyRegion outputPointer outputPosition payload (Offset 0) copyLength
              applyActionStream
                (nextAction actionIndex)
                (advance outputPosition copyLength)
                sourceRelative
                targetRelative

            SourceCopy actionLength actionDelta -> do
              let nextSourceRelative = displace sourceRelative actionDelta
                  clampedLength = min actionLength (remainingFromOffset outputPosition targetSize)
                  leadingClipLength = Length (max 0 (negate (unSignedOffset nextSourceRelative)))
                  safeSourceStart = clampToOffset nextSourceRelative
                  availableFromSource = remainingFromOffset safeSourceStart sourceSize
                  adjustedLength = Length (max 0 (unLength clampedLength - unLength leadingClipLength))
                  safeSourceLength = min adjustedLength availableFromSource
              -- Zero-fill any leading out-of-bounds bytes
              when (unLength leadingClipLength > 0) $
                fillBytes (outputPointer `plusPtr` unOffset outputPosition)
                          0
                          (min (unLength leadingClipLength) (unLength clampedLength))
              -- Bulk copy the in-bounds portion
              copyRegion outputPointer
                (advance outputPosition leadingClipLength)
                source safeSourceStart safeSourceLength
              -- Zero-fill any trailing out-of-bounds bytes
              let copiedLength = leadingClipLength <> safeSourceLength
              when (copiedLength < clampedLength) $
                fillBytes (outputPointer `plusPtr` (unOffset outputPosition + unLength copiedLength))
                          0
                          (unLength clampedLength - unLength copiedLength)
              applyActionStream
                (nextAction actionIndex)
                (advance outputPosition clampedLength)
                (advance nextSourceRelative clampedLength)
                targetRelative

            TargetCopy actionLength actionDelta -> do
              let nextTargetRelative = displace targetRelative actionDelta
                  clampedLength = min actionLength (remainingFromOffset outputPosition targetSize)
                  readStart = unSignedOffset nextTargetRelative
              -- Byte-by-byte: source region may overlap with destination
              forM_ [0 .. unLength clampedLength - 1] $ \byteOffset -> do
                let readIndex = readStart + byteOffset
                byte <- if readIndex >= 0 && readIndex < unFileSize targetSize
                          then peekByteOff outputPointer readIndex :: IO Word8
                          else pure 0
                pokeByteOff outputPointer (unOffset outputPosition + byteOffset) byte
              applyActionStream
                (nextAction actionIndex)
                (advance outputPosition clampedLength)
                sourceRelative
                (advance nextTargetRelative clampedLength)

    in applyActionStream firstAction (Offset 0) (SignedOffset 0) (SignedOffset 0)
  where
    targetSize      = bpsTargetSize patch
    sourceSize      = FileSize (ByteString.length source)
    actions         = bpsActions patch
    actionStreamEnd = ActionIndex (Vector.length actions)
