{-# LANGUAGE StrictData #-}

module Slap.Measure
  ( -- * Newtypes
    Offset(..)
  , Length(..)
  , FileSize(..)
  , Delta(..)
  , Position(..)
  , SignedOffset(..)
  , ActionIndex(..)
    -- * Records
  , Hunk(..)
  , UndoHunk(..)
  , EncodedHunk(..)
  , EncodingLimits(..)
    -- * Conversions
  , offsetToInt
  , fileSizeToInt
  , lengthToFileSize
  , lengthToOffset
    -- * Seeking
  , seekTo
    -- * Cursor typeclass
  , Cursor(..)
    -- * Cursor helpers
  , clampToOffset
  , remainingFromOffset
  , firstAction
  , nextAction
    -- * Arithmetic
  , distance
  , fitsWithin
  , byteLength
  , hunkEnd
    -- * Narrowing
  , narrowHunk
  , narrowHunks
  , narrowHunkUnbounded
  , narrowHunksUnbounded
    -- * Memory
  , copyRegion
    -- * Encoding limits
  , ipsLimits
  , ips32Limits
  , ebpLimits
    -- * IPS sentinel values
  , ipsSentinel
  , ips32Sentinel
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Unsafe as UnsafeByteString
import Data.Word (Word8, Word32)
import Foreign.Marshal.Utils (copyBytes)
import Foreign.Ptr (Ptr, plusPtr, castPtr)
import Numeric (showHex)
import Slap.FormatLabel (FormatLabel(..), formatLabelName)
import System.IO (Handle, SeekMode(AbsoluteSeek), hSeek)

----------------------------------------------------------------------------
-- Newtypes
----------------------------------------------------------------------------

newtype Offset   = Offset   { unOffset   :: Int } deriving (Eq, Ord, Show)
newtype Length   = Length   { unLength   :: Int } deriving (Eq, Ord, Show)
newtype FileSize = FileSize { unFileSize :: Int } deriving (Eq, Ord, Show)
newtype Delta    = Delta    { unDelta    :: Int } deriving (Eq, Ord, Show)
newtype Position = Position { unPosition :: Int } deriving (Eq, Ord, Show)

newtype SignedOffset = SignedOffset { unSignedOffset :: Int }
  deriving (Eq, Ord, Show)

newtype ActionIndex = ActionIndex { unActionIndex :: Int }
  deriving (Eq, Ord, Show)

----------------------------------------------------------------------------
-- Records
----------------------------------------------------------------------------

data Hunk = Hunk
  { hunkOffset  :: !Offset
  , hunkPayload :: !ByteString
  } deriving (Show)

data UndoHunk = UndoHunk
  { undoOffset   :: !Offset
  , undoPayload  :: !ByteString
  , undoOriginal :: !ByteString
  } deriving (Show)

data EncodedHunk = EncodedHunk
  { encodedOffset  :: !Offset
  , encodedPayload :: !ByteString
  } deriving (Eq, Show)

data EncodingLimits = EncodingLimits
  { maximumOffset  :: !Offset
  , sentinelOffset :: !(Maybe Offset)
  , formatLabel    :: !FormatLabel
  } deriving (Show)

----------------------------------------------------------------------------
-- Instances
----------------------------------------------------------------------------

instance Semigroup Length where
  Length left <> Length right = Length (left + right)

instance Monoid Length where
  mempty = Length 0

----------------------------------------------------------------------------
-- Conversions
----------------------------------------------------------------------------

offsetToInt :: Offset -> Int
offsetToInt = unOffset

fileSizeToInt :: FileSize -> Int
fileSizeToInt = unFileSize

lengthToFileSize :: Length -> FileSize
lengthToFileSize (Length lengthValue) = FileSize lengthValue

lengthToOffset :: Length -> Offset
lengthToOffset (Length lengthValue) = Offset lengthValue

----------------------------------------------------------------------------
-- Seeking
----------------------------------------------------------------------------

seekTo :: Handle -> Offset -> IO ()
seekTo handle targetOffset =
  hSeek handle AbsoluteSeek (fromIntegral (unOffset targetOffset))

----------------------------------------------------------------------------
-- Cursor typeclass
----------------------------------------------------------------------------

-- | Buffer cursors that support position arithmetic. 'Offset' is the
-- everyday case (forward-walking, non-negative by convention).
-- 'SignedOffset' is the rare case where transient negative values
-- are legitimate before being clamped at the read site (currently
-- only BPS apply's source/target relative cursors).
class Cursor cursor where
  advance  :: cursor -> Length -> cursor
  displace :: cursor -> Delta  -> cursor

instance Cursor Offset where
  advance  (Offset position) (Length stride) =
    Offset (position + stride)
  displace (Offset position) (Delta displacement) =
    Offset (position + displacement)

instance Cursor SignedOffset where
  advance  (SignedOffset position) (Length stride) =
    SignedOffset (position + stride)
  displace (SignedOffset position) (Delta displacement) =
    SignedOffset (position + displacement)

----------------------------------------------------------------------------
-- Cursor helpers
----------------------------------------------------------------------------

-- | Clamp a 'SignedOffset' to a non-negative 'Offset'. The only
-- legal way to obtain an 'Offset' from a 'SignedOffset', so the
-- clamping step is impossible to forget.
clampToOffset :: SignedOffset -> Offset
clampToOffset (SignedOffset position) = Offset (max 0 position)

-- | The number of bytes remaining in a file from a given offset.
-- Returns a non-negative 'Length' (clamped to zero if the offset is
-- past the end).
remainingFromOffset :: Offset -> FileSize -> Length
remainingFromOffset (Offset position) (FileSize totalSize) =
  Length (max 0 (totalSize - position))

-- | The first index in any action stream.
firstAction :: ActionIndex
firstAction = ActionIndex 0

-- | Step to the next action in a stream.
nextAction :: ActionIndex -> ActionIndex
nextAction (ActionIndex index) = ActionIndex (index + 1)

----------------------------------------------------------------------------
-- Arithmetic
----------------------------------------------------------------------------

distance :: Offset -> Offset -> Length
distance (Offset startOffset) (Offset endOffset) =
  Length (endOffset - startOffset)

fitsWithin :: Offset -> Length -> FileSize -> Bool
fitsWithin (Offset regionStart) (Length regionLength) (FileSize totalSize) =
  regionStart + regionLength <= totalSize

byteLength :: ByteString -> Length
byteLength bytes = Length (ByteString.length bytes)

hunkEnd :: Hunk -> Offset
hunkEnd hunk = advance (hunkOffset hunk) (byteLength (hunkPayload hunk))

----------------------------------------------------------------------------
-- Narrowing
----------------------------------------------------------------------------

narrowHunk :: EncodingLimits -> Hunk -> Either String EncodedHunk
narrowHunk limits hunk
  | unOffset (hunkOffset hunk) > unOffset (maximumOffset limits) =
      Left (formatLabelName (formatLabel limits) ++ ": hunk offset 0x"
            ++ showHex (unOffset (hunkOffset hunk)) ""
            ++ " exceeds maximum offset 0x"
            ++ showHex (unOffset (maximumOffset limits)) "")
  | Just sentinel <- sentinelOffset limits
  , hunkOffset hunk == sentinel =
      Left (formatLabelName (formatLabel limits) ++ ": hunk offset 0x"
            ++ showHex (unOffset sentinel) ""
            ++ " collides with sentinel 0x"
            ++ showHex (unOffset sentinel) "")
  | otherwise =
      Right EncodedHunk
        { encodedOffset  = hunkOffset hunk
        , encodedPayload = hunkPayload hunk
        }

narrowHunks :: EncodingLimits -> [Hunk] -> Either String [EncodedHunk]
narrowHunks limits = traverse (narrowHunk limits)

narrowHunkUnbounded :: Hunk -> EncodedHunk
narrowHunkUnbounded hunk = EncodedHunk
  { encodedOffset  = hunkOffset hunk
  , encodedPayload = hunkPayload hunk
  }

narrowHunksUnbounded :: [Hunk] -> [EncodedHunk]
narrowHunksUnbounded = map narrowHunkUnbounded

----------------------------------------------------------------------------
-- Memory
----------------------------------------------------------------------------

copyRegion :: Ptr Word8 -> Offset -> ByteString -> Offset -> Length -> IO ()
copyRegion _           _                 _      _              regionLength | unLength regionLength <= 0 = pure ()
copyRegion destination destinationOffset source sourcePosition regionLength =
  UnsafeByteString.unsafeUseAsCStringLen source $ \(sourcePointer, _) ->
    copyBytes (destination `plusPtr` unOffset destinationOffset)
              (castPtr sourcePointer `plusPtr` unOffset sourcePosition)
              (unLength regionLength)

----------------------------------------------------------------------------
-- Encoding limits
----------------------------------------------------------------------------

ipsLimits :: EncodingLimits
ipsLimits = EncodingLimits
  { maximumOffset  = Offset 0xFFFFFF
  , sentinelOffset = Just (Offset (fromIntegral ipsSentinel))
  , formatLabel    = LabelIPS
  }

ips32Limits :: EncodingLimits
ips32Limits = EncodingLimits
  { maximumOffset  = Offset 0xFFFFFFFF
  , sentinelOffset = Just (Offset (fromIntegral ips32Sentinel))
  , formatLabel    = LabelIPS32
  }

ebpLimits :: EncodingLimits
ebpLimits = EncodingLimits
  { maximumOffset  = Offset 0xFFFFFF
  , sentinelOffset = Just (Offset (fromIntegral ipsSentinel))
  , formatLabel    = LabelEBP
  }

-- | IPS EOF marker value (ASCII "EOF").
ipsSentinel :: Word32
ipsSentinel = 0x454F46

-- | IPS32 EEOF marker value (ASCII "EEOF").
ips32Sentinel :: Word32
ips32Sentinel = 0x45454F46
