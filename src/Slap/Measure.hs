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
  , ReadOffset(..)
  , WritePosition(..)
  , RequestedLength(..)
  , RemainingLength(..)
  , ActualSize(..)
  , ExpectedSize(..)
  , MaxAddressableSize(..)
  , DeclaredTargetSize(..)
  , NaturalTargetSize(..)
    -- * Parse/create-error role newtypes
  , RequiredLength(..)
  , ActualLength(..)
  , EncodedLength(..)
  , MaxLength(..)
  , OriginalLength(..)
  , TruncatedLength(..)
  , ActualOffset(..)
  , MaxOffset(..)
  , SentinelOffset(..)
  , ExpectedMagic(..)
  , ActualMagic(..)
  , TrailerMarker(..)
  , ParsedSizeValue(..)
  , FoundVersion(..)
  , RawFlagByte(..)
  , EncodingMethodByte(..)
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
  , subtractLength
  , minLength
  , negativeOvershoot
  , plusOffset
  , SignedOffsetSign(..)
  , examineSignedOffset
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
    -- * Splitting
  , splitHunks
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
import Data.Word (Word8, Word32)
import Foreign.Ptr (Ptr, plusPtr)
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
-- Apply-error role newtypes
----------------------------------------------------------------------------

-- | The offset at which a read was requested. Used in error
-- contexts where a bare 'Offset' would be ambiguous with another
-- offset-valued field.
newtype ReadOffset = ReadOffset { unReadOffset :: Offset }
  deriving (Eq, Ord, Show)

-- | The current write position in a buffer being populated. Used
-- in error contexts where a bare 'Offset' would be ambiguous with
-- another offset-valued field.
newtype WritePosition = WritePosition { unWritePosition :: Offset }
  deriving (Eq, Ord, Show)

-- | A length an action requested to copy or write. Used in error
-- contexts where a bare 'Length' would be ambiguous with another
-- length-valued field.
newtype RequestedLength = RequestedLength { unRequestedLength :: Length }
  deriving (Eq, Ord, Show)

-- | The length of space remaining in a buffer being populated.
-- Used in error contexts where a bare 'Length' would be ambiguous
-- with another length-valued field.
newtype RemainingLength = RemainingLength { unRemainingLength :: Length }
  deriving (Eq, Ord, Show)

-- | The actual size achieved by a partial or completed operation.
-- Used in error contexts where a bare 'FileSize' would be
-- ambiguous with another size-valued field.
newtype ActualSize = ActualSize { unActualSize :: FileSize }
  deriving (Eq, Ord, Show)

-- | The expected or declared size of something. Used in error
-- contexts where a bare 'FileSize' would be ambiguous with another
-- size-valued field.
newtype ExpectedSize = ExpectedSize { unExpectedSize :: FileSize }
  deriving (Eq, Ord, Show)

-- | The maximum size slap can address on the host platform, given
-- that offsets and lengths flow through 'Int'. Used in error contexts
-- where a create-path size guard rejects an input larger than the
-- platform's 'Int' range (the byuu-varint encoder in BPS would
-- silently produce a malformed patch via 'fromIntegral' truncation
-- on 32-bit, where 'Int' is 31-bit-addressable).
newtype MaxAddressableSize = MaxAddressableSize { unMaxAddressableSize :: FileSize }
  deriving (Eq, Ord, Show)

-- | A target file size declared explicitly by something in the
-- patch — a header field, a trailer marker, or similar. Distinct
-- from 'NaturalTargetSize' because some formats compare the two at
-- apply time to decide whether the declaration is honoured (only
-- IPS does this today, via its optional post-EOF truncation marker).
-- Bare 'FileSize' arguments at the comparison would let a
-- transposition silently invert the policy decision.
newtype DeclaredTargetSize = DeclaredTargetSize
  { unDeclaredTargetSize :: FileSize }
  deriving (Eq, Ord, Show)

-- | A target file size derived from operation inputs alone: the
-- source size and the maximum write end across the patch's records,
-- actions, or hunks. Equal to @max sourceSize maxRecordEnd@ for IPS
-- (the format that uses this distinction today). Distinct from
-- 'DeclaredTargetSize' for the same reason 'DeclaredTargetSize'
-- exists.
newtype NaturalTargetSize = NaturalTargetSize
  { unNaturalTargetSize :: FileSize }
  deriving (Eq, Ord, Show)

----------------------------------------------------------------------------
-- Parse/create-error role newtypes
----------------------------------------------------------------------------

-- | The minimum length a parser requires before it can proceed.
newtype RequiredLength = RequiredLength { unRequiredLength :: Length }
  deriving (Eq, Ord, Show)

-- | The actual length available when a parser found it insufficient.
newtype ActualLength = ActualLength { unActualLength :: Length }
  deriving (Eq, Ord, Show)

-- | The encoded byte length of a field that exceeded its format's
-- maximum.
newtype EncodedLength = EncodedLength { unEncodedLength :: Length }
  deriving (Eq, Ord, Show)

-- | The maximum byte length a format allows for a given field.
newtype MaxLength = MaxLength { unMaxLength :: Length }
  deriving (Eq, Ord, Show)

-- | The original byte length of a field before truncation.
newtype OriginalLength = OriginalLength { unOriginalLength :: Length }
  deriving (Eq, Ord, Show)

-- | The byte length of a field after truncation to fit its format.
newtype TruncatedLength = TruncatedLength { unTruncatedLength :: Length }
  deriving (Eq, Ord, Show)

-- | An offset that a hunk or record actually carried, used in
-- encode-error contexts where a bare 'Offset' would be ambiguous.
newtype ActualOffset = ActualOffset { unActualOffset :: Offset }
  deriving (Eq, Ord, Show)

-- | The maximum offset a format allows, used in encode-error
-- contexts where a bare 'Offset' would be ambiguous.
newtype MaxOffset = MaxOffset { unMaxOffset :: Offset }
  deriving (Eq, Ord, Show)

-- | The offset at which a format's trailer sentinel sits: the
-- big-endian encoding of this offset collides with the format's
-- stream-closing marker on the wire, so a record emitted at this
-- offset would be indistinguishable from the trailer. IPS's
-- @0x454F46@ ("EOF") and IPS32's @0x45454F46@ ("EEOF") are the
-- motivating examples. Carried distinct from plain 'Offset' so that
-- sentinel-collision code can never accidentally be passed a record
-- offset, and vice versa.
newtype SentinelOffset = SentinelOffset { unSentinelOffset :: Offset }
  deriving (Eq, Ord, Show)

-- | The magic bytes a parser expected to find.
newtype ExpectedMagic = ExpectedMagic { unExpectedMagic :: ByteString }
  deriving (Eq, Show)

-- | The magic bytes a parser actually found.
newtype ActualMagic = ActualMagic { unActualMagic :: ByteString }
  deriving (Eq, Show)

-- | The trailer-marker bytes a parser was looking for when it
-- encountered unrecognized post-trailer content. The IPS family's
-- @"EOF"@ and @"EEOF"@ markers are the motivating example: when
-- 'Slap.IPS.Parse' rejects bytes that follow one of these markers,
-- the marker bytes are carried in the resulting error so the
-- renderer can name the marker the parser was anchored to without
-- knowing about IPS variants. The bytes are stored verbatim;
-- whether they print as ASCII or hex is the renderer's problem.
newtype TrailerMarker = TrailerMarker { unTrailerMarker :: ByteString }
  deriving (Eq, Show)

-- | A size field whose decoded value was negative (an Int that
-- should have been non-negative).
newtype ParsedSizeValue = ParsedSizeValue { unParsedSizeValue :: Int }
  deriving (Eq, Ord, Show)

-- | A version byte the parser did not recognise.
newtype FoundVersion = FoundVersion { unFoundVersion :: Word8 }
  deriving (Eq, Ord, Show)

-- | A flag byte the parser did not recognise.
newtype RawFlagByte = RawFlagByte { unRawFlagByte :: Word8 }
  deriving (Eq, Ord, Show)

-- | An encoding-method byte the parser did not recognise.
newtype EncodingMethodByte = EncodingMethodByte { unEncodingMethodByte :: Word8 }
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

-- | Subtract two 'Length' values, clamping to zero on underflow.
-- Used in apply workers when computing the remaining bytes after a
-- partial copy or fill.
subtractLength :: Length -> Length -> Length
subtractLength (Length minuend) (Length subtrahend) =
  Length (max 0 (minuend - subtrahend))

-- | The smaller of two 'Length' values. Used in apply workers when
-- splitting a region into in-bounds and zero-fill phases: the
-- in-bounds length is the minimum of the requested length and the
-- bytes remaining in source.
minLength :: Length -> Length -> Length
minLength (Length left) (Length right) = Length (min left right)

-- | The amount by which a 'SignedOffset' has overshot into the
-- negative range, expressed as a non-negative 'Length'. Returns
-- zero if the cursor is non-negative. Used by apply workers when
-- a relative-delta cursor has been driven below zero by a malformed
-- patch and the leading out-of-range bytes need to be zero-filled.
negativeOvershoot :: SignedOffset -> Length
negativeOvershoot (SignedOffset position) = Length (max 0 (negate position))

-- | The result of examining a 'SignedOffset' for non-negativity.
-- 'NonNegativeCursor' carries an 'Offset' with its non-negativity
-- proven by construction — the only way to obtain this constructor
-- is via 'examineSignedOffset', which performs the check. This lets
-- apply workers branch on cursor validity and receive a refinement-
-- typed 'Offset' in the valid branch, rather than calling
-- 'clampToOffset' after a manual guard (which reads as if clamping
-- were still happening when it isn't).
data SignedOffsetSign
  = NegativeCursor SignedOffset
  | NonNegativeCursor Offset
  deriving (Show, Eq)

-- | Examine a 'SignedOffset' and return either the original negative
-- value or a proven-non-negative 'Offset'.
examineSignedOffset :: SignedOffset -> SignedOffsetSign
examineSignedOffset signedCursor@(SignedOffset position)
  | position < 0 = NegativeCursor signedCursor
  | otherwise    = NonNegativeCursor (Offset position)

-- | Advance a raw byte pointer by a typed 'Offset'. Used at the
-- FFI boundary in apply workers, where the typed cursor needs to
-- be turned into a destination address for 'fillBytes', 'pokeByteOff',
-- or similar primitives.
plusOffset :: Ptr Word8 -> Offset -> Ptr Word8
plusOffset pointer (Offset position) = pointer `plusPtr` position

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
-- Splitting
----------------------------------------------------------------------------

-- | Split hunks so each payload is <= maxSize bytes.
splitHunks :: Int -> [Hunk] -> [Hunk]
splitHunks maxSize = concatMap splitOne
  where
    splitOne (Hunk hunkOffset hunkPayload)
      | ByteString.length hunkPayload <= maxSize = [Hunk hunkOffset hunkPayload]
      | otherwise =
          let (chunk, remaining) = ByteString.splitAt maxSize hunkPayload
              nextOffset = advance hunkOffset (Length maxSize)
          in Hunk hunkOffset chunk : splitOne (Hunk nextOffset remaining)

----------------------------------------------------------------------------
-- Encoding limits
----------------------------------------------------------------------------

ipsLimits :: EncodingLimits
ipsLimits = EncodingLimits
  { maximumOffset  = Offset 0xFFFFFF
  , formatLabel    = LabelIPS
  }

ips32Limits :: EncodingLimits
ips32Limits = EncodingLimits
  { maximumOffset  = Offset 0xFFFFFFFF
  , formatLabel    = LabelIPS32
  }

ebpLimits :: EncodingLimits
ebpLimits = EncodingLimits
  { maximumOffset  = Offset 0xFFFFFF
  , formatLabel    = LabelEBP
  }

-- | IPS EOF marker value (ASCII "EOF").
ipsSentinel :: Word32
ipsSentinel = 0x454F46

-- | IPS32 EEOF marker value (ASCII "EEOF").
ips32Sentinel :: Word32
ips32Sentinel = 0x45454F46
