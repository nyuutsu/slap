module Slap.Binary
  ( -- * Little-endian readers
    getWord16LE
  , getWord32LE
  , getInt64LE
    -- * Big-endian readers
  , getWord16BE
  , getWord24BE
  , getWord32BE
  , getInt64BE
    -- * Variable-length integers
  , VarintResult(..)
  , VarintReadFailure(..)
  , getByuuVarint
  , getVcdiffVarint
  , minimalVcdiffVarintLength
    -- * Builders
  , putWord16BE
  , putWord32LE
  , word32LEBytes
  , putByuuVarint
  , putVcdiffVarint
  , putEdsioVarint
    -- * CRC-16
  , crc16
    -- * Cryptographic hashes
  , md5
  , sha1
  , sha256
    -- * Bulk memory operations
  , copyByteStringRange
  , copyRegion
  , copyInPlace
  , viewBytesInRange
  , fillNewBuffer
    -- * Diff
  , diffHunks
    -- * String utilities
  , trimNull
    -- * Additional builders
  , putWord16LE
  , putWord32BE
  , word32BEBytes
  , putInt64BE
  ) where

import Control.Monad (when)
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Internal as Internal
import qualified Data.ByteString.Unsafe as UnsafeByteString
import Data.ByteString.Builder (Builder, word8)
import Data.Array (Array, listArray, (!))
import Data.Bits (shiftL, shiftR, xor, (.&.), (.|.), testBit)
import Data.Int (Int64)
import Data.Word (Word8, Word16, Word32, Word64)
import Foreign.Marshal.Utils (copyBytes, moveBytes)
import Foreign.Ptr (Ptr, plusPtr, castPtr)
import qualified Crypto.Hash as Hash
import qualified Data.ByteArray as ByteArray
import Slap.Checksum (CRC16(..), MD5Hash(..), SHA1Hash(..))
import Slap.FileContents (InputFileContents(..), OutputFileContents(..))
import Slap.Measure (Offset(..), Length(..), FileSize(..), Hunk(..),
                     advance, byteLength, distance)

----------------------------------------------------------------------------
-- Little-endian readers
----------------------------------------------------------------------------

getWord16LE :: Int -> ByteString -> Word16
getWord16LE offset input =
  let byteAt index = fromIntegral (ByteString.index input (offset + index)) :: Word16
  in byteAt 0 .|. (byteAt 1 `shiftL` 8)

getWord32LE :: Int -> ByteString -> Word32
getWord32LE offset input =
  let byteAt index = fromIntegral (ByteString.index input (offset + index)) :: Word32
  in byteAt 0 .|. (byteAt 1 `shiftL` 8) .|. (byteAt 2 `shiftL` 16) .|. (byteAt 3 `shiftL` 24)

getInt64LE :: Int -> ByteString -> Int64
getInt64LE offset input =
  let byteAt index = fromIntegral (ByteString.index input (offset + index)) :: Int64
  in byteAt 0 .|. (byteAt 1 `shiftL` 8) .|. (byteAt 2 `shiftL` 16) .|. (byteAt 3 `shiftL` 24)
     .|. (byteAt 4 `shiftL` 32) .|. (byteAt 5 `shiftL` 40) .|. (byteAt 6 `shiftL` 48) .|. (byteAt 7 `shiftL` 56)

----------------------------------------------------------------------------
-- Big-endian readers
----------------------------------------------------------------------------

getWord16BE :: Int -> ByteString -> Word16
getWord16BE offset input =
  let byteAt index = fromIntegral (ByteString.index input (offset + index)) :: Word16
  in (byteAt 0 `shiftL` 8) .|. byteAt 1

getWord24BE :: Int -> ByteString -> Word32
getWord24BE offset input =
  let byteAt index = fromIntegral (ByteString.index input (offset + index)) :: Word32
  in (byteAt 0 `shiftL` 16) .|. (byteAt 1 `shiftL` 8) .|. byteAt 2

getWord32BE :: Int -> ByteString -> Word32
getWord32BE offset input =
  let byteAt index = fromIntegral (ByteString.index input (offset + index)) :: Word32
  in (byteAt 0 `shiftL` 24) .|. (byteAt 1 `shiftL` 16) .|. (byteAt 2 `shiftL` 8) .|. byteAt 3

getInt64BE :: Int -> ByteString -> Int64
getInt64BE offset input =
  let byteAt index = fromIntegral (ByteString.index input (offset + index)) :: Int64
  in (byteAt 0 `shiftL` 56) .|. (byteAt 1 `shiftL` 48) .|. (byteAt 2 `shiftL` 40) .|. (byteAt 3 `shiftL` 32)
     .|. (byteAt 4 `shiftL` 24) .|. (byteAt 5 `shiftL` 16) .|. (byteAt 6 `shiftL` 8) .|. byteAt 7

----------------------------------------------------------------------------
-- Variable-length integers
----------------------------------------------------------------------------

-- | The two failure modes a varint reader can surface. Both varint
-- formats slap reads ('byuu', 'VCDIFF') share this failure space;
-- the EDSIO varint in 'Slap.ByteParser.edsioVarint' is decoded
-- against the parser monad directly and surfaces the same
-- meanings through 'ByteParserError' constructors.
data VarintReadFailure
  -- | The decoded value is too large to represent and slap declines
  -- it outright. Both readers detect this by value — the running
  -- accumulation would exceed the largest 'Int64' slap can carry —
  -- rather than by a byte-count proxy: a nine-byte byuu varint can
  -- already encode a value past 'Int64', so counting bytes would let
  -- it wrap silently. For VCDIFF this is the @>= 2^64@ band, beyond
  -- even xd3's @uint64@; for byuu it is the single over-width verdict
  -- (byuu makes no apology — see 'VarintExceedsSignedButFitsUnsigned').
  = VarintTooManyContinuationBytes
  -- | A continuation byte was followed by no more input; the
  -- varint started inside the buffer but its continuation bytes
  -- ran past the end. Distinct from "read started at or past
  -- EOF", which is an 'ByteParserUnderflow' at the lifting seam.
  | VarintRanPastEndOfInput
  -- | A VCDIFF varint decoded a value in @[2^63, 2^64)@: representable
  -- by xd3's unsigned @uint64@ reader, but not by the signed 'Int64'
  -- slap threads sizes and offsets through. The apologetic verdict —
  -- the format's effective definition admits these and slap, knowingly,
  -- does not. Only 'getVcdiffVarint' produces it; the byuu reader caps
  -- at the same value with the plain 'VarintTooManyContinuationBytes',
  -- because byuu is canonical and made the coarser call deliberately.
  | VarintExceedsSignedButFitsUnsigned
  deriving (Eq, Show)

-- | byuu/Near-style varint used by BPS and UPS.
-- LSB-first encoding: each 7-bit group is stored low byte first.
-- High bit clear = more bytes follow. High bit set = final byte.
-- Each continuation adds 1 to accumulator before shifting (the "subtract-one" trick).
-- Returns (value, bytes consumed).
getByuuVarint :: Int -> ByteString -> Either VarintReadFailure VarintResult
getByuuVarint offset input = decode offset 0 1
  where
    inputLength    = ByteString.length input
    largestSigned  = fromIntegral (maxBound :: Int64) :: Word64
    -- A value needing a tenth byte already exceeds the nine-byte
    -- maximum, which itself sits above 'Int64'; the bound also keeps
    -- 'multiplier' below the point where the 'Word64' arithmetic
    -- could wrap, so the value test below stays honest.
    decode position accumulated multiplier
      | position - offset >= 9  = Left VarintTooManyContinuationBytes
      | position >= inputLength  = Left VarintRanPastEndOfInput
      | otherwise =
          let byte         = ByteString.index input position
              payload      = fromIntegral (byte .&. 0x7F) :: Word64
              valueSoFar   = accumulated + payload * multiplier
          in if valueSoFar > largestSigned
             then Left VarintTooManyContinuationBytes
             else if testBit byte 7
               then Right (VarintResult (fromIntegral valueSoFar) (position - offset + 1))
               else let nextMultiplier = multiplier `shiftL` 7
                    in decode (position + 1) (valueSoFar + nextMultiplier) nextMultiplier

-- | VCDIFF varint (RFC 3284).  MSB-first: high bit set = more bytes follow.
-- Returns (value, bytes consumed).
getVcdiffVarint :: Int -> ByteString -> Either VarintReadFailure VarintResult
getVcdiffVarint offset input = decode offset 0
  where
    inputLength    = ByteString.length input
    largestSigned  = fromIntegral (maxBound :: Int64)  :: Word64  -- 2^63 - 1
    -- Folding in another 7-bit group shifts the accumulator left by
    -- seven; once it carries bits at position 57 or above, that shift
    -- would push the value past 'Word64' — i.e. past @2^64@, beyond
    -- even xd3's @uint64@ — so it is a plain over-width rejection.
    shiftWouldOverflow = (maxBound :: Word64) `shiftR` 7
    decode position accumulated
      | accumulated > shiftWouldOverflow = Left VarintTooManyContinuationBytes
      | position >= inputLength           = Left VarintRanPastEndOfInput
      | otherwise =
          let byte  = ByteString.index input position
              value = (accumulated `shiftL` 7) .|. fromIntegral (byte .&. 0x7F)
          in if testBit byte 7
             then decode (position + 1) value
             else if value > largestSigned
               then Left VarintExceedsSignedButFitsUnsigned
               else Right (VarintResult (fromIntegral value) (position - offset + 1))

-- | Byte count of the canonical (shortest) VCDIFF varint encoding of a
-- non-negative value: one base-128 group per seven significant bits,
-- and at least one group so zero still costs a byte. The seam compares
-- this against the bytes actually consumed to spot an overlong encoding.
minimalVcdiffVarintLength :: Int64 -> Int
minimalVcdiffVarintLength value = groupsNeeded 1 (value `shiftR` 7)
  where
    groupsNeeded groupsSoFar remainingBits
      | remainingBits <= 0 = groupsSoFar
      | otherwise          = groupsNeeded (groupsSoFar + 1) (remainingBits `shiftR` 7)

----------------------------------------------------------------------------
-- Builders
----------------------------------------------------------------------------

putWord16BE :: Word16 -> Builder
putWord16BE value =
  word8 (fromIntegral (value `shiftR` 8))
  <> word8 (fromIntegral value)

putWord32LE :: Word32 -> Builder
putWord32LE value =
  word8 (fromIntegral (value .&. 0xFF))
  <> word8 (fromIntegral ((value `shiftR` 8) .&. 0xFF))
  <> word8 (fromIntegral ((value `shiftR` 16) .&. 0xFF))
  <> word8 (fromIntegral ((value `shiftR` 24) .&. 0xFF))

-- | Strict-ByteString sister to 'putWord32LE'. Useful when four bytes
-- need to be appended to an existing 'ByteString' without going through
-- the Builder machinery — e.g. computing a trailing CRC over a patch
-- body and appending the CRC bytes directly. See 'createBPS' and
-- 'createUPS' for callers.
word32LEBytes :: Word32 -> ByteString
word32LEBytes value = ByteString.pack
  [ fromIntegral (value .&. 0xFF)
  , fromIntegral ((value `shiftR`  8) .&. 0xFF)
  , fromIntegral ((value `shiftR` 16) .&. 0xFF)
  , fromIntegral ((value `shiftR` 24) .&. 0xFF)
  ]

-- | Encode a non-negative Int64 as a byuu-style varint.
putByuuVarint :: Int64 -> Builder
putByuuVarint = encode
  where
    encode value
      | value <= 0x7F = word8 (fromIntegral value .|. 0x80)
      | otherwise =
          let lowBits = fromIntegral (value .&. 0x7F) :: Word8
              remaining = (value `shiftR` 7) - 1
          in word8 lowBits <> encode remaining

-- | Encode a non-negative Int64 as a VCDIFF varint (RFC 3284 §2):
-- big-endian base-128, most-significant 7-bit group first, with the
-- high bit set on every byte but the last. The inverse of
-- 'getVcdiffVarint', and emitting only the canonical (no leading
-- zero-group) form, so zero is the single byte @0x00@. Non-negative by
-- the same caller's-domain convention as 'putByuuVarint'.
putVcdiffVarint :: Int64 -> Builder
putVcdiffVarint value =
  emitHighGroups (value `shiftR` 7) <> word8 (fromIntegral (value .&. 0x7F))
  where
    -- The groups above the final one, emitted most-significant first,
    -- each carrying the continuation flag. Recurses into the higher
    -- bits before emitting its own group, so the bytes land big-endian.
    emitHighGroups remaining
      | remaining == 0 = mempty
      | otherwise =
          emitHighGroups (remaining `shiftR` 7)
          <> word8 (fromIntegral (remaining .&. 0x7F) .|. 0x80)

-- | Payload bits carried per byte.
edsioVarintBitsPerByte :: Int
edsioVarintBitsPerByte = 7

-- | Mask isolating the payload bits.
edsioVarintPayloadMask :: Word8
edsioVarintPayloadMask = 0x7F

-- | The continuation flag — high bit set when more bytes follow.
edsioVarintContinuationFlag :: Word8
edsioVarintContinuationFlag = 0x80

-- | Highest payload value that fits in a single byte's seven
-- payload bits. The number is the same as
-- 'edsioVarintPayloadMask', expressed at 'Word64' for use as a
-- threshold against the encoder's accumulator rather than as a
-- bit mask against a byte.
edsioVarintMaxSingleByteValue :: Word64
edsioVarintMaxSingleByteValue = fromIntegral edsioVarintPayloadMask

-- | Encode a non-negative integer as an EDSIO-style varint:
-- 7 payload bits per byte, LSB first, high bit set on every byte
-- except the last. Inverse of 'Slap.ByteParser.edsioVarint'. Takes
-- 'Word64' under the same convention as 'putByuuVarint'
-- (caller's domain says non-negative; encoder doesn't redo the
-- check).
putEdsioVarint :: Word64 -> Builder
putEdsioVarint = writePayload
  where
    writePayload remainingBits
      | remainingBits <= edsioVarintMaxSingleByteValue =
          word8 (fromIntegral remainingBits)
      | otherwise =
          let thisBytePayload   = fromIntegral (remainingBits .&. fromIntegral edsioVarintPayloadMask) :: Word8
              thisByteWithFlag  = thisBytePayload .|. edsioVarintContinuationFlag
              bitsAfterThisByte = remainingBits `shiftR` edsioVarintBitsPerByte
          in word8 thisByteWithFlag <> writePayload bitsAfterThisByte

----------------------------------------------------------------------------
-- Cryptographic hashes
----------------------------------------------------------------------------

md5 :: ByteString -> MD5Hash
md5 = MD5Hash . ByteArray.convert . Hash.hashWith Hash.MD5

sha1 :: ByteString -> SHA1Hash
sha1 = SHA1Hash . ByteArray.convert . Hash.hashWith Hash.SHA1

sha256 :: ByteString -> ByteString
sha256 = ByteArray.convert . Hash.hashWith Hash.SHA256

----------------------------------------------------------------------------
-- Bulk memory operations
----------------------------------------------------------------------------

-- | Bulk copy @copyLength@ bytes from a ByteString (at @sourceOffset@) to a
-- raw pointer (at @destinationOffset@).  Uses memcpy internally.
copyByteStringRange :: Ptr Word8 -> Int -> ByteString -> Int -> Int -> IO ()
copyByteStringRange destination destinationOffset source sourceOffset copyLength =
  when (copyLength > 0) $
    UnsafeByteString.unsafeUseAsCStringLen source $ \(sourcePointer, _) ->
      copyBytes (destination `plusPtr` destinationOffset)
                (castPtr sourcePointer `plusPtr` sourceOffset)
                copyLength

-- | Bulk copy @regionLength@ bytes from a ByteString (at a typed
-- 'Offset') to a raw pointer (at a typed 'Offset'). Uses memcpy
-- internally. A no-op when @regionLength@ is zero or negative.
copyRegion :: Ptr Word8 -> Offset -> ByteString -> Offset -> Length -> IO ()
copyRegion destination destinationOffset source sourcePosition regionLength =
  when (unLength regionLength > 0) $
    UnsafeByteString.unsafeUseAsCStringLen source $ \(sourcePointer, _) ->
      copyBytes (destination `plusPtr` unOffset destinationOffset)
                (castPtr sourcePointer `plusPtr` unOffset sourcePosition)
                (unLength regionLength)

-- | The bytes in a given range of a 'ByteString' — the subrange
-- starting at 'Offset' and continuing for 'Length' bytes. The input
-- buffer is unchanged; the result is a view (a shared substring in
-- the 'ByteString' sense, O(1)). Out-of-range arguments are handled
-- gracefully by the underlying 'ByteString.drop' / 'ByteString.take':
-- a starting 'Offset' past the end yields an empty result, and a
-- 'Length' that runs past the end yields the bytes that exist.
viewBytesInRange :: Offset -> Length -> ByteString -> ByteString
viewBytesInRange rangeStart rangeLength input =
  ByteString.take (unLength rangeLength) (ByteString.drop (unOffset rangeStart) input)

-- | Copy @regionLength@ bytes from one position in a buffer to
-- another position in the SAME buffer. Used by apply workers for
-- in-buffer copies (e.g., BPS TargetCopy's non-overlapping back
-- references). Uses C @memmove@ under the hood, so it's correct
-- even when the source and destination regions overlap — but
-- callers are responsible for knowing whether overlap is
-- semantically correct for their use case. A no-op when
-- @regionLength@ is zero or negative.
copyInPlace :: Ptr Word8 -> Offset -> Offset -> Length -> IO ()
copyInPlace buffer sourceOffset destinationOffset regionLength =
  when (unLength regionLength > 0) $
    moveBytes (buffer `plusPtr` unOffset destinationOffset)
              (buffer `plusPtr` unOffset sourceOffset)
              (unLength regionLength)

-- | Allocate an output buffer of exactly @size@ bytes, run a fill
-- action over it, and return the filled buffer paired with whatever
-- the action computed (an apply\/undo error, an 'Slap.Status.Outcome',
-- ...).
--
-- This is the one shape slap ever asks of bytestring's internal
-- 'Internal.createAndTrim'': start at offset 0, keep the full
-- requested length, never actually trim. That primitive's name half-
-- hides its calling convention — the @(offset, length, extra)@ triple
-- the fill action must return — and the format @Apply@ modules were
-- each spelling that triple identically. Closing over it here keeps
-- the 'Data.ByteString.Internal' import in one module and lets the
-- call sites pass a 'FileSize' and their fill action with nothing in
-- between.
fillNewBuffer :: FileSize -> (Ptr Word8 -> IO a) -> IO (ByteString, a)
fillNewBuffer size fill =
  Internal.createAndTrim' (unFileSize size) $ \bufferPointer -> do
    extra <- fill bufferPointer
    pure (0, unFileSize size, extra)

----------------------------------------------------------------------------
-- CRC-16/IBM (reflected polynomial 0xA001, init 0x0000)
----------------------------------------------------------------------------

crc16 :: ByteString -> CRC16
crc16 = CRC16 . ByteString.foldl' updateChecksum 0
  where
    updateChecksum :: Word16 -> Word8 -> Word16
    updateChecksum checksum byte =
      let tableIndex = fromIntegral ((checksum `xor` fromIntegral byte) .&. 0xFF)
      in (checksum `shiftR` 8) `xor` (crc16Table ! tableIndex)

crc16Table :: Array Word16 Word16
crc16Table = listArray (0, 255) [computeEntry entry | entry <- [0..255]]
  where
    computeEntry :: Word16 -> Word16
    computeEntry initial = iterate reflect initial !! 8
    reflect :: Word16 -> Word16
    reflect checksum
      | testBit checksum 0 = (checksum `shiftR` 1) `xor` 0xA001
      | otherwise           = checksum `shiftR` 1

----------------------------------------------------------------------------
-- Diff
----------------------------------------------------------------------------

-- | Maximum gap (in bytes) between adjacent diff hunks that triggers merging.
mergeGapThreshold :: Int
mergeGapThreshold = 5

-- | Find contiguous regions where two ByteStrings differ.
-- Merges nearby hunks (gap <= mergeGapThreshold bytes) to reduce record count.
-- Returns [Hunk] from the target side.
diffHunks :: InputFileContents -> OutputFileContents -> [Hunk]
diffHunks (InputFileContents original) (OutputFileContents modified) =
  mergeNearby (scanDiffs 0 ++ extension)
  where
    originalLength = ByteString.length original
    modifiedLength = ByteString.length modified
    sharedLength = min originalLength modifiedLength
    extension
      | modifiedLength > originalLength = [Hunk (Offset originalLength) (ByteString.drop originalLength modified)]
      | otherwise                       = []
    scanDiffs position
      | position >= sharedLength = []
      | ByteString.index original position == ByteString.index modified position = scanDiffs (position + 1)
      | otherwise =
          let diffEnd = findDiffEnd (position + 1)
          in Hunk (Offset position) (ByteString.take (diffEnd - position) (ByteString.drop position modified)) : scanDiffs diffEnd
    findDiffEnd position
      | position >= sharedLength = sharedLength
      | ByteString.index original position /= ByteString.index modified position = findDiffEnd (position + 1)
      | otherwise = position
    mergeNearby [] = []
    mergeNearby [hunk] = [hunk]
    mergeNearby (Hunk firstOffset firstData : Hunk nextOffset nextData : rest)
      | gapBetween <= Length mergeGapThreshold =
          let merged = ByteString.take (unLength mergedLength)
                         (ByteString.drop (unOffset firstOffset) modified)
          in mergeNearby (Hunk firstOffset merged : rest)
      | otherwise = Hunk firstOffset firstData : mergeNearby (Hunk nextOffset nextData : rest)
      where
        gapBetween   = distance (advance firstOffset (byteLength firstData)) nextOffset
        mergedLength = distance firstOffset (advance nextOffset (byteLength nextData))


----------------------------------------------------------------------------
-- Additional builders
----------------------------------------------------------------------------

putWord16LE :: Word16 -> Builder
putWord16LE value =
  word8 (fromIntegral (value .&. 0xFF))
  <> word8 (fromIntegral ((value `shiftR` 8) .&. 0xFF))

putWord32BE :: Word32 -> Builder
putWord32BE value =
  word8 (fromIntegral (value `shiftR` 24))
  <> word8 (fromIntegral ((value `shiftR` 16) .&. 0xFF))
  <> word8 (fromIntegral ((value `shiftR` 8) .&. 0xFF))
  <> word8 (fromIntegral (value .&. 0xFF))

-- | Strict-ByteString sister to 'putWord32BE'. The big-endian
-- counterpart to 'word32LEBytes'. Useful when four bytes need to be
-- appended to an existing 'ByteString' without going through the
-- 'Builder' machinery — e.g. writing an xdelta1 control-offset
-- pointer into the patch's trailer. See 'Slap.XDelta1.Create.encodeXDelta1'
-- for a caller.
word32BEBytes :: Word32 -> ByteString
word32BEBytes value = ByteString.pack
  [ fromIntegral ((value `shiftR` 24) .&. 0xFF)
  , fromIntegral ((value `shiftR` 16) .&. 0xFF)
  , fromIntegral ((value `shiftR`  8) .&. 0xFF)
  , fromIntegral (value .&. 0xFF)
  ]

putInt64BE :: Int64 -> Builder
putInt64BE value =
  word8 (fromIntegral (value `shiftR` 56))
  <> word8 (fromIntegral ((value `shiftR` 48) .&. 0xFF))
  <> word8 (fromIntegral ((value `shiftR` 40) .&. 0xFF))
  <> word8 (fromIntegral ((value `shiftR` 32) .&. 0xFF))
  <> word8 (fromIntegral ((value `shiftR` 24) .&. 0xFF))
  <> word8 (fromIntegral ((value `shiftR` 16) .&. 0xFF))
  <> word8 (fromIntegral ((value `shiftR` 8) .&. 0xFF))
  <> word8 (fromIntegral (value .&. 0xFF))

----------------------------------------------------------------------------
-- Variable-length integer result
----------------------------------------------------------------------------

-- | Result of decoding a variable-length integer: the decoded value
-- and the number of bytes it consumed from the input. The fields are
-- named for readability; the positional constructor still matches, so
-- existing @VarintResult value consumed@ patterns are undisturbed.
data VarintResult = VarintResult
  { varintDecodedValue  :: !Int64
  , varintBytesConsumed :: !Int
  }
  deriving (Show)

----------------------------------------------------------------------------
-- String utilities
----------------------------------------------------------------------------

-- | Strip trailing null bytes from a ByteString.
trimNull :: ByteString -> ByteString
trimNull = ByteString.takeWhile (/= 0)

