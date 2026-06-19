-- | VCDIFF cover-matcher binding to rusty-slap.
--
-- The Rust side (@rusty-slap/src/vcdiff_diff.rs@) owns the naive greedy
-- longest-match scan over the superstring @U = source ++
-- produced-target@. This module is the seam: it assembles the FFI call
-- and zips the three parallel-array buffers back into a typed 'Cover'.
--
-- It is total — every input yields a cover, the empty target included —
-- so it follows 'Slap.BPS.FFI.bpsDiff''s shape (no error channel)
-- rather than 'Slap.XDelta1.FFI.xdelta1Diff''s. The one thing that
-- cannot happen — a torn cover, a buffer the Rust side could only
-- produce if it were broken — is a loud 'error' rather than a silently
-- defaulted segment.
module Slap.VCDIFF.FFI
  ( vcdiffCover
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.Word (Word8)
import Foreign.C.Types (CSize(..), CInt(..))
import Foreign.Marshal.Alloc (alloca)
import Foreign.Ptr (Ptr)
import System.IO.Unsafe (unsafeDupablePerformIO)

import Slap.FFI (readByteString, withByteString, readWord64LE)
import Slap.FileContents (InputFileContents(..), OutputFileContents(..))
import Slap.Measure (Offset(..), Length(..))
import Slap.VCDIFF.Cover (Cover(..), CoverSegment(..))

foreign import ccall unsafe "rusty_vcdiff_cover"
  rustyVCDIFFCover
    :: Ptr Word8 -> CSize -> Ptr Word8 -> CSize
    -> Ptr (Ptr Word8) -> Ptr CSize    -- kinds
    -> Ptr (Ptr Word8) -> Ptr CSize    -- offsets
    -> Ptr (Ptr Word8) -> Ptr CSize    -- lengths
    -> IO CInt

-- | Segment a target into a 'Cover' against a source, via the Rust
-- matcher. Total, like 'Slap.BPS.FFI.bpsDiff': the return code is 0 by
-- construction and carries no information, so it is discarded.
vcdiffCover :: InputFileContents -> OutputFileContents -> Cover
vcdiffCover (InputFileContents source) (OutputFileContents target) =
  unsafeDupablePerformIO $
    withByteString source $ \sourcePointer sourceLength ->
    withByteString target $ \targetPointer targetLength ->
    alloca $ \kindsAddressPointer   ->
    alloca $ \kindsLengthPointer    ->
    alloca $ \offsetsAddressPointer ->
    alloca $ \offsetsLengthPointer  ->
    alloca $ \lengthsAddressPointer ->
    alloca $ \lengthsLengthPointer  -> do
      _ <- rustyVCDIFFCover
             sourcePointer sourceLength
             targetPointer targetLength
             kindsAddressPointer   kindsLengthPointer
             offsetsAddressPointer offsetsLengthPointer
             lengthsAddressPointer lengthsLengthPointer
      kindBytes   <- readByteString kindsAddressPointer   kindsLengthPointer
      offsetBytes <- readByteString offsetsAddressPointer offsetsLengthPointer
      lengthBytes <- readByteString lengthsAddressPointer lengthsLengthPointer
      pure (decodeCover kindBytes offsetBytes lengthBytes)

-- | Zip the three parallel buffers — one kind byte, eight LE offset
-- bytes, and eight LE length bytes per segment — back into a 'Cover',
-- preserving segment order. A buffer-shape mismatch or a kind byte
-- outside {0, 1} is a torn cover: impossible from the Rust matcher, so
-- a loud 'error' rather than a quietly fabricated segment.
decodeCover :: ByteString -> ByteString -> ByteString -> Cover
decodeCover kindBytes offsetBytes lengthBytes
  | ByteString.length offsetBytes /= 8 * segmentCount = tornCover "offsets" offsetBytes
  | ByteString.length lengthBytes /= 8 * segmentCount = tornCover "lengths" lengthBytes
  | otherwise = Cover (map decodeSegment [0 .. segmentCount - 1])
  where
    segmentCount = ByteString.length kindBytes

    decodeSegment index =
      let segmentOffset = Offset (fromIntegral (readWord64LE offsetBytes (8 * index)))
          segmentLength = Length (fromIntegral (readWord64LE lengthBytes (8 * index)))
      in case ByteString.index kindBytes index of
           0   -> CoverLiteral segmentOffset segmentLength
           1   -> CoverCopy    segmentLength segmentOffset
           tag -> error (tornCoverMessage
                    ("kind byte " <> show tag <> " at segment " <> show index
                     <> " (expected 0 = literal or 1 = copy)"))

    tornCover field buffer = error (tornCoverMessage
      (field <> " buffer is " <> show (ByteString.length buffer) <> " bytes, expected "
             <> show (8 * segmentCount) <> " (8 LE bytes per segment × "
             <> show segmentCount <> " segments)"))

tornCoverMessage :: String -> String
tornCoverMessage detail = "Slap.VCDIFF.FFI: torn cover from rusty_vcdiff_cover: " <> detail
