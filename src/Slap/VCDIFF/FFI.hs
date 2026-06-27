-- | VCDIFF cover-matcher binding to rusty-slap.
--
-- The Rust side owns the longest-match search over the superstring @U@: a greedy cover walk (@rusty-slap/src/vcdiff_diff.rs@) driven by a suffix-array matcher (@rusty-slap/src/vcdiff_suffix_sort.rs@).
--
-- Total: every input yields a cover, the empty target included, so there is no error channel. A malformed buffer is a loud 'error', not a silently defaulted segment.
module Slap.VCDIFF.FFI
  ( vcdiffCover
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.Word (Word8)
import Foreign.C.Types (CSize(..), CInt(..))
import Foreign.Marshal.Alloc (alloca)
import Foreign.Ptr (Ptr)
import System.IO.Unsafe (unsafePerformIO)

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

-- | The Rust matcher cannot fail, so its return code is ignored.
vcdiffCover :: InputFileContents -> OutputFileContents -> Cover
vcdiffCover (InputFileContents source) (OutputFileContents target) =
  unsafePerformIO $
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

-- | Zip the three parallel buffers (one kind byte, eight LE offset bytes, eight LE length bytes per segment) back into a 'Cover', in order.
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
