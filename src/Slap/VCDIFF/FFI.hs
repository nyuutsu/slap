-- | VCDIFF cover-matcher binding to rusty-slap.
--
-- The Rust side owns the match search over the superstring @U@: a greedy cover walk (@rusty-slap/src/vcdiff_diff.rs@)
-- driven by a cost-aware matcher (@rusty-slap/src/vcdiff_hash_chain.rs@),
-- which offers a copy only where it beats writing the bytes as literals.
-- The windowed entry covers each window of the target against @source ++ that window's slice@:
-- the matcher indexes the source once and forgets each window's output as the next begins,
-- so a cover that copies from an earlier window's output cannot come back across this seam.
--
-- Total: every input yields covers, the empty target included (one empty window), so there is no error channel.
-- A malformed buffer is a loud 'error', not a silently defaulted segment.
module Slap.VCDIFF.FFI
  ( vcdiffCover
  , vcdiffWindowedCovers
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.List.NonEmpty (NonEmpty)
import qualified Data.List.NonEmpty as NonEmpty
import Data.Word (Word8)
import Foreign.C.Types (CSize(..), CInt(..))
import Foreign.Marshal.Alloc (alloca)
import Foreign.Ptr (Ptr)
import System.IO.Unsafe (unsafePerformIO)

import Slap.FFI (readByteString, withByteString, readWord64LE)
import Slap.FileContents (InputFileContents(..), OutputFileContents(..))
import Slap.Measure (Offset(..), Length(..))
import Slap.VCDIFF.Cover (Cover(..), CoverSegment(..))
import Slap.VCDIFF.Types (XDelta3WindowSize, unXDelta3WindowSize)

foreign import ccall unsafe "rusty_vcdiff_cover"
  rustyVCDIFFCover
    :: Ptr Word8 -> CSize -> Ptr Word8 -> CSize
    -> CSize                           -- window length
    -> Ptr (Ptr Word8) -> Ptr CSize    -- kinds
    -> Ptr (Ptr Word8) -> Ptr CSize    -- offsets
    -> Ptr (Ptr Word8) -> Ptr CSize    -- lengths
    -> Ptr (Ptr Word8) -> Ptr CSize    -- per-window segment counts
    -> IO CInt

-- | One cover spanning the whole target: the single-window reading of 'vcdiffWindowedCovers',
-- what the RFC arc's one-window emission and the custom-table inner delta run on.
vcdiffCover :: InputFileContents -> OutputFileContents -> Cover
vcdiffCover source target@(OutputFileContents targetBytes) =
  NonEmpty.head (coversOfWindowLength (max 1 (ByteString.length targetBytes)) source target)

-- | One cover per window: full-size windows in order, then the remainder, the empty target one empty window.
-- A cover's copy offsets address @source ++ its own window's slice@, and its literal offsets index that slice.
vcdiffWindowedCovers :: XDelta3WindowSize -> InputFileContents -> OutputFileContents -> NonEmpty Cover
vcdiffWindowedCovers windowSize = coversOfWindowLength (unXDelta3WindowSize windowSize)

-- | The Rust matcher cannot fail, so its return code is ignored.
coversOfWindowLength :: Int -> InputFileContents -> OutputFileContents -> NonEmpty Cover
coversOfWindowLength windowLength (InputFileContents source) (OutputFileContents target) =
  unsafePerformIO $
    withByteString source $ \sourcePointer sourceLength ->
    withByteString target $ \targetPointer targetLength ->
    alloca $ \kindsAddressPointer   ->
    alloca $ \kindsLengthPointer    ->
    alloca $ \offsetsAddressPointer ->
    alloca $ \offsetsLengthPointer  ->
    alloca $ \lengthsAddressPointer ->
    alloca $ \lengthsLengthPointer  ->
    alloca $ \countsAddressPointer  ->
    alloca $ \countsLengthPointer   -> do
      _ <- rustyVCDIFFCover
             sourcePointer sourceLength
             targetPointer targetLength
             (fromIntegral windowLength)
             kindsAddressPointer   kindsLengthPointer
             offsetsAddressPointer offsetsLengthPointer
             lengthsAddressPointer lengthsLengthPointer
             countsAddressPointer  countsLengthPointer
      kindBytes   <- readByteString kindsAddressPointer   kindsLengthPointer
      offsetBytes <- readByteString offsetsAddressPointer offsetsLengthPointer
      lengthBytes <- readByteString lengthsAddressPointer lengthsLengthPointer
      countBytes  <- readByteString countsAddressPointer  countsLengthPointer
      pure (decodeWindowedCovers countBytes kindBytes offsetBytes lengthBytes)

-- | Zip the flat parallel buffers (one kind byte, eight LE offset bytes, eight LE length bytes per segment)
-- back into per-window 'Cover's, split by the per-window segment counts (eight LE bytes each), in window order.
decodeWindowedCovers :: ByteString -> ByteString -> ByteString -> ByteString -> NonEmpty Cover
decodeWindowedCovers countBytes kindBytes offsetBytes lengthBytes
  | ByteString.length countBytes `mod` 8 /= 0        = tornCover "window counts" countBytes (8 * windowCount)
  | ByteString.length offsetBytes /= 8 * segmentCount = tornCover "offsets" offsetBytes (8 * segmentCount)
  | ByteString.length lengthBytes /= 8 * segmentCount = tornCover "lengths" lengthBytes (8 * segmentCount)
  | sum segmentCountPerWindow /= segmentCount =
      error (tornCoverMessage
        ("window counts sum to " <> show (sum segmentCountPerWindow)
         <> " segments but the buffers hold " <> show segmentCount))
  | otherwise = case NonEmpty.nonEmpty (coversFromSegment 0 segmentCountPerWindow) of
      Just covers -> covers
      Nothing     -> error (tornCoverMessage "zero windows (there is always at least one)")
  where
    segmentCount = ByteString.length kindBytes
    windowCount  = ByteString.length countBytes `div` 8
    segmentCountPerWindow =
      [ fromIntegral (readWord64LE countBytes (8 * windowIndex))
      | windowIndex <- [0 .. windowCount - 1] ]

    coversFromSegment _ [] = []
    coversFromSegment firstSegment (windowSegments : laterWindows) =
      Cover (map decodeSegment [firstSegment .. firstSegment + windowSegments - 1])
        : coversFromSegment (firstSegment + windowSegments) laterWindows

    decodeSegment index =
      let segmentOffset = Offset (fromIntegral (readWord64LE offsetBytes (8 * index)))
          segmentLength = Length (fromIntegral (readWord64LE lengthBytes (8 * index)))
      in case ByteString.index kindBytes index of
           0   -> CoverLiteral segmentOffset segmentLength
           1   -> CoverCopy    segmentLength segmentOffset
           tag -> error (tornCoverMessage
                    ("kind byte " <> show tag <> " at segment " <> show index
                     <> " (expected 0 = literal or 1 = copy)"))

    tornCover field buffer expected = error (tornCoverMessage
      (field <> " buffer is " <> show (ByteString.length buffer) <> " bytes, expected "
             <> show expected <> " (8 LE bytes per entry)"))

tornCoverMessage :: String -> String
tornCoverMessage detail = "Slap.VCDIFF.FFI: torn cover from rusty_vcdiff_cover: " <> detail
