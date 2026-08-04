-- | UPS run-finder binding to rusty-slap. Sibling to the cross-format
-- primitives in "Slap.FFI": this pair answers only the block walk in
-- "Slap.UPS.Create" ('rusty-slap/src/ups_scan.rs') and lives next to
-- the rest of the UPS module family.
module Slap.UPS.FFI (nextDifference, nextAgreement) where

import Data.ByteString (ByteString)
import Data.Word (Word8)
import Foreign.C.Types (CSize(..))
import Foreign.Ptr (Ptr)
import Slap.FFI (withByteString)
import Slap.Measure (Offset(..))
import System.IO.Unsafe (unsafePerformIO)

foreign import ccall unsafe "rusty_ups_next_difference"
  rustyUpsNextDifference :: Ptr Word8 -> CSize -> Ptr Word8 -> CSize -> CSize -> CSize

foreign import ccall unsafe "rusty_ups_next_agreement"
  rustyUpsNextAgreement :: Ptr Word8 -> CSize -> Ptr Word8 -> CSize -> CSize -> CSize

-- | The first position at or after @from@, over the target, where source and target disagree —
-- the start of a UPS XOR run. Source bytes past the source's end read as zero, and "no such
-- position" answers with the target-end sentinel; both rules are 'rusty-slap/src/ups_scan.rs''s.
-- The @pure $!@ is load-bearing for the reason 'Slap.FFI.crc32' spells out.
nextDifference :: ByteString -> ByteString -> Offset -> Offset
nextDifference source target (Offset from) = unsafePerformIO $
  withByteString source $ \sourcePointer sourceLength ->
  withByteString target $ \targetPointer targetLength ->
    pure $! Offset (fromIntegral (rustyUpsNextDifference sourcePointer sourceLength
                                                         targetPointer targetLength
                                                         (fromIntegral from)))

-- | The first position at or after @from@, over the target, where source and target agree —
-- the end of a UPS XOR run. Padding and sentinel as in 'nextDifference'.
nextAgreement :: ByteString -> ByteString -> Offset -> Offset
nextAgreement source target (Offset from) = unsafePerformIO $
  withByteString source $ \sourcePointer sourceLength ->
  withByteString target $ \targetPointer targetLength ->
    pure $! Offset (fromIntegral (rustyUpsNextAgreement sourcePointer sourceLength
                                                        targetPointer targetLength
                                                        (fromIntegral from)))
