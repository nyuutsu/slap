-- | IPS region-finder binding to rusty-slap. Sibling to the cross-format
-- primitives in "Slap.FFI": this pair answers only the region scan in
-- "Slap.IPS.Optimize" ('rusty-slap/src/ips_scan.rs') and lives next to
-- the rest of the IPS module family.
module Slap.IPS.FFI (nextDifference, nextAgreement) where

import Data.ByteString (ByteString)
import Data.Word (Word8)
import Foreign.C.Types (CSize(..))
import Foreign.Ptr (Ptr)
import Slap.FFI (withByteString)
import Slap.Measure (Offset(..))
import System.IO.Unsafe (unsafePerformIO)

foreign import ccall unsafe "rusty_ips_next_difference"
  rustyIpsNextDifference :: Ptr Word8 -> CSize -> Ptr Word8 -> CSize -> CSize -> CSize

foreign import ccall unsafe "rusty_ips_next_agreement"
  rustyIpsNextAgreement :: Ptr Word8 -> CSize -> Ptr Word8 -> CSize -> CSize -> CSize

-- | The first position at or after @from@, within the shared prefix, where source and target
-- disagree — the start of an IPS diff region. No such position answers with the shared length;
-- the rules live in rusty-slap/src/ips_scan.rs.
-- The @pure $!@ is load-bearing for the reason 'Slap.FFI.crc32' spells out.
nextDifference :: ByteString -> ByteString -> Offset -> Offset
nextDifference source target (Offset from) = unsafePerformIO $
  withByteString source $ \sourcePointer sourceLength ->
  withByteString target $ \targetPointer targetLength ->
    pure $! Offset (fromIntegral (rustyIpsNextDifference sourcePointer sourceLength
                                                         targetPointer targetLength
                                                         (fromIntegral from)))

-- | The first position at or after @from@, within the shared prefix, where source and target
-- agree — the end of an IPS diff region. Bounds and sentinel as in 'nextDifference'.
nextAgreement :: ByteString -> ByteString -> Offset -> Offset
nextAgreement source target (Offset from) = unsafePerformIO $
  withByteString source $ \sourcePointer sourceLength ->
  withByteString target $ \targetPointer targetLength ->
    pure $! Offset (fromIntegral (rustyIpsNextAgreement sourcePointer sourceLength
                                                        targetPointer targetLength
                                                        (fromIntegral from)))
