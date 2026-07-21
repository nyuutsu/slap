-- | ZIP reading via rusty-slap.
module Archive.Zip
  ( zipEntryNames
  , zipExtractEntry
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.Text (Text)
import qualified Data.Text.Encoding as TextEncoding
import Data.Word (Word8)
import Foreign.C.Types (CSize(..), CInt(..))
import Foreign.Marshal.Alloc (alloca)
import Foreign.Ptr (Ptr)
import System.IO.Unsafe (unsafePerformIO)

import Slap.Archive.Types (UnreadableReason(..))
import Slap.Binary (getWord32LE)
import Slap.FFI (readByteString, readText, withByteString)

foreign import ccall unsafe "rusty_zip_entry_names"
  rustyZipEntryNames
    :: Ptr Word8 -> CSize
    -> Ptr (Ptr Word8) -> Ptr CSize     -- entry names, length-prefixed
    -> Ptr (Ptr Word8) -> Ptr CSize     -- failure reason
    -> IO CInt

foreign import ccall unsafe "rusty_zip_extract_entry"
  rustyZipExtractEntry
    :: Ptr Word8 -> CSize               -- archive bytes
    -> CSize                            -- entry index
    -> Ptr (Ptr Word8) -> Ptr CSize     -- decompressed entry bytes
    -> Ptr (Ptr Word8) -> Ptr CSize     -- failure reason
    -> IO CInt

-- | A ZIP's entry names, read from the central directory in order, so a name's position is its extraction index.
zipEntryNames :: ByteString -> Either UnreadableReason [Text]
zipEntryNames archiveBytes = unsafePerformIO $
  withByteString archiveBytes $ \dataPointer dataLength ->
    fmap parseLengthPrefixedNames <$> callZipReader (rustyZipEntryNames dataPointer dataLength)

-- | The decompressed bytes of the entry at a central-directory index.
zipExtractEntry :: ByteString -> Int -> Either UnreadableReason ByteString
zipExtractEntry archiveBytes entryIndex = unsafePerformIO $
  withByteString archiveBytes $ \dataPointer dataLength ->
    callZipReader (rustyZipExtractEntry dataPointer dataLength (fromIntegral entryIndex))

-- | Run a zip FFI call — already given its input pointers, awaiting only
-- the result and error out-pointers — and turn its return code into the
-- result buffer or a faithful 'UnreadableReason'.
callZipReader
  :: (Ptr (Ptr Word8) -> Ptr CSize -> Ptr (Ptr Word8) -> Ptr CSize -> IO CInt)
  -> IO (Either UnreadableReason ByteString)
callZipReader call =
  alloca $ \resultAddressPointer ->
  alloca $ \resultLengthPointer ->
  alloca $ \errorAddressPointer ->
  alloca $ \errorLengthPointer -> do
    returnCode <- call resultAddressPointer resultLengthPointer
                       errorAddressPointer  errorLengthPointer
    if returnCode /= 0
      then Left . UnreadableReason <$> readText errorAddressPointer errorLengthPointer
      else Right <$> readByteString resultAddressPointer resultLengthPointer

-- | The name buffer is each name's little-endian u32 byte length, then that many bytes.
-- Length-prefixed rather than separated, so a NUL in a name is a byte of the name, not a boundary.
parseLengthPrefixedNames :: ByteString -> [Text]
parseLengthPrefixedNames buffer
  | ByteString.length buffer < 4 = []
  | otherwise =
      let nameLength             = fromIntegral (getWord32LE 0 buffer)
          (nameBytes, remaining) = ByteString.splitAt nameLength (ByteString.drop 4 buffer)
      in TextEncoding.decodeUtf8Lenient nameBytes : parseLengthPrefixedNames remaining
