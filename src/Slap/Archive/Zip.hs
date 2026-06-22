-- | ZIP reading via rusty-slap: list the entry names, then pull one entry
-- out. A thin binding over the FFI marshalling helpers in "Slap.FFI",
-- sibling to "Slap.BPS.FFI".
module Slap.Archive.Zip
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
import Slap.FFI (readByteString, readText, withByteString)

foreign import ccall unsafe "rusty_zip_entry_names"
  rustyZipEntryNames
    :: Ptr Word8 -> CSize
    -> Ptr (Ptr Word8) -> Ptr CSize     -- entry names, NUL-terminated
    -> Ptr (Ptr Word8) -> Ptr CSize     -- failure reason
    -> IO CInt

foreign import ccall unsafe "rusty_zip_extract_entry"
  rustyZipExtractEntry
    :: Ptr Word8 -> CSize               -- archive bytes
    -> Ptr Word8 -> CSize               -- entry name (UTF-8)
    -> Ptr (Ptr Word8) -> Ptr CSize     -- decompressed entry bytes
    -> Ptr (Ptr Word8) -> Ptr CSize     -- failure reason
    -> IO CInt

-- | A ZIP's entry names, read from the central directory.
zipEntryNames :: ByteString -> Either UnreadableReason [Text]
zipEntryNames archiveBytes = unsafePerformIO $
  withByteString archiveBytes $ \dataPointer dataLength ->
    fmap splitNames <$> callZipReader (rustyZipEntryNames dataPointer dataLength)

-- | The decompressed bytes of one named entry.
zipExtractEntry :: ByteString -> Text -> Either UnreadableReason ByteString
zipExtractEntry archiveBytes entryName = unsafePerformIO $
  withByteString archiveBytes $ \dataPointer dataLength ->
  withByteString (TextEncoding.encodeUtf8 entryName) $ \namePointer nameLength ->
    callZipReader (rustyZipExtractEntry dataPointer dataLength namePointer nameLength)

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

-- | Split the NUL-terminated name buffer, decoding each name as UTF-8.
splitNames :: ByteString -> [Text]
splitNames =
  map TextEncoding.decodeUtf8Lenient . filter (not . ByteString.null) . ByteString.split 0
