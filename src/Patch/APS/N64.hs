{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StrictData #-}

module Patch.APS.N64
  ( APSN64Patch(..)
  , APSN64Header(..)
  , APSN64Record(..)
  , APSPatchType(..)
  , APSImageFormat(..)
  , fromAPSImageFormat
  , parseAPSN64
  , applyAPSN64
  , applyAPSN64Memory
  , encodeAPSN64
  , apsN64Meta
  , apsN64Info
  ) where

-- Canonical reference: https://github.com/btimofeev/UniPatcher/wiki/APS-(N64) (Blackbag spec, 1998)
-- Secondary: RomPatcher.js modules/RomPatcher.format.aps_n64.js

import Patch.Get (Get, runGet, getByte, getBytes, skip, atEnd, remaining, word32LE)
import Patch.Measure (Length(..))
import Patch.Binary (copyByteStringRange)
import Patch.Format (padHex, renderField)

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Char8 as ByteString8
import Data.ByteString.Internal (unsafeCreate)
import qualified Data.ByteString.Lazy as LazyByteString
import Data.ByteString.Builder (Builder, word8, byteString, toLazyByteString)
import Patch.Binary (putWord32LE)
import Data.Int (Int64)
import Data.Word (Word8, Word32)
import Control.Monad (forM_, when)
import Foreign.Marshal.Utils (fillBytes)
import Foreign.Ptr (plusPtr)
import System.IO

----------------------------------------------------------------------------
-- Types
----------------------------------------------------------------------------

data APSPatchType = APSSimple | APSN64Specific
  deriving (Show, Eq)

toAPSPatchType :: Word8 -> Either String APSPatchType
toAPSPatchType 0 = Right APSSimple
toAPSPatchType 1 = Right APSN64Specific
toAPSPatchType byte = Left ("APS-N64: unknown patch type: " ++ show byte)

fromAPSPatchType :: APSPatchType -> Word8
fromAPSPatchType APSSimple       = 0
fromAPSPatchType APSN64Specific  = 1

data APSImageFormat = V64Format | Z64Format | UnknownImageFormat Word8
  deriving (Show, Eq)

toAPSImageFormat :: Word8 -> APSImageFormat
toAPSImageFormat 0 = V64Format
toAPSImageFormat 1 = Z64Format
toAPSImageFormat byte = UnknownImageFormat byte

fromAPSImageFormat :: APSImageFormat -> Word8
fromAPSImageFormat V64Format              = 0
fromAPSImageFormat Z64Format              = 1
fromAPSImageFormat (UnknownImageFormat byte) = byte

data APSN64Patch = APSN64Patch APSN64Header [APSN64Record]
  deriving (Show)

data APSN64Header = APSN64Header
  { apsN64PatchType   :: APSPatchType
  , apsN64Encoding    :: Word8        -- encoding method byte (0 in all known patches)
  , apsN64Description :: ByteString   -- 50 bytes
  , apsN64ImageFormat :: Maybe APSImageFormat
  , apsN64CartId      :: Maybe ByteString  -- 2 bytes
  , apsN64Country     :: Maybe Word8
  , apsN64Crc         :: Maybe ByteString  -- 8 bytes
  , apsN64DestinationSize    :: Word32
  } deriving (Show)

data APSN64Record
  = APSN64Normal Int64 ByteString    -- offset, data
  | APSN64RLE    Int64 Word8 Word8   -- offset, value, count
  deriving (Show)

----------------------------------------------------------------------------
-- Parse
----------------------------------------------------------------------------

parseAPSN64 :: ByteString -> Either String APSN64Patch
parseAPSN64 input
  | ByteString.length input < 5 = Left "APS-N64: input too short"
  | ByteString.take 5 input /= "APS10" = Left "not an APS-N64 file (bad magic)"
  | otherwise = runGet parseN64 input

parseN64 :: Get APSN64Patch
parseN64 = do
  skip (Length 5)  -- "APS10"
  patchTypeByte <- getByte
  case toAPSPatchType patchTypeByte of
    Left errorMessage -> fail errorMessage
    Right patchType -> do
      encodingByte <- getByte
      description <- getBytes (Length 50)
      case patchType of
        APSSimple -> do
          destinationSize <- word32LE
          records <- parseN64Records
          pure $ APSN64Patch
            APSN64Header
              { apsN64PatchType = patchType, apsN64Encoding = encodingByte, apsN64Description = description
              , apsN64ImageFormat = Nothing, apsN64CartId = Nothing
              , apsN64Country = Nothing, apsN64Crc = Nothing, apsN64DestinationSize = destinationSize
              }
            records
        APSN64Specific -> do
          imageFormat  <- toAPSImageFormat <$> getByte
          cartId  <- getBytes (Length 2)
          country <- getByte
          crcBytes  <- getBytes (Length 8)
          skip (Length 5)  -- padding (bytes 69-73)
          destinationSize <- word32LE
          records <- parseN64Records
          pure $ APSN64Patch
            APSN64Header
              { apsN64PatchType = patchType, apsN64Encoding = encodingByte, apsN64Description = description
              , apsN64ImageFormat = Just imageFormat, apsN64CartId = Just cartId
              , apsN64Country = Just country, apsN64Crc = Just crcBytes, apsN64DestinationSize = destinationSize
              }
            records

parseN64Records :: Get [APSN64Record]
parseN64Records = do
  done <- atEnd
  if done then pure []
  else do
    avail <- remaining
    if unLength avail < 5 then pure []
    else do
      offset <- fromIntegral <$> word32LE
      dataLength <- getByte
      if dataLength == 0
        then do  -- RLE record
          value <- getByte
          count <- getByte
          rest <- parseN64Records
          pure (APSN64RLE offset value count : rest)
        else do  -- Normal record
          payload <- getBytes (Length (fromIntegral dataLength))
          rest <- parseN64Records
          pure (APSN64Normal offset payload : rest)

----------------------------------------------------------------------------
-- Apply
----------------------------------------------------------------------------

applyAPSN64 :: APSN64Patch -> FilePath -> IO Int
applyAPSN64 (APSN64Patch _ records) target = withBinaryFile target ReadWriteMode $ \handle -> do
  mapM_ (applyN64Record handle) records
  pure (length records)

applyN64Record :: Handle -> APSN64Record -> IO ()
applyN64Record handle (APSN64Normal offset payload) = do
  hSeek handle AbsoluteSeek (fromIntegral offset)
  ByteString.hPut handle payload
applyN64Record handle (APSN64RLE offset value count) = do
  hSeek handle AbsoluteSeek (fromIntegral offset)
  ByteString.hPut handle (ByteString.replicate (fromIntegral count) value)

applyAPSN64Memory :: APSN64Patch -> ByteString -> ByteString
applyAPSN64Memory (APSN64Patch _ records) source = unsafeCreate outputLength $ \targetPointer -> do
    copyByteStringRange targetPointer 0 source 0 (min sourceLength outputLength)
    when (outputLength > sourceLength) $
      fillBytes (targetPointer `plusPtr` sourceLength) (0 :: Word8) (outputLength - sourceLength)
    forM_ records $ \case
      APSN64Normal offset payload ->
        copyByteStringRange targetPointer (fromIntegral offset) payload 0 (ByteString.length payload)
      APSN64RLE offset value count ->
        fillBytes (targetPointer `plusPtr` fromIntegral offset) value (fromIntegral count)
  where
    sourceLength = ByteString.length source
    recordEnd (APSN64Normal offset payload) = fromIntegral offset + ByteString.length payload
    recordEnd (APSN64RLE offset _ count)     = fromIntegral offset + fromIntegral count
    outputLength = foldl' max sourceLength (map recordEnd records)

----------------------------------------------------------------------------
-- Info
----------------------------------------------------------------------------

apsN64Meta :: APSN64Patch -> [(String, String)]
apsN64Meta (APSN64Patch header _) = concat
  [ [("patch type", patchTypeName (apsN64PatchType header))]
  , [("encoding", show (apsN64Encoding header)) | apsN64Encoding header /= 0]
  , descriptionField (apsN64Description header)
  , formatField (apsN64ImageFormat header)
  , cartField (apsN64CartId header)
  , countryField (apsN64Country header)
  , [("dest size", show (apsN64DestinationSize header))]
  ]
  where
    descriptionField description
      | ByteString.all (\byte -> byte == 0x20 || byte == 0) description = []
      | otherwise = [("description", show (ByteString.takeWhile (/= 0) description))]
    patchTypeName APSSimple      = "simple"
    patchTypeName APSN64Specific = "N64-specific"
    formatField Nothing                       = []
    formatField (Just V64Format)              = [("image", "V64 (byteswapped)")]
    formatField (Just Z64Format)              = [("image", "Z64 (big-endian)")]
    formatField (Just (UnknownImageFormat format)) = [("image", "unknown (" ++ show format ++ ")")]
    cartField Nothing      = []
    cartField (Just cartId) = [("cart ID", concatMap (\byte -> padHex 2 (fromIntegral byte)) (ByteString.unpack cartId))]
    countryField Nothing        = []
    countryField (Just country) = [("country", "0x" ++ padHex 2 (fromIntegral country))]

apsN64Info :: APSN64Patch -> String
apsN64Info patch@(APSN64Patch _ records) = unlines $ filter (not . null) $
  [ "format:      APS (N64)" ]
  ++ map renderField (apsN64Meta patch)
  ++ [ "records:     " ++ show (length records) ]

----------------------------------------------------------------------------
-- Create (simple type, raw overwrite records, max 255 bytes each)
----------------------------------------------------------------------------

-- | Encode pre-diffed records as an APS N64 patch.
-- Records are split at 255 bytes internally.
-- Patch type: APSSimple matches the simple-record structure we emit.
-- N64-specific (type 1) would require image format, cart ID, country.
-- Encoding byte: genuinely unused by all known implementations; 0 is canonical.
encodeAPSN64 :: [(Int, ByteString)] -> Word32 -> String -> ByteString
encodeAPSN64 records destinationSize description = LazyByteString.toStrict $ toLazyByteString $
    byteString "APS10"             -- magic
    <> word8 (fromAPSPatchType APSSimple)  -- patch type: simple
    <> word8 0                     -- encoding: not used
    <> byteString descriptionBytes        -- 50-byte description
    <> putWord32LE destinationSize -- dest size
    <> foldMap encodeN64Record (splitLong records)
  where
    descriptionBytes = let padded = ByteString8.pack (take 50 description)
                in padded <> ByteString.replicate (50 - ByteString.length padded) 0

splitLong :: [(Int, ByteString)] -> [(Int, ByteString)]
splitLong = concatMap splitRecord
  where
    splitRecord (offset, payload)
      | ByteString.length payload <= 255 = [(offset, payload)]
      | otherwise =
          let (chunk, rest) = ByteString.splitAt 255 payload
          in (offset, chunk) : splitRecord (offset + 255, rest)

encodeN64Record :: (Int, ByteString) -> Builder
encodeN64Record (offset, payload) =
    putWord32LE (fromIntegral offset :: Word32)
    <> word8 (fromIntegral (ByteString.length payload))
    <> byteString payload
