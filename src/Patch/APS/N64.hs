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
import Patch.Binary (copyBSRange)
import Patch.Format (padHex, renderField)

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BS8
import Data.ByteString.Internal (unsafeCreate)
import qualified Data.ByteString.Lazy as BL
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
toAPSPatchType b = Left ("APS-N64: unknown patch type: " ++ show b)

fromAPSPatchType :: APSPatchType -> Word8
fromAPSPatchType APSSimple       = 0
fromAPSPatchType APSN64Specific  = 1

data APSImageFormat = V64Format | Z64Format | UnknownImageFormat Word8
  deriving (Show, Eq)

toAPSImageFormat :: Word8 -> APSImageFormat
toAPSImageFormat 0 = V64Format
toAPSImageFormat 1 = Z64Format
toAPSImageFormat b = UnknownImageFormat b

fromAPSImageFormat :: APSImageFormat -> Word8
fromAPSImageFormat V64Format              = 0
fromAPSImageFormat Z64Format              = 1
fromAPSImageFormat (UnknownImageFormat b) = b

data APSN64Patch = APSN64Patch APSN64Header [APSN64Record]
  deriving (Show)

data APSN64Header = APSN64Header
  { n64PatchType   :: APSPatchType
  , n64Encoding    :: Word8        -- encoding method byte (0 in all known patches)
  , n64Description :: ByteString   -- 50 bytes
  , n64ImageFormat :: Maybe APSImageFormat
  , n64CartId      :: Maybe ByteString  -- 2 bytes
  , n64Country     :: Maybe Word8
  , n64Crc         :: Maybe ByteString  -- 8 bytes
  , n64DestSize    :: Word32
  } deriving (Show)

data APSN64Record
  = APSN64Normal Int64 ByteString    -- offset, data
  | APSN64RLE    Int64 Word8 Word8   -- offset, value, count
  deriving (Show)

----------------------------------------------------------------------------
-- Parse
----------------------------------------------------------------------------

parseAPSN64 :: ByteString -> Either String APSN64Patch
parseAPSN64 bs
  | BS.length bs < 5 = Left "APS-N64: input too short"
  | BS.take 5 bs /= "APS10" = Left "not an APS-N64 file (bad magic)"
  | otherwise = runGet parseN64 bs

parseN64 :: Get APSN64Patch
parseN64 = do
  skip 5  -- "APS10"
  ptypeByte <- getByte
  case toAPSPatchType ptypeByte of
    Left err -> fail err
    Right ptype -> do
      encodingByte <- getByte
      desc <- getBytes 50
      case ptype of
        APSSimple -> do
          destSize <- word32LE
          recs <- parseN64Records
          pure $ APSN64Patch
            (APSN64Header ptype encodingByte desc Nothing Nothing Nothing Nothing destSize)
            recs
        APSN64Specific -> do
          imgFmt  <- toAPSImageFormat <$> getByte
          cartId  <- getBytes 2
          country <- getByte
          crcVal  <- getBytes 8
          skip 5  -- padding (bytes 69-73)
          destSize <- word32LE
          recs <- parseN64Records
          pure $ APSN64Patch
            (APSN64Header ptype encodingByte desc (Just imgFmt) (Just cartId)
                          (Just country) (Just crcVal) destSize)
            recs

parseN64Records :: Get [APSN64Record]
parseN64Records = do
  done <- atEnd
  if done then pure []
  else do
    avail <- remaining
    if avail < 5 then pure []
    else do
      off <- fromIntegral <$> word32LE
      len <- getByte
      if len == 0
        then do  -- RLE record
          val   <- getByte
          count <- getByte
          rest <- parseN64Records
          pure (APSN64RLE off val count : rest)
        else do  -- Normal record
          dat <- getBytes (fromIntegral len)
          rest <- parseN64Records
          pure (APSN64Normal off dat : rest)

----------------------------------------------------------------------------
-- Apply
----------------------------------------------------------------------------

applyAPSN64 :: APSN64Patch -> FilePath -> IO Int
applyAPSN64 (APSN64Patch _ recs) target = withBinaryFile target ReadWriteMode $ \h -> do
  mapM_ (applyN64Record h) recs
  pure (length recs)

applyN64Record :: Handle -> APSN64Record -> IO ()
applyN64Record h (APSN64Normal off dat) = do
  hSeek h AbsoluteSeek (fromIntegral off)
  BS.hPut h dat
applyN64Record h (APSN64RLE off val count) = do
  hSeek h AbsoluteSeek (fromIntegral off)
  BS.hPut h (BS.replicate (fromIntegral count) val)

applyAPSN64Memory :: APSN64Patch -> ByteString -> ByteString
applyAPSN64Memory (APSN64Patch _ recs) source = unsafeCreate outLen $ \ptr -> do
    copyBSRange ptr 0 source 0 (min srcLen outLen)
    when (outLen > srcLen) $
      fillBytes (ptr `plusPtr` srcLen) (0 :: Word8) (outLen - srcLen)
    forM_ recs $ \case
      APSN64Normal off dat ->
        copyBSRange ptr (fromIntegral off) dat 0 (BS.length dat)
      APSN64RLE off val count ->
        fillBytes (ptr `plusPtr` fromIntegral off) val (fromIntegral count)
  where
    srcLen = BS.length source
    recEnd (APSN64Normal off dat) = fromIntegral off + BS.length dat
    recEnd (APSN64RLE off _ cnt)  = fromIntegral off + fromIntegral cnt
    outLen = foldl' max srcLen (map recEnd recs)

----------------------------------------------------------------------------
-- Info
----------------------------------------------------------------------------

apsN64Meta :: APSN64Patch -> [(String, String)]
apsN64Meta (APSN64Patch hdr _) = concat
  [ [("patch type", patchTypeName (n64PatchType hdr))]
  , [("encoding", show (n64Encoding hdr)) | n64Encoding hdr /= 0]
  , descField (n64Description hdr)
  , fmtField (n64ImageFormat hdr)
  , cartField (n64CartId hdr)
  , countryField (n64Country hdr)
  , [("dest size", show (n64DestSize hdr))]
  ]
  where
    descField d
      | BS.all (\b -> b == 0x20 || b == 0) d = []
      | otherwise = [("description", show (BS.takeWhile (/= 0) d))]
    patchTypeName APSSimple      = "simple"
    patchTypeName APSN64Specific = "N64-specific"
    fmtField Nothing                       = []
    fmtField (Just V64Format)              = [("image", "V64 (byteswapped)")]
    fmtField (Just Z64Format)              = [("image", "Z64 (big-endian)")]
    fmtField (Just (UnknownImageFormat f)) = [("image", "unknown (" ++ show f ++ ")")]
    cartField Nothing  = []
    cartField (Just c) = [("cart ID", concatMap (\b -> padHex 2 (fromIntegral b)) (BS.unpack c))]
    countryField Nothing  = []
    countryField (Just c) = [("country", "0x" ++ padHex 2 (fromIntegral c))]

apsN64Info :: APSN64Patch -> String
apsN64Info p@(APSN64Patch _ recs) = unlines $ filter (not . null) $
  [ "format:      APS (N64)" ]
  ++ map renderField (apsN64Meta p)
  ++ [ "records:     " ++ show (length recs) ]

----------------------------------------------------------------------------
-- Create (simple type, raw overwrite records, max 255 bytes each)
----------------------------------------------------------------------------

-- | Encode pre-diffed records as an APS N64 patch.
-- Records are split at 255 bytes internally.
-- Patch type: APSSimple matches the simple-record structure we emit.
-- N64-specific (type 1) would require image format, cart ID, country.
-- Encoding byte: genuinely unused by all known implementations; 0 is canonical.
encodeAPSN64 :: [(Int, ByteString)] -> Word32 -> String -> ByteString
encodeAPSN64 recs destSize desc = BL.toStrict $ toLazyByteString $
    byteString "APS10"             -- magic
    <> word8 (fromAPSPatchType APSSimple)  -- patch type: simple
    <> word8 0                     -- encoding: not used
    <> byteString descBytes        -- 50-byte description
    <> putWord32LE destSize        -- dest size
    <> foldMap encodeN64Rec (splitLong recs)
  where
    descBytes = let bs = BS8.pack (take 50 desc)
                in bs <> BS.replicate (50 - BS.length bs) 0

splitLong :: [(Int, ByteString)] -> [(Int, ByteString)]
splitLong = concatMap split1
  where
    split1 (off, dat)
      | BS.length dat <= 255 = [(off, dat)]
      | otherwise =
          let (chunk, rest) = BS.splitAt 255 dat
          in (off, chunk) : split1 (off + 255, rest)

encodeN64Rec :: (Int, ByteString) -> Builder
encodeN64Rec (off, dat) =
    putWord32LE (fromIntegral off :: Word32)
    <> word8 (fromIntegral (BS.length dat))
    <> byteString dat
