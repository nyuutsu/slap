{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StrictData #-}

module Patch.RUP
  ( RUPPatch(..)
  , RUPInfo(..)
  , RUPRecord(..)
  , OverflowMode(..)
  , parseRUP
  , applyRUP
  , applyRUPMemory
  , createRUP
  , rupMeta
  , rupInfo
  ) where

-- Canonical reference: docs/specs/ninja2-filespec20.txt (Derrick Sobodash, 2006)
-- Archived from http://ninja.cinnamonpirate.com/files/filespec20.txt
-- Secondary: RomPatcher.js modules/RomPatcher.format.rup.js
-- Note: NINJA2 ROM type numbering differs from NINJA1 (10 types vs 18);
-- see docs/specs/ninja2-cliusage.txt. slap stores RUP ROM type as raw Word8.

import Patch.Get (Get, runGet, getByte, getBytes, atEnd)
import Patch.Binary (diffHunks, md5, copyBSRange)
import Patch.Format (padHex, renderField)

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BS8
import Data.ByteString.Internal (unsafeCreate)
import qualified Data.ByteString.Lazy as BL
import Data.ByteString.Builder (Builder, word8, byteString, toLazyByteString)
import Data.Bits (xor, (.&.), shiftR)
import Data.Int (Int64)
import Data.Word (Word8)
import Control.Monad (forM_, when)
import Foreign.Marshal.Utils (fillBytes)
import Foreign.Ptr (plusPtr)
import Foreign.Storable (peekByteOff, pokeByteOff)
import System.IO

----------------------------------------------------------------------------
-- Types
----------------------------------------------------------------------------

-- | Overflow mode: how size changes between source and target are handled.
-- 'A' (0x41) = append extra bytes, 'M' (0x4D) = truncate.
-- Spec does not mention XOR-with-0xFF encoding of overflow data;
-- that is a RomPatcher.js convention which we follow for compatibility.
data OverflowMode = OverflowAppend | OverflowTruncate
  deriving (Show, Eq)

toOverflowMode :: Word8 -> Either String OverflowMode
toOverflowMode 0x41 = Right OverflowAppend
toOverflowMode 0x4D = Right OverflowTruncate
toOverflowMode b    = Left ("RUP: unknown overflow type: 0x" ++ padHex 2 (fromIntegral b))

fromOverflowMode :: OverflowMode -> Word8
fromOverflowMode OverflowAppend   = 0x41  -- 'A'
fromOverflowMode OverflowTruncate = 0x4D  -- 'M'

data RUPPatch = RUPPatch
  { rupHeader       :: RUPInfo
  , rupRecords      :: [RUPRecord]
  , rupOverflow     :: Maybe ByteString  -- on-disk overflow data (XOR'd with 0xFF)
  , rupOverflowType :: Maybe OverflowMode
  , rupSourceMD5    :: Maybe ByteString  -- 16 bytes
  , rupTargetMD5    :: Maybe ByteString  -- 16 bytes
  , rupSourceSize     :: Int64
  , rupTargetSize     :: Int64
  , rupPatchEnc     :: Word8             -- PATCH_ENC (text encoding, byte 6)
  , rupRomType      :: Word8             -- ROM type byte from OPEN_NEW_FILE command
  } deriving (Show)

data RUPInfo = RUPInfo
  { rupAuthor      :: Maybe ByteString
  , rupVersion     :: Maybe ByteString
  , rupTitle       :: Maybe ByteString
  , rupGenre       :: Maybe ByteString
  , rupLanguage    :: Maybe ByteString
  , rupDate        :: Maybe ByteString
  , rupWebsite     :: Maybe ByteString
  , rupDescription :: Maybe ByteString
  } deriving (Show)

data RUPRecord = RUPRecord
  { rupRecOffset :: Int64
  , rupRecXor    :: ByteString
  } deriving (Show)


----------------------------------------------------------------------------
-- VLV: Variable Length Value (1-byte length prefix, then N LE bytes)
----------------------------------------------------------------------------

packedInt :: Get Int64
packedInt = do
  n <- fromIntegral <$> getByte
  bytes <- getBytes n
  -- Only interpret first 8 bytes (enough for Int64); extra bytes are
  -- consumed from the stream but don't contribute to the value.
  let n' = min n 8
  pure $ foldl' (\acc i ->
    acc + fromIntegral (BS.index bytes i) * (256 ^ i)) 0 [0..n'-1]

packedBS :: Get ByteString
packedBS = do
  len <- fromIntegral <$> packedInt
  getBytes len

----------------------------------------------------------------------------
-- Fixed header (2048 bytes): NINJA2 format
-- Spec says "first sector of the patch (1024 bytes)" but actual total is 2048.
-- PATCH_ENC (1B text encoding at offset 6) is stored in rupPatchEnc.
----------------------------------------------------------------------------

headerSize :: Int
headerSize = 0x800  -- NINJA2 spec: fixed 2048-byte header

-- | Parse the fixed header region.  Field offsets per ninja2-filespec20.txt §2.
parseFixedHeader :: ByteString -> RUPInfo
parseFixedHeader bs = RUPInfo
  { rupAuthor      = extractField 0x007 84
  , rupVersion     = extractField 0x05B 11
  , rupTitle       = extractField 0x066 256
  , rupGenre       = extractField 0x166 48
  , rupLanguage    = extractField 0x196 48
  , rupDate        = extractField 0x1C6 8
  , rupWebsite     = extractField 0x1CE 512
  , rupDescription = extractField 0x3CE 1074
  }
  where
    extractField offset len =
      let field = BS.take len (BS.drop offset bs)
          trimmed = BS.takeWhile (/= 0) field
      in if BS.null trimmed then Nothing else Just trimmed

----------------------------------------------------------------------------
-- Command stream (starts at offset 0x800)
--   0x01: OPEN_NEW_FILE
--   0x02: XOR record
--   0x00: END
----------------------------------------------------------------------------

parseRUP :: ByteString -> Either String RUPPatch
parseRUP bs
  | BS.length bs < 7 = Left "RUP: input too short"
  | BS.take 6 bs /= "NINJA2" = Left "not a RUP file (bad magic)"
  | BS.length bs < headerSize = Left "RUP: truncated header"
  | otherwise = runGet parseRUPBody bs
  where
    parseRUPBody :: Get RUPPatch
    parseRUPBody = do
      hdr <- getBytes headerSize
      let meta = parseFixedHeader hdr
          enc  = BS.index hdr 6  -- PATCH_ENC byte
      p <- parseCommands (emptyPatch meta enc)
      pure p { rupRecords = reverse (rupRecords p) }

    emptyPatch m enc = RUPPatch
      { rupHeader = m, rupRecords = [], rupOverflow = Nothing
      , rupOverflowType = Nothing, rupSourceMD5 = Nothing, rupTargetMD5 = Nothing
      , rupSourceSize = 0, rupTargetSize = 0, rupPatchEnc = enc, rupRomType = 0
      }

parseCommands :: RUPPatch -> Get RUPPatch
parseCommands patch = do
  done <- atEnd
  if done then pure patch
  else do
    code <- getByte
    case code of
      0x01 -> parseFileCmd patch >>= parseCommands
      0x02 -> parseXorRecord patch >>= parseCommands
      0x00 -> pure patch  -- END marker
      _    -> fail ("RUP: unknown command code: 0x" ++ padHex 2 (fromIntegral code))

-- | Command 0x01: OPEN_NEW_FILE
parseFileCmd :: RUPPatch -> Get RUPPatch
parseFileCmd patch = do
  _filename <- packedBS
  rt <- getByte  -- ROM type byte
  srcSz <- packedInt
  tgtSz <- packedInt
  srcMD5 <- getBytes 16
  tgtMD5 <- getBytes 16
  (ovType, overflow) <- if srcSz /= tgtSz
    then do
      ty <- getByte
      case toOverflowMode ty of
        Left err -> fail err
        Right mode -> do
          dat <- packedBS
          pure (Just mode, Just dat)
    else pure (Nothing, Nothing)
  pure patch { rupSourceMD5    = Just srcMD5
             , rupTargetMD5    = Just tgtMD5
             , rupSourceSize     = srcSz
             , rupTargetSize     = tgtSz
             , rupOverflow     = overflow
             , rupOverflowType = ovType
             , rupRomType      = rt
             }

-- | Command 0x02: XOR record
parseXorRecord :: RUPPatch -> Get RUPPatch
parseXorRecord patch = do
  off <- packedInt
  xorDat <- packedBS
  pure patch { rupRecords = RUPRecord off xorDat : rupRecords patch }

----------------------------------------------------------------------------
-- Apply
----------------------------------------------------------------------------

applyRUP :: RUPPatch -> FilePath -> IO Int
applyRUP patch target = do
  withBinaryFile target ReadWriteMode $ \h -> do
    mapM_ (applyRecord h) (rupRecords patch)
    -- Handle overflow (append data for file size changes).
    -- On-disk overflow is XOR'd with 0xFF; decode before writing.
    case rupOverflow patch of
      Nothing -> pure ()
      Just overflow -> do
        let appendPos = rupSourceSize patch
        hSeek h AbsoluteSeek (fromIntegral appendPos)
        BS.hPut h (BS.map (xor 0xFF) overflow)
    -- Handle truncation (if target is smaller than source)
    when (rupTargetSize patch < rupSourceSize patch) $
      hSetFileSize h (fromIntegral (rupTargetSize patch))
  pure (length (rupRecords patch))

applyRecord :: Handle -> RUPRecord -> IO ()
applyRecord h (RUPRecord off xorDat) = do
  hSeek h AbsoluteSeek (fromIntegral off)
  srcBytes <- BS.hGet h (BS.length xorDat)
  let padded = if BS.length srcBytes < BS.length xorDat
               then srcBytes <> BS.replicate (BS.length xorDat - BS.length srcBytes) 0
               else srcBytes
      result = BS.packZipWith xor padded xorDat
  hSeek h AbsoluteSeek (fromIntegral off)
  BS.hPut h result

-- | Apply a RUP patch in memory: XOR records + overflow handling.
applyRUPMemory :: RUPPatch -> ByteString -> ByteString
applyRUPMemory patch source = unsafeCreate outLen $ \ptr -> do
    -- Copy source, zero-fill any extension
    copyBSRange ptr 0 source 0 (min srcLen outLen)
    when (outLen > srcLen) $
      fillBytes (ptr `plusPtr` srcLen) (0 :: Word8) (outLen - srcLen)
    -- XOR records: read from buffer, XOR, write back
    forM_ (rupRecords patch) $ \(RUPRecord off xorDat) -> do
      let recOff = fromIntegral off :: Int
          len    = BS.length xorDat
      forM_ [0..len-1] $ \i -> do
        let pos = recOff + i
        old <- peekByteOff ptr pos :: IO Word8
        pokeByteOff ptr pos (old `xor` BS.index xorDat i)
    -- Overflow: decoded data (XOR'd with 0xFF on disk) written at source end
    case rupOverflow patch of
      Nothing -> pure ()
      Just overflow -> do
        let appendPos = fromIntegral (rupSourceSize patch) :: Int
            decoded = BS.map (xor 0xFF) overflow
        copyBSRange ptr appendPos decoded 0 (BS.length decoded)
  where
    srcLen = BS.length source
    tgt    = fromIntegral (rupTargetSize patch) :: Int
    outLen = if tgt > 0 then tgt else srcLen

----------------------------------------------------------------------------
-- Info
----------------------------------------------------------------------------

rupMeta :: RUPPatch -> [(String, String)]
rupMeta p = concat
  [ metaField "title"       (rupTitle (rupHeader p))
  , metaField "author"      (rupAuthor (rupHeader p))
  , metaField "version"     (rupVersion (rupHeader p))
  , metaField "date"        (rupDate (rupHeader p))
  , metaField "genre"       (rupGenre (rupHeader p))
  , metaField "language"    (rupLanguage (rupHeader p))
  , metaField "website"     (rupWebsite (rupHeader p))
  , metaField "description" (rupDescription (rupHeader p))
  , romTypeField
  , sizeFields
  , md5Field "source MD5" (rupSourceMD5 p)
  , md5Field "target MD5" (rupTargetMD5 p)
  , overflowField
  ]
  where
    metaField _ Nothing = []
    metaField label (Just v) = [(label, BS8.unpack v)]

    romTypeField
      | rupRomType p == 0 = []
      | otherwise = [("ROM type", show (rupRomType p))]

    sizeFields
      | rupSourceSize p == 0 && rupTargetSize p == 0 = []
      | otherwise = [ ("source size", show (rupSourceSize p))
                     , ("target size", show (rupTargetSize p)) ]

    md5Field _ Nothing = []
    md5Field label (Just h) =
      [(label, concatMap (\b -> padHex 2 (fromIntegral b)) (BS.unpack h))]

    overflowField = case (rupOverflowType p, rupOverflow p) of
      (Just OverflowAppend,   Just d) -> [("overflow", "append " ++ show (BS.length d) ++ " bytes")]
      (Just OverflowTruncate, Just d) -> [("overflow", "truncate " ++ show (BS.length d) ++ " bytes")]
      (_, Just d)                     -> [("overflow", show (BS.length d) ++ " bytes")]
      _                               -> []

rupInfo :: RUPPatch -> String
rupInfo p = unlines $ filter (not . null) $
  [ "format:      RUP (NINJA2)" ]
  ++ map renderField (rupMeta p)
  ++ [ "records:     " ++ show (length (rupRecords p)) ]

----------------------------------------------------------------------------
-- Create
----------------------------------------------------------------------------

-- | Create a RUP/NINJA2 patch from original and modified ByteStrings.
-- XOR-based records with VLV encoding; handles size changes via overflow.
createRUP :: ByteString -> ByteString -> RUPInfo -> Word8 -> ByteString
createRUP old new info romType = BL.toStrict $ toLazyByteString $
    byteString "NINJA2"                  -- magic (6 bytes)
    <> word8 0                           -- text encoding
    <> byteString (encodeFixedHeader info)  -- rest of 2048-byte header
    <> word8 0x01                        -- OPEN_NEW_FILE command
    <> putVLV 0                          -- filename length (empty)
    <> word8 romType                     -- ROM type byte
    <> putVLV (fromIntegral (BS.length old))   -- source size
    <> putVLV (fromIntegral (BS.length new))   -- target size
    <> byteString (md5 old)              -- source MD5
    <> byteString (md5 new)              -- target MD5
    <> overflowPart
    <> foldMap encodeXorRec xorHunks
    <> word8 0x00                        -- END command
  where
    -- XOR hunks over the shared region
    minLen = min (BS.length old) (BS.length new)
    oldTrim = BS.take minLen old
    newTrim = BS.take minLen new
    -- diffHunks finds changed regions; we then XOR old and new at those positions
    xorHunks = map toXor (diffHunks oldTrim newTrim)
    toXor (off, newDat) =
      let oldDat = BS.take (BS.length newDat) (BS.drop off oldTrim)
      in (off, BS.packZipWith xor oldDat newDat)

    -- Overflow section: emitted whenever sizes differ (parser expects it).
    -- Type byte: 'A' (0x41) = append, 'M' (0x4D) = truncate/minify.
    -- Data is XOR'd with 0xFF on disk (RomPatcher.js convention).
    overflowPart
      | BS.length new > BS.length old =
          let extra = BS.drop (BS.length old) new
          in word8 (fromOverflowMode OverflowAppend)
             <> putVLV (fromIntegral (BS.length extra))
             <> byteString (BS.map (xor 0xFF) extra)
      | BS.length new < BS.length old =
          let extra = BS.drop (BS.length new) old
          in word8 (fromOverflowMode OverflowTruncate)
             <> putVLV (fromIntegral (BS.length extra))
             <> byteString (BS.map (xor 0xFF) extra)
      | otherwise = mempty

-- | Encode a RUPInfo into the fixed header region (bytes 7..2047).
-- Mirrors parseFixedHeader layout: author@0x007/84, version@0x05B/11,
-- title@0x066/256, genre@0x166/48, language@0x196/48, date@0x1C6/8,
-- website@0x1CE/512, description@0x3CE/1074.
encodeFixedHeader :: RUPInfo -> ByteString
encodeFixedHeader info = BS.pack $ map byteAt [0 .. headerSize - 8]
  where
    -- Offset relative to byte 7 in the file (first byte after magic+textenc)
    byteAt i = case lookup i fieldBytes of
      Just b  -> b
      Nothing -> 0
    fieldBytes = concatMap expand fields
    expand (off, len, mbs) = case mbs of
      Nothing -> []
      Just bs -> zip [off..off+len-1] (BS.unpack (padTo len bs))
    padTo n bs = BS.take n bs <> BS.replicate (max 0 (n - BS.length bs)) 0
    fields =
      [ (0x007 - 7, 84,   rupAuthor info)
      , (0x05B - 7, 11,   rupVersion info)
      , (0x066 - 7, 256,  rupTitle info)
      , (0x166 - 7, 48,   rupGenre info)
      , (0x196 - 7, 48,   rupLanguage info)
      , (0x1C6 - 7, 8,    rupDate info)
      , (0x1CE - 7, 512,  rupWebsite info)
      , (0x3CE - 7, 1074, rupDescription info)
      ]

encodeXorRec :: (Int, ByteString) -> Builder
encodeXorRec (off, dat) =
    word8 0x02                                -- XOR command
    <> putVLV (fromIntegral off)              -- offset
    <> putVLV (fromIntegral (BS.length dat))  -- length
    <> byteString dat                         -- XOR data

-- | VLV: 1-byte length prefix, then N bytes little-endian.
putVLV :: Int64 -> Builder
putVLV 0 = word8 1 <> word8 0
putVLV n =
  let bytes = vlvBytes n
  in word8 (fromIntegral (length bytes)) <> foldMap word8 bytes

vlvBytes :: Int64 -> [Word8]
vlvBytes 0 = []
vlvBytes n = fromIntegral (n .&. 0xFF) : vlvBytes (n `shiftR` 8)

