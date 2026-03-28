{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StrictData #-}

module Patch.GDIFF
  ( GDiffPatch(..)
  , GDiffCommand(..)
  , parseGDIFF
  , applyGDIFF
  , createGDIFF
  , gdiffMeta
  , gdiffInfo
  ) where

-- Canonical reference: W3C NOTE-GDIFF-19970901

import Patch.Binary (copyByteStringRange, diffHunks, putWord16BE, putWord32BE, putInt64BE)
import Patch.Get (runGet, getByte, getBytes, word16BE, word32BE, int64BE)
import Patch.Measure (Length(..))

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Lazy as LazyByteString
import Data.ByteString.Builder (Builder, word8, byteString, toLazyByteString)
import Data.ByteString.Internal (unsafeCreate)
import Data.Int (Int64)
import Data.Word (Word8)
import Foreign.Ptr (Ptr)

----------------------------------------------------------------------------
-- Types
----------------------------------------------------------------------------

data GDiffCommand
  = GDiffData ByteString       -- literal data to append
  | GDiffCopy Int64 Int64      -- offset into source, length
  deriving (Show)

data GDiffPatch = GDiffPatch
  { gdiffCommands :: [GDiffCommand]
  } deriving (Show)

----------------------------------------------------------------------------
-- Parsing
----------------------------------------------------------------------------

parseGDIFF :: ByteString -> Either String GDiffPatch
parseGDIFF input
  | ByteString.length input < 5 = Left "GDIFF: input too short"
  | ByteString.take 4 input /= "\xd1\xff\xd1\xff" = Left "not a GDIFF file (bad magic)"
  | ByteString.index input 4 /= 4 = Left ("GDIFF: unsupported version: " ++ show (ByteString.index input 4))
  | otherwise = runGet (do { _ <- getBytes (Length 5); parseCommands [] }) input
  where
    parseCommands accumulated = do
      opcode <- getByte
      case opcode of
        0 -> pure (GDiffPatch (reverse accumulated))

        -- DATA: opcode IS the length (1-246 bytes)
        _ | opcode <= 246 -> do
              payload <- getBytes (Length (fromIntegral opcode))
              parseCommands (GDiffData payload : accumulated)

        -- DATA with ushort length
        247 -> do dataLength <- fromIntegral <$> word16BE
                  payload <- getBytes (Length dataLength)
                  parseCommands (GDiffData payload : accumulated)

        -- DATA with int length
        248 -> do dataLength <- fromIntegral <$> word32BE
                  payload <- getBytes (Length dataLength)
                  parseCommands (GDiffData payload : accumulated)

        -- COPY ushort offset, ubyte length
        249 -> do offset <- fromIntegral <$> word16BE
                  copyLength <- fromIntegral <$> getByte
                  parseCommands (GDiffCopy offset copyLength : accumulated)

        -- COPY ushort offset, ushort length
        250 -> do offset <- fromIntegral <$> word16BE
                  copyLength <- fromIntegral <$> word16BE
                  parseCommands (GDiffCopy offset copyLength : accumulated)

        -- COPY ushort offset, int length
        251 -> do offset <- fromIntegral <$> word16BE
                  copyLength <- fromIntegral <$> word32BE
                  parseCommands (GDiffCopy offset copyLength : accumulated)

        -- COPY int offset, ubyte length
        252 -> do offset <- fromIntegral <$> word32BE
                  copyLength <- fromIntegral <$> getByte
                  parseCommands (GDiffCopy offset copyLength : accumulated)

        -- COPY int offset, ushort length
        253 -> do offset <- fromIntegral <$> word32BE
                  copyLength <- fromIntegral <$> word16BE
                  parseCommands (GDiffCopy offset copyLength : accumulated)

        -- COPY int offset, int length
        254 -> do offset <- fromIntegral <$> word32BE
                  copyLength <- fromIntegral <$> word32BE
                  parseCommands (GDiffCopy offset copyLength : accumulated)

        -- COPY long offset, int length
        255 -> do offset <- int64BE
                  copyLength <- fromIntegral <$> word32BE
                  parseCommands (GDiffCopy offset copyLength : accumulated)

        _ -> fail "impossible GDIFF opcode"  -- 0-255 covered above; GHC can't prove guard exhaustiveness

commandOutputSize :: GDiffCommand -> Int64
commandOutputSize (GDiffData payload)       = fromIntegral (ByteString.length payload)
commandOutputSize (GDiffCopy _ copyLength) = copyLength

----------------------------------------------------------------------------
-- Apply
----------------------------------------------------------------------------

applyGDIFF :: GDiffPatch -> ByteString -> Either String ByteString
applyGDIFF patch source
  | totalSize == 0 = Right ByteString.empty
  | otherwise = Right $ unsafeCreate (fromIntegral totalSize) $ \outputPointer ->
      applyLoop outputPointer 0 (gdiffCommands patch)
  where
    totalSize = sum (map commandOutputSize (gdiffCommands patch))

    applyLoop :: Ptr Word8 -> Int -> [GDiffCommand] -> IO ()
    applyLoop _outputPointer _position [] = pure ()
    applyLoop outputPointer position (command:remaining) = case command of
      GDiffData payload -> do
        let dataLength = ByteString.length payload
        copyByteStringRange outputPointer position payload 0 dataLength
        applyLoop outputPointer (position + dataLength) remaining
      GDiffCopy sourceOffset copyLength -> do
        let sourceStart = fromIntegral sourceOffset
            count = fromIntegral copyLength :: Int
        copyByteStringRange outputPointer position source sourceStart count
        applyLoop outputPointer (position + count) remaining

----------------------------------------------------------------------------
-- Info
----------------------------------------------------------------------------

-- | GDIFF carries no header metadata; this returns an empty list.
gdiffMeta :: GDiffPatch -> [(String, String)]
gdiffMeta _ = []

gdiffInfo :: GDiffPatch -> String
gdiffInfo patch = unlines $ filter (not . null)
  [ "format:      GDIFF (W3C)"
  , "commands:    " ++ show commandCount
  , "data cmds:   " ++ show dataCount ++ " (" ++ show dataBytes ++ " bytes)"
  , "copy cmds:   " ++ show copyCount
  , "output size: " ++ show totalOut
  ]
  where
    commands = gdiffCommands patch
    commandCount = length commands
    dataCount = length [() | GDiffData _ <- commands]
    copyCount = length [() | GDiffCopy _ _ <- commands]
    dataBytes = sum [ByteString.length payload | GDiffData payload <- commands]
    totalOut = sum (map commandOutputSize commands)

----------------------------------------------------------------------------
-- Create
----------------------------------------------------------------------------

-- Unchanged regions become COPY commands; changed regions become DATA commands.
createGDIFF :: ByteString -> ByteString -> ByteString
createGDIFF original modified = LazyByteString.toStrict $ toLazyByteString $
    byteString "\xd1\xff\xd1\xff"   -- magic
    <> word8 4                       -- version
    <> buildCommands 0 (diffHunks original modified)
    <> word8 0                       -- EOF command
  where
    minLength = min (ByteString.length original) (ByteString.length modified)
    buildCommands position [] =
      -- trailing unchanged region
      if position < minLength then encodeCopy (fromIntegral position) (fromIntegral (minLength - position))
      else mempty
    buildCommands position ((offset, payload) : remaining) =
      let gap = offset - position
          copyPart = if gap > 0 then encodeCopy (fromIntegral position) (fromIntegral gap) else mempty
          dataBuilder = encodeData payload
      in copyPart <> dataBuilder <> buildCommands (offset + ByteString.length payload) remaining

-- | Encode a DATA command, splitting into chunks if > 2^31.
encodeData :: ByteString -> Builder
encodeData payload
  | ByteString.null payload = mempty
  | payloadLength <= 246  = word8 (fromIntegral payloadLength) <> byteString payload
  | payloadLength <= 0xFFFF = word8 247 <> putWord16BE payloadLength <> byteString payload
  | otherwise     = word8 248 <> putWord32BE (fromIntegral payloadLength) <> byteString payload
  where payloadLength = ByteString.length payload

-- | Encode a COPY command with optimal opcode selection.
encodeCopy :: Int64 -> Int64 -> Builder
encodeCopy offset copyLength
  -- COPY ushort,ubyte (249)
  | offset <= 0xFFFF && copyLength <= 0xFF =
      word8 249 <> putWord16BE (fromIntegral offset) <> word8 (fromIntegral copyLength)
  -- COPY ushort,ushort (250)
  | offset <= 0xFFFF && copyLength <= 0xFFFF =
      word8 250 <> putWord16BE (fromIntegral offset) <> putWord16BE (fromIntegral copyLength)
  -- COPY ushort,int (251)
  | offset <= 0xFFFF =
      word8 251 <> putWord16BE (fromIntegral offset) <> putWord32BE (fromIntegral copyLength)
  -- COPY int,ubyte (252)
  | offset <= 0xFFFFFFFF && copyLength <= 0xFF =
      word8 252 <> putWord32BE (fromIntegral offset) <> word8 (fromIntegral copyLength)
  -- COPY int,ushort (253)
  | offset <= 0xFFFFFFFF && copyLength <= 0xFFFF =
      word8 253 <> putWord32BE (fromIntegral offset) <> putWord16BE (fromIntegral copyLength)
  -- COPY int,int (254)
  | offset <= 0xFFFFFFFF =
      word8 254 <> putWord32BE (fromIntegral offset) <> putWord32BE (fromIntegral copyLength)
  -- COPY long,int (255)
  | otherwise =
      word8 255 <> putInt64BE offset <> putWord32BE (fromIntegral copyLength)
