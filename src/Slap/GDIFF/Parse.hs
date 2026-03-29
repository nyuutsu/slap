{-# LANGUAGE OverloadedStrings #-}

module Slap.GDIFF.Parse
  ( parseGDIFF
  ) where

-- Canonical reference: W3C NOTE-GDIFF-19970901

import Slap.GDIFF.Types (GDiffPatch(..), GDiffCommand(..))
import Slap.Get (runGet, getByte, getBytes, word16BE, word32BE, int64BE)
import Slap.Measure (Length(..), Offset(..), FileSize(..))

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString

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
                  parseCommands (GDiffCopy (Offset offset) (FileSize copyLength) : accumulated)

        -- COPY ushort offset, ushort length
        250 -> do offset <- fromIntegral <$> word16BE
                  copyLength <- fromIntegral <$> word16BE
                  parseCommands (GDiffCopy (Offset offset) (FileSize copyLength) : accumulated)

        -- COPY ushort offset, int length
        251 -> do offset <- fromIntegral <$> word16BE
                  copyLength <- fromIntegral <$> word32BE
                  parseCommands (GDiffCopy (Offset offset) (FileSize copyLength) : accumulated)

        -- COPY int offset, ubyte length
        252 -> do offset <- fromIntegral <$> word32BE
                  copyLength <- fromIntegral <$> getByte
                  parseCommands (GDiffCopy (Offset offset) (FileSize copyLength) : accumulated)

        -- COPY int offset, ushort length
        253 -> do offset <- fromIntegral <$> word32BE
                  copyLength <- fromIntegral <$> word16BE
                  parseCommands (GDiffCopy (Offset offset) (FileSize copyLength) : accumulated)

        -- COPY int offset, int length
        254 -> do offset <- fromIntegral <$> word32BE
                  copyLength <- fromIntegral <$> word32BE
                  parseCommands (GDiffCopy (Offset offset) (FileSize copyLength) : accumulated)

        -- COPY long offset, int length
        255 -> do offset <- int64BE
                  copyLength <- fromIntegral <$> word32BE
                  parseCommands (GDiffCopy (Offset offset) (FileSize copyLength) : accumulated)

        _ -> fail "impossible GDIFF opcode"  -- 0-255 covered above; GHC can't prove guard exhaustiveness
