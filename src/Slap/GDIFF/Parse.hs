{-# LANGUAGE OverloadedStrings #-}

module Slap.GDIFF.Parse
  ( parseGDIFF
  ) where

-- Canonical reference: W3C NOTE-GDIFF-19970901

import Slap.GDIFF.Types (GDiffPatch(..), GDiffCommand(..), gdiffMagicBytes)
import Slap.Error (SlapError(..), Parsed(..))
import Slap.FileContents (PatchFileContents(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.Get (runGet, getByte, getBytes, word16BE, word32BE, int64BE)
import Slap.Measure (Length(..), Offset(..), FileSize(..),
                     RequiredLength(..), ActualLength(..),
                     ActualMagic(..), FoundVersion(..))

import qualified Data.ByteString as ByteString

parseGDIFF :: PatchFileContents -> Either SlapError (Parsed GDiffPatch)
parseGDIFF (PatchFileContents input)
  | ByteString.length input < 5 = Left (InputTooShort LabelGDIFF (RequiredLength (Length 5)) (ActualLength (Length (ByteString.length input))))
  | ByteString.take 4 input /= gdiffMagicBytes = Left (BadMagic LabelGDIFF (ActualMagic (ByteString.take 4 input)))
  | ByteString.index input 4 /= 4 = Left (BadVersion LabelGDIFF (FoundVersion (ByteString.index input 4)))
  | otherwise = case runGet (do { _ <- getBytes (Length 5); parseCommands [] }) input of
      Left errorMessage -> Left (ParseError LabelGDIFF errorMessage)
      Right patch -> Right (Parsed patch [])
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
        255 -> do offset <- fromIntegral <$> int64BE
                  copyLength <- fromIntegral <$> word32BE
                  parseCommands (GDiffCopy (Offset offset) (FileSize copyLength) : accumulated)

        _ -> fail "impossible opcode"  -- 0-255 covered above; GHC can't prove guard exhaustiveness
