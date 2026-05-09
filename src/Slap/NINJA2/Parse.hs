{-# LANGUAGE OverloadedStrings #-}

module Slap.NINJA2.Parse
  ( parseNINJA2
  , parseFixedHeader
  , parseCommands
  , parseFileCommand
  , parseXorRecord
  ) where

import Slap.NINJA2.Types
import Slap.Checksum (MD5Hash(..))
import Slap.Error (SlapError(..), Parsed(..))
import Slap.FileContents (PatchFileContents(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.Get (Get, runGet, getByte, getBytes, atEnd)
import Slap.Measure (Length(..), Offset(..), FileSize(..),
                     RequiredLength(..), ActualLength(..), ActualMagic(..),
                     byteLength)
import Slap.Display.Primitives (padHex)

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString

----------------------------------------------------------------------------
-- Fixed header (2048 bytes): NINJA2 format
-- Spec says "first sector of the patch (1024 bytes)" but actual total is 2048.
-- PATCH_ENC (1B text encoding at offset 6) is stored in ninja2PatchEncoding.
----------------------------------------------------------------------------

-- | Parse the fixed header region. Field offsets/widths per
-- ninja2-filespec20.txt §2; the eight named constants in
-- 'Slap.NINJA2.Types' are the single source of truth.
parseFixedHeader :: ByteString -> NINJA2Info
parseFixedHeader input = NINJA2Info
  { ninja2Author      = extractField ninja2AuthorOffset      ninja2AuthorWidth
  , ninja2Version     = extractField ninja2VersionOffset     ninja2VersionWidth
  , ninja2Title       = extractField ninja2TitleOffset       ninja2TitleWidth
  , ninja2Genre       = extractField ninja2GenreOffset       ninja2GenreWidth
  , ninja2Language    = extractField ninja2LanguageOffset    ninja2LanguageWidth
  , ninja2Date        = extractField ninja2DateOffset        ninja2DateWidth
  , ninja2Website     = extractField ninja2WebsiteOffset     ninja2WebsiteWidth
  , ninja2Description = extractField ninja2DescriptionOffset ninja2DescriptionWidth
  }
  where
    extractField :: Offset -> Length -> Maybe ByteString
    extractField fieldOffset fieldWidth =
      let dropCount = unOffset fieldOffset
          takeCount = unLength fieldWidth
          field     = ByteString.take takeCount (ByteString.drop dropCount input)
          trimmed   = ByteString.takeWhile (/= 0) field
      in if ByteString.null trimmed then Nothing else Just trimmed

----------------------------------------------------------------------------
-- Command stream (starts at offset 0x800)
--   0x01: OPEN_NEW_FILE
--   0x02: XOR record
--   0x00: END
----------------------------------------------------------------------------

parseNINJA2 :: PatchFileContents -> Either SlapError (Parsed NINJA2Patch)
parseNINJA2 (PatchFileContents input)
  | byteLength input < Length 7 =
      Left (InputTooShort LabelNINJA2 (RequiredLength (Length 7)) (ActualLength (byteLength input)))
  | ByteString.take 6 input /= ninja2MagicBytes =
      Left (BadMagic LabelNINJA2 (ActualMagic (ByteString.take 6 input)))
  | byteLength input < headerSize =
      Left (InputTooShort LabelNINJA2 (RequiredLength headerSize) (ActualLength (byteLength input)))
  | otherwise = case toPatchEncoding (ByteString.index input 6) of
      Left unrecognizedByte -> Left (NINJA2UnrecognizedPatchEncoding unrecognizedByte)
      Right encoding -> case runGet (parseNINJA2Body encoding) input of
        Left errorMessage -> Left (ParseError LabelNINJA2 errorMessage)
        Right patch -> Right (Parsed patch [])
  where
    parseNINJA2Body :: PatchEncoding -> Get NINJA2Patch
    parseNINJA2Body encoding = do
      headerBytes <- getBytes headerSize
      let meta = parseFixedHeader headerBytes
      patch <- parseCommands (emptyPatch meta encoding)
      pure patch { ninja2Records = reverse (ninja2Records patch) }

    emptyPatch meta encoding = NINJA2Patch
      { ninja2Header = meta, ninja2Records = [], ninja2Overflow = Nothing
      , ninja2OverflowType = Nothing, ninja2OpenNewFile = Nothing
      , ninja2PatchEncoding = encoding
      }

parseCommands :: NINJA2Patch -> Get NINJA2Patch
parseCommands patch = do
  done <- atEnd
  if done then pure patch
  else do
    code <- getByte
    case code of
      0x01 -> parseFileCommand patch >>= parseCommands
      0x02 -> parseXorRecord patch >>= parseCommands
      0x00 -> pure patch  -- END marker
      _    -> fail ("unknown command code: 0x" ++ padHex 2 code)

-- | Command 0x01: OPEN_NEW_FILE
parseFileCommand :: NINJA2Patch -> Get NINJA2Patch
parseFileCommand patch = do
  _filename <- parsePackedByteString
  romTypeByte <- getByte  -- ROM type byte
  sourceSize <- FileSize . fromIntegral <$> parsePackedInteger
  targetSize <- FileSize . fromIntegral <$> parsePackedInteger
  sourceMD5 <- MD5Hash <$> getBytes (Length 16)
  targetMD5 <- MD5Hash <$> getBytes (Length 16)
  (overflowType, overflowData) <- if sourceSize /= targetSize
    then do
      typeByte <- getByte
      case toOverflowMode typeByte of
        Left errorMessage -> fail errorMessage
        Right mode -> do
          payload <- parsePackedByteString
          pure (Just mode, Just payload)
    else pure (Nothing, Nothing)
  pure patch { ninja2OpenNewFile  = Just NINJA2OpenNewFile
                 { openNewFileSourceMD5  = sourceMD5
                 , openNewFileTargetMD5  = targetMD5
                 , openNewFileSourceSize = sourceSize
                 , openNewFileTargetSize = targetSize
                 , openNewFileRomType    = toNINJA2RomType romTypeByte
                 }
             , ninja2Overflow     = overflowData
             , ninja2OverflowType = overflowType
             }

-- | Command 0x02: XOR record
parseXorRecord :: NINJA2Patch -> Get NINJA2Patch
parseXorRecord patch = do
  recordOffset <- Offset . fromIntegral <$> parsePackedInteger
  xorPayload <- parsePackedByteString
  pure patch { ninja2Records = NINJA2Record recordOffset xorPayload : ninja2Records patch }
