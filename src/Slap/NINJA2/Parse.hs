{-# LANGUAGE OverloadedStrings #-}

module Slap.NINJA2.Parse
  ( parseNINJA2
  , parseFixedHeader
  , parseCommands
  , parseFileCommand
  , parseXorRecord
  ) where

import Slap.NINJA2.Types
import Slap.Error (SlapError(..), Parsed(..))
import Slap.FileContents (PatchFileContents(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.Get (Get, runGet, getByte, getBytes, atEnd)
import Slap.Measure (Length(..), Offset(..), FileSize(..),
                     RequiredLength(..), ActualLength(..), ActualMagic(..))
import Slap.Format (padHex)

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString

----------------------------------------------------------------------------
-- Fixed header (2048 bytes): NINJA2 format
-- Spec says "first sector of the patch (1024 bytes)" but actual total is 2048.
-- PATCH_ENC (1B text encoding at offset 6) is stored in ninja2PatchEncoding.
----------------------------------------------------------------------------

-- | Parse the fixed header region.  Field offsets per ninja2-filespec20.txt §2.
parseFixedHeader :: ByteString -> NINJA2Info
parseFixedHeader input = NINJA2Info
  { ninja2Author      = extractField 0x007 ninja2AuthorWidth
  , ninja2Version     = extractField 0x05B ninja2VersionWidth
  , ninja2Title       = extractField 0x066 ninja2TitleWidth
  , ninja2Genre       = extractField 0x166 ninja2GenreWidth
  , ninja2Language    = extractField 0x196 ninja2LanguageWidth
  , ninja2Date        = extractField 0x1C6 ninja2DateWidth
  , ninja2Website     = extractField 0x1CE ninja2WebsiteWidth
  , ninja2Description = extractField 0x3CE ninja2DescriptionWidth
  }
  where
    extractField fieldOffset fieldLength =
      let field = ByteString.take fieldLength (ByteString.drop fieldOffset input)
          trimmed = ByteString.takeWhile (/= 0) field
      in if ByteString.null trimmed then Nothing else Just trimmed

----------------------------------------------------------------------------
-- Command stream (starts at offset 0x800)
--   0x01: OPEN_NEW_FILE
--   0x02: XOR record
--   0x00: END
----------------------------------------------------------------------------

parseNINJA2 :: PatchFileContents -> Either SlapError (Parsed NINJA2Patch)
parseNINJA2 (PatchFileContents input)
  | ByteString.length input < 7 = Left (InputTooShort LabelNINJA2 (RequiredLength (Length 7)) (ActualLength (Length (ByteString.length input))))
  | ByteString.take 6 input /= ninja2MagicBytes = Left (BadMagic LabelNINJA2 (ActualMagic (ByteString.take 6 input)))
  | ByteString.length input < headerSize = Left (InputTooShort LabelNINJA2 (RequiredLength (Length headerSize)) (ActualLength (Length (ByteString.length input))))
  | otherwise = case runGet parseNINJA2Body input of
      Left errorMessage -> Left (ParseError LabelNINJA2 errorMessage)
      Right patch -> Right (Parsed patch [])
  where
    parseNINJA2Body :: Get NINJA2Patch
    parseNINJA2Body = do
      headerBytes <- getBytes (Length headerSize)
      let meta = parseFixedHeader headerBytes
          encoding = toPatchEncoding (ByteString.index headerBytes 6)
      patch <- parseCommands (emptyPatch meta encoding)
      pure patch { ninja2Records = reverse (ninja2Records patch) }

    emptyPatch meta encoding = NINJA2Patch
      { ninja2Header = meta, ninja2Records = [], ninja2Overflow = Nothing
      , ninja2OverflowType = Nothing, ninja2SourceMD5 = Nothing, ninja2TargetMD5 = Nothing
      , ninja2SourceSize = FileSize 0, ninja2TargetSize = FileSize 0, ninja2PatchEncoding = encoding, ninja2RomType = Ninja2Raw
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
  sourceMD5 <- getBytes (Length 16)
  targetMD5 <- getBytes (Length 16)
  (overflowType, overflowData) <- if sourceSize /= targetSize
    then do
      typeByte <- getByte
      case toOverflowMode typeByte of
        Left errorMessage -> fail errorMessage
        Right mode -> do
          payload <- parsePackedByteString
          pure (Just mode, Just payload)
    else pure (Nothing, Nothing)
  pure patch { ninja2SourceMD5    = Just sourceMD5
             , ninja2TargetMD5    = Just targetMD5
             , ninja2SourceSize   = sourceSize
             , ninja2TargetSize   = targetSize
             , ninja2Overflow     = overflowData
             , ninja2OverflowType = overflowType
             , ninja2RomType      = toNINJA2RomType romTypeByte
             }

-- | Command 0x02: XOR record
parseXorRecord :: NINJA2Patch -> Get NINJA2Patch
parseXorRecord patch = do
  recordOffset <- Offset . fromIntegral <$> parsePackedInteger
  xorPayload <- parsePackedByteString
  pure patch { ninja2Records = NINJA2Record recordOffset xorPayload : ninja2Records patch }
