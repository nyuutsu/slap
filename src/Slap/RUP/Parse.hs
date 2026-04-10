{-# LANGUAGE OverloadedStrings #-}

module Slap.RUP.Parse
  ( parseRUP
  , parseFixedHeader
  , parseCommands
  , parseFileCommand
  , parseXorRecord
  ) where

import Slap.RUP.Types
import Slap.Error (SlapError(..))
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
-- PATCH_ENC (1B text encoding at offset 6) is stored in rupPatchEncoding.
----------------------------------------------------------------------------

-- | Parse the fixed header region.  Field offsets per ninja2-filespec20.txt §2.
parseFixedHeader :: ByteString -> RUPInfo
parseFixedHeader input = RUPInfo
  { rupAuthor      = extractField 0x007 rupAuthorWidth
  , rupVersion     = extractField 0x05B rupVersionWidth
  , rupTitle       = extractField 0x066 rupTitleWidth
  , rupGenre       = extractField 0x166 rupGenreWidth
  , rupLanguage    = extractField 0x196 rupLanguageWidth
  , rupDate        = extractField 0x1C6 rupDateWidth
  , rupWebsite     = extractField 0x1CE rupWebsiteWidth
  , rupDescription = extractField 0x3CE rupDescriptionWidth
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

parseRUP :: PatchFileContents -> Either SlapError RUPPatch
parseRUP (PatchFileContents input)
  | ByteString.length input < 7 = Left (InputTooShort LabelRUP (RequiredLength (Length 7)) (ActualLength (Length (ByteString.length input))))
  | ByteString.take 6 input /= "NINJA2" = Left (BadMagic LabelRUP (ActualMagic (ByteString.take 6 input)))
  | ByteString.length input < headerSize = Left (InputTooShort LabelRUP (RequiredLength (Length headerSize)) (ActualLength (Length (ByteString.length input))))
  | otherwise = case runGet parseRUPBody input of
      Left errorMessage -> Left (ParseError LabelRUP errorMessage)
      Right patch -> Right patch
  where
    parseRUPBody :: Get RUPPatch
    parseRUPBody = do
      headerBytes <- getBytes (Length headerSize)
      let meta = parseFixedHeader headerBytes
          encoding = toPatchEncoding (ByteString.index headerBytes 6)
      patch <- parseCommands (emptyPatch meta encoding)
      pure patch { rupRecords = reverse (rupRecords patch) }

    emptyPatch meta encoding = RUPPatch
      { rupHeader = meta, rupRecords = [], rupOverflow = Nothing
      , rupOverflowType = Nothing, rupSourceMD5 = Nothing, rupTargetMD5 = Nothing
      , rupSourceSize = FileSize 0, rupTargetSize = FileSize 0, rupPatchEncoding = encoding, rupRomType = Ninja2Raw
      }

parseCommands :: RUPPatch -> Get RUPPatch
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
parseFileCommand :: RUPPatch -> Get RUPPatch
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
  pure patch { rupSourceMD5    = Just sourceMD5
             , rupTargetMD5    = Just targetMD5
             , rupSourceSize   = sourceSize
             , rupTargetSize   = targetSize
             , rupOverflow     = overflowData
             , rupOverflowType = overflowType
             , rupRomType      = toNINJA2RomType romTypeByte
             }

-- | Command 0x02: XOR record
parseXorRecord :: RUPPatch -> Get RUPPatch
parseXorRecord patch = do
  recordOffset <- Offset . fromIntegral <$> parsePackedInteger
  xorPayload <- parsePackedByteString
  pure patch { rupRecords = RUPRecord recordOffset xorPayload : rupRecords patch }
