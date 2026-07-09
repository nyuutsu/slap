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
import Slap.Status (SlapError(..), SlapAdvisory, Parsed(..), ByteParserError(..))
import Slap.FieldName (FieldName(..))
import Slap.FileContents (PatchFileContents(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.ByteParser (ByteParser, runFormatParser, flattenParse, throwByteParserError,
                        getByte, getBytes, atEnd)
import Slap.Measure (Length(..), Offset(unOffset), offsetFromParsed, FileSize(..),
                     RequiredLength(..), ActualLength(..), ActualMagic(..),
                     RawFlagByte(..),
                     ActionIndex, firstAction, nextAction,
                     byteLength)
import Slap.Text (EncodedText, EncodingName(..), decodeFixedWidthTextField,
                  encodedTextContent)
import qualified Data.Text as Text

import Control.Monad.Trans.Class (lift)
import Control.Monad.Trans.Except (ExceptT, runExceptT, throwE)
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.Bifunctor (first)
import Data.Int (Int64)

----------------------------------------------------------------------------
-- Variable-length values
----------------------------------------------------------------------------

-- | Decode a variable-length value: a one-byte count, then that many little-endian bytes.
-- A value wider than an 'Int' is refused ('ByteParserFieldExceedsAddressableRange'), not folded to a wrong low-byte one.
parsePackedInteger :: ActionIndex -> FieldName -> ByteParser Int64
parsePackedInteger commandIndex field = do
  count       <- fromIntegral <$> getByte
  packedBytes <- getBytes (Length count)
  let value = ByteString.foldr (\byte accumulated -> toInteger byte + 256 * accumulated) 0 packedBytes
  if value > toInteger (maxBound :: Int)
    then throwByteParserError (ByteParserFieldExceedsAddressableRange commandIndex field)
    else pure (fromInteger value)

-- | Decode a length-prefixed byte string: a VLV count, then that many bytes.
parsePackedByteString :: ActionIndex -> FieldName -> ByteParser ByteString
parsePackedByteString commandIndex field = do
  dataLength <- fromIntegral <$> parsePackedInteger commandIndex field
  getBytes (Length dataLength)

----------------------------------------------------------------------------
-- Fixed header (2048 bytes)
-- Spec says "first sector of the patch (1024 bytes)" but actual total is 2048.
-- PATCH_ENC (1B text mode at offset 6) is stored in ninja2TextMode.
----------------------------------------------------------------------------

-- | Per-field substitution events surface as 'Slap.Status.FieldDecodedSubstituted' advisories tagged with the field name;
-- an empty (all-zero-padded) slot decodes to 'Nothing' and never emits an advisory.
parseFixedHeader :: EncodingName -> TextMode -> ByteString -> (NINJA2Info, [SlapAdvisory])
parseFixedHeader metadataEncoding textMode input =
  let (authorField,      authorAdvisories)      = extractField FieldAuthor      ninja2AuthorOffset      ninja2AuthorWidth
      (versionField,     versionAdvisories)     = extractField FieldVersion     ninja2VersionOffset     ninja2VersionWidth
      (titleField,       titleAdvisories)       = extractField FieldTitle       ninja2TitleOffset       ninja2TitleWidth
      (genreField,       genreAdvisories)       = extractField FieldGenre       ninja2GenreOffset       ninja2GenreWidth
      (languageField,    languageAdvisories)    = extractField FieldLanguage    ninja2LanguageOffset    ninja2LanguageWidth
      (dateField,        dateAdvisories)        = extractField FieldDate        ninja2DateOffset        ninja2DateWidth
      (websiteField,     websiteAdvisories)     = extractField FieldWebsite     ninja2WebsiteOffset     ninja2WebsiteWidth
      (descriptionField, descriptionAdvisories) = extractField FieldDescription ninja2DescriptionOffset ninja2DescriptionWidth
      info = NINJA2Info
        { ninja2Author      = authorField
        , ninja2Version     = versionField
        , ninja2Title       = titleField
        , ninja2Genre       = genreField
        , ninja2Language    = languageField
        , ninja2Date        = dateField
        , ninja2Website     = websiteField
        , ninja2Description = descriptionField
        }
      advisories = authorAdvisories ++ versionAdvisories ++ titleAdvisories
                ++ genreAdvisories ++ languageAdvisories ++ dateAdvisories
                ++ websiteAdvisories ++ descriptionAdvisories
  in (info, advisories)
  where
    -- The wire's PATCH_ENC byte either declares UTF-8 or leaves the encoding undeclared;
    -- an undeclared patch defers to the user's metadata-encoding choice.
    effectiveEncoding = case textMode of
      TextModeUTF8       -> EncodingUtf8
      TextModeUndeclared -> metadataEncoding

    extractField :: FieldName -> Offset -> Length
                 -> (Maybe EncodedText, [SlapAdvisory])
    extractField fieldName fieldOffset fieldWidth =
      let dropCount = unOffset fieldOffset
          takeCount = unLength fieldWidth
          fieldBytes = ByteString.take takeCount (ByteString.drop dropCount input)
          (content, advisories) =
            decodeFixedWidthTextField effectiveEncoding LabelNINJA2 fieldName fieldBytes
      in if Text.null (encodedTextContent content)
           then (Nothing, [])
           else (Just content, advisories)

----------------------------------------------------------------------------
-- Command stream (starts at offset 0x800)
--   0x01: OPEN_NEW_FILE
--   0x02: XOR record
--   0x00: END
----------------------------------------------------------------------------

parseNINJA2 :: EncodingName -> PatchFileContents -> Either SlapError (Parsed NINJA2Patch)
parseNINJA2 metadataEncoding (PatchFileContents input)
  | byteLength input < Length 7 =
      Left (InputTooShort LabelNINJA2 (RequiredLength (Length 7)) (ActualLength (byteLength input)))
  | ByteString.take 6 input /= ninja2MagicBytes =
      Left (BadMagic LabelNINJA2 (ActualMagic (ByteString.take 6 input)))
  | byteLength input < headerSize =
      Left (InputTooShort LabelNINJA2 (RequiredLength headerSize) (ActualLength (byteLength input)))
  | otherwise = do
      textMode <- first NINJA2UnrecognizedTextMode (toTextMode (ByteString.index input 6))
      (patch, headerAdvisories) <- flattenParse (runFormatParser LabelNINJA2 (parseNINJA2Body textMode) input)
      Right (Parsed patch headerAdvisories)
  where
    parseNINJA2Body :: TextMode -> ByteParser (Either SlapError (NINJA2Patch, [SlapAdvisory]))
    parseNINJA2Body textMode = do
      headerBytes <- getBytes headerSize
      let (info, headerAdvisories) = parseFixedHeader metadataEncoding textMode headerBytes
      runExceptT $ do
        patch <- parseCommands firstAction (emptyPatch info textMode)
        pure (patch { ninja2Records = reverse (ninja2Records patch) }, headerAdvisories)

    emptyPatch info textMode = NINJA2Patch
      { ninja2Header = info, ninja2Records = [], ninja2Overflow = Nothing
      , ninja2OverflowType = Nothing, ninja2OpenNewFile = Nothing
      , ninja2TextMode = textMode
      }

-- | The walk runs over an 'ExceptT' 'SlapError' channel so a format-semantic refusal within a command — an unknown overflow mode — surfaces as itself.
-- Byte-level framing failures (an unknown command code, a short read) stay on the parser's own 'ByteParserError'.
parseCommands :: ActionIndex -> NINJA2Patch -> ExceptT SlapError ByteParser NINJA2Patch
parseCommands commandIndex patch = do
  done <- lift atEnd
  if done then pure patch
  else do
    code <- lift getByte
    case code of
      0x01 -> parseFileCommand commandIndex patch     >>= parseCommands (nextAction commandIndex)
      0x02 -> lift (parseXorRecord commandIndex patch) >>= parseCommands (nextAction commandIndex)
      0x00 -> pure patch
      _    -> lift (throwByteParserError (ByteParserUnknownCommandByte commandIndex code))

-- | The OPEN_NEW_FILE command. An unknown overflow-mode byte is refused as 'UnknownFlag'.
parseFileCommand :: ActionIndex -> NINJA2Patch -> ExceptT SlapError ByteParser NINJA2Patch
parseFileCommand commandIndex patch = do
  _filename   <- lift (parsePackedByteString commandIndex FieldFileName)
  romTypeByte <- lift getByte
  sourceSize  <- FileSize . fromIntegral <$> lift (parsePackedInteger commandIndex FieldSourceSize)
  targetSize  <- FileSize . fromIntegral <$> lift (parsePackedInteger commandIndex FieldTargetSize)
  sourceMD5   <- MD5Hash <$> lift (getBytes (Length 16))
  targetMD5   <- MD5Hash <$> lift (getBytes (Length 16))
  (overflowType, overflowData) <- if sourceSize == targetSize
    then pure (Nothing, Nothing)
    else do
      typeByte <- lift getByte
      case toOverflowMode typeByte of
        Nothing   -> throwE (UnknownFlag LabelNINJA2 FieldOverflowMode (RawFlagByte typeByte))
        Just mode -> do
          payload <- lift (parsePackedByteString commandIndex FieldOverflowData)
          pure (Just mode, Just payload)
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

-- | The XOR-record command.
parseXorRecord :: ActionIndex -> NINJA2Patch -> ByteParser NINJA2Patch
parseXorRecord commandIndex patch = do
  recordOffset <- offsetFromParsed <$> parsePackedInteger commandIndex FieldRecordOutputOffset
  xorPayload <- parsePackedByteString commandIndex FieldRecordLength
  pure patch { ninja2Records = NINJA2Record recordOffset xorPayload : ninja2Records patch }
