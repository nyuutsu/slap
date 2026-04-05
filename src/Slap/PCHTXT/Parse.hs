{-# LANGUAGE OverloadedStrings #-}

module Slap.PCHTXT.Parse
  ( parsePCHTXT
  , parseFlag
  , parseHexInt
  , parsePatchLine
  , parseHexBytes
  , parseQuotedString
  , decodeHexPairs
  ) where

import Slap.PCHTXT.Types (PCHTXTPatch(..), PCHTXTBlock(..), PCHTXTEntry(..), FlagResult(..))
import Slap.Error (SlapError(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.Measure (Offset(..))

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Char8 as ByteString8
import Data.Char (digitToInt, isHexDigit, isSpace)
import qualified Data.Text as Text
import qualified Data.Text.Encoding as Text
import Data.List (dropWhileEnd, isPrefixOf)
import Data.Word (Word8)
import Numeric (readHex)

parsePCHTXT :: ByteString -> Either SlapError PCHTXTPatch
parsePCHTXT input = parseLines (map (Text.unpack . Text.decodeUtf8Lenient) (ByteString8.lines input)) Nothing [] Nothing 0 False Nothing
  where
    -- parseLines lines nsobid finishedBlocks lastComment shift shifted currentBlock
    -- currentBlock = Maybe (enabled, description, reversedEntries)
    parseLines [] nsobid blocks _ _ shifted currentBlock =
      Right (PCHTXTPatch nsobid (reverse (finishBlock currentBlock blocks)) shifted)

    parseLines (rawLine:rest) nsobid blocks lastComment shift shifted currentBlock
      | null stripped = parseLines rest nsobid blocks lastComment shift shifted currentBlock
      | "@stop" `isPrefixOf` stripped =
          Right (PCHTXTPatch nsobid (reverse (finishBlock currentBlock blocks)) shifted)
      | "@nsobid-" `isPrefixOf` stripped =
          parseLines rest (Just (takeWhile isHexDigit (drop 8 stripped))) blocks Nothing shift shifted currentBlock
      | "@flag " `isPrefixOf` stripped = case parseFlag (drop 6 stripped) of
          FlagShift value -> parseLines rest nsobid blocks lastComment value True currentBlock
          FlagIgnored     -> parseLines rest nsobid blocks lastComment shift shifted currentBlock
          FlagError errorMessage   -> Left (MalformedTextField LabelPCHTXT errorMessage)
      | "@enabled" `isPrefixOf` stripped =
          let closedBlocks = finishBlock currentBlock blocks
          in parseLines rest nsobid closedBlocks Nothing shift shifted (Just (True, lastComment, []))
      | "@disabled" `isPrefixOf` stripped =
          let closedBlocks = finishBlock currentBlock blocks
          in parseLines rest nsobid closedBlocks Nothing shift shifted (Just (False, lastComment, []))
      | "/" `isPrefixOf` stripped =
          parseLines rest nsobid blocks (Just (dropWhile isSpace (dropWhile (== '/') stripped))) shift shifted currentBlock
      | "#" `isPrefixOf` stripped =
          parseLines rest nsobid blocks lastComment shift shifted currentBlock
      | "@" `isPrefixOf` stripped =
          parseLines rest nsobid blocks lastComment shift shifted currentBlock
      | otherwise = case currentBlock of
          Nothing -> Left (EntryOutsideBlock LabelPCHTXT stripped)
          Just (enabled, description, reversedEntries) -> case parsePatchLine stripped shift of
            Left errorMessage -> Left errorMessage
            Right entry ->
              parseLines rest nsobid blocks lastComment shift shifted (Just (enabled, description, entry : reversedEntries))
      where
        stripped = stripLine rawLine

    finishBlock Nothing blocks = blocks
    finishBlock (Just (enabled, description, reversedEntries)) blocks =
      PCHTXTBlock enabled description (reverse reversedEntries) : blocks

    stripLine = dropWhileEnd (\character -> character == '\r' || character == ' ' || character == '\t')
              . dropWhile (\character -> character == ' ' || character == '\t')

parseFlag :: String -> FlagResult
parseFlag text
  | "print_values" `isPrefixOf` text = FlagIgnored
  | "offset_shift" `isPrefixOf` text =
      let value = dropWhile isSpace (drop 12 text)
      in if null value
         then FlagError "missing offset_shift value"
         else case parseHexInt value of
           Just number -> FlagShift number
           Nothing     -> FlagError ("invalid offset_shift value: " ++ value)
  | otherwise = FlagIgnored

parseHexInt :: String -> Maybe Int
parseHexInt text =
  let stripped = case text of
              '0':'x':hexRest -> hexRest
              '0':'X':hexRest -> hexRest
              _               -> text
      (hexPart, _) = span isHexDigit stripped
  in if null hexPart then Nothing
     else case readHex hexPart of
       [(value, "")] -> Just value
       _ -> Nothing

parsePatchLine :: String -> Int -> Either SlapError PCHTXTEntry
parsePatchLine line shift = do
  let (offsetString, rest) = span isHexDigit line
  if null offsetString
    then Left (MalformedTextField LabelPCHTXT ("expected hex offset: " ++ line))
    else do
      offset <- case readHex offsetString :: [(Int, String)] of
               [(value, "")] -> Right value
               _ -> Left (MalformedTextField LabelPCHTXT ("invalid hex offset: " ++ offsetString))
      let dataString = dropWhile isSpace rest
      if null dataString
        then Left (MalformedTextField LabelPCHTXT ("no data after offset: " ++ line))
        else do
          payload <- case dataString of
                   '"':quotedRest -> parseQuotedString quotedRest
                   _              -> parseHexBytes dataString
          Right (PCHTXTEntry (Offset (offset + shift)) payload)

parseHexBytes :: String -> Either SlapError ByteString
parseHexBytes text =
  let hexChars = takeWhile isHexDigit text
  in if odd (length hexChars)
     then Left (MalformedTextField LabelPCHTXT ("odd number of hex digits: " ++ text))
     else Right (ByteString.pack (decodeHexPairs hexChars))

decodeHexPairs :: String -> [Word8]
decodeHexPairs (highNibble:lowNibble:rest) = fromIntegral (digitToInt highNibble * 16 + digitToInt lowNibble) : decodeHexPairs rest
decodeHexPairs _ = []

parseQuotedString :: String -> Either SlapError ByteString
parseQuotedString = fmap (Text.encodeUtf8 . Text.pack) . parseEscaped
  where
    parseEscaped [] = Left (MalformedTextField LabelPCHTXT "unterminated quoted string")
    parseEscaped ('"':_) = Right []
    parseEscaped ('\\':'n':rest) = ('\n' :) <$> parseEscaped rest
    parseEscaped ('\\':'t':rest) = ('\t' :) <$> parseEscaped rest
    parseEscaped ('\\':'\\':rest) = ('\\' :) <$> parseEscaped rest
    parseEscaped ('\\':'"':rest) = ('"' :) <$> parseEscaped rest
    parseEscaped ('\\':character:rest) = (character :) <$> parseEscaped rest
    parseEscaped (character:rest) = (character :) <$> parseEscaped rest
