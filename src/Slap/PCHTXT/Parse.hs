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
import Slap.Measure (Offset(..))

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Char8 as ByteString8
import Data.Char (digitToInt, isHexDigit, isSpace)
import Data.Int (Int64)
import Data.List (dropWhileEnd, isPrefixOf)
import Data.Word (Word8)
import Numeric (readHex)

parsePCHTXT :: ByteString -> Either String PCHTXTPatch
parsePCHTXT input = parseLines (map ByteString8.unpack (ByteString8.lines input)) Nothing [] Nothing 0 False Nothing
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
          FlagError errorMessage   -> Left errorMessage
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
          Nothing -> Left ("PCHTXT: entry outside @enabled/@disabled block: " ++ stripped)
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
         then FlagError "PCHTXT: missing offset_shift value"
         else case parseHexInt value of
           Just number -> FlagShift number
           Nothing     -> FlagError ("PCHTXT: invalid offset_shift value: " ++ value)
  | otherwise = FlagIgnored

parseHexInt :: String -> Maybe Int64
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

parsePatchLine :: String -> Int64 -> Either String PCHTXTEntry
parsePatchLine line shift = do
  let (offsetString, rest) = span isHexDigit line
  if null offsetString
    then Left ("PCHTXT: expected hex offset: " ++ line)
    else do
      offset <- case readHex offsetString :: [(Int64, String)] of
               [(value, "")] -> Right value
               _ -> Left ("PCHTXT: invalid hex offset: " ++ offsetString)
      let dataString = dropWhile isSpace rest
      if null dataString
        then Left ("PCHTXT: no data after offset: " ++ line)
        else do
          payload <- case dataString of
                   '"':quotedRest -> parseQuotedString quotedRest
                   _              -> parseHexBytes dataString
          Right (PCHTXTEntry (Offset (offset + shift)) payload)

parseHexBytes :: String -> Either String ByteString
parseHexBytes text =
  let hexChars = takeWhile isHexDigit text
  in if odd (length hexChars)
     then Left ("PCHTXT: odd number of hex digits: " ++ text)
     else Right (ByteString.pack (decodeHexPairs hexChars))

decodeHexPairs :: String -> [Word8]
decodeHexPairs (highNibble:lowNibble:rest) = fromIntegral (digitToInt highNibble * 16 + digitToInt lowNibble) : decodeHexPairs rest
decodeHexPairs _ = []

parseQuotedString :: String -> Either String ByteString
parseQuotedString = fmap ByteString.pack . parseEscaped
  where
    parseEscaped [] = Left "PCHTXT: unterminated quoted string"
    parseEscaped ('"':_) = Right []
    parseEscaped ('\\':'n':rest) = (0x0A :) <$> parseEscaped rest
    parseEscaped ('\\':'t':rest) = (0x09 :) <$> parseEscaped rest
    parseEscaped ('\\':'\\':rest) = (0x5C :) <$> parseEscaped rest
    parseEscaped ('\\':'"':rest) = (0x22 :) <$> parseEscaped rest
    parseEscaped ('\\':character:rest) = (fromIntegral (fromEnum character) :) <$> parseEscaped rest
    parseEscaped (character:rest) = (fromIntegral (fromEnum character) :) <$> parseEscaped rest
