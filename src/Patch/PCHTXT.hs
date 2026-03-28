{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StrictData #-}

module Patch.PCHTXT
  ( PCHTXTEntry(..)
  , PCHTXTBlock(..)
  , PCHTXTPatch(..)
  , parsePCHTXT
  , applyPCHTXT
  , applyPCHTXTMemory
  , encodePCHTXT
  , encodePCHTXTBlocks
  , pchtxtMeta
  , pchtxtInfo
  ) where

-- Canonical reference: https://github.com/3096/ipswitch (IPSwitch, PCHTXT format creator)

import Patch.Binary (copyByteStringRange)

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Char8 as ByteString8
import Data.ByteString.Internal (unsafeCreate)
import Data.Char (digitToInt, intToDigit, isHexDigit, isSpace, toUpper)
import Control.Monad (forM_, when)
import Foreign.Marshal.Utils (fillBytes)
import Foreign.Ptr (plusPtr)
import Patch.Measure (Offset(..), EncodedHunk(..), seekTo, offsetToInt)
import Patch.Format (renderField)
import Data.Int (Int64)
import Data.List (dropWhileEnd, isPrefixOf)
import Data.Word (Word8, Word64)
import Numeric (readHex, showHex)
import System.IO

----------------------------------------------------------------------------
-- Types
----------------------------------------------------------------------------

-- | A single PCHTXT patch entry: absolute offset + data to write.
data PCHTXTEntry = PCHTXTEntry
  { pchtxtOffset :: !Offset
  , pchtxtData   :: !ByteString
  } deriving (Show)

-- | A patch block: enabled/disabled, optional description, entries.
data PCHTXTBlock = PCHTXTBlock
  { pchtxtBlockEnabled :: Bool
  , pchtxtBlockDescription    :: Maybe String
  , pchtxtBlockEntries :: [PCHTXTEntry]
  } deriving (Show)

-- | A parsed PCHTXT patch.
data PCHTXTPatch = PCHTXTPatch
  { pchtxtNsobid   :: Maybe String
  , pchtxtBlocks   :: [PCHTXTBlock]
  , pchtxtHasShift :: Bool  -- ^ True if @flag offset_shift was applied during parse
  } deriving (Show)

----------------------------------------------------------------------------
-- Parsing
----------------------------------------------------------------------------

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

data FlagResult = FlagShift Int64 | FlagIgnored | FlagError String

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
  where
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

----------------------------------------------------------------------------
-- Apply
----------------------------------------------------------------------------

applyPCHTXT :: PCHTXTPatch -> FilePath -> IO Int
applyPCHTXT patch target = withBinaryFile target ReadWriteMode $ \handle -> do
  let entries = concatMap pchtxtBlockEntries
                  (filter pchtxtBlockEnabled (pchtxtBlocks patch))
  mapM_ (\entry -> do
    seekTo handle (pchtxtOffset entry)
    ByteString.hPut handle (pchtxtData entry)) entries
  pure (length entries)

-- | Apply a PCHTXT patch in memory: copy source, then overwrite at offsets.
applyPCHTXTMemory :: PCHTXTPatch -> ByteString -> ByteString
applyPCHTXTMemory patch source = unsafeCreate outputSize $ \outputPointer -> do
    copyByteStringRange outputPointer 0 source 0 (min sourceLength outputSize)
    when (outputSize > sourceLength) $
      fillBytes (outputPointer `plusPtr` sourceLength) (0 :: Word8) (outputSize - sourceLength)
    forM_ entries $ \entry ->
      copyByteStringRange outputPointer (offsetToInt (pchtxtOffset entry)) (pchtxtData entry) 0 (ByteString.length (pchtxtData entry))
  where
    entries = concatMap pchtxtBlockEntries
                (filter pchtxtBlockEnabled (pchtxtBlocks patch))
    sourceLength = ByteString.length source
    outputSize = foldl' max sourceLength
      [ offsetToInt (pchtxtOffset entry) + ByteString.length (pchtxtData entry) | entry <- entries ]

----------------------------------------------------------------------------
-- Create / Encode
----------------------------------------------------------------------------

-- | Encode records as PCHTXT text (for direct conversion and create).
-- If a description is provided and looks like a hex build ID (all hex, 32+ chars),
-- emit @nsobid-<id>; otherwise emit // <description> as a comment.
encodePCHTXT :: [EncodedHunk] -> Maybe ByteString -> ByteString
encodePCHTXT records maybeDescription = ByteString8.pack $ unlines $
  descLines ++ "@enabled" : map encodeHunkEntry records
  where
    descLines = case maybeDescription of
      Nothing -> []
      Just rawDescription -> let text = trimNull (ByteString8.unpack rawDescription)
                 in if null text then []
                    else if length text >= 32 && all isHexDigit text
                         then ["@nsobid-" ++ text, ""]
                         else ["// " ++ text, ""]
    trimNull = reverse . dropWhile (\character -> character == ' ' || character == '\0') . reverse
    encodeHunkEntry (EncodedHunk hunkOffset hunkPayload) = hexPad 8 (fromIntegral hunkOffset) ++ " " ++ hexBytes hunkPayload

-- | Encode from full block structure, preserving disabled blocks and descriptions.
encodePCHTXTBlocks :: [PCHTXTBlock] -> Maybe ByteString -> ByteString
encodePCHTXTBlocks blocks maybeDescription = ByteString8.pack $ unlines $
  descLines ++ concatMap encodeBlock blocks
  where
    descLines = case maybeDescription of
      Nothing -> []
      Just rawDescription -> let text = trimNull (ByteString8.unpack rawDescription)
                 in if null text then []
                    else if length text >= 32 && all isHexDigit text
                         then ["@nsobid-" ++ text, ""]
                         else ["// " ++ text, ""]
    trimNull = reverse . dropWhile (\character -> character == ' ' || character == '\0') . reverse
    encodeBlock block =
      let header = if pchtxtBlockEnabled block then "@enabled" else "@disabled"
          description = case pchtxtBlockDescription block of
            Just text  -> ["// " ++ text]
            Nothing -> []
      in description ++ [header] ++ map encodeEntry (pchtxtBlockEntries block)
    encodeEntry entry = hexPad 8 (unOffset (pchtxtOffset entry)) ++ " " ++ hexBytes (pchtxtData entry)

hexPad :: Int -> Int64 -> String
hexPad width value =
  let text = map toUpper (showHex (fromIntegral value :: Word64) "")
  in replicate (width - length text) '0' ++ text

hexBytes :: ByteString -> String
hexBytes = concatMap (\byte ->
  [ toUpper (intToDigit (fromIntegral byte `div` 16))
  , toUpper (intToDigit (fromIntegral byte `mod` 16))
  ]) . ByteString.unpack

----------------------------------------------------------------------------
-- Info
----------------------------------------------------------------------------

pchtxtMeta :: PCHTXTPatch -> [(String, String)]
pchtxtMeta patch = case pchtxtNsobid patch of
  Just nsobid -> [("nsobid", nsobid)]
  Nothing     -> []

pchtxtInfo :: PCHTXTPatch -> String
pchtxtInfo patch = unlines $ filter (not . null) $
  [ "format:      PCHTXT (Nintendo Switch)" ]
  ++ map renderField (pchtxtMeta patch)
  ++ [ "blocks:      " ++ show totalBlocks
       ++ " (" ++ show enabledBlocks ++ " enabled, "
       ++ show disabledBlocks ++ " disabled)"
     , "entries:     " ++ show totalEntries
     , "total bytes: " ++ show totalBytes
     , rangeString
     ]
  where
    totalBlocks = length (pchtxtBlocks patch)
    enabledBlocks = length (filter pchtxtBlockEnabled (pchtxtBlocks patch))
    disabledBlocks = totalBlocks - enabledBlocks
    enabledEntries = concatMap pchtxtBlockEntries
                       (filter pchtxtBlockEnabled (pchtxtBlocks patch))
    totalEntries = length enabledEntries
    totalBytes = sum (map (ByteString.length . pchtxtData) enabledEntries)
    rangeString
      | null enabledEntries = "range:       (empty patch)"
      | otherwise =
          let lowest = minimum (map (unOffset . pchtxtOffset) enabledEntries)
              highest = maximum (map (\entry -> unOffset (pchtxtOffset entry) + fromIntegral (ByteString.length (pchtxtData entry))) enabledEntries)
          in "range:       0x" ++ hexPad 8 lowest ++ " - 0x" ++ hexPad 8 highest
