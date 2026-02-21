{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StrictData #-}

module Patch.PCHTXT
  ( PCHTXTEntry(..)
  , PCHTXTBlock(..)
  , PCHTXTPatch(..)
  , parsePCHTXT
  , applyPCHTXT
  , createPCHTXT
  , encodePCHTXT
  , pchtxtInfo
  ) where

import Patch.Binary (diffHunks)

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BS8
import Data.Char (digitToInt, intToDigit, isHexDigit, isSpace, toUpper)
import Data.Int (Int64)
import Data.List (dropWhileEnd, isPrefixOf)
import Data.Word (Word64)
import Numeric (readHex, showHex)
import System.IO

----------------------------------------------------------------------------
-- Types
----------------------------------------------------------------------------

-- | A single PCHTXT patch entry: absolute offset + data to write.
data PCHTXTEntry = PCHTXTEntry
  { pchtxtOffset :: Int64
  , pchtxtData   :: ByteString
  } deriving (Show)

-- | A patch block: enabled/disabled, optional description, entries.
data PCHTXTBlock = PCHTXTBlock
  { pchtxtBlockEnabled :: Bool
  , pchtxtBlockDesc    :: Maybe String
  , pchtxtBlockEntries :: [PCHTXTEntry]
  } deriving (Show)

-- | A parsed PCHTXT patch.
data PCHTXTPatch = PCHTXTPatch
  { pchtxtNsobid :: Maybe String
  , pchtxtBlocks :: [PCHTXTBlock]
  } deriving (Show)

----------------------------------------------------------------------------
-- Parsing
----------------------------------------------------------------------------

parsePCHTXT :: ByteString -> Either String PCHTXTPatch
parsePCHTXT bs = go (map BS8.unpack (BS8.lines bs)) Nothing [] Nothing 0 Nothing
  where
    -- go lines nsobid finishedBlocks lastComment shift curBlock
    -- curBlock = Maybe (enabled, description, revEntries)
    go [] nso blocks _ _ curBlock =
      Right (PCHTXTPatch nso (reverse (finishBlock curBlock blocks)))

    go (rawL:ls) nso blocks lastComment shift curBlock
      | null l = go ls nso blocks lastComment shift curBlock
      | "@stop" `isPrefixOf` l =
          Right (PCHTXTPatch nso (reverse (finishBlock curBlock blocks)))
      | "@nsobid-" `isPrefixOf` l =
          go ls (Just (takeWhile isHexDigit (drop 8 l))) blocks Nothing shift curBlock
      | "@flag " `isPrefixOf` l = case parseFlag (drop 6 l) of
          FlagShift val -> go ls nso blocks lastComment val curBlock
          FlagIgnored   -> go ls nso blocks lastComment shift curBlock
          FlagError err -> Left err
      | "@enabled" `isPrefixOf` l =
          let blocks' = finishBlock curBlock blocks
          in go ls nso blocks' Nothing shift (Just (True, lastComment, []))
      | "@disabled" `isPrefixOf` l =
          let blocks' = finishBlock curBlock blocks
          in go ls nso blocks' Nothing shift (Just (False, lastComment, []))
      | "/" `isPrefixOf` l =
          go ls nso blocks (Just (dropWhile isSpace (dropWhile (== '/') l))) shift curBlock
      | "#" `isPrefixOf` l =
          go ls nso blocks lastComment shift curBlock
      | "@" `isPrefixOf` l =
          go ls nso blocks lastComment shift curBlock
      | otherwise = case curBlock of
          Nothing -> Left ("patch entry outside of @enabled/@disabled block: " ++ l)
          Just (en, desc, revEntries) -> case parsePatchLine l shift of
            Left err -> Left err
            Right entry ->
              go ls nso blocks lastComment shift (Just (en, desc, entry : revEntries))
      where
        l = stripLine rawL

    finishBlock Nothing blocks = blocks
    finishBlock (Just (en, desc, revEntries)) blocks =
      PCHTXTBlock en desc (reverse revEntries) : blocks

    stripLine = dropWhileEnd (\c -> c == '\r' || c == ' ' || c == '\t')
              . dropWhile (\c -> c == ' ' || c == '\t')

data FlagResult = FlagShift Int64 | FlagIgnored | FlagError String

parseFlag :: String -> FlagResult
parseFlag s
  | "print_values" `isPrefixOf` s = FlagIgnored
  | "offset_shift" `isPrefixOf` s =
      let val = dropWhile isSpace (drop 12 s)
      in if null val
         then FlagError "missing offset_shift value"
         else case parseHexInt val of
           Just v  -> FlagShift v
           Nothing -> FlagError ("bad offset_shift value: " ++ val)
  | otherwise = FlagIgnored

parseHexInt :: String -> Maybe Int64
parseHexInt s =
  let s' = case s of
              '0':'x':rest -> rest
              '0':'X':rest -> rest
              _            -> s
      (hexPart, _) = span isHexDigit s'
  in if null hexPart then Nothing
     else case readHex hexPart of
       [(v, "")] -> Just v
       _ -> Nothing

parsePatchLine :: String -> Int64 -> Either String PCHTXTEntry
parsePatchLine s shift = do
  let (offStr, rest) = span isHexDigit s
  if null offStr
    then Left ("expected hex offset: " ++ s)
    else do
      off <- case readHex offStr :: [(Int64, String)] of
               [(v, "")] -> Right v
               _ -> Left ("bad hex offset: " ++ offStr)
      let dataStr = dropWhile isSpace rest
      if null dataStr
        then Left ("no data after offset: " ++ s)
        else do
          dat <- case dataStr of
                   '"':qstr -> parseQuotedString qstr
                   _        -> parseHexBytes dataStr
          Right (PCHTXTEntry (off + shift) dat)

parseHexBytes :: String -> Either String ByteString
parseHexBytes s =
  let hexChars = takeWhile isHexDigit s
  in if odd (length hexChars)
     then Left ("odd number of hex digits: " ++ s)
     else Right (BS.pack (pairUp hexChars))
  where
    pairUp (a:b:rest) = fromIntegral (digitToInt a * 16 + digitToInt b) : pairUp rest
    pairUp _ = []

parseQuotedString :: String -> Either String ByteString
parseQuotedString = fmap BS.pack . go
  where
    go [] = Left "unterminated quoted string"
    go ('"':_) = Right []
    go ('\\':'n':rest) = (0x0A :) <$> go rest
    go ('\\':'t':rest) = (0x09 :) <$> go rest
    go ('\\':'\\':rest) = (0x5C :) <$> go rest
    go ('\\':'"':rest) = (0x22 :) <$> go rest
    go ('\\':c:rest) = (fromIntegral (fromEnum c) :) <$> go rest
    go (c:rest) = (fromIntegral (fromEnum c) :) <$> go rest

----------------------------------------------------------------------------
-- Apply
----------------------------------------------------------------------------

applyPCHTXT :: PCHTXTPatch -> FilePath -> IO Int
applyPCHTXT patch target = withBinaryFile target ReadWriteMode $ \h -> do
  let entries = concatMap pchtxtBlockEntries
                  (filter pchtxtBlockEnabled (pchtxtBlocks patch))
  mapM_ (\e -> do
    hSeek h AbsoluteSeek (fromIntegral (pchtxtOffset e))
    BS.hPut h (pchtxtData e)) entries
  pure (length entries)

----------------------------------------------------------------------------
-- Create / Encode
----------------------------------------------------------------------------

-- | Create a PCHTXT patch from source and target bytes.
createPCHTXT :: ByteString -> ByteString -> ByteString
createPCHTXT src tgt = encodePCHTXT (diffHunks src tgt) Nothing

-- | Encode overlay records as PCHTXT text (for overlay conversion).
-- If a description is provided and looks like a hex build ID (all hex, 32+ chars),
-- emit @nsobid-<id>; otherwise emit // <description> as a comment.
encodePCHTXT :: [(Int, ByteString)] -> Maybe ByteString -> ByteString
encodePCHTXT recs mDesc = BS8.pack $ unlines $
  descLines ++ "@enabled" : map encodeEntry recs
  where
    descLines = case mDesc of
      Nothing -> []
      Just d  -> let s = trimNul (BS8.unpack d)
                 in if null s then []
                    else if length s >= 32 && all isHexDigit s
                         then ["@nsobid-" ++ s, ""]
                         else ["// " ++ s, ""]
    trimNul = reverse . dropWhile (\c -> c == ' ' || c == '\0') . reverse
    encodeEntry (off, dat) = hexPad 8 (fromIntegral off) ++ " " ++ hexBytes dat

hexPad :: Int -> Int64 -> String
hexPad w val =
  let s = map toUpper (showHex (fromIntegral val :: Word64) "")
  in replicate (w - length s) '0' ++ s

hexBytes :: ByteString -> String
hexBytes = concatMap (\b ->
  [ toUpper (intToDigit (fromIntegral b `div` 16))
  , toUpper (intToDigit (fromIntegral b `mod` 16))
  ]) . BS.unpack

----------------------------------------------------------------------------
-- Info
----------------------------------------------------------------------------

pchtxtInfo :: PCHTXTPatch -> String
pchtxtInfo p = unlines $ filter (not . null)
  [ "format:      PCHTXT (Nintendo Switch)"
  , nsobidStr
  , "blocks:      " ++ show totalBlocks
      ++ " (" ++ show enabledBlocks ++ " enabled, "
      ++ show disabledBlocks ++ " disabled)"
  , "entries:     " ++ show totalEntries
  , "total bytes: " ++ show totalBytes
  , rangeStr
  ]
  where
    totalBlocks = length (pchtxtBlocks p)
    enabledBlocks = length (filter pchtxtBlockEnabled (pchtxtBlocks p))
    disabledBlocks = totalBlocks - enabledBlocks
    enabledEntries = concatMap pchtxtBlockEntries
                       (filter pchtxtBlockEnabled (pchtxtBlocks p))
    totalEntries = length enabledEntries
    totalBytes = sum (map (BS.length . pchtxtData) enabledEntries)
    nsobidStr = case pchtxtNsobid p of
      Just nso -> "nsobid:      " ++ nso
      Nothing  -> ""
    rangeStr
      | null enabledEntries = "range:       (empty patch)"
      | otherwise =
          let offsets = map pchtxtOffset enabledEntries
              lo = minimum offsets
              hi = maximum offsets
                   + fromIntegral (BS.length (pchtxtData (last enabledEntries)))
          in "range:       0x" ++ hexPad 8 lo ++ " - 0x" ++ hexPad 8 hi
