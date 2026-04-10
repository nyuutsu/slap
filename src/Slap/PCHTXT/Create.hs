{-# LANGUAGE OverloadedStrings #-}

module Slap.PCHTXT.Create
  ( encodePCHTXT
  , encodePCHTXTBlocks
  , hexPad
  , hexBytes
  ) where

import Slap.PCHTXT.Types (PCHTXTBlock(..), PCHTXTEntry(..))
import Slap.Measure (Offset(..), EncodedHunk(..))

import Slap.FileContents (PatchFileContents(..))

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.Char (intToDigit, isHexDigit, toUpper)
import qualified Data.Text as Text
import qualified Data.Text.Encoding as Text
import Data.Word (Word64)
import Numeric (showHex)

-- | Encode records as PCHTXT text (for direct conversion and create).
-- If a description is provided and looks like a hex build ID (all hex, 32+ chars),
-- emit @nsobid-<id>; otherwise emit // <description> as a comment.
encodePCHTXT :: [EncodedHunk] -> Maybe String -> PatchFileContents
encodePCHTXT records maybeDescription = PatchFileContents $ Text.encodeUtf8 $ Text.pack $ unlines $
  descriptionLines ++ "@enabled" : map encodeHunkEntry records
  where
    descriptionLines = case maybeDescription of
      Nothing -> []
      Just rawDescription -> let text = trimNull rawDescription
                 in if null text then []
                    else if length text >= 32 && all isHexDigit text
                         then ["@nsobid-" ++ text, ""]
                         else ["// " ++ text, ""]
    trimNull = reverse . dropWhile (\character -> character == ' ' || character == '\0') . reverse
    encodeHunkEntry (EncodedHunk hunkOffset hunkPayload) = hexPad 8 (unOffset hunkOffset) ++ " " ++ hexBytes hunkPayload

-- | Encode from full block structure, preserving disabled blocks and descriptions.
encodePCHTXTBlocks :: [PCHTXTBlock] -> Maybe String -> PatchFileContents
encodePCHTXTBlocks blocks maybeDescription = PatchFileContents $ Text.encodeUtf8 $ Text.pack $ unlines $
  descriptionLines ++ concatMap encodeBlock blocks
  where
    descriptionLines = case maybeDescription of
      Nothing -> []
      Just rawDescription -> let text = trimNull rawDescription
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

hexPad :: (Integral a) => Int -> a -> String
hexPad width value =
  let text = map toUpper (showHex (fromIntegral value :: Word64) "")
  in replicate (width - length text) '0' ++ text

hexBytes :: ByteString -> String
hexBytes = concatMap (\byte ->
  [ toUpper (intToDigit (fromIntegral byte `div` 16))
  , toUpper (intToDigit (fromIntegral byte `mod` 16))
  ]) . ByteString.unpack
