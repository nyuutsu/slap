{-# LANGUAGE OverloadedStrings #-}

module Slap.IPS.Parse
  ( parseIPS
  , parseRecords
  ) where

-- Canonical reference: https://zerosoft.zophar.net/ips.php (Z.e.r.o, ZeroSoft, 1998-2002)
-- No formal spec exists.

import Slap.IPS.Types (IPSVariant(..), IPSRecord(..), IPSPatch(..))
import Slap.Binary (getWord24BE, getWord32BE)
import Slap.Error (SlapError(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.Get (Get, runGet, getByte, getBytes, skip, getPosition, getInput,
                  remaining)
import Slap.Measure (Position(..), Offset(..), Length(..), FileSize(..),
                     ipsSentinel, ips32Sentinel)
import qualified Slap.Get as Get

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.Int (Int64)
import Data.Word (Word32, Word64)
import Control.Monad (when)
import Numeric (showHex)

parseIPS :: ByteString -> Either SlapError IPSPatch
parseIPS input
  | ByteString.take 5 input == "PATCH" =
      case runGet (skip (Length 5) >> parseRecords StandardIPS 3 ipsSentinel) input of
        Left errorMessage -> Left (ParseError LabelIPS errorMessage)
        Right patch -> Right patch
  | ByteString.take 5 input == "IPS32" =
      case runGet (skip (Length 5) >> parseRecords IPS32 4 ips32Sentinel) input of
        Left errorMessage -> Left (ParseError LabelIPS32 errorMessage)
        Right patch -> Right patch
  | otherwise = Left (BadMagic LabelIPS (ByteString.take 5 input))

parseRecords :: IPSVariant -> Int -> Word32 -> Get IPSPatch
parseRecords variant offsetWidth eofMarker = parseLoop []
  where
    -- Peek at the next offsetWidth bytes to check for EOF marker without consuming.
    peekEOF :: Get (Maybe Bool)
    peekEOF = do
      available <- remaining
      if unLength available < offsetWidth then pure Nothing
      else do
        position <- getPosition
        inputBytes <- getInput
        pure $ Just $ if offsetWidth == 3
               then getWord24BE (unPosition position) inputBytes == eofMarker
               else getWord32BE (unPosition position) inputBytes == eofMarker

    readOffset :: Get Int64
    readOffset
      | offsetWidth == 3 = fromIntegral <$> Get.word24BE
      | otherwise     = fromIntegral <$> Get.word32BE

    parseLoop accumulated = do
      eof <- peekEOF
      case eof of
        Nothing -> finish accumulated False       -- ran out of bytes, no EOF marker
        Just True -> do
          skip (Length offsetWidth)
          finish accumulated True                 -- proper EOF marker found
        Just False -> do
          recordOffset <- Offset <$> readOffset
          size   <- fromIntegral <$> Get.word16BE :: Get Int
          if size == 0
            then do  -- RLE record
              rleCount <- fromIntegral <$> Get.word16BE
              when (rleCount == 0) $
                fail ("IPS: RLE record with count 0 at offset 0x"
                      ++ showHex (fromIntegral (unOffset recordOffset) :: Word64) "")
              rleFillByte  <- getByte
              parseLoop (IPSRecordRLE recordOffset (Length rleCount) rleFillByte : accumulated)
            else do  -- Normal record
              payload <- getBytes (Length size)
              parseLoop (IPSRecord recordOffset payload : accumulated)

    finish accumulated clean = do
      available <- remaining
      if unLength available > 0
        then do
          position <- getPosition
          inputBytes <- getInput
          let trailing = ByteString.drop (unPosition position) inputBytes
          if ByteString.index trailing 0 == 0x7B  -- '{' -> EBP JSON metadata (no truncation)
            then pure (IPSPatch variant (reverse accumulated) Nothing (Just trailing) clean)
            else
              -- Try truncation marker, then check for trailing EBP JSON
              let truncation = if unLength available >= offsetWidth
                          then Just (FileSize (fromIntegral (if offsetWidth == 3
                                 then getWord24BE (unPosition position) inputBytes
                                 else getWord32BE (unPosition position) inputBytes)))
                          else Nothing
                  jsonStart = if unLength available >= offsetWidth then offsetWidth else unLength available
                  afterTruncation = ByteString.drop jsonStart trailing
                  ebpMeta = if not (ByteString.null afterTruncation) && ByteString.index afterTruncation 0 == 0x7B
                            then Just afterTruncation
                            else Nothing
              in pure (IPSPatch variant (reverse accumulated) truncation ebpMeta clean)
        else pure (IPSPatch variant (reverse accumulated) Nothing Nothing clean)
