{-# LANGUAGE OverloadedStrings #-}

module Slap.GDIFF.Parse
  ( parseGDIFF
  ) where

-- Canonical reference: W3C NOTE-GDIFF-19970901

import Slap.GDIFF.Types (GDiffPatch(..), GDiffCommand(..), gdiffMagicBytes)
import Slap.Status (SlapError(..), Parsed(..))
import Slap.FileContents (PatchFileContents(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.ByteParser (runByteParser, getByte, getBytes, word16BE, word32BE, int64BE)
import Slap.Measure (Length(..), Offset(..),
                     RequiredLength(..), ActualLength(..),
                     ActualMagic(..), FoundVersion(..), byteLength)

import qualified Data.ByteString as ByteString

parseGDIFF :: PatchFileContents -> Either SlapError (Parsed GDiffPatch)
parseGDIFF (PatchFileContents input)
  | ByteString.length input < 5 = Left (InputTooShort LabelGDIFF (RequiredLength (Length 5)) (ActualLength (byteLength input)))
  | ByteString.take 4 input /= gdiffMagicBytes = Left (BadMagic LabelGDIFF (ActualMagic (ByteString.take 4 input)))
  | ByteString.index input 4 /= 4 = Left (BadVersion LabelGDIFF (FoundVersion (ByteString.index input 4)))
  | otherwise = case runByteParser (do { _ <- getBytes (Length 5); parseCommands [] }) input of
      Left parserError -> Left (ParseError LabelGDIFF parserError)
      Right patch -> Right (Parsed patch [])
  where
    parseCommands accumulated = do
      opcode <- getByte
      let copy offsetReader lengthReader = do
            offset     <- offsetReader
            copyLength <- lengthReader
            parseCommands (GDiffCommandCopy { gdiffCopyOffset = Offset offset
                                            , gdiffCopyLength = Length copyLength } : accumulated)
          dataCommand lengthReader = do
            dataLength <- lengthReader
            payload    <- getBytes (Length dataLength)
            parseCommands (GDiffCommandData { gdiffDataPayload = payload } : accumulated)
      case opcode of
        0   -> pure (GDiffPatch (reverse accumulated))
        247 -> dataCommand (fromIntegral <$> word16BE)
        248 -> dataCommand (fromIntegral <$> word32BE)
        249 -> copy (fromIntegral <$> word16BE) (fromIntegral <$> getByte)
        250 -> copy (fromIntegral <$> word16BE) (fromIntegral <$> word16BE)
        251 -> copy (fromIntegral <$> word16BE) (fromIntegral <$> word32BE)
        252 -> copy (fromIntegral <$> word32BE) (fromIntegral <$> getByte)
        253 -> copy (fromIntegral <$> word32BE) (fromIntegral <$> word16BE)
        254 -> copy (fromIntegral <$> word32BE) (fromIntegral <$> word32BE)
        255 -> copy (fromIntegral <$> int64BE)  (fromIntegral <$> word32BE)
        -- DATA whose opcode is itself the length (1-246 bytes);
        -- 0 and 247-255 are matched above, so this arm is exactly that range.
        _   -> dataCommand (pure (fromIntegral opcode))
