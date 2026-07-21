{-# LANGUAGE OverloadedStrings #-}

module Slap.GDIFF.Parse
  ( parseGDIFF
  ) where

-- Canonical reference: W3C NOTE-GDIFF-19970901

import Slap.GDIFF.Types (GDiffPatch(..), GDiffCommand(..), gdiffMagicBytes)
import Slap.Status (SlapError(..), Parsed(..))
import Slap.FileContents (PatchFileContents(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.ByteParser (runFormatParser, getByte, getBytes, word16BE, int32BE, int64BE)
import Slap.Measure (Length(..), Offset(..),
                     RequiredLength(..), ActualLength(..), ParsedSizeValue(..),
                     ActualMagic(..), FoundVersion(..), byteLength, firstAction, nextAction)

import qualified Data.ByteString as ByteString
import Data.Foldable (traverse_)

parseGDIFF :: PatchFileContents -> Either SlapError (Parsed GDiffPatch)
parseGDIFF (PatchFileContents input)
  | ByteString.length input < 5 = Left (InputTooShort LabelGDIFF (RequiredLength (Length 5)) (ActualLength (byteLength input)))
  | ByteString.take 4 input /= gdiffMagicBytes = Left (BadMagic LabelGDIFF (ActualMagic (ByteString.take 4 input)))
  | ByteString.index input 4 /= 4 = Left (BadVersion LabelGDIFF (FoundVersion (ByteString.index input 4)))
  | otherwise = do
      patch <- runFormatParser LabelGDIFF (getBytes (Length 5) *> parseCommands []) input
      rejectNegativeCopyLength patch
      Right (Parsed patch [])
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
        -- Each arm reads the argument types the spec's command table gives for that opcode: @ushort@ unsigned, @int@ and @long@ signed.
        -- A high-bit @int@ reads negative; 'rejectNegativeCopyLength' answers that for a length, the apply pre-flight for a position.
        0   -> pure (GDiffPatch (reverse accumulated))
        247 -> dataCommand (fromIntegral <$> word16BE)
        248 -> dataCommand int32BE
        249 -> copy (fromIntegral <$> word16BE) (fromIntegral <$> getByte)
        250 -> copy (fromIntegral <$> word16BE) (fromIntegral <$> word16BE)
        251 -> copy (fromIntegral <$> word16BE) int32BE
        252 -> copy int32BE                     (fromIntegral <$> getByte)
        253 -> copy int32BE                     (fromIntegral <$> word16BE)
        254 -> copy int32BE                     int32BE
        255 -> copy int64BE                     int32BE
        -- DATA whose opcode is itself the length (1-246 bytes);
        -- 0 and 247-255 are matched above, so this arm is exactly that range.
        _   -> dataCommand (pure (fromIntegral opcode))

-- | A COPY length the spec's signed @int@ admits but no region can have.
-- Refused at parse so every verb answers alike, and so no later stage holds a 'Length' that arithmetic would take as a real extent.
-- DATA needs no counterpart: its length reaches 'getBytes', which refuses a negative request itself.
rejectNegativeCopyLength :: GDiffPatch -> Either SlapError ()
rejectNegativeCopyLength (GDiffPatch commands) =
  traverse_ refuseNegativeLength (zip (iterate nextAction firstAction) commands)
  where
    refuseNegativeLength (actionIndex, GDiffCommandCopy { gdiffCopyLength = copyLength })
      | unLength copyLength < 0 =
          Left (NegativeRecordLength LabelGDIFF actionIndex (ParsedSizeValue (unLength copyLength)))
    refuseNegativeLength _ = Right ()
