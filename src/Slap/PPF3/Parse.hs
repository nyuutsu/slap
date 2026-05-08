module Slap.PPF3.Parse (parsePPF3) where

-- Canonical reference: Icarus/PPF-Studio (public spec).

import Slap.PPF.Common (wrapError, checkPPF3Encoding,
                        detectFileId, stripFileId, truncatedMessage)
import Slap.PPF.Types (PPFPatch(..), PPFRecord(..),
                       PPFVersion(..),
                       PPFValidation(..), PPFImageType(..),
                       ValidationBlockBytes(..),
                       ppfPreambleLength, ppfDescriptionLength,
                       ppf3MinHeaderLength, validationSize)
import Slap.Binary (getWord16LE)
import Slap.Error (SlapError(..), FieldName(..), Parsed(..))
import Slap.FileContents (PatchFileContents(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.Get (Get, runGet, getByte, getBytes, skip, remaining, int64LE)
import Slap.Measure (Offset(..), Length(..),
                     RequiredLength(..), ActualLength(..),
                     RawFlagByte(..),
                     ActionIndex, firstAction, nextAction)

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.Word (Word8)

-- | Intermediate result of parsing the PPF3 fixed header fields.
data PPF3ParsedHeader = PPF3ParsedHeader
  { ppf3Description     :: !ByteString
  , ppf3ImageTypeByte   :: !Word8
  , ppf3HasBlockCheck   :: !Bool
  , ppf3HasUndo         :: !Bool
  , ppf3ValidationBlock :: !(Maybe ValidationBlockBytes)
  }

-- | Parse a PPF3 patch file from raw bytes.
parsePPF3 :: PatchFileContents -> Either SlapError (Parsed PPFPatch)
parsePPF3 (PatchFileContents input)
  | ByteString.length input < unLength minPPF3Length =
      Left (InputTooShort LabelPPF3
              (RequiredLength minPPF3Length)
              (ActualLength (Length (ByteString.length input))))
  | otherwise = do
      () <- checkPPF3Encoding input
      header <- wrapError LabelPPF3 (runGet parsePPF3Header input)
      imageType <- case ppf3ImageTypeByte header of
        0x00 -> Right BIN
        0x01 -> Right GI
        byte -> Left (UnknownFlag LabelPPF3 FieldImageType (RawFlagByte byte))
      let validation = PPFValidation imageType <$> ppf3ValidationBlock header
          headerLength = if ppf3HasBlockCheck header then ppf3MinHeaderLength <> validationSize else ppf3MinHeaderLength
          fileId     = detectFileId getWord16LE 2 input
          recordBody = stripFileId 2 fileId (ByteString.drop (unLength headerLength) input)
      records <- wrapError LabelPPF3 (runGet (parseRecords64 LabelPPF3 (ppf3HasUndo header) firstAction) recordBody)
      pure (Parsed
        PPFPatch
          { ppfVersion     = PPF3
          , ppfDescription = ppf3Description header
          , ppfFileSize    = Nothing
          , ppfValidation  = validation
          , ppfHasUndo     = ppf3HasUndo header
          , ppfImageType   = Just imageType
          , ppfRecords     = records
          , ppfFileId      = fileId
          }
        [])
  where
    parsePPF3Header :: Get PPF3ParsedHeader
    parsePPF3Header = do
      skip ppfPreambleLength
      description <- getBytes ppfDescriptionLength
      imageTypeByte <- getByte
      hasBlockByte <- getByte
      hasUndoByte <- getByte
      skip (Length 1)
      validationBlock <- if hasBlockByte /= 0
        then Just . ValidationBlockBytes <$> getBytes validationSize
        else pure Nothing
      pure PPF3ParsedHeader
        { ppf3Description     = description
        , ppf3ImageTypeByte   = imageTypeByte
        , ppf3HasBlockCheck   = hasBlockByte /= 0
        , ppf3HasUndo         = hasUndoByte /= 0
        , ppf3ValidationBlock = validationBlock
        }

-- | Minimum bytes required before 'parsePPF3' can index into the
-- input. The encoding-byte check reads index 5, so the minimum is
-- 6 bytes (the preamble length).
minPPF3Length :: Length
minPPF3Length = ppfPreambleLength

-- | Parse PPF3 records (8-byte offset, 1-byte count, N bytes data,
-- optional undo).
parseRecords64 :: FormatLabel -> Bool -> ActionIndex -> Get [PPFRecord]
parseRecords64 label hasUndo recordIndex = do
  remainingBytes <- remaining
  if unLength remainingBytes < 9 then pure []
  else do
    recordOffset <- Offset . fromIntegral <$> int64LE
    count <- fromIntegral <$> getByte
    let need = 9 + count + if hasUndo then count else 0
    if need > unLength remainingBytes
      then fail (truncatedMessage recordIndex
                                  (RequiredLength (Length need))
                                  (ActualLength remainingBytes))
      else do
        payload <- getBytes (Length count)
        undoData <- if hasUndo
                    then Just <$> getBytes (Length count)
                    else pure Nothing
        rest <- parseRecords64 label hasUndo (nextAction recordIndex)
        pure (PPFRecord recordOffset payload undoData : rest)
