module Slap.PPF2.Parse (parsePPF2) where

-- Canonical reference: Icarus/PPF-Studio (public spec).

import Slap.PPF.Common (wrapError, checkPPF2Encoding, parseRecords32,
                        detectFileId, stripFileId)
import Slap.PPF.Types (PPFPatch(..), PPFVersion(..),
                       PPFValidation(..), PPFImageType(..),
                       ValidationBlockBytes(..),
                       ppfPreambleLength, ppfDescriptionLength,
                       ppf2HeaderLength, validationSize)
import Slap.Binary (getWord32LE)
import Slap.Error (SlapError(..), Parsed(..))
import Slap.FileContents (PatchFileContents(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.Get (Get, runGet, getBytes, skip, word32LE)
import Slap.Measure (Length(..), FileSize(..),
                     RequiredLength(..), ActualLength(..), firstAction)

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString

-- | Parse a PPF2 patch file from raw bytes.
parsePPF2 :: PatchFileContents -> Either SlapError (Parsed PPFPatch)
parsePPF2 (PatchFileContents input)
  | ByteString.length input < unLength minPPF2Length =
      Left (InputTooShort LabelPPF2
              (RequiredLength minPPF2Length)
              (ActualLength (Length (ByteString.length input))))
  | otherwise = do
      () <- checkPPF2Encoding input
      let fileId     = detectFileId getWord32LE 4 input
          recordBody = stripFileId 4 fileId (ByteString.drop (unLength ppf2HeaderLength) input)
      (description, fileSize, validationBlock) <-
        wrapError LabelPPF2 (runGet parsePPF2Header input)
      records <- wrapError LabelPPF2 (runGet (parseRecords32 LabelPPF2 firstAction) recordBody)
      pure (Parsed
        PPFPatch
          { ppfVersion     = PPF2
          , ppfDescription = description
          , ppfFileSize    = Just fileSize
          , ppfValidation  = Just (PPFValidation BIN validationBlock)
          , ppfHasUndo     = False
          , ppfImageType   = Nothing
          , ppfRecords     = records
          , ppfFileId      = fileId
          }
        [])
  where
    parsePPF2Header :: Get (ByteString, FileSize, ValidationBlockBytes)
    parsePPF2Header = do
      skip ppfPreambleLength
      description <- getBytes ppfDescriptionLength
      fileSize <- FileSize . fromIntegral <$> word32LE
      validationBlock <- ValidationBlockBytes <$> getBytes validationSize
      pure (description, fileSize, validationBlock)

-- | Minimum bytes required before 'parsePPF2' can index into the
-- input. The encoding-byte check reads index 5, so the minimum is
-- 6 bytes (the preamble length).
minPPF2Length :: Length
minPPF2Length = ppfPreambleLength
