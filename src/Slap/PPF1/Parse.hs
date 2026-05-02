module Slap.PPF1.Parse (parsePPF1) where

-- Canonical reference: Icarus/PPF-Studio (public spec).

import Slap.PPF.Common (wrapError, checkPPF1Encoding, parseRecords32)
import Slap.PPF.Types (PPFPatch(..), PPFVersion(..),
                       ppfPreambleLength, ppfDescriptionLength)
import Slap.Error (SlapError(..), Parsed(..))
import Slap.FileContents (PatchFileContents(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.Get (Get, runGet, getBytes, skip)
import Slap.Measure (Length(..), RequiredLength(..), ActualLength(..))

import qualified Data.ByteString as ByteString

-- | Parse a PPF1 patch file from raw bytes.
parsePPF1 :: PatchFileContents -> Either SlapError (Parsed PPFPatch)
parsePPF1 (PatchFileContents input)
  | ByteString.length input < unLength minPPF1Length =
      Left (InputTooShort LabelPPF1
              (RequiredLength minPPF1Length)
              (ActualLength (Length (ByteString.length input))))
  | otherwise = do
      () <- checkPPF1Encoding input
      patch <- wrapError LabelPPF1 (runGet parsePPF1Body input)
      pure (Parsed patch [])
  where
    parsePPF1Body :: Get PPFPatch
    parsePPF1Body = do
      skip ppfPreambleLength
      description <- getBytes ppfDescriptionLength
      records <- parseRecords32 LabelPPF1 0
      pure PPFPatch
        { ppfVersion     = PPF1
        , ppfDescription = description
        , ppfFileSize    = Nothing
        , ppfValidation  = Nothing
        , ppfHasUndo     = False
        , ppfImageType   = Nothing
        , ppfRecords     = records
        , ppfFileId      = Nothing
        }

-- | Minimum bytes required before 'parsePPF1' can index into the
-- input. The encoding-byte check reads index 5, so the minimum is
-- 6 bytes (the preamble length).
minPPF1Length :: Length
minPPF1Length = ppfPreambleLength
