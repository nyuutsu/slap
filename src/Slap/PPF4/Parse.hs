module Slap.PPF4.Parse (parsePPF4) where

-- Pyriel's internal format (magic "PPF4"): 60-byte header, records with
-- command byte + 4-byte offsets. Reverse-engineered from the Suikoden I/II
-- bug fix patchers; not a published spec — only ever generated and
-- consumed within those patchers' Lua runtime. Canonical references:
-- Pyriel's patcher.lua and ppfmaker.cpp.

import Slap.PPF4.Types (PPF4Patch(..), PPF4Replace(..), PPF4Append(..),
                        ppf4PostDescriptionLength)
import Slap.PPF.Types (ppfPreambleLength, ppfDescriptionLength)
import Slap.Error (SlapError(..), Parsed(..))
import Slap.FileContents (PatchFileContents(..))
import Slap.Display.Primitives (padHex)
import Slap.FormatLabel (FormatLabel(..))
import Slap.Get (Get, runGet, getByte, getBytes, skip, remaining, word32LE)
import Slap.Measure (Offset(..), Length(..),
                     RequiredLength(..), ActualLength(..),
                     ActionIndex(unActionIndex), firstAction, nextAction)

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString

-- | Tracks which phase the record walk is in. Wire-format invariant:
-- once a record with command=1 (Append) is seen, every subsequent
-- record must also be Append. A Replace after the phase transition is
-- a structural parse error.
data PPF4ParsePhase = ReplacePhase | AppendPhase
  deriving (Show, Eq)

-- | Parse a PPF4 patch file from raw bytes.
parsePPF4 :: PatchFileContents -> Either SlapError (Parsed PPF4Patch)
parsePPF4 (PatchFileContents input)
  | ByteString.length input < unLength minPPF4Length =
      Left (InputTooShort LabelPPF4
              (RequiredLength minPPF4Length)
              (ActualLength (Length (ByteString.length input))))
  | otherwise = do
      (description, replaces, appends) <- ppf4WrapError (runGet parsePPF4Body input)
      pure (Parsed
        PPF4Patch
          { ppf4Description = description
          , ppf4Replaces    = replaces
          , ppf4Appends     = appends
          }
        [])
  where
    parsePPF4Body :: Get (ByteString, [PPF4Replace], [PPF4Append])
    parsePPF4Body = do
      skip ppfPreambleLength
      description <- getBytes ppfDescriptionLength
      skip ppf4PostDescriptionLength
      (replaces, appends) <- parsePPF4Records firstAction ReplacePhase [] []
      pure (description, replaces, appends)

-- | Minimum bytes required before 'parsePPF4' can index into the
-- input. PPF4 has no encoding-byte check, but the body still skips
-- the 6-byte preamble before reading anything.
minPPF4Length :: Length
minPPF4Length = ppfPreambleLength

-- | Wrap a Get error string into a SlapError, labeled PPF4.
ppf4WrapError :: Either String a -> Either SlapError a
ppf4WrapError = either (Left . ParseError LabelPPF4) Right

-- | Parse PPF4 records (1-byte cmd, 4-byte offset, 1-byte count, N
-- bytes data) while enforcing the two-phase invariant: every Replace
-- record must precede every Append record.
parsePPF4Records :: ActionIndex -> PPF4ParsePhase
                 -> [PPF4Replace] -> [PPF4Append]
                 -> Get ([PPF4Replace], [PPF4Append])
parsePPF4Records recordIndex phase replacesAcc appendsAcc = do
  remainingBytes <- remaining
  if unLength remainingBytes < 6
    then pure (reverse replacesAcc, reverse appendsAcc)
    else do
      commandByte <- getByte
      wireOffset  <- word32LE
      count       <- fromIntegral <$> getByte
      remainingAfterHeader <- remaining
      if unLength remainingAfterHeader < count
        then fail (ppf4TruncatedMessage recordIndex
                                        (RequiredLength (Length (6 + count)))
                                        (ActualLength remainingBytes))
        else do
          payload <- getBytes (Length count)
          case commandByte of
            0 -> case phase of
              ReplacePhase ->
                let replace = PPF4Replace
                      { replaceOffset = Offset (fromIntegral wireOffset)
                      , replaceData   = payload
                      }
                in parsePPF4Records (nextAction recordIndex) ReplacePhase
                     (replace : replacesAcc) appendsAcc
              AppendPhase ->
                fail ("record " ++ show (unActionIndex recordIndex)
                      ++ ": Replace after Append (PPF4 is two-phase; "
                      ++ "once an Append record appears, every subsequent "
                      ++ "record must also be Append)")
            1 ->
              parsePPF4Records (nextAction recordIndex) AppendPhase
                replacesAcc (PPF4Append payload : appendsAcc)
            _ ->
              fail ("record " ++ show (unActionIndex recordIndex)
                    ++ " has unknown command byte: 0x" ++ padHex 2 commandByte)

-- | Format a truncated-record error message (PPF4 copy; the wording
-- matches Common's 'truncatedMessage' but lives here so PPF4 does not
-- import from Slap.PPF.Common).
ppf4TruncatedMessage :: ActionIndex -> RequiredLength -> ActualLength -> String
ppf4TruncatedMessage recordIndex
                     (RequiredLength (Length needed))
                     (ActualLength   (Length available)) =
  "record " ++ show (unActionIndex recordIndex)
  ++ " truncated (need " ++ show needed ++ " bytes, " ++ show available ++ " available)"
