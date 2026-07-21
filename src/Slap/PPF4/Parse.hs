module Slap.PPF4.Parse (parsePPF4) where

-- Pyriel's internal format (magic "PPF4"): 60-byte header, records with
-- command byte + 4-byte offsets. Reverse-engineered from the Suikoden I/II
-- bug fix patchers; not a published spec — only ever generated and
-- consumed within those patchers' Lua runtime. Canonical references:
-- Pyriel's patcher.lua and ppfmaker.cpp.

import Slap.PPF4.Types (PPF4Patch(..), PPF4Replace(..), PPF4Append(..),
                        ppf4PreambleLength, ppf4DescriptionLength,
                        ppf4PostDescriptionLength, ppf4RecordHeaderLength,
                        ppf4MinimumRecordLength)
import Slap.Status (SlapError(..), SlapAdvisory, ByteParserError(..), Parsed(..))
import Slap.FieldName (FieldName(..))
import Slap.FileContents (PatchFileContents(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.ByteParser (ByteParser, runFormatParser, throwByteParserError,
                        getByte, getBytes, skip, remaining, word32LE)
import Slap.Measure (offsetFromParsed, Length(..),
                     EncodingMethodByte(..), RawFlagByte(..),
                     RequiredLength(..), ActualLength(..), RemainingLength(..),
                     ActionIndex, firstAction, nextAction,
                     byteLength)
import Slap.Text (EncodedText, EncodingName(..), decodeFixedWidthTextField)

import Control.Monad (when)
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString

-- | Intermediate result of running the PPF4 body parser.
data PPF4ParsedBody = PPF4ParsedBody
  { ppf4BodyDescription           :: !EncodedText
  , ppf4BodyDescriptionAdvisories :: ![SlapAdvisory]
  , ppf4BodyPostDescriptionBytes  :: !ByteString
  , ppf4BodyWireRecords           :: ![PPF4WireRecord]
  }

-- | One wire record with its command still attached, tagged with its
-- wire-order index. The walk collects these as read; whether the
-- stream honors PPF4's two-phase order — every Replace before every
-- Append — is format semantics, judged outside the byte parser by
-- 'partitionPhases'.
data PPF4WireRecord
  = WireReplace !ActionIndex !PPF4Replace
  | WireAppend  !ActionIndex !PPF4Append

parsePPF4 :: EncodingName -> PatchFileContents -> Either SlapError (Parsed PPF4Patch)
parsePPF4 metadataEncoding (PatchFileContents input)
  | byteLength input < minPPF4Length =
      Left (InputTooShort LabelPPF4
              (RequiredLength minPPF4Length)
              (ActualLength (byteLength input)))
  | otherwise = do
      () <- checkEncodingByte input
      body <- runFormatParser LabelPPF4 parsePPF4Body input
      () <- requirePostDescriptionZero (ppf4BodyPostDescriptionBytes body)
      (replaces, appends) <- partitionPhases (ppf4BodyWireRecords body)
      pure (Parsed
        PPF4Patch
          { ppf4Description = ppf4BodyDescription body
          , ppf4Replaces    = replaces
          , ppf4Appends     = appends
          }
        (ppf4BodyDescriptionAdvisories body))
  where
    parsePPF4Body :: ByteParser PPF4ParsedBody
    parsePPF4Body = do
      skip ppf4PreambleLength
      descriptionBytes <- getBytes ppf4DescriptionLength
      let (descriptionText, descriptionAdvisories) =
            decodeFixedWidthTextField metadataEncoding LabelPPF4 FieldDescription descriptionBytes
      postDescriptionBytes <- getBytes ppf4PostDescriptionLength
      wireRecords <- parsePPF4Records firstAction []
      pure PPF4ParsedBody
        { ppf4BodyDescription           = descriptionText
        , ppf4BodyDescriptionAdvisories = descriptionAdvisories
        , ppf4BodyPostDescriptionBytes  = postDescriptionBytes
        , ppf4BodyWireRecords           = wireRecords
        }

-- | Minimum bytes 'parsePPF4' needs before indexing in: the 6-byte preamble,
-- so 'checkEncodingByte' can read the encoding byte at offset 5 and the body can skip past it.
minPPF4Length :: Length
minPPF4Length = ppf4PreambleLength

-- | The encoding byte (offset 5) must be @0xFF@ — the reference (patcher.lua) rejects anything else with @ERROR_BAD_VERSION@,
-- and @0xFF@ was chosen upstream so incompatible tools fail loudly rather than misread the patch.
checkEncodingByte :: ByteString -> Either SlapError ()
checkEncodingByte input
  | actual == 0xFF = Right ()
  | otherwise      = Left (UnsupportedEncodingMethod LabelPPF4 (EncodingMethodByte actual))
  where actual = ByteString.index input 5

-- | The four post-description header bytes (offsets 56–59) are reserved and required zero:
-- the reference reads them as one word and rejects nonzero with @ERROR_BAD_FLAGS@.
-- PPF4 supports none of the features they nominally carry, so any nonzero byte is off-spec.
requirePostDescriptionZero :: ByteString -> Either SlapError ()
requirePostDescriptionZero postDescriptionBytes =
  case ByteString.find (/= 0) postDescriptionBytes of
    Just offendingByte -> Left (UnknownFlag LabelPPF4 FieldReservedHeader (RawFlagByte offendingByte))
    Nothing            -> Right ()

-- | Parse PPF4 records (1-byte command, 4-byte offset, 1-byte
-- count, N data bytes) in wire order, commands attached. Truncation
-- and an unknown command byte are wire-level refusals raised here,
-- typed; the two-phase order is format semantics, judged after the
-- walk by 'partitionPhases'.
parsePPF4Records :: ActionIndex -> [PPF4WireRecord] -> ByteParser [PPF4WireRecord]
parsePPF4Records recordIndex accumulatedReversed = do
  remainingBytes <- remaining
  if unLength remainingBytes == 0
    then pure (reverse accumulatedReversed)
    else if unLength remainingBytes < unLength ppf4MinimumRecordLength
      then throwByteParserError (ByteParserTrailingBytesTooFewForRecord recordIndex
             (RequiredLength ppf4MinimumRecordLength)
             (RemainingLength remainingBytes))
      else readOneRecord remainingBytes
  where
    readOneRecord remainingBytes = do
      commandByte <- getByte
      wireOffset  <- word32LE
      count       <- fromIntegral <$> getByte
      remainingAfterHeader <- remaining
      when (unLength remainingAfterHeader < count) $
        throwByteParserError (ByteParserTruncatedRecord recordIndex
          (RequiredLength (Length (unLength ppf4RecordHeaderLength + count)))
          (RemainingLength remainingBytes))
      payload    <- getBytes (Length count)
      wireRecord <- case commandByte of
        0 -> pure (WireReplace recordIndex PPF4Replace
                     { replaceOffset = offsetFromParsed wireOffset
                     , replaceData   = payload
                     })
        1 -> pure (WireAppend recordIndex (PPF4Append payload))
        _ -> throwByteParserError (ByteParserUnknownCommandByte recordIndex commandByte)
      parsePPF4Records (nextAction recordIndex) (wireRecord : accumulatedReversed)

-- | Enforce PPF4's two-phase order — every Replace precedes every
-- Append — and shed the wire tags. 'span' splits the stream at the
-- first Append; a Replace appearing anywhere after that point is the
-- structural violation 'PPF4ReplaceAfterAppend' names, attributed to
-- the first offender. The two comprehensions are total under the
-- split: the leading run is all Replaces by 'span''s definition, and
-- the tail has been proven free of them before its Appends are
-- extracted.
partitionPhases :: [PPF4WireRecord] -> Either SlapError ([PPF4Replace], [PPF4Append])
partitionPhases wireRecords = case strayReplaces of
    offendingIndex : _ -> Left (PPF4ReplaceAfterAppend offendingIndex)
    []                 -> Right
      ( [replace | WireReplace _ replace <- replaceRun]
      , [append  | WireAppend  _ append  <- appendRun]
      )
  where
    (replaceRun, appendRun) = span isWireReplace wireRecords
    strayReplaces           = [offending | WireReplace offending _ <- appendRun]

    isWireReplace :: PPF4WireRecord -> Bool
    isWireReplace WireReplace{} = True
    isWireReplace WireAppend{}  = False
