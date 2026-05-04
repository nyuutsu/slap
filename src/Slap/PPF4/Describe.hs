module Slap.PPF4.Describe
  ( ppf4Info, ppf4Meta, explainPPF4
  , ppf4ReplacesRange
  ) where

import Slap.PPF4.Types (PPF4Patch(..), PPF4Replace(..), PPF4Append(..))
import Slap.Measure (Offset(..), Length(..),
                     OffsetRange(..), advance, byteLength)
import Slap.Display (InfoLine(..), renderInfoLine)
import Slap.Explain
  ( ExplainData(..)
  , ExplainSection(SectionRegions)
  , ExplainRegion(..)
  , ExplainPayload(PayloadWrite)
  , ExplainSummary(Summary)
  , SummaryInfo(..)
  , SummaryByteInfo(..)
  , SummaryBytes(BytesTotal)
  , Annotation(AnnotAt)
  , OffsetKind(AtOffset)
  )

import Slap.TextEncoding (decodeLocaleField)

import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Char8 as ByteStringChar

-- | All key-value metadata carried by a PPF4 patch header. PPF4 has
-- only a description field; no validation block, no file size, no
-- undo, no image type, no File_ID.diz.
ppf4Meta :: PPF4Patch -> [InfoLine]
ppf4Meta patch =
  let description = decodeLocaleField (stripTrailing (ppf4Description patch))
  in [InfoLine "description" description | not (null description)]

-- | Format a human-readable summary of a parsed PPF4 patch.
ppf4Info :: PPF4Patch -> String
ppf4Info patch = unlines $ filter (not . null) $
  [ "format:      PPF4 (Pyriel internal format)" ]
  ++ map renderInfoLine (ppf4Meta patch)
  ++ [ "records:     " ++ show (length (ppf4Replaces patch) + length (ppf4Appends patch))
     , "total bytes: " ++ show (totalPayloadBytes patch)
     ]

totalPayloadBytes :: PPF4Patch -> Int
totalPayloadBytes patch =
  sum (map (ByteString.length . replaceData) (ppf4Replaces patch))
  + sum (map (ByteString.length . appendData) (ppf4Appends patch))

stripTrailing :: ByteString.ByteString -> ByteString.ByteString
stripTrailing = ByteStringChar.dropWhileEnd (\character -> character == ' ' || character == '\0')

----------------------------------------------------------------------------
-- Explain
----------------------------------------------------------------------------

-- | Build an ExplainData for a PPF4 patch, suitable for detailed
-- rendering.
explainPPF4 :: PPF4Patch -> ExplainData
explainPPF4 patch = ExplainData
  { explainFormat   = "PPF4 (Pyriel internal format)"
  , explainHeader   = ppf4Meta patch
  , explainSections =
      [ SectionRegions (map replaceRegion (ppf4Replaces patch)
                        ++ zipWith appendRegion appendDisplayOffsets (ppf4Appends patch)) ]
  , explainSummary  = Summary (SummaryInfo recordCount "records"
                                (Just (SummaryByteInfo totalBytes BytesTotal)))
  , explainNotes    = []
  }
  where
    recordCount = length (ppf4Replaces patch) + length (ppf4Appends patch)
    totalBytes  = totalPayloadBytes patch

    -- Append regions are displayed as if they sit at consecutive
    -- offsets starting at zero. The Explain layer doesn't know the
    -- source size, so this is a *display* offset, not the actual
    -- apply-time offset (which uses sourceFileSize as the starting
    -- point). The display approximation matches what users see in
    -- @slap explain@ output for PPF4 today.
    appendDisplayOffsets = scanl advance (Offset 0)
                                  (map (byteLength . appendData) (ppf4Appends patch))

replaceRegion :: PPF4Replace -> ExplainRegion
replaceRegion replace = ExplainRegion
  { regionOffset     = replaceOffset replace
  , regionSize       = byteLength (replaceData replace)
  , regionLabel      = "Write  "
  , regionPayload    = PayloadWrite (replaceData replace)
  , regionAnnotation = AnnotAt AtOffset (replaceOffset replace) []
  }

appendRegion :: Offset -> PPF4Append -> ExplainRegion
appendRegion displayOffset (PPF4Append payloadBytes) = ExplainRegion
  { regionOffset     = displayOffset
  , regionSize       = byteLength payloadBytes
  , regionLabel      = "Append "
  , regionPayload    = PayloadWrite payloadBytes
  , regionAnnotation = AnnotAt AtOffset displayOffset []
  }

----------------------------------------------------------------------------
-- Display range
----------------------------------------------------------------------------

-- | The 'OffsetRange' spanning a non-empty list of PPF4 'Replace'
-- records, consumed by the cheap display path's
-- 'Slap.Display.PatchHeader' construction. Append records are
-- excluded — they have no addressable offset (PPF4 places appended
-- bytes at the end of the file, with no per-record offset on the
-- wire). Returns 'Nothing' on an empty list so the display layer
-- suppresses the range line.
ppf4ReplacesRange :: [PPF4Replace] -> Maybe OffsetRange
ppf4ReplacesRange [] = Nothing
ppf4ReplacesRange replaces =
  let firstAffectedOffset = minimum (map replaceOffset replaces)
      endOfLastRecord     = maximum (map replaceEndOffset replaces)
  in Just OffsetRange
      { rangeStart  = firstAffectedOffset
      , rangeLength = Length (unOffset endOfLastRecord - unOffset firstAffectedOffset)
      }
  where
    replaceEndOffset replace =
      advance (replaceOffset replace) (byteLength (replaceData replace))
