{-# LANGUAGE OverloadedStrings #-}

module Slap.PPF4.Describe
  ( ppf4Meta, analyzePPF4
  , ppf4ReplacesRange
  ) where

import Slap.PPF4.Types (PPF4Patch(..), PPF4Replace(..), PPF4Append(..))
import Slap.Measure (Offset(Offset), Length(..),
                     OffsetRange(..), advance, byteLength, distance)
import Slap.Display.Common (InfoLine(..),
                     Tally(..), CountUnit(Records), ByteCount(TotalPayloadBytes))
import Slap.Display.Analysis
  ( PatchAnalysis(..)
  , AnalysisSection(SectionRegions)
  , AnalysisRegion(..)
  , AnalysisPayload(PayloadWrite)
  , AnalysisSummary(Summary)
  , SummaryInfo(..)
  , Annotation(AnnotationAt)
  , OffsetKind(AtOffset)
  )

import Slap.Text (encodedTextContent)

import qualified Data.ByteString as ByteString
import qualified Data.Text as Text

-- | All key-value metadata carried by a PPF4 patch header. PPF4 has
-- only a description field; no validation block, no file size, no
-- undo, no image type, no File_ID.diz.
ppf4Meta :: PPF4Patch -> [InfoLine]
ppf4Meta patch =
  let description = encodedTextContent (ppf4Description patch)
  in [InfoLine "description" description | not (Text.null description)]

totalPayloadBytes :: PPF4Patch -> Int
totalPayloadBytes patch =
  sum (map (ByteString.length . replaceData) (ppf4Replaces patch))
  + sum (map (ByteString.length . appendData) (ppf4Appends patch))

----------------------------------------------------------------------------
-- Analyze
----------------------------------------------------------------------------

analyzePPF4 :: PPF4Patch -> PatchAnalysis
analyzePPF4 patch = PatchAnalysis
  { analysisSections =
      [ SectionRegions (map replaceRegion (ppf4Replaces patch)
                        ++ zipWith appendRegion appendDisplayOffsets (ppf4Appends patch)) ]
  , analysisSummary  = Summary (SummaryInfo (Tally recordCount) Records
                                  (Just (TotalPayloadBytes (Length totalBytes))))
  }
  where
    recordCount = length (ppf4Replaces patch) + length (ppf4Appends patch)
    totalBytes  = totalPayloadBytes patch

    -- Append regions are displayed as if they sit at consecutive
    -- offsets starting at zero. The analytical layer doesn't know
    -- the source size, so this is a *display* offset, not the actual
    -- apply-time offset (which uses sourceFileSize as the starting
    -- point). The display approximation matches what users see in
    -- @slap explain@ output for PPF4 today.
    appendDisplayOffsets = scanl advance (Offset 0)
                                  (map (byteLength . appendData) (ppf4Appends patch))

replaceRegion :: PPF4Replace -> AnalysisRegion
replaceRegion replace = AnalysisRegion
  { regionOffset     = replaceOffset replace
  , regionSize       = byteLength (replaceData replace)
  , regionLabel      = "Write  "
  , regionPayload    = PayloadWrite (replaceData replace)
  , regionAnnotation = AnnotationAt AtOffset (replaceOffset replace) []
  }

appendRegion :: Offset -> PPF4Append -> AnalysisRegion
appendRegion displayOffset (PPF4Append payloadBytes) = AnalysisRegion
  { regionOffset     = displayOffset
  , regionSize       = byteLength payloadBytes
  , regionLabel      = "Append "
  , regionPayload    = PayloadWrite payloadBytes
  , regionAnnotation = AnnotationAt AtOffset displayOffset []
  }

----------------------------------------------------------------------------
-- Display range
----------------------------------------------------------------------------

-- | The 'OffsetRange' spanning a non-empty list of PPF4 'Replace'
-- records, consumed by the cheap display path's
-- 'Slap.Display.Info.PatchInfo' construction. Append records are
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
      , rangeLength = distance firstAffectedOffset endOfLastRecord
      }
  where
    replaceEndOffset replace =
      advance (replaceOffset replace) (byteLength (replaceData replace))
