{-# LANGUAGE OverloadedStrings #-}

-- | Pretty-print metadata and per-record analysis for a parsed PPF1
-- patch. PPF1's metadata is just the description, so 'ppf1Meta'
-- has at most one line; the analysis ('analyzePPF1') is the
-- per-record region listing the cheap and full inspection paths
-- both consume.
module Slap.PPF1.Describe
  ( ppf1Meta
  , analyzePPF1
  , ppf1RecordsRange
  ) where

import Slap.PPF1.Types (PPF1Patch(..), PPF1Record(..))
import Slap.Measure (Offset(..), Length(..), OffsetRange(..),
                     advance, byteLength)
import Slap.Display.Common (InfoLine(..),
                            Tally(..), CountUnit(Records),
                            ByteCount(TotalPayloadBytes))
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
import Slap.TextEncoding (decodeLocaleField)

import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Char8 as ByteStringChar

ppf1Meta :: PPF1Patch -> [InfoLine]
ppf1Meta patch =
  let description = decodeLocaleField (stripTrailing (ppf1Description patch))
  in [InfoLine "description" description | not (null description)]

stripTrailing :: ByteString.ByteString -> ByteString.ByteString
stripTrailing = ByteStringChar.dropWhileEnd (\char -> char == ' ' || char == '\0')

analyzePPF1 :: PPF1Patch -> PatchAnalysis
analyzePPF1 patch = PatchAnalysis
  { analysisSections = [SectionRegions (map makeRegion (ppf1Records patch))]
  , analysisSummary  = Summary (SummaryInfo (Tally recordCount) Records (Just (TotalPayloadBytes (Length totalBytes))))
  }
  where
    recordCount = length (ppf1Records patch)
    totalBytes = sum (map (ByteString.length . ppf1RecordPayload) (ppf1Records patch))
    makeRegion record = AnalysisRegion
      { regionOffset     = ppf1RecordOffset record
      , regionSize       = byteLength (ppf1RecordPayload record)
      , regionLabel      = "Write  "
      , regionPayload    = PayloadWrite (ppf1RecordPayload record)
      , regionAnnotation = AnnotationAt AtOffset (ppf1RecordOffset record) []
      }

ppf1RecordsRange :: [PPF1Record] -> Maybe OffsetRange
ppf1RecordsRange [] = Nothing
ppf1RecordsRange records =
  let firstAffectedOffset = minimum (map ppf1RecordOffset records)
      endOfLastRecord     = maximum (map recordEndOffset records)
  in Just OffsetRange
      { rangeStart  = firstAffectedOffset
      , rangeLength = Length (unOffset endOfLastRecord - unOffset firstAffectedOffset)
      }
  where
    recordEndOffset record =
      advance (ppf1RecordOffset record) (byteLength (ppf1RecordPayload record))
