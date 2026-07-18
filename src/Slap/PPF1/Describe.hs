{-# LANGUAGE OverloadedStrings #-}

-- | Pretty-print metadata and per-record analysis for a parsed PPF1
-- patch. PPF1's metadata is just the description, so 'ppf1Meta'
-- has at most one line; the analysis ('analyzePPF1') is the
-- per-record region listing the cheap and full inspection paths
-- both consume.
module Slap.PPF1.Describe
  ( ppf1Meta
  , ppf1UndeclaredTextFields
  , analyzePPF1
  , ppf1RecordsRange
  ) where

import Slap.PPF1.Types (PPF1Patch(..), PPF1Record(..))
import Slap.Measure (OffsetRange(..),
                     advance, byteLength, distance)
import Slap.Display.Common (InfoLine(..),
                            Tally(..), CountUnit(Records),
                            ByteCount(TotalPayloadBytes))
import Slap.Display.Analysis
  ( PatchAnalysis(..)
  , AnalysisSection(SectionRegions)
  , AnalysisRegion(..)
  , AnalysisPayload(PayloadWrite)
  , LiteralWriteBytes(..)
  , AnalysisSummary(Summary)
  , SummaryInfo(..)
  , Annotation(AnnotationAt)
  , OffsetKind(AtOffset)
  )
import Slap.Text (encodedTextContent)

import Data.Text (Text)
import qualified Data.Text as Text

ppf1Meta :: PPF1Patch -> [InfoLine]
ppf1Meta patch =
  let description = encodedTextContent (ppf1Description patch)
  in [InfoLine "description" description | not (Text.null description)]

ppf1UndeclaredTextFields :: PPF1Patch -> [Text]
ppf1UndeclaredTextFields patch =
  ["description" | not (Text.null (encodedTextContent (ppf1Description patch)))]

analyzePPF1 :: PPF1Patch -> PatchAnalysis
analyzePPF1 patch = PatchAnalysis
  { analysisSections = [SectionRegions (map makeRegion (ppf1Records patch))]
  , analysisSummary  = Summary (SummaryInfo (Tally recordCount) Records (Just (TotalPayloadBytes totalBytes)))
  }
  where
    recordCount = length (ppf1Records patch)
    totalBytes = foldMap (byteLength . ppf1RecordPayload) (ppf1Records patch)
    makeRegion record = AnalysisRegion
      { regionOffset     = ppf1RecordOffset record
      , regionSize       = byteLength (ppf1RecordPayload record)
      , regionLabel      = "Write  "
      , regionPayload    = PayloadWrite (LiteralWriteBytes (ppf1RecordPayload record))
      , regionAnnotation = AnnotationAt AtOffset (ppf1RecordOffset record) []
      }

ppf1RecordsRange :: [PPF1Record] -> Maybe OffsetRange
ppf1RecordsRange [] = Nothing
ppf1RecordsRange records =
  let firstAffectedOffset = minimum (map ppf1RecordOffset records)
      endOfLastRecord     = maximum (map recordEndOffset records)
  in Just OffsetRange
      { rangeStart  = firstAffectedOffset
      , rangeLength = distance firstAffectedOffset endOfLastRecord
      }
  where
    recordEndOffset record =
      advance (ppf1RecordOffset record) (byteLength (ppf1RecordPayload record))
