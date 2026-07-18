{-# LANGUAGE OverloadedStrings #-}

-- | Pretty-print a parsed PPF2 patch's metadata and per-record
-- analysis. PPF2 carries a description, declared source size,
-- a 1024-byte validation block, and an optional FILE_ID.DIZ.
module Slap.PPF2.Describe
  ( ppf2Meta
  , ppf2EmbeddedContent
  , ppf2UndeclaredTextFields
  , analyzePPF2
  , ppf2RecordsRange
  ) where

import Slap.PPF2.Types (PPF2Patch(..), PPF2Record(..),
                        PPF2ValidationBlock(..),
                        PPF2CarriedFileId(..),
                        unPPF2SourceSize,
                        ppf2ValidationOffset)
import Slap.Measure (OffsetRange(..), advance, byteLength, distance)
import Slap.Display.Common (InfoLine(..),
                            Tally(..), CountUnit(Records),
                            ByteCount(TotalPayloadBytes), renderAsText, renderOffsetAsHex)
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
import Slap.Display.EmbeddedContent (EmbeddedContent(..), EmbeddedField(..), EmbeddedWireBytes(..))
import Slap.Text (encodedTextContent)

import qualified Data.ByteString as ByteString
import Data.Maybe (isJust)
import Data.Text (Text)
import qualified Data.Text as Text

ppf2Meta :: PPF2Patch -> [InfoLine]
ppf2Meta patch = concat
  [ let description = encodedTextContent (ppf2Description patch)
    in [InfoLine "description" description | not (Text.null description)]
  , [InfoLine "file size" (renderAsText (unPPF2SourceSize (ppf2SourceFileSize patch)) <> " bytes (validation)")]
  , [InfoLine "validation" validationLine]
  ]
  where
    validationBlockBytes = unPPF2ValidationBlock (ppf2ValidationBlock patch)
    validationLine =
      "BIN block at "
      <> renderOffsetAsHex ppf2ValidationOffset
      <> " (" <> renderAsText (ByteString.length validationBlockBytes) <> " bytes)"

ppf2UndeclaredTextFields :: PPF2Patch -> [Text]
ppf2UndeclaredTextFields patch = concat
  [ ["description" | not (Text.null (encodedTextContent (ppf2Description patch)))]
  , ["file_id.diz" | isJust (ppf2FileId patch)]
  ]

ppf2EmbeddedContent :: PPF2Patch -> [EmbeddedContent]
ppf2EmbeddedContent patch = case ppf2FileId patch of
  Nothing         -> []
  Just fileIdDiz  -> [EmbeddedContent "file_id.diz"
                        (FieldContent (EmbeddedWireBytes (ppf2CarriedFileIdBytes fileIdDiz))
                                      (ppf2CarriedFileIdText fileIdDiz)
                                      (ppf2CarriedFileIdSubstitutions fileIdDiz))]

analyzePPF2 :: PPF2Patch -> PatchAnalysis
analyzePPF2 patch = PatchAnalysis
  { analysisSections = [SectionRegions (map makeRegion (ppf2Records patch))]
  , analysisSummary  = Summary (SummaryInfo (Tally recordCount) Records (Just (TotalPayloadBytes totalBytes)))
  }
  where
    recordCount = length (ppf2Records patch)
    totalBytes = foldMap (byteLength . ppf2RecordPayload) (ppf2Records patch)
    makeRegion record = AnalysisRegion
      { regionOffset     = ppf2RecordOffset record
      , regionSize       = byteLength (ppf2RecordPayload record)
      , regionLabel      = "Write  "
      , regionPayload    = PayloadWrite (LiteralWriteBytes (ppf2RecordPayload record))
      , regionAnnotation = AnnotationAt AtOffset (ppf2RecordOffset record) []
      }

ppf2RecordsRange :: [PPF2Record] -> Maybe OffsetRange
ppf2RecordsRange [] = Nothing
ppf2RecordsRange records =
  let firstAffectedOffset = minimum (map ppf2RecordOffset records)
      endOfLastRecord     = maximum (map recordEndOffset records)
  in Just OffsetRange
      { rangeStart  = firstAffectedOffset
      , rangeLength = distance firstAffectedOffset endOfLastRecord
      }
  where
    recordEndOffset record =
      advance (ppf2RecordOffset record) (byteLength (ppf2RecordPayload record))
