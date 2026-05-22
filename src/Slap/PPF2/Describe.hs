{-# LANGUAGE OverloadedStrings #-}

-- | Pretty-print a parsed PPF2 patch's metadata and per-record
-- analysis. PPF2 carries a description, declared source size,
-- a 1024-byte validation block, and an optional FILE_ID.DIZ.
module Slap.PPF2.Describe
  ( ppf2Meta
  , analyzePPF2
  , ppf2RecordsRange
  ) where

import Slap.PPF2.Types (PPF2Patch(..), PPF2Record(..),
                        PPF2ValidationBlock(..),
                        unPPF2FileId,
                        unPPF2SourceSize,
                        ppf2ValidationOffset)
import Slap.Measure (Offset(..), Length(..),
                     OffsetRange(..), advance, byteLength, distance)
import Slap.Display.Common (InfoLine(..),
                            Tally(..), CountUnit(Records),
                            ByteCount(TotalPayloadBytes), renderAsText, renderHexAsText)
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
import Data.Word (Word64)

ppf2Meta :: PPF2Patch -> [InfoLine]
ppf2Meta patch = concat
  [ let description = stripTrailing (encodedTextContent (ppf2Description patch))
    in [InfoLine "description" description | not (Text.null description)]
  , [InfoLine "file size" (renderAsText (unPPF2SourceSize (ppf2SourceFileSize patch)) <> " bytes (validation)")]
  , [InfoLine "validation" validationLine]
  , case ppf2FileId patch of
      Nothing  -> []
      Just fid -> [InfoLine "file_id.diz"
                     (renderAsText (Text.length (encodedTextContent (unPPF2FileId fid)))
                       <> " characters")]
  ]
  where
    validationBlockBytes = unPPF2ValidationBlock (ppf2ValidationBlock patch)
    validationLine =
      "BIN block at 0x"
      <> renderHexAsText (fromIntegral (unOffset ppf2ValidationOffset) :: Word64)
      <> " (" <> renderAsText (ByteString.length validationBlockBytes) <> " bytes)"

stripTrailing :: Text.Text -> Text.Text
stripTrailing =
  Text.dropWhileEnd (\character -> character == ' ' || character == '\0')

analyzePPF2 :: PPF2Patch -> PatchAnalysis
analyzePPF2 patch = PatchAnalysis
  { analysisSections = [SectionRegions (map makeRegion (ppf2Records patch))]
  , analysisSummary  = Summary (SummaryInfo (Tally recordCount) Records (Just (TotalPayloadBytes (Length totalBytes))))
  }
  where
    recordCount = length (ppf2Records patch)
    totalBytes = sum (map (ByteString.length . ppf2RecordPayload) (ppf2Records patch))
    makeRegion record = AnalysisRegion
      { regionOffset     = ppf2RecordOffset record
      , regionSize       = byteLength (ppf2RecordPayload record)
      , regionLabel      = "Write  "
      , regionPayload    = PayloadWrite (ppf2RecordPayload record)
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
