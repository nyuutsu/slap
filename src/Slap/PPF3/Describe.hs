{-# LANGUAGE OverloadedStrings #-}

-- | Pretty-print a parsed PPF3 patch's metadata and per-record
-- analysis. PPF3 carries a description, an image-type byte (which
-- chooses the validation block's source-side offset), an optional
-- 1024-byte validation block, optional per-record undo bytes,
-- and an optional FILE_ID.DIZ.
module Slap.PPF3.Describe
  ( ppf3Meta
  , ppf3EmbeddedContent
  , analyzePPF3
  , ppf3RecordsRange
  ) where

import Slap.PPF3.Types (PPF3Patch(..), PPF3Record(..),
                        PPF3ValidationBlock(..),
                        PPF3CarriedFileId(..),
                        ppf3ValidationOffset)
import Slap.Measure (Length(..), OffsetRange(..),
                     advance, byteLength, distance)
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
  , AnnotDetail(DetailUndo)
  )
import Slap.Display.EmbeddedContent (EmbeddedContent(..), EmbeddedField(..), EmbeddedWireBytes(..))
import Slap.Text (encodedTextContent)

import qualified Data.ByteString as ByteString
import qualified Data.Text as Text

ppf3Meta :: PPF3Patch -> [InfoLine]
ppf3Meta patch = concat
  [ let description = encodedTextContent (ppf3Description patch)
    in [InfoLine "description" description | not (Text.null description)]
  , [InfoLine "validation" validationLine]
  , [InfoLine "undo data" (if ppf3HasUndo patch then "yes" else "no")]
  ]
  where
    validationLine = case ppf3ValidationBlock patch of
      Nothing -> "none"
      Just (PPF3ValidationBlock blockBytes) ->
        renderAsText (ppf3ImageType patch)
        <> " block at "
        <> renderOffsetAsHex (ppf3ValidationOffset (ppf3ImageType patch))
        <> " (" <> renderAsText (ByteString.length blockBytes) <> " bytes)"

ppf3EmbeddedContent :: PPF3Patch -> [EmbeddedContent]
ppf3EmbeddedContent patch = case ppf3FileId patch of
  Nothing        -> []
  Just fileIdDiz -> [EmbeddedContent "file_id.diz"
                       (FieldContent (EmbeddedWireBytes (ppf3CarriedFileIdBytes fileIdDiz))
                                     (ppf3CarriedFileIdText fileIdDiz)
                                     (ppf3CarriedFileIdSubstitutions fileIdDiz))]

analyzePPF3 :: PPF3Patch -> PatchAnalysis
analyzePPF3 patch = PatchAnalysis
  { analysisSections = [SectionRegions (map makeRegion (ppf3Records patch))]
  , analysisSummary  = Summary (SummaryInfo (Tally recordCount) Records (Just (TotalPayloadBytes (Length (fromIntegral totalBytes)))))
  }
  where
    recordCount = length (ppf3Records patch)
    totalBytes = sum (map (ByteString.length . ppf3RecordPayload) (ppf3Records patch))
    makeRegion record = AnalysisRegion
      { regionOffset     = ppf3RecordOffset record
      , regionSize       = byteLength (ppf3RecordPayload record)
      , regionLabel      = "Write  "
      , regionPayload    = PayloadWrite (LiteralWriteBytes (ppf3RecordPayload record))
      , regionAnnotation = AnnotationAt AtOffset (ppf3RecordOffset record) undoDetail
      }
      where
        undoDetail = case ppf3RecordUndo record of
          Nothing -> []
          Just _  -> [DetailUndo]

ppf3RecordsRange :: [PPF3Record] -> Maybe OffsetRange
ppf3RecordsRange [] = Nothing
ppf3RecordsRange records =
  let firstAffectedOffset = minimum (map ppf3RecordOffset records)
      endOfLastRecord     = maximum (map recordEndOffset records)
  in Just OffsetRange
      { rangeStart  = firstAffectedOffset
      , rangeLength = distance firstAffectedOffset endOfLastRecord
      }
  where
    recordEndOffset record =
      advance (ppf3RecordOffset record) (byteLength (ppf3RecordPayload record))
