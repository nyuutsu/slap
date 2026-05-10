{-# LANGUAGE OverloadedStrings #-}

-- | Pretty-print a parsed PPF3 patch's metadata and per-record
-- analysis. PPF3 carries a description, an image-type byte (which
-- chooses the validation block's source-side offset), an optional
-- 1024-byte validation block, optional per-record undo bytes,
-- and an optional FILE_ID.DIZ.
module Slap.PPF3.Describe
  ( ppf3Meta
  , analyzePPF3
  , ppf3RecordsRange
  ) where

import Slap.PPF3.Types (PPF3Patch(..), PPF3Record(..),
                        PPF3ValidationBlock(..),
                        unPPF3FileId,
                        ppf3ValidationOffset)
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
  , AnnotDetail(DetailUndo)
  )
import Slap.TextEncoding (decodeLocaleField)

import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Char8 as ByteStringChar
import Data.Word (Word64)
import Numeric (showHex)

ppf3Meta :: PPF3Patch -> [InfoLine]
ppf3Meta patch = concat
  [ let description = decodeLocaleField (stripTrailing (ppf3Description patch))
    in [InfoLine "description" description | not (null description)]
  , [InfoLine "validation" validationLine]
  , [InfoLine "undo data" (if ppf3HasUndo patch then "yes" else "no")]
  , case ppf3FileId patch of
      Nothing  -> []
      Just fid -> [InfoLine "file_id.diz" (show (ByteString.length (unPPF3FileId fid)) ++ " bytes")]
  ]
  where
    validationLine = case ppf3ValidationBlock patch of
      Nothing -> "none"
      Just (PPF3ValidationBlock blockBytes) ->
        show (ppf3ImageType patch)
        ++ " block at 0x"
        ++ showHex (fromIntegral
                     (unOffset (ppf3ValidationOffset (ppf3ImageType patch))) :: Word64) ""
        ++ " (" ++ show (ByteString.length blockBytes) ++ " bytes)"

stripTrailing :: ByteString.ByteString -> ByteString.ByteString
stripTrailing = ByteStringChar.dropWhileEnd (\char -> char == ' ' || char == '\0')

analyzePPF3 :: PPF3Patch -> PatchAnalysis
analyzePPF3 patch = PatchAnalysis
  { analysisSections = [SectionRegions (map makeRegion (ppf3Records patch))]
  , analysisSummary  = Summary (SummaryInfo (Tally recordCount) Records (Just (TotalPayloadBytes (Length totalBytes))))
  }
  where
    recordCount = length (ppf3Records patch)
    totalBytes = sum (map (ByteString.length . ppf3RecordPayload) (ppf3Records patch))
    makeRegion record = AnalysisRegion
      { regionOffset     = ppf3RecordOffset record
      , regionSize       = Length (ByteString.length (ppf3RecordPayload record))
      , regionLabel      = "Write  "
      , regionPayload    = PayloadWrite (ppf3RecordPayload record)
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
      , rangeLength = Length (unOffset endOfLastRecord - unOffset firstAffectedOffset)
      }
  where
    recordEndOffset record =
      advance (ppf3RecordOffset record) (byteLength (ppf3RecordPayload record))
