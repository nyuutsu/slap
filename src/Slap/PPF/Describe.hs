module Slap.PPF.Describe
  ( ppfMeta, analyzePPF
  , ppfRecordsRange
  ) where

import Slap.PPF.Types (PPFPatch(..), PPFRecord(..),
                        PPFValidation(..),
                        ValidationBlockBytes(..), PPFFileId(..),
                        validationOffset)
import Slap.Measure (Offset(..), Length(..), FileSize(..),
                     OffsetRange(..), advance, byteLength)
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
  , AnnotDetail(DetailUndo)
  )

import Slap.TextEncoding (decodeLocaleField)

import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Char8 as ByteStringChar
import Data.Word (Word64)
import Numeric (showHex)

-- | All key-value metadata carried by a PPF patch header.
ppfMeta :: PPFPatch -> [InfoLine]
ppfMeta patch = concat
  [ let description = decodeLocaleField (stripTrailing (ppfDescription patch))
    in [InfoLine "description" description | not (null description)]
  , case ppfFileSize patch of
      Nothing   -> []
      Just size -> [InfoLine "file size" (show (unFileSize size) ++ " bytes (validation)")]
  , [InfoLine "validation" (validationString (ppfValidation patch))]
  , [InfoLine "undo data" (if ppfHasUndo patch then "yes" else "no")]
  , case ppfFileId patch of
      Nothing             -> []
      Just (PPFFileId content) -> [InfoLine "file_id.diz" (show (ByteString.length content) ++ " bytes")]
  ]
  where
    validationString Nothing = "none"
    validationString (Just validation) =
      show (validationImageType validation)
      ++ " block at 0x" ++ showHex (fromIntegral (unOffset (validationOffset (validationImageType validation))) :: Word64) ""
      ++ " (" ++ show (ByteString.length (unValidationBlockBytes (validationBlock validation))) ++ " bytes)"

stripTrailing :: ByteString.ByteString -> ByteString.ByteString
stripTrailing = ByteStringChar.dropWhileEnd (\char -> char == ' ' || char == '\0')

----------------------------------------------------------------------------
-- Analyze
----------------------------------------------------------------------------

-- | Build a 'PatchAnalysis' for a PPF patch, suitable for detailed rendering.
analyzePPF :: PPFPatch -> PatchAnalysis
analyzePPF patch = PatchAnalysis
  { analysisSections = [SectionRegions (map makePPFRegion (ppfRecords patch))]
  , analysisSummary  = Summary (SummaryInfo (Tally recordCount) Records (Just (TotalPayloadBytes (Length totalBytes))))
  }
  where
    recordCount = length (ppfRecords patch)
    totalBytes = sum (map (ByteString.length . recordData) (ppfRecords patch))

makePPFRegion :: PPFRecord -> AnalysisRegion
makePPFRegion record = AnalysisRegion
  { regionOffset     = recordOffset record
  , regionSize       = Length (ByteString.length (recordData record))
  , regionLabel      = "Write  "
  , regionPayload    = PayloadWrite (recordData record)
  , regionAnnotation = AnnotationAt AtOffset (recordOffset record) undoDetail
  }
  where
    undoDetail = case recordUndo record of
      Nothing -> []
      Just _  -> [DetailUndo]

----------------------------------------------------------------------------
-- Display range
----------------------------------------------------------------------------

-- | The 'OffsetRange' spanning a non-empty PPF record stream,
-- consumed by the cheap display path's 'Slap.Display.Info.PatchInfo'
-- construction. Returns 'Nothing' on an empty stream so the display
-- layer suppresses the range line.
ppfRecordsRange :: [PPFRecord] -> Maybe OffsetRange
ppfRecordsRange [] = Nothing
ppfRecordsRange records =
  let firstAffectedOffset = minimum (map recordOffset records)
      endOfLastRecord     = maximum (map recordEndOffset records)
  in Just OffsetRange
      { rangeStart  = firstAffectedOffset
      , rangeLength = Length (unOffset endOfLastRecord - unOffset firstAffectedOffset)
      }
  where
    recordEndOffset record =
      advance (recordOffset record) (byteLength (recordData record))
