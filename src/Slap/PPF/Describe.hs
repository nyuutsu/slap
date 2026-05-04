module Slap.PPF.Describe
  ( ppfInfo, ppfMeta, analyzePPF
  , ppfRecordsRange
  ) where

import Slap.PPF.Types (PPFPatch(..), PPFRecord(..),
                        PPFVersion(..), PPFValidation(..),
                        ValidationBlockBytes(..), PPFFileId(..),
                        validationOffset)
import Slap.Measure (Offset(..), Length(..), FileSize(..),
                     OffsetRange(..), advance, byteLength)
import Slap.Display (InfoLine(..), renderInfoLine,
                     Tally(..), CountUnit(Records), ByteCount(TotalPayloadBytes))
import Slap.Explain
  ( PatchAnalysis(..)
  , AnalysisSection(SectionRegions)
  , AnalysisRegion(..)
  , AnalysisPayload(PayloadWrite)
  , AnalysisSummary(Summary)
  , SummaryInfo(..)
  , Annotation(AnnotAt)
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

-- | Format a human-readable summary of a parsed PPF patch.
ppfInfo :: PPFPatch -> String
ppfInfo patch = unlines $ filter (not . null) $
  [ "format:      PPF" ++ versionString (ppfVersion patch) ]
  ++ map renderInfoLine (ppfMeta patch)
  ++ [ "records:     " ++ show (length (ppfRecords patch))
     , bytesInfo (ppfRecords patch)
     , rangeInfo (ppfRecords patch)
     ]
  ++ fileIdLines (ppfFileId patch)

versionString :: PPFVersion -> String
versionString PPF1 = "1"
versionString PPF2 = "2"
versionString PPF3 = "3"

bytesInfo :: [PPFRecord] -> String
bytesInfo records =
  let total = sum (map (ByteString.length . recordData) records)
  in "total bytes: " ++ show total

rangeInfo :: [PPFRecord] -> String
rangeInfo [] = "range:       (empty patch)"
rangeInfo records =
  let lowest  = minimum (map (unOffset . recordOffset) records)
      highest = unOffset (maximum (map (\record -> advance (recordOffset record) (byteLength (recordData record))) records))
  in "range:       0x" ++ showHex (fromIntegral lowest :: Word64) ""
     ++ " - 0x" ++ showHex (fromIntegral highest :: Word64) ""

fileIdLines :: Maybe PPFFileId -> [String]
fileIdLines Nothing = []
fileIdLines (Just (PPFFileId content)) = [decodeLocaleField content]

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
  , regionAnnotation = AnnotAt AtOffset (recordOffset record) undoDetail
  }
  where
    undoDetail = case recordUndo record of
      Nothing -> []
      Just _  -> [DetailUndo]

----------------------------------------------------------------------------
-- Display range
----------------------------------------------------------------------------

-- | The 'OffsetRange' spanning a non-empty PPF record stream,
-- consumed by the cheap display path's 'Slap.Display.PatchHeader'
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
