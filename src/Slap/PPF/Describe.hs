module Slap.PPF.Describe (ppfInfo, ppfMeta, explainPPF) where

import Slap.PPF.Types
import Slap.Measure (Offset(..), Length(..), FileSize(..))
import Slap.Format (MetaField(..), renderField)
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
  , AnnotDetail(DetailUndo)
  )

import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Char8 as ByteStringChar
import Data.Word (Word64)
import Numeric (showHex)

-- | All key-value metadata carried by a PPF patch header.
ppfMeta :: Patch -> [MetaField]
ppfMeta patch = concat
  [ let description = ByteStringChar.unpack (stripTrailing (ppfDescription patch))
    in [MetaField "description" description | not (null description)]
  , case ppfFileSize patch of
      Nothing   -> []
      Just size -> [MetaField "file size" (show (unFileSize size) ++ " bytes (validation)")]
  , [MetaField "validation" (validationString (ppfValidation patch))]
  , [MetaField "undo data" (if ppfHasUndo patch then "yes" else "no")]
  , case ppfFileId patch of
      Nothing             -> []
      Just (FileId content) -> [MetaField "file_id.diz" (show (ByteString.length content) ++ " bytes")]
  ]
  where
    validationString Nothing = "none"
    validationString (Just validation) =
      show (validationImageType validation)
      ++ " block at 0x" ++ showHex (fromIntegral (unOffset (validationOffset (validationImageType validation))) :: Word64) ""
      ++ " (" ++ show (ByteString.length (validationBlock validation)) ++ " bytes)"

-- | Format a human-readable summary of a parsed PPF patch.
ppfInfo :: Patch -> String
ppfInfo patch = unlines $ filter (not . null) $
  [ "format:      PPF" ++ versionString (ppfVersion patch) ]
  ++ map renderField (ppfMeta patch)
  ++ [ "records:     " ++ show (length (ppfRecords patch))
     , bytesInfo (ppfRecords patch)
     , rangeInfo (ppfRecords patch)
     ]
  ++ fileIdLines (ppfFileId patch)

versionString :: Version -> String
versionString PPF1 = "1"
versionString PPF2 = "2"
versionString PPF3 = "3"
versionString PPF4 = "4 (Pyriel internal format)"

bytesInfo :: [Record] -> String
bytesInfo records =
  let total = sum (map (ByteString.length . recordData) records)
  in "total bytes: " ++ show total

rangeInfo :: [Record] -> String
rangeInfo [] = "range:       (empty patch)"
rangeInfo records =
  let lowest  = minimum (map (unOffset . recordOffset) records)
      highest = maximum (map (\record -> unOffset (recordOffset record) + fromIntegral (ByteString.length (recordData record))) records)
  in "range:       0x" ++ showHex (fromIntegral lowest :: Word64) ""
     ++ " - 0x" ++ showHex (fromIntegral highest :: Word64) ""

fileIdLines :: Maybe FileId -> [String]
fileIdLines Nothing = []
fileIdLines (Just (FileId content)) = [ByteStringChar.unpack content]

stripTrailing :: ByteString.ByteString -> ByteString.ByteString
stripTrailing = ByteStringChar.dropWhileEnd (\char -> char == ' ' || char == '\0')

----------------------------------------------------------------------------
-- Explain
----------------------------------------------------------------------------

-- | Build an ExplainData for a PPF patch, suitable for detailed rendering.
explainPPF :: Patch -> ExplainData
explainPPF patch = ExplainData
  { explainFormat   = ppfExplainVersionString (ppfVersion patch)
  , explainHeader   = ppfMeta patch
  , explainSections = [SectionRegions (zipWith makePPFRegion [1..] (ppfRecords patch))]
  , explainSummary  = Summary (SummaryInfo recordCount "records" (Just (SummaryByteInfo totalBytes BytesTotal)))
  , explainNotes    = []
  }
  where
    recordCount = length (ppfRecords patch)
    totalBytes = sum (map (ByteString.length . recordData) (ppfRecords patch))

ppfExplainVersionString :: Version -> String
ppfExplainVersionString PPF1 = "PPF1"
ppfExplainVersionString PPF2 = "PPF2"
ppfExplainVersionString PPF3 = "PPF3"
ppfExplainVersionString PPF4 = "PPF4 (Pyriel internal format)"

makePPFRegion :: Int -> Record -> ExplainRegion
makePPFRegion _ record = ExplainRegion
  { regionOffset     = recordOffset record
  , regionSize       = Length (ByteString.length (recordData record))
  , regionLabel      = commandString
  , regionPayload    = PayloadWrite (recordData record)
  , regionAnnotation = AnnotAt AtOffset (recordOffset record) undoDetail
  }
  where
    commandString = case recordCommand record of
      Replace -> "Write  "
      Append  -> "Append "
    undoDetail = case recordUndo record of
      Nothing -> []
      Just _  -> [DetailUndo]
