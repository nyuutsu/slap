module Patch.PPF.Info (ppfInfo, ppfMeta) where

import Patch.PPF.Types
import Patch.Measure (Offset(..))
import Patch.Format (renderField)

import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Char8 as ByteStringChar
import Data.Word (Word64)
import Numeric (showHex)

-- | All key-value metadata carried by a PPF patch header.
ppfMeta :: Patch -> [(String, String)]
ppfMeta patch = concat
  [ let description = ByteStringChar.unpack (stripTrailing (ppfDescription patch))
    in [("description", description) | not (null description)]
  , case ppfFileSize patch of
      Nothing   -> []
      Just size -> [("file size", show size ++ " bytes (validation)")]
  , [("validation", validationString (ppfValidation patch))]
  , [("undo data", if ppfHasUndo patch then "yes" else "no")]
  , case ppfFileId patch of
      Nothing             -> []
      Just (FileId content) -> [("file_id.diz", show (ByteString.length content) ++ " bytes")]
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
