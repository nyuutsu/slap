module Patch.PPF.Info (showInfo) where

import Patch.PPF.Types

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BC
import Data.Word (Word32, Word64)
import Numeric (showHex)

-- | Format a human-readable summary of a parsed PPF patch.
showInfo :: Patch -> String
showInfo p = unlines $ filter (not . null)
  [ "format:      PPF" ++ verStr (patchVersion p)
  , "description: " ++ BC.unpack (stripTrailing (patchDescription p))
  , sizeInfo (patchFileSize p)
  , validationInfo (patchValidation p)
  , undoInfo (patchHasUndo p)
  , "records:     " ++ show (length (patchRecords p))
  , bytesInfo (patchRecords p)
  , rangeInfo (patchRecords p)
  , fileIdInfo (patchFileId p)
  ]

verStr :: Version -> String
verStr PPF1 = "1"
verStr PPF2 = "2"
verStr PPF3 = "3"
verStr PPF4 = " (Pyriel internal format)"

sizeInfo :: Maybe Word32 -> String
sizeInfo Nothing  = ""
sizeInfo (Just s) = "file size:   " ++ show s ++ " bytes (validation)"

validationInfo :: Maybe Validation -> String
validationInfo Nothing  = "validation:  none"
validationInfo (Just v) =
  "validation:  " ++ show (valImageType v)
  ++ " block at 0x" ++ showHex (fromIntegral (validationOffset (valImageType v)) :: Word64) ""
  ++ " (" ++ show (BS.length (valBlock v)) ++ " bytes)"

undoInfo :: Bool -> String
undoInfo True  = "undo data:   yes"
undoInfo False = "undo data:   no"

bytesInfo :: [Record] -> String
bytesInfo recs =
  let total = sum (map (BS.length . recData) recs)
  in "total bytes: " ++ show total

rangeInfo :: [Record] -> String
rangeInfo [] = "range:       (empty patch)"
rangeInfo recs =
  let offsets = map recOffset recs
      lo = minimum offsets
      hi = maximum offsets + fromIntegral (BS.length (recData (last recs)))
  in "range:       0x" ++ showHex (fromIntegral lo :: Word64) ""
     ++ " - 0x" ++ showHex (fromIntegral hi :: Word64) ""

fileIdInfo :: Maybe FileId -> String
fileIdInfo Nothing = ""
fileIdInfo (Just (FileId content)) =
  "file_id.diz: " ++ show (BS.length content) ++ " bytes\n"
  ++ BC.unpack content

stripTrailing :: BS.ByteString -> BS.ByteString
stripTrailing = BC.dropWhileEnd (\c -> c == ' ' || c == '\0')
