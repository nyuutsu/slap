module Patch.PPF.Info (showInfo, ppfMeta) where

import Patch.PPF.Types
import Patch.Format (renderField)

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BC
import Data.Word (Word64)
import Numeric (showHex)

-- | All key-value metadata carried by a PPF patch header.
ppfMeta :: Patch -> [(String, String)]
ppfMeta p = concat
  [ let d = BC.unpack (stripTrailing (patchDescription p))
    in [("description", d) | not (null d)]
  , case patchFileSize p of
      Nothing -> []
      Just s  -> [("file size", show s ++ " bytes (validation)")]
  , [("validation", validationStr (patchValidation p))]
  , [("undo data", if patchHasUndo p then "yes" else "no")]
  , case patchFileId p of
      Nothing -> []
      Just (FileId c) -> [("file_id.diz", show (BS.length c) ++ " bytes")]
  ]
  where
    validationStr Nothing  = "none"
    validationStr (Just v) =
      show (valImageType v)
      ++ " block at 0x" ++ showHex (fromIntegral (validationOffset (valImageType v)) :: Word64) ""
      ++ " (" ++ show (BS.length (valBlock v)) ++ " bytes)"

-- | Format a human-readable summary of a parsed PPF patch.
showInfo :: Patch -> String
showInfo p = unlines $ filter (not . null) $
  [ "format:      PPF" ++ verStr (patchVersion p) ]
  ++ map renderField (ppfMeta p)
  ++ [ "records:     " ++ show (length (patchRecords p))
     , bytesInfo (patchRecords p)
     , rangeInfo (patchRecords p)
     ]
  ++ fileIdLines (patchFileId p)

verStr :: Version -> String
verStr PPF1 = "1"
verStr PPF2 = "2"
verStr PPF3 = "3"
verStr PPF4 = "4 (Pyriel internal format)"

bytesInfo :: [Record] -> String
bytesInfo recs =
  let total = sum (map (BS.length . recData) recs)
  in "total bytes: " ++ show total

rangeInfo :: [Record] -> String
rangeInfo [] = "range:       (empty patch)"
rangeInfo recs =
  let lo = minimum (map recOffset recs)
      hi = maximum (map (\r -> recOffset r + fromIntegral (BS.length (recData r))) recs)
  in "range:       0x" ++ showHex (fromIntegral lo :: Word64) ""
     ++ " - 0x" ++ showHex (fromIntegral hi :: Word64) ""

fileIdLines :: Maybe FileId -> [String]
fileIdLines Nothing = []
fileIdLines (Just (FileId content)) = [BC.unpack content]

stripTrailing :: BS.ByteString -> BS.ByteString
stripTrailing = BC.dropWhileEnd (\c -> c == ' ' || c == '\0')
