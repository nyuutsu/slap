module Slap.IPS.Describe
  ( ipsInfo
  , ipsMeta
  , jsonPairs
  , jsonFieldCI
  , explainIPS
  , makeIPSRegion
  ) where

import Slap.IPS.Types (IPSVariant(..), IPSRecord(..), IPSPatch(..))
import Slap.Explain (ExplainData(..), ExplainSection(..), ExplainRegion(..),
                      ExplainPayload(..), ExplainSummary(..), SummaryBytes(..),
                      Annotation(..), OffsetKind(..), AnnotDetail(..))
import Slap.Format (renderField)
import Slap.Measure (Offset(..), Length(..), FileSize(..))

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Char8 as ByteString8
import Data.Char (toLower)
import Data.List (sortBy)
import Data.Ord (comparing)
import Data.Word (Word64)
import Numeric (showHex)

ipsMeta :: IPSPatch -> [(String, String)]
ipsMeta patch = concat
  [ case ipsTruncate patch of
      Nothing        -> []
      Just truncSize -> [("truncate", show (unFileSize truncSize) ++ " bytes")]
  , ebpFields
  ]
  where
    ebpFields = case ipsEBPMeta patch of
      Nothing   -> []
      Just meta ->
        let pairs = jsonPairs meta
            known = ["patcher", "title", "author", "description"]
            knownFields = [ (key, value) | key <- known
                          , Just value <- [jsonFieldCI pairs key]
                          , not (null value) ]
            unknownFields = sortBy (comparing fst)
                          [ (key, value) | (key, value) <- pairs
                          , map toLower key `notElem` known
                          , not (null value) ]
        in knownFields ++ unknownFields

ipsInfo :: IPSPatch -> String
ipsInfo patch = unlines $ filter (not . null) $
  [ "format:      " ++ case ipsVariant patch of
      StandardIPS -> case ipsEBPMeta patch of
        Nothing -> "IPS"
        Just _  -> "IPS (EBP)"
      IPS32       -> "IPS32"
  ]
  ++ map renderField (ipsMeta patch)
  ++ [ "records:     " ++ show (length (ipsRecords patch))
     , "total bytes: " ++ show totalBytes
     , rangeString
     ]
  where
    totalBytes = sum (map ipsPayloadSize (ipsRecords patch))
    ipsPayloadSize (IPSRecord _ payload)          = ByteString.length payload
    ipsPayloadSize (IPSRecordRLE _ fillCount _)   = unLength fillCount

    rangeString
      | null (ipsRecords patch) = "range:       (empty patch)"
      | otherwise =
          let lowest  = minimum [ unOffset (ipsOffset record) | record <- ipsRecords patch ]
              highest = maximum [ unOffset (ipsOffset record) + fromIntegral (ipsPayloadSize record)
                                | record <- ipsRecords patch ]
          in "range:       0x" ++ showHex (fromIntegral lowest :: Word64) ""
             ++ " - 0x" ++ showHex (fromIntegral highest :: Word64) ""

    ipsOffset (IPSRecord recordOffset _)       = recordOffset
    ipsOffset (IPSRecordRLE recordOffset _ _)  = recordOffset

-- | Extract all string key-value pairs from a flat JSON object.
jsonPairs :: ByteString -> [(String, String)]
jsonPairs = extractPairs . ByteString8.unpack
  where
    extractPairs text = case dropWhile (/= '{') text of
      ('{':rest) -> scanEntries rest
      _          -> []
    scanEntries text = case dropWhile (\char -> char == ' ' || char == ',' || char == '\n' || char == '\r') text of
      ('}':_)    -> []
      ('"':rest) -> case takeQuoted rest of
        (key, afterKey) -> case dropWhile (\char -> char == ' ' || char == ':') afterKey of
          ('"':valueRest) -> case takeQuoted valueRest of
            (value, afterValue) -> (key, value) : scanEntries afterValue
          other -> scanEntries other   -- non-string value, skip
      _ -> []
    takeQuoted = scanQuoted []
      where
        scanQuoted accumulated ('"' : rest)         = (reverse accumulated, rest)
        scanQuoted accumulated ('\\' : '"' : rest)  = scanQuoted ('"' : accumulated) rest
        scanQuoted accumulated ('\\' : '\\' : rest) = scanQuoted ('\\' : accumulated) rest
        scanQuoted accumulated ('\\' : char : rest) = scanQuoted (char : accumulated) rest
        scanQuoted accumulated (char : rest)        = scanQuoted (char : accumulated) rest
        scanQuoted accumulated []                   = (reverse accumulated, [])

-- | Case-insensitive key lookup in extracted JSON pairs.
jsonFieldCI :: [(String, String)] -> String -> Maybe String
jsonFieldCI pairs key =
  let lowerKey = map toLower key
  in lookup lowerKey [(map toLower entryKey, value) | (entryKey, value) <- pairs]

----------------------------------------------------------------------------
-- Explain
----------------------------------------------------------------------------

explainIPS :: IPSPatch -> ExplainData
explainIPS patch = ExplainData
  { explainFormat   = case ipsVariant patch of
      StandardIPS -> case ipsEBPMeta patch of
        Nothing -> "IPS"
        Just _  -> "IPS (EBP)"
      IPS32       -> "IPS32"
  , explainHeader   = ipsMeta patch
  , explainSections = [SectionRegions (map makeIPSRegion (ipsRecords patch))]
  , explainSummary  = Summary recordCount "records" (Just (totalBytes, BytesTotal))
  , explainNotes    = truncNote
  }
  where
    recordCount = length (ipsRecords patch)
    totalBytes = sum (map ipsRecordSize (ipsRecords patch))
    truncNote = case ipsTruncate patch of
      Nothing         -> []
      Just outputSize -> ["truncate to " ++ show (unFileSize outputSize) ++ " bytes"]

makeIPSRegion :: IPSRecord -> ExplainRegion
makeIPSRegion (IPSRecord recordOffset recordPayload) = ExplainRegion
  { regionOffset     = recordOffset
  , regionSize       = Length (ByteString.length recordPayload)
  , regionLabel      = "Write  "
  , regionPayload    = PayloadWrite recordPayload
  , regionAnnotation = AnnotAt AtOffset recordOffset []
  }
makeIPSRegion (IPSRecordRLE recordOffset fillCount fillByte) = ExplainRegion
  { regionOffset     = recordOffset
  , regionSize       = fillCount
  , regionLabel      = "Fill "
  , regionPayload    = PayloadFill fillByte (unLength fillCount)
  , regionAnnotation = AnnotAt AtOffset recordOffset [DetailRLE]
  }

ipsRecordSize :: IPSRecord -> Int
ipsRecordSize (IPSRecord _ recordPayload) = ByteString.length recordPayload
ipsRecordSize (IPSRecordRLE _ fillCount _) = unLength fillCount
