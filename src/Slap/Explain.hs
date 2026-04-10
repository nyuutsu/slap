module Slap.Explain
  ( ExplainData(..)
  , ExplainSection(..)
  , ExplainRegion(..)
  , ExplainPayload(..)
  , CopySource(..)
  , ExplainSummary(..)
  , SummaryInfo(..)
  , SummaryByteInfo(..)
  , SummaryBytes(..)
  , Annotation(..)
  , OffsetKind(..)
  , AnnotDetail(..)
  , renderExplain
  , renderSummary
  ) where

import Slap.Checksum (CRC16, showCRC16)
import Slap.Format (MetaField(..), padHex, padNum, padRight, showSigned, hexDump, renderField)
import Slap.Measure (Offset(..), Length(..), Delta(..), advance)
import Data.Array (accumArray, elems)
import Data.Bits (xor)
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.Char (isDigit)
import Data.List (find, sort, intercalate, partition)
import Data.Int (Int64)
import Data.Word (Word8)

----------------------------------------------------------------------------
-- Types
----------------------------------------------------------------------------

data ExplainData = ExplainData
  { explainFormat   :: String              -- "PPF3", "IPS (EBP)", "BPS", etc.
  , explainHeader   :: [MetaField]         -- key-value metadata
  , explainSections :: [ExplainSection]    -- grouped content
  , explainSummary  :: ExplainSummary      -- structured summary
  , explainNotes    :: [String]            -- trailing messages
  }

data ExplainSection
  = SectionRegions [ExplainRegion]              -- flat numbered list
  | SectionBlock String [ExplainRegion]         -- labeled block + entries (PCHTXT)
  | SectionLabeled String [MetaField]            -- labeled block + kv pairs (VCDIFF)
  | SectionText String                          -- free text line

data ExplainRegion = ExplainRegion
  { regionOffset     :: Offset             -- primary offset (output or target)
  , regionSize       :: Length             -- bytes affected
  , regionLabel      :: String             -- operation label with trailing space
  , regionPayload    :: ExplainPayload
  , regionAnnotation :: Annotation         -- structured trailing metadata
  }

data ExplainPayload
  = PayloadWrite ByteString            -- literal data (renderer hex dumps)
  | PayloadFill !Word8 !Length         -- fill byte + repeat count
  | PayloadCopy CopySource             -- copy operation
  | PayloadXOR (Maybe ByteString)      -- XOR delta
  | PayloadMeta ![MetaField]           -- key-value details (BSDiff ctrl)

data CopySource = FromSource | FromTarget | FromPatch
  deriving (Eq, Show)

data ExplainSummary
  = SummaryNone
  | Summary !SummaryInfo

data SummaryInfo = SummaryInfo
  { summaryCount     :: !Int
  , summaryUnitLabel :: !String
  , summaryBytes     :: !(Maybe SummaryByteInfo)
  }

data SummaryByteInfo = SummaryByteInfo
  { summaryByteCount  :: !Int
  , summaryByteSuffix :: !SummaryBytes
  }

data SummaryBytes = BytesTotal | BytesTotalOutput

data Annotation
  = AnnotNone                                    -- no annotation (PCHTXT)
  | AnnotAt
      { annotOffsetKind :: !OffsetKind
      , annotOffset     :: !Offset
      , annotDetails    :: ![AnnotDetail]
      }
  | AnnotBSDiff
      { annotAddSize  :: !Length
      , annotCopySize :: !Length
      , annotSeek     :: !Delta
      }

data OffsetKind = AtOffset | AtOutput

data AnnotDetail
  = DetailRLE                   -- "(RLE)"
  | DetailUndo                  -- "(undo data)"
  | DetailDelta Delta           -- "(delta +N)"
  | DetailSkip Length           -- "(skip N)"
  | DetailSource Offset         -- "(source 0xN)"
  | DetailSourceIndex Int64     -- "from source N" (rendered before offset)
  | DetailCRC16 CRC16 CRC16     -- "(src CRC16 0xN, tgt CRC16 0xN)"

-- | Byte offset range for a non-empty set of regions.
-- 'rangeStart' is the first modified byte; 'rangeEnd' is one past the last.
data OffsetRange = OffsetRange
  { rangeStart :: !Offset
  , rangeEnd   :: !Offset
  }

-- | Per-payload-type record counts, accumulated across regions.
data PayloadCounts = PayloadCounts
  { writeCount :: !Int
  , fillCount  :: !Int
  , copyCount  :: !Int
  , xorCount   :: !Int
  , metaCount  :: !Int
  }

----------------------------------------------------------------------------
-- Renderer
----------------------------------------------------------------------------

renderExplain :: Maybe ByteString -> ExplainData -> String
renderExplain mSource explainData = unlines $
  [ "format:      " ++ explainFormat explainData ]
  ++ map renderField (explainHeader explainData)
  ++ [""]
  ++ concatMap renderSection (explainSections explainData)
  ++ notesLines
  ++ [renderSummaryLine (explainSummary explainData) | not (isSummaryNone (explainSummary explainData))]
  where
    notesLines = explainNotes explainData

    renderSection (SectionRegions regions) =
      zipWith renderRegion [1..] regions

    renderSection (SectionBlock label regions) =
      label : map renderBlockEntry regions ++ [""]

    renderSection (SectionLabeled label fields) =
      label : map renderLabeledField fields ++ [""]

    renderSection (SectionText text) = [text]

    renderLabeledField (MetaField key value) =
      "  " ++ key ++ ":" ++ replicate (max 1 (18 - length key - 3)) ' ' ++ value

    renderBlockEntry region =
      "    " ++ padHex 8 (unOffset (regionOffset region)) ++ "  " ++ regionLabel region
      ++ padRight 10 (show (unLength (regionSize region)) ++ " B")
      ++ "\n" ++ hexDump (payloadBytes (regionPayload region))

    payloadBytes (PayloadWrite writeData) = writeData
    payloadBytes _ = ByteString.empty

    annotation = renderAnnotation . regionAnnotation

    renderRegion index region = case regionPayload region of
      PayloadWrite writeData ->
        padNum index ++ "  " ++ regionLabel region ++ padRight 10 (show (unLength (regionSize region)) ++ " B")
        ++ annotation region
        ++ "\n" ++ hexDump writeData
      PayloadFill fillByte fillCount ->
        padNum index ++ "  " ++ regionLabel region ++ show (unLength fillCount) ++ " x 0x"
        ++ padHex 2 fillByte
        ++ annotation region
      PayloadCopy _ ->
        padNum index ++ "  " ++ regionLabel region ++ padRight 10 (show (unLength (regionSize region)) ++ " B")
        ++ annotation region
        ++ renderCopySource mSource region
      PayloadXOR (Just deltaBytes) ->
        padNum index ++ "  " ++ regionLabel region ++ padRight 10 (show (unLength (regionSize region)) ++ " B")
        ++ annotation region
        ++ "\n" ++ labeledHexDump "delta" deltaBytes
        ++ renderResolvedXOR mSource (unOffset (regionOffset region)) deltaBytes
      PayloadXOR Nothing ->
        padNum index ++ "  " ++ regionLabel region ++ padRight 10 (show (unLength (regionSize region)) ++ " B")
        ++ annotation region
      PayloadMeta _ ->
        padNum index ++ "  " ++ regionLabel region ++ annotation region

isSummaryNone :: ExplainSummary -> Bool
isSummaryNone SummaryNone = True
isSummaryNone _           = False

renderSummaryLine :: ExplainSummary -> String
renderSummaryLine SummaryNone = ""
renderSummaryLine (Summary info) =
  show (summaryCount info) ++ " " ++ summaryUnitLabel info
  ++ case summaryBytes info of
       Nothing -> ""
       Just byteInfo -> ", " ++ show (summaryByteCount byteInfo) ++ " " ++ renderBytesSuffix (summaryByteSuffix byteInfo)

renderBytesSuffix :: SummaryBytes -> String
renderBytesSuffix BytesTotal       = "bytes total"
renderBytesSuffix BytesTotalOutput = "bytes total output"

renderAnnotation :: Annotation -> String
renderAnnotation AnnotNone = ""
renderAnnotation (AnnotBSDiff addSize copySize seekDelta) =
  "add " ++ padRight 10 (show (unLength addSize) ++ " B")
  ++ "  copy " ++ padRight 10 (show (unLength copySize) ++ " B")
  ++ "  seek " ++ showSigned (unDelta seekDelta)
renderAnnotation (AnnotAt kind offset details) =
  sourcePrefix ++ "  " ++ kindString kind ++ "0x" ++ padHex 6 (unOffset offset)
  ++ concatMap renderDetail remaining
  where
    (sourceIndices, remaining) = partition isSourceIndex details
    isSourceIndex (DetailSourceIndex _) = True
    isSourceIndex _                     = False
    sourcePrefix = case sourceIndices of
      (DetailSourceIndex sourceIndex : _) -> "  from source " ++ show sourceIndex
      _                                   -> ""
    kindString AtOffset = "at "
    kindString AtOutput = "at output "

renderDetail :: AnnotDetail -> String
renderDetail DetailRLE                      = "  (RLE)"
renderDetail DetailUndo                     = "  (undo data)"
renderDetail (DetailDelta delta)            = "  (delta " ++ showSigned (unDelta delta) ++ ")"
renderDetail (DetailSkip skipAmount)        = "  (skip " ++ show (unLength skipAmount) ++ ")"
renderDetail (DetailSource sourceOffset)    = "  (source 0x" ++ padHex 6 (unOffset sourceOffset) ++ ")"
renderDetail (DetailSourceIndex _)          = ""
renderDetail (DetailCRC16 sourceCrc targetCrc) =
  "  (src CRC16 " ++ showCRC16 sourceCrc ++ ", tgt CRC16 " ++ showCRC16 targetCrc ++ ")"

----------------------------------------------------------------------------
-- Source-aware helpers
----------------------------------------------------------------------------

labeledHexDump :: String -> ByteString -> String
labeledHexDump label bytes = "      " ++ label ++ ":\n" ++ hexDump bytes

resolveXOR :: ByteString -> Int -> ByteString -> ByteString
resolveXOR source offset deltaBytes =
  let sourceSlice = ByteString.take (ByteString.length deltaBytes) (ByteString.drop offset source)
      -- zero-pad if source is shorter
      padded = sourceSlice <> ByteString.replicate (ByteString.length deltaBytes - ByteString.length sourceSlice) 0
  in ByteString.pack (ByteString.zipWith xor padded deltaBytes)

findSourceOffset :: Annotation -> Maybe Offset
findSourceOffset (AnnotAt _ _ details) = searchDetails details
  where
    searchDetails []                           = Nothing
    searchDetails (DetailSource sourceOffset:_) = Just sourceOffset
    searchDetails (_:remaining)                = searchDetails remaining
findSourceOffset _ = Nothing

renderResolvedXOR :: Maybe ByteString -> Int -> ByteString -> String
renderResolvedXOR Nothing _ _ = ""
renderResolvedXOR (Just source) offset deltaBytes =
  "\n" ++ labeledHexDump "resolved" (resolveXOR source offset deltaBytes)

renderCopySource :: Maybe ByteString -> ExplainRegion -> String
renderCopySource Nothing _ = ""
renderCopySource (Just source) region =
  case findSourceOffset (regionAnnotation region) of
    Nothing          -> ""
    Just sourceOffset ->
      let slice = ByteString.take (unLength (regionSize region)) (ByteString.drop (unOffset sourceOffset) source)
      in "\n" ++ labeledHexDump "source data" slice

----------------------------------------------------------------------------
-- Summary renderer
----------------------------------------------------------------------------

renderSummary :: Maybe ByteString -> ExplainData -> String
renderSummary mSource explainData = unlines $ filter (not . null) $
  [ "format:      " ++ explainFormat explainData
  , "records:     " ++ commaNum totalRecords
  ]
  ++ modifiedLine
  ++ rangeLine
  ++ sizeChangeLine
  ++ [""]
  ++ regionsBlock
  ++ recordSizeLine
  ++ [""]
  ++ sparkline
  ++ capabilityNotes
  where
    allRegions = concatMap sectionRegions (explainSections explainData)

    totalRecords = length allRegions

    sectionRegions (SectionRegions regions)  = regions
    sectionRegions (SectionBlock _ regions)  = regions
    sectionRegions (SectionLabeled _ _) = []
    sectionRegions (SectionText _)      = []

    -- Modified bytes breakdown
    totalModified = sum (map (unLength . regionSize) allRegions)
    payloadCounts = foldl' countPayload (PayloadCounts 0 0 0 0 0) allRegions
    countPayload counts region = case regionPayload region of
      PayloadWrite _  -> counts { writeCount = writeCount counts + 1 }
      PayloadFill _ _ -> counts { fillCount  = fillCount  counts + 1 }
      PayloadCopy _   -> counts { copyCount  = copyCount  counts + 1 }
      PayloadXOR _    -> counts { xorCount   = xorCount   counts + 1 }
      PayloadMeta _   -> counts { metaCount  = metaCount  counts + 1 }
    breakdownString =
      let parts = filter ((/= 0) . fst)
            [ (writeCount payloadCounts, "writes")
            , (fillCount  payloadCounts, "fills")
            , (copyCount  payloadCounts, "copies")
            , (xorCount   payloadCounts, "XOR")
            , (metaCount  payloadCounts, "structural") ]
      in case parts of
           [] -> ""
           items -> " (" ++ intercalate ", "
                   (map (\(count,label) -> commaNum count ++ " " ++ label) items)
                 ++ ")"
    modifiedLine
      | totalRecords == 0 = []
      | otherwise = ["modified:    " ++ commaNum totalModified
                     ++ " bytes" ++ breakdownString]

    -- Offset range (Nothing for empty patches — no partial minimum/maximum)
    offsetRange :: Maybe OffsetRange
    offsetRange
      | null allRegions = Nothing
      | otherwise = Just OffsetRange
          { rangeStart = minimum (map regionOffset allRegions)
          , rangeEnd   = maximum [ advance (regionOffset region) (regionSize region)
                                 | region <- allRegions ]
          }
    rangeLine = case offsetRange of
      Nothing    -> ["range:       (empty patch)"]
      Just range -> ["range:       0x" ++ padHex 6 (unOffset (rangeStart range))
                     ++ " \8211 0x" ++ padHex 6 (unOffset (rangeEnd range) - 1)]

    -- Size change from header
    sizeChangeLine = case (lookupHeader "source size", lookupHeader "target size",
                           lookupHeader "new size") of
      (Just sourceString, Just targetString, _) -> makeSizeLine sourceString targetString
      (Just sourceString, _, Just targetString) -> makeSizeLine sourceString targetString
      _ -> []

    lookupHeader key = metaFieldValue <$> find (\field -> metaFieldLabel field == key) (explainHeader explainData)

    makeSizeLine sourceString targetString =
      case (parseSize sourceString, parseSize targetString) of
        (Just sourceSize, Just targetSize) ->
          let diff = targetSize - sourceSize
              sign = if diff >= 0 then "+" else ""
              truncNote = case lookupHeader "truncation" of
                Just truncation -> " (truncation at " ++ truncation ++ ")"
                Nothing         -> ""
          in ["size change: " ++ sign ++ commaNum diff
              ++ " bytes" ++ truncNote]
        _ -> []

    parseSize input =
      let digits = filter isDigit (takeWhile (\character -> isDigit character || character == ',') input)
      in case reads digits of
           [(number, "")] -> Just (number :: Int)
           _              -> Nothing

    -- Bucket-based analysis
    bucketCount = 56 :: Int  -- terminal sparkline width

    bucketWidth :: OffsetRange -> Int
    bucketWidth range = max 1 (max 1 (unOffset (rangeEnd range) - unOffset (rangeStart range)) `div` bucketCount)

    toBucket :: OffsetRange -> ExplainRegion -> [(Int, Int)]
    toBucket range region =
      let width = bucketWidth range
          startBucket = (unOffset (regionOffset region) - unOffset (rangeStart range)) `div` width
          endBucket   = (unOffset (advance (regionOffset region) (regionSize region)) - 1 - unOffset (rangeStart range)) `div` width
      in [ (bucket, unLength (regionSize region)) | bucket <- [max 0 startBucket .. min (bucketCount-1) endBucket] ]

    -- Bucket arrays: sums (for sparkline/run detection), counts, bytes.
    -- All three are empty when offsetRange is Nothing; computed together otherwise.
    (bucketSums, bucketCounts, bucketBytes) = case offsetRange of
      Nothing -> ([], [], [])
      Just range ->
        let width = bucketWidth range
            regionBucket region = (unOffset (regionOffset region) - unOffset (rangeStart range)) `div` width
            sums   = elems (accumArray (+) 0 (0, bucketCount - 1) (concatMap (toBucket range) allRegions))
            counts = elems (accumArray (+) 0 (0, bucketCount - 1)
                      [ (bucket, 1 :: Int) | region <- allRegions
                      , let bucket = regionBucket region, bucket >= 0, bucket < bucketCount ])
            bytes  = elems (accumArray (+) 0 (0, bucketCount - 1)
                      [ (bucket, unLength (regionSize region)) | region <- allRegions
                      , let bucket = regionBucket region, bucket >= 0, bucket < bucketCount ])
        in (sums, counts, bytes)

    -- Contiguous runs of non-empty buckets, as (startIdx, endIdx) pairs
    findRuns :: [Int] -> [(Int, Int)]
    findRuns sums = scanRuns 0 Nothing []
      where
        sumsLength = length sums
        scanRuns position (Just runStart) accumulated | position >= sumsLength = reverse ((runStart, position-1) : accumulated)
        scanRuns position Nothing  accumulated | position >= sumsLength = reverse accumulated
        scanRuns position Nothing  accumulated
          | sums !! position > 0 = scanRuns (position+1) (Just position) accumulated
          | otherwise            = scanRuns (position+1) Nothing accumulated
        scanRuns position (Just runStart) accumulated
          | sums !! position > 0 = scanRuns (position+1) (Just runStart) accumulated
          | otherwise            = scanRuns (position+1) Nothing ((runStart, position-1) : accumulated)

    regionsBlock = case offsetRange of
      Nothing -> []
      Just range ->
          let width = bucketWidth range
              runs = findRuns bucketSums
              formatRun (runStart, runEnd) =
                let startOffset = unOffset (rangeStart range) + runStart * width
                    endOffset = unOffset (rangeStart range) + (runEnd + 1) * width - 1
                    recordsInRun = sum (take (runEnd - runStart + 1) (drop runStart bucketCounts))
                    bytesInRun = sum (take (runEnd - runStart + 1) (drop runStart bucketBytes))
                    percentage = if totalModified > 0
                          then 100.0 * fromIntegral bytesInRun / fromIntegral totalModified :: Double
                          else 0
                in "  0x" ++ padHex 6 startOffset ++ " \8211 0x" ++ padHex 6 endOffset
                   ++ "   " ++ padRight 5 (show recordsInRun) ++ " records"
                   ++ "   " ++ padRight 10 (commaNum bytesInRun ++ " B")
                   ++ "   " ++ showPercent percentage
          in case runs of
               [] -> []
               _  -> "regions:" : map formatRun runs

    showPercent :: Double -> String
    showPercent percent =
      let formatted = show (round (percent * 10) :: Int)
          (whole, fractional) = splitAt (length formatted - 1) formatted
          wholeString = if null whole then "0" else whole
      in padRight 6 (wholeString ++ "." ++ fractional ++ "%")

    -- Record size distribution
    sizes = sort (map (unLength . regionSize) allRegions)
    recordSizeLine = case sizes of
      []        -> []
      (uniform:_) | all (== uniform) sizes ->
          ["record sizes: " ++ commaNum uniform ++ " B"]
      (smallest:_) ->
          let largest = last sizes
              medianSize = sizes !! (length sizes `div` 2)
              meanSize   = totalModified `div` totalRecords
          in ["record sizes: " ++ commaNum smallest ++ " \8211 "
              ++ commaNum largest ++ " B"
              ++ " (median " ++ commaNum medianSize
              ++ ", mean " ++ commaNum meanSize ++ ")"]

    -- Sparkline
    sparkline = case offsetRange of
      Nothing -> []
      Just range ->
          let chars = map (\entry -> if entry > 0 then '#' else '.') bucketSums
              leftLabel = "0x" ++ padHex 6 (unOffset (rangeStart range))
              rightLabel = "0x" ++ padHex 6 (unOffset (rangeEnd range) - 1)
              barLine = "[" ++ chars ++ "]"
              -- right-align rightLabel to closing bracket
              gap = max 1 (length barLine - length leftLabel - length rightLabel)
              labelLine = " " ++ leftLabel
                          ++ replicate gap ' ' ++ rightLabel
          in [barLine, labelLine]

    -- Capability notes
    capabilityNotes =
      let hasCopy = any (\region -> case regionPayload region of PayloadCopy _ -> True; _ -> False) allRegions
          hasXOR  = any (\region -> case regionPayload region of PayloadXOR _  -> True; _ -> False) allRegions
          hasMeta = any (\region -> case regionPayload region of PayloadMeta _ -> True; _ -> False) allRegions
          hasDelta = hasCopy || hasXOR || hasMeta
      in case (hasDelta, mSource) of
           (True, Just _)  -> ["", "note: source file provided; use --records to see resolved content"]
           (True, Nothing) -> ["", "note: patch uses delta/reference operations (requires source file)"]
           _               -> []

-- | Format an integer with comma grouping.
commaNum :: Int -> String
commaNum number
  | number < 0     = "-" ++ commaNum (negate number)
  | otherwise = reverse (insertCommas (reverse (show number)))
  where
    insertCommas [] = []
    insertCommas digits = let (group, rest) = splitAt 3 digits
            in group ++ if null rest then "" else "," ++ insertCommas rest


