module Slap.Explain
  ( ExplainData(..)
  , ExplainSection(..)
  , ExplainRegion(..)
  , ExplainPayload(..)
  , CopySource(..)
  , ExplainSummary(..)
  , SummaryBytes(..)
  , Annotation(..)
  , OffsetKind(..)
  , AnnotDetail(..)
  , renderExplain
  , renderSummary
  ) where

import Slap.Format (padHex, padNum, padRight, showSigned, hexDump, renderField)
import Slap.Measure (Offset(..), Length(..), FileSize(..), Delta(..))
import Data.Array (accumArray, elems)
import Data.Bits (xor)
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.Char (isDigit)
import Data.List (sort, intercalate, partition)
import Data.Int (Int64)
import Data.Word (Word8)

----------------------------------------------------------------------------
-- Types
----------------------------------------------------------------------------

data ExplainData = ExplainData
  { explainFormat   :: String              -- "PPF3", "IPS (EBP)", "BPS", etc.
  , explainHeader   :: [(String, String)]  -- key-value metadata (key without colon)
  , explainSections :: [ExplainSection]    -- grouped content
  , explainSummary  :: ExplainSummary      -- structured summary
  , explainNotes    :: [String]            -- trailing messages
  }

data ExplainSection
  = SectionRegions [ExplainRegion]              -- flat numbered list
  | SectionBlock String [ExplainRegion]         -- labeled block + entries (PCHTXT)
  | SectionLabeled String [(String, String)]    -- labeled block + kv pairs (VCDIFF)
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
  | PayloadFill Word8 Int              -- fill byte + repeat count
  | PayloadCopy CopySource             -- copy operation
  | PayloadXOR (Maybe ByteString)      -- XOR delta
  | PayloadMeta [(String, String)]     -- key-value details (BSDiff ctrl)

data CopySource = FromSource | FromTarget | FromPatch
  deriving (Eq, Show)

data ExplainSummary
  = SummaryNone
  | Summary Int String (Maybe (Int, SummaryBytes))
    -- ^ count, unit label, optional (byteCount, bytesSuffix)

data SummaryBytes = BytesTotal | BytesTotalOutput

data Annotation
  = AnnotNone                                    -- no annotation (PCHTXT)
  | AnnotAt OffsetKind Offset [AnnotDetail]      -- offset display + details
  | AnnotBSDiff FileSize FileSize Delta          -- add, copy, seek

data OffsetKind = AtOffset | AtOutput

data AnnotDetail
  = DetailRLE                   -- "(RLE)"
  | DetailUndo                  -- "(undo data)"
  | DetailDelta Delta           -- "(delta +N)"
  | DetailSkip Delta            -- "(skip N)"
  | DetailSource Offset         -- "(source 0xN)"
  | DetailSourceIndex Int64     -- "from source N" (rendered before offset)
  | DetailCRC16 Int64 Int64     -- "(src CRC16 0xN, tgt CRC16 0xN)"

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

    renderSection (SectionLabeled label keyValues) =
      label : map renderLabeledPair keyValues ++ [""]

    renderSection (SectionText text) = [text]

    renderLabeledPair (key, value) =
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
      PayloadFill fillByte count ->
        padNum index ++ "  " ++ regionLabel region ++ show count ++ " x 0x"
        ++ padHex 2 (fromIntegral fillByte :: Int64)
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
renderSummaryLine (Summary count unit Nothing) =
  show count ++ " " ++ unit
renderSummaryLine (Summary count unit (Just (bytes, suffix))) =
  show count ++ " " ++ unit ++ ", " ++ show bytes ++ " " ++ renderBytesSuffix suffix

renderBytesSuffix :: SummaryBytes -> String
renderBytesSuffix BytesTotal       = "bytes total"
renderBytesSuffix BytesTotalOutput = "bytes total output"

renderAnnotation :: Annotation -> String
renderAnnotation AnnotNone = ""
renderAnnotation (AnnotBSDiff addSize copySize seekDelta) =
  "add " ++ padRight 10 (show (unFileSize addSize) ++ " B")
  ++ "  copy " ++ padRight 10 (show (unFileSize copySize) ++ " B")
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
renderDetail (DetailSkip skipAmount)        = "  (skip " ++ show (unDelta skipAmount) ++ ")"
renderDetail (DetailSource sourceOffset)    = "  (source 0x" ++ padHex 6 (unOffset sourceOffset) ++ ")"
renderDetail (DetailSourceIndex _)          = ""
renderDetail (DetailCRC16 sourceCrc targetCrc) =
  "  (src CRC16 " ++ padHex 4 sourceCrc ++ ", tgt CRC16 " ++ padHex 4 targetCrc ++ ")"

----------------------------------------------------------------------------
-- Source-aware helpers
----------------------------------------------------------------------------

labeledHexDump :: String -> ByteString -> String
labeledHexDump label bytes = "      " ++ label ++ ":\n" ++ hexDump bytes

resolveXOR :: ByteString -> Int64 -> ByteString -> ByteString
resolveXOR source offset deltaBytes =
  let sourceSlice = ByteString.take (ByteString.length deltaBytes) (ByteString.drop (fromIntegral offset) source)
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

renderResolvedXOR :: Maybe ByteString -> Int64 -> ByteString -> String
renderResolvedXOR Nothing _ _ = ""
renderResolvedXOR (Just source) offset deltaBytes =
  "\n" ++ labeledHexDump "resolved" (resolveXOR source offset deltaBytes)

renderCopySource :: Maybe ByteString -> ExplainRegion -> String
renderCopySource Nothing _ = ""
renderCopySource (Just source) region =
  case findSourceOffset (regionAnnotation region) of
    Nothing          -> ""
    Just sourceOffset ->
      let slice = ByteString.take (unLength (regionSize region)) (ByteString.drop (fromIntegral (unOffset sourceOffset)) source)
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
    payloadCounts = foldl' countPayload (0,0,0,0,0) allRegions
    countPayload (!writes,!fills,!copies,!xors,!metas) region = case regionPayload region of
      PayloadWrite _  -> (writes+1,fills,copies,xors,metas)
      PayloadFill _ _ -> (writes,fills+1,copies,xors,metas)
      PayloadCopy _   -> (writes,fills,copies+1,xors,metas)
      PayloadXOR _    -> (writes,fills,copies,xors+1,metas)
      PayloadMeta _   -> (writes,fills,copies,xors,metas+1)
    breakdownString =
      let (writes,fills,copies,xors,metas) = payloadCounts
          parts = filter ((/= 0) . fst)
            [ (writes, "writes"), (fills, "fills"), (copies, "copies")
            , (xors, "XOR"), (metas, "structural") ]
      in case parts of
           [] -> ""
           items -> " (" ++ intercalate ", "
                   (map (\(count,label) -> commaNum count ++ " " ++ label) items)
                 ++ ")"
    modifiedLine
      | totalRecords == 0 = []
      | otherwise = ["modified:    " ++ commaNum totalModified
                     ++ " bytes" ++ breakdownString]

    -- Offset range
    offsets = map (unOffset . regionOffset) allRegions
    lowestOffset = minimum offsets
    highestEnd = maximum [ unOffset (regionOffset region) + fromIntegral (unLength (regionSize region))
                     | region <- allRegions ]
    rangeLine
      | totalRecords == 0 = ["range:       (empty patch)"]
      | otherwise = ["range:       0x" ++ padHex 6 lowestOffset
                     ++ " \8211 0x" ++ padHex 6 (highestEnd - 1)]

    -- Size change from header
    sizeChangeLine = case (lookupHeader "source size", lookupHeader "target size",
                           lookupHeader "new size") of
      (Just sourceString, Just targetString, _) -> makeSizeLine sourceString targetString
      (Just sourceString, _, Just targetString) -> makeSizeLine sourceString targetString
      _ -> []

    lookupHeader key = lookup key (explainHeader explainData)

    makeSizeLine sourceString targetString =
      case (parseSize sourceString, parseSize targetString) of
        (Just sourceSize, Just targetSize) ->
          let diff = targetSize - sourceSize
              sign = if diff >= 0 then "+" else ""
              truncNote = case lookupHeader "truncation" of
                Just truncation -> " (truncation at " ++ truncation ++ ")"
                Nothing         -> ""
          in ["size change: " ++ sign ++ commaNum (fromIntegral diff)
              ++ " bytes" ++ truncNote]
        _ -> []

    parseSize input =
      let digits = filter isDigit (takeWhile (\character -> isDigit character || character == ',') input)
      in case reads digits of
           [(number, "")] -> Just (number :: Int64)
           _              -> Nothing

    -- Bucket-based analysis
    bucketCount = 56 :: Int  -- terminal sparkline width

    rangeSize = max 1 (highestEnd - lowestOffset)
    bucketSize = max 1 (rangeSize `div` fromIntegral bucketCount)

    toBucket region =
      let startBucket = fromIntegral ((unOffset (regionOffset region) - lowestOffset) `div` bucketSize)
          endBucket   = fromIntegral (((unOffset (regionOffset region) + fromIntegral (unLength (regionSize region)) - 1) - lowestOffset) `div` bucketSize)
      in [ (bucket, unLength (regionSize region)) | bucket <- [max 0 startBucket .. min (bucketCount-1) endBucket] ]

    bucketSums :: [Int]
    bucketSums
      | totalRecords == 0 = []
      | otherwise = elems (accumArray (+) 0 (0, bucketCount - 1)
                             (concatMap toBucket allRegions))

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

    -- Per-bucket record counts and byte sums, computed in one pass each
    bucketCounts :: [Int]
    bucketCounts
      | totalRecords == 0 = []
      | otherwise = elems (accumArray (+) 0 (0, bucketCount - 1)
                     [ (bucket, 1 :: Int) | region <- allRegions
                     , let bucket = fromIntegral ((unOffset (regionOffset region) - lowestOffset) `div` bucketSize)
                     , bucket >= 0, bucket < bucketCount ])
    bucketBytes :: [Int]
    bucketBytes
      | totalRecords == 0 = []
      | otherwise = elems (accumArray (+) 0 (0, bucketCount - 1)
                     [ (bucket, unLength (regionSize region)) | region <- allRegions
                     , let bucket = fromIntegral ((unOffset (regionOffset region) - lowestOffset) `div` bucketSize)
                     , bucket >= 0, bucket < bucketCount ])

    regionsBlock
      | totalRecords == 0 = []
      | otherwise =
          let runs = findRuns bucketSums
              formatRun (runStart, runEnd) =
                let startOffset = lowestOffset + fromIntegral runStart * bucketSize
                    endOffset = lowestOffset + fromIntegral (runEnd + 1) * bucketSize - 1
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
    sparkline
      | totalRecords == 0 = []
      | otherwise =
          let chars = map (\entry -> if entry > 0 then '#' else '.') bucketSums
              leftLabel = "0x" ++ padHex 6 lowestOffset
              rightLabel = "0x" ++ padHex 6 (highestEnd - 1)
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


