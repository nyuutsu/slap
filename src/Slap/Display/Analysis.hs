{-# LANGUAGE OverloadedStrings #-}

module Slap.Display.Analysis
  ( PatchAnalysis(..)
  , AnalysisSection(..)
  , AnalysisRegion(..)
  , AnalysisPayload(..)
  , CopySource(..)
  , AnalysisSummary(..)
  , SummaryInfo(..)
  , Annotation(..)
  , OffsetKind(..)
  , AnnotDetail(..)
  , renderAnalysisFull
  , renderAnalysisSummary
  ) where

import Slap.Checksum (CRC16, showCRC16)
import Slap.Display.Common (InfoLine(..), renderInfoLine,
                             Tally(..), CountUnit, ByteCount,
                             renderCountUnit, renderByteCount,
                             renderAsText)
import Slap.Display.Info (PatchInfo(..), renderPatchInfo)
import Slap.Display.Primitives (padHex, padNum, padRight, showSigned, hexDump)
import Slap.Display.Glyph (spacePaddedEnDash)
import Slap.Measure (Offset(..), Length(..), Delta(..), SignedOffset(unSignedOffset),
                     OffsetRange(..), rangeLastByte, advance, distance)
import Slap.Status (CursorKind, renderCursorKind)
import Data.Array (accumArray, elems)
import Data.Bits (xor)
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.Char (isDigit)
import Data.List (find, intercalate, sort, partition)
import Data.Int (Int64)
import Data.Text (Text)
import qualified Data.Text as Text
import Data.Word (Word8)

----------------------------------------------------------------------------
-- Types
----------------------------------------------------------------------------

-- | The analytical-pass result: per-record breakdown and structured summary.
-- Populated by per-format @analyze\<Format\>@ functions (in each format's @Describe@ module).
-- Each walks the record stream and produces 'AnalysisSection' values describing every record's offset, size, label, payload, and annotation.
--
-- Consumed by @slap explain@ (both verbosity modes), never by @slap info@ or @slap apply@ —
-- those read the cheaper 'Slap.Display.Info.PatchInfo' instead.
-- The cost of the analytical walk is deferred by the non-strict 'Slap.SomePatch.patchAnalysis' field;
-- see that field for the force discipline.
data PatchAnalysis = PatchAnalysis
  { analysisSections :: [AnalysisSection]
  , analysisSummary  :: AnalysisSummary
  }

data AnalysisSection
  = SectionRegions [AnalysisRegion]              -- flat numbered list
  | SectionLabeled Text [InfoLine]               -- labeled block + kv pairs (VCDIFF)
  | SectionText Text                             -- free text line

data AnalysisRegion = AnalysisRegion
  { regionOffset     :: Offset             -- primary offset (output or target)
  , regionSize       :: Length             -- bytes affected
  , regionLabel      :: Text               -- operation label with trailing space
  , regionPayload    :: AnalysisPayload
  , regionAnnotation :: Annotation         -- structured trailing metadata
  }

data AnalysisPayload
  = PayloadWrite ByteString            -- literal data (renderer hex dumps)
  | PayloadFill !Word8 !Length         -- fill byte + repeat count
  | PayloadCopy CopySource             -- copy operation
  | PayloadXOR (Maybe ByteString)      -- XOR delta
  | PayloadMeta ![InfoLine]            -- key-value details (BSDiff ctrl)

data CopySource = FromSource | FromTarget | FromPatch
  deriving (Eq, Show)

data AnalysisSummary
  = SummaryNone
  | Summary !SummaryInfo

data SummaryInfo = SummaryInfo
  { summaryTally :: !Tally
  , summaryUnit  :: !CountUnit
  , summaryBytes :: !(Maybe ByteCount)
  }

data Annotation
  = AnnotationAt { annotationOffsetKind :: !OffsetKind
                 , annotationOffset     :: !Offset
                 , annotationDetails    :: ![AnnotDetail]
                 }

data OffsetKind = AtOffset | AtOutput

data AnnotDetail
  = DetailRLE                   -- "(RLE)"
  | DetailUndo                  -- "(undo data)"
  | DetailDelta Delta           -- "(delta +N)"
  | DetailSkip Length           -- "(skip N)"
  | DetailAdd Length            -- "(add N)"   bsdiff: bytes summed with the source run
  | DetailCopy Length           -- "(copy N)"  bsdiff: literal bytes from the extra block
  | DetailSeek Delta            -- "(seek +N)" bsdiff: signed move of the source cursor
  | DetailSource Offset         -- "(source 0xN)"
  | DetailSourceIndex Int64     -- "from source N" (rendered before offset)
  | DetailCRC16 CRC16 CRC16     -- "(src CRC16 0xN, tgt CRC16 0xN)"
  | DetailCursorUnderflow CursorKind SignedOffset
                                -- "*** <kind> cursor underflow: -N (patch invalid here) ***"

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

renderAnalysisFull :: PatchInfo -> PatchAnalysis -> Maybe ByteString -> Text
renderAnalysisFull info analysis mSource = Text.unlines $ joinSections
  [ map renderInfoLine (renderPatchInfo info)
  , concatMap renderSection (analysisSections analysis)
  , summaryLines (analysisSummary analysis)
  ]
  where
    summaryLines SummaryNone     = []
    summaryLines (Summary summary)  = [renderSummaryLine summary]

    renderSection (SectionRegions regions) =
      zipWith renderRegion [1..] regions

    renderSection (SectionLabeled label fields) =
      label : map renderLabeledField fields

    renderSection (SectionText text) = [text]

    renderLabeledField (InfoLine key value) =
      "  " <> key <> ":" <> Text.replicate (max 1 (18 - Text.length key - 3)) " " <> value

    annotation = renderAnnotation . regionAnnotation

    renderRegion index region = case regionPayload region of
      PayloadWrite writeData ->
        padNum index <> "  " <> regionLabel region <> padRight 10 (renderAsText (unLength (regionSize region)) <> " B")
        <> annotation region
        <> "\n" <> hexDump writeData
      PayloadFill fillByte fillCount ->
        padNum index <> "  " <> regionLabel region <> renderAsText (unLength fillCount) <> " x 0x"
        <> padHex 2 fillByte
        <> annotation region
      PayloadCopy _ ->
        padNum index <> "  " <> regionLabel region <> padRight 10 (renderAsText (unLength (regionSize region)) <> " B")
        <> annotation region
        <> renderCopySource mSource region
      PayloadXOR (Just deltaBytes) ->
        padNum index <> "  " <> regionLabel region <> padRight 10 (renderAsText (unLength (regionSize region)) <> " B")
        <> annotation region
        <> "\n" <> labeledHexDump "delta" deltaBytes
        <> renderResolvedXOR mSource (unOffset (regionOffset region)) deltaBytes
      PayloadXOR Nothing ->
        padNum index <> "  " <> regionLabel region <> padRight 10 (renderAsText (unLength (regionSize region)) <> " B")
        <> annotation region
      PayloadMeta _ ->
        padNum index <> "  " <> regionLabel region <> annotation region

-- | Stitch a list of section blocks into a single line stream with a
-- blank line separating each non-empty block. Empty blocks are dropped
-- so the output never carries adjacent blanks. Defined once here and
-- shared by 'renderAnalysisFull' and 'renderAnalysisSummary' so
-- blank-line semantics live in one named place.
joinSections :: [[Text]] -> [Text]
joinSections = intercalate [""] . filter (not . null)

renderSummaryLine :: SummaryInfo -> Text
renderSummaryLine summary =
  renderAsText (unTally (summaryTally summary)) <> " " <> renderCountUnit (summaryTally summary) (summaryUnit summary)
  <> case summaryBytes summary of
       Nothing        -> ""
       Just byteCount -> ", " <> renderByteCount byteCount

renderAnnotation :: Annotation -> Text
renderAnnotation (AnnotationAt kind offset details) =
  sourcePrefix <> "  " <> kindString kind <> "0x" <> padHex 6 (unOffset offset)
  <> Text.concat (map renderDetail remaining)
  where
    (sourceIndices, remaining) = partition isSourceIndex details
    isSourceIndex (DetailSourceIndex _) = True
    isSourceIndex _                     = False
    sourcePrefix = case sourceIndices of
      (DetailSourceIndex sourceIndex : _) -> "  from source " <> renderAsText sourceIndex
      _                                   -> ""
    kindString AtOffset = "at "
    kindString AtOutput = "at output "

renderDetail :: AnnotDetail -> Text
renderDetail DetailRLE                      = "  (RLE)"
renderDetail DetailUndo                     = "  (undo data)"
renderDetail (DetailDelta delta)            = "  (delta " <> showSigned (unDelta delta) <> ")"
renderDetail (DetailSkip skipAmount)        = "  (skip " <> renderAsText (unLength skipAmount) <> ")"
renderDetail (DetailAdd addLength)          = "  (add " <> renderAsText (unLength addLength) <> ")"
renderDetail (DetailCopy copyLength)        = "  (copy " <> renderAsText (unLength copyLength) <> ")"
renderDetail (DetailSeek seekDelta)         = "  (seek " <> showSigned (unDelta seekDelta) <> ")"
renderDetail (DetailSource sourceOffset)    = "  (source 0x" <> padHex 6 (unOffset sourceOffset) <> ")"
renderDetail (DetailSourceIndex _)          = ""
renderDetail (DetailCRC16 sourceCrc targetCrc) =
  "  (src CRC16 " <> showCRC16 sourceCrc <> ", tgt CRC16 " <> showCRC16 targetCrc <> ")"
renderDetail (DetailCursorUnderflow cursorKind underflowedCursor) =
  "  *** " <> renderCursorKind cursorKind <> " cursor underflow: "
  <> renderAsText (unSignedOffset underflowedCursor) <> " (patch invalid here) ***"

----------------------------------------------------------------------------
-- Source-aware helpers
----------------------------------------------------------------------------

labeledHexDump :: Text -> ByteString -> Text
labeledHexDump label bytes = "      " <> label <> ":\n" <> hexDump bytes

resolveXOR :: ByteString -> Int -> ByteString -> ByteString
resolveXOR source offset deltaBytes =
  let sourceSlice = ByteString.take (ByteString.length deltaBytes) (ByteString.drop offset source)
      padded = sourceSlice <> ByteString.replicate (ByteString.length deltaBytes - ByteString.length sourceSlice) 0
  in ByteString.pack (ByteString.zipWith xor padded deltaBytes)

findSourceOffset :: Annotation -> Maybe Offset
findSourceOffset (AnnotationAt _ _ details) = searchDetails details
  where
    searchDetails []                           = Nothing
    searchDetails (DetailSource sourceOffset:_) = Just sourceOffset
    searchDetails (_:remaining)                = searchDetails remaining

renderResolvedXOR :: Maybe ByteString -> Int -> ByteString -> Text
renderResolvedXOR Nothing _ _ = ""
renderResolvedXOR (Just source) offset deltaBytes =
  "\n" <> labeledHexDump "resolved" (resolveXOR source offset deltaBytes)

renderCopySource :: Maybe ByteString -> AnalysisRegion -> Text
renderCopySource Nothing _ = ""
renderCopySource (Just source) region =
  case findSourceOffset (regionAnnotation region) of
    Nothing          -> ""
    Just sourceOffset ->
      let slice = ByteString.take (unLength (regionSize region)) (ByteString.drop (unOffset sourceOffset) source)
      in "\n" <> labeledHexDump "source data" slice

----------------------------------------------------------------------------
-- Summary renderer
----------------------------------------------------------------------------

renderAnalysisSummary :: PatchInfo -> PatchAnalysis -> Maybe ByteString -> Text
renderAnalysisSummary info analysis mSource = Text.unlines $ joinSections
  [ map renderInfoLine (renderPatchInfo info)
  , modifiedLine ++ rangeLine ++ sizeChangeLine
  , regionsBlock ++ recordSizeLine
  , sparkline
  , capabilityNotes
  ]
  where
    allRegions = concatMap sectionRegions (analysisSections analysis)

    totalRecords = length allRegions

    sectionRegions (SectionRegions regions)  = regions
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
            [ (writeCount payloadCounts, "writes" :: Text)
            , (fillCount  payloadCounts, "fills")
            , (copyCount  payloadCounts, "copies")
            , (xorCount   payloadCounts, "XOR")
            , (metaCount  payloadCounts, "structural") ]
      in case parts of
           [] -> ""
           items -> " (" <> Text.intercalate ", "
                   (map (\(count,label) -> commaNum count <> " " <> label) items)
                 <> ")"
    modifiedLine
      | totalRecords == 0 = []
      | otherwise = ["modified:    " <> commaNum totalModified
                     <> " bytes" <> breakdownString]

    -- Offset range (Nothing for empty patches — no partial minimum/maximum)
    offsetRange :: Maybe OffsetRange
    offsetRange
      | null allRegions = Nothing
      | otherwise =
          let firstAffectedOffset = minimum (map regionOffset allRegions)
              endOfLastRecord     = maximum [ advance (regionOffset region) (regionSize region)
                                            | region <- allRegions ]
          in Just OffsetRange
              { rangeStart  = firstAffectedOffset
              , rangeLength = distance firstAffectedOffset endOfLastRecord
              }
    rangeLine = case offsetRange of
      Nothing    -> ["range:       (empty patch)"]
      Just range -> ["range:       0x" <> padHex 6 (unOffset (rangeStart range))
                     <> spacePaddedEnDash <> "0x" <> padHex 6 (unOffset (rangeLastByte range))]

    -- Size change from header
    sizeChangeLine = case (lookupHeader "source size", lookupHeader "target size",
                           lookupHeader "new size") of
      (Just sourceString, Just targetString, _) -> makeSizeLine sourceString targetString
      (Just sourceString, _, Just targetString) -> makeSizeLine sourceString targetString
      _ -> []

    lookupHeader key = infoLineValue <$> find (\line -> infoLineLabel line == key) (infoLines info)

    makeSizeLine sourceString targetString =
      case (parseSize sourceString, parseSize targetString) of
        (Just sourceSize, Just targetSize) ->
          let diff = targetSize - sourceSize
              sign = if diff >= 0 then "+" else ""
              truncNote = case lookupHeader "truncation" of
                Just truncation -> " (truncation at " <> truncation <> ")"
                Nothing         -> ""
          in ["size change: " <> sign <> commaNum diff
              <> " bytes" <> truncNote]
        _ -> []

    parseSize input =
      let digits = filter isDigit (Text.unpack (Text.takeWhile (\character -> isDigit character || character == ',') input))
      in case reads digits of
           [(number, "")] -> Just (number :: Int)
           _              -> Nothing

    -- Bucket-based analysis
    bucketCount = 56 :: Int  -- terminal sparkline width

    bucketWidth :: OffsetRange -> Int
    bucketWidth range = max 1 (max 1 (unLength (rangeLength range)) `div` bucketCount)

    toBucket :: OffsetRange -> AnalysisRegion -> [(Int, Int)]
    toBucket range region =
      let width = bucketWidth range
          startBucket = unLength (distance (rangeStart range) (regionOffset region)) `div` width
          endBucket   = (unOffset (advance (regionOffset region) (regionSize region)) - 1 - unOffset (rangeStart range)) `div` width
      in [ (bucket, unLength (regionSize region)) | bucket <- [max 0 startBucket .. min (bucketCount-1) endBucket] ]

    -- Bucket arrays: sums (for sparkline/run detection), counts, bytes.
    -- All three are empty when offsetRange is Nothing; computed together otherwise.
    (bucketSums, bucketCounts, bucketBytes) = case offsetRange of
      Nothing -> ([], [], [])
      Just range ->
        let width = bucketWidth range
            regionBucket region = unLength (distance (rangeStart range) (regionOffset region)) `div` width
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
                in "  0x" <> padHex 6 startOffset <> spacePaddedEnDash <> "0x" <> padHex 6 endOffset
                   <> "   " <> padRight 5 (renderAsText recordsInRun) <> " records"
                   <> "   " <> padRight 10 (commaNum bytesInRun <> " B")
                   <> "   " <> showPercent percentage
          in case runs of
               [] -> []
               _  -> "regions:" : map formatRun runs

    showPercent :: Double -> Text
    showPercent percent =
      let formatted = show (round (percent * 10) :: Int)
          (whole, fractional) = splitAt (length formatted - 1) formatted
          wholeString = if null whole then "0" else whole
      in padRight 6 (Text.pack (wholeString ++ "." ++ fractional ++ "%"))

    -- Record size distribution
    sizes = sort (map (unLength . regionSize) allRegions)
    recordSizeLine = case sizes of
      []        -> []
      (uniform:_) | all (== uniform) sizes ->
          ["record sizes: " <> commaNum uniform <> " B"]
      (smallest:_) ->
          let largest = last sizes
              medianSize = sizes !! (length sizes `div` 2)
              meanSize   = totalModified `div` totalRecords
          in ["record sizes: " <> commaNum smallest <> spacePaddedEnDash
              <> commaNum largest <> " B"
              <> " (median " <> commaNum medianSize
              <> ", mean " <> commaNum meanSize <> ")"]

    -- Sparkline
    sparkline = case offsetRange of
      Nothing -> []
      Just range ->
          let chars = map (\entry -> if entry > 0 then '#' else '.') bucketSums
              leftLabel = "0x" <> padHex 6 (unOffset (rangeStart range))
              rightLabel = "0x" <> padHex 6 (unOffset (rangeLastByte range))
              barLine = "[" <> Text.pack chars <> "]"
              -- right-align rightLabel to closing bracket
              gap = max 1 (Text.length barLine - Text.length leftLabel - Text.length rightLabel)
              labelLine = " " <> leftLabel
                          <> Text.replicate gap " " <> rightLabel
          in [barLine, labelLine]

    -- Capability notes
    capabilityNotes =
      let hasCopy = any (\region -> case regionPayload region of PayloadCopy _ -> True; _ -> False) allRegions
          hasXOR  = any (\region -> case regionPayload region of PayloadXOR _  -> True; _ -> False) allRegions
          hasMeta = any (\region -> case regionPayload region of PayloadMeta _ -> True; _ -> False) allRegions
          hasDelta = hasCopy || hasXOR || hasMeta
      in case (hasDelta, mSource) of
           (True, Just _)  -> ["note: source file provided; use --records to see resolved content"]
           (True, Nothing) -> ["note: patch uses delta/reference operations (requires source file)"]
           _               -> []

-- | Format an integer with comma grouping.
commaNum :: Int -> Text
commaNum number
  | number < 0     = "-" <> commaNum (negate number)
  | otherwise = Text.reverse (insertCommas (Text.reverse (renderAsText number)))
  where
    insertCommas digits
      | Text.null digits = ""
      | otherwise =
          let (group, rest) = Text.splitAt 3 digits
          in group <> if Text.null rest then "" else "," <> insertCommas rest
