{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE DerivingVia #-}

module Slap.Display.Analysis
  ( PatchAnalysis(..)
  , AnalysisSection(..)
  , AnalysisRegion(..)
  , AnalysisPayload(..)
  , LiteralWriteBytes(..)
  , XORDeltaBytes(..)
  , CopySource(..)
  , AnalysisSummary(..)
  , SummaryInfo(..)
  , Annotation(..)
  , OffsetKind(..)
  , AnnotDetail(..)
  , renderAnalysisFull
  , renderAnalysisSummary
  ) where

import Slap.Binary (viewBytesInRange, zeroExtendedBlock)
import Slap.Checksum (CRC16, showCRC16)
import Slap.JSON.Bytes (BytesAsBase64(..))
import Slap.Display.Common (InfoLine(..),
                             Tally(..), CountUnit, ByteCount,
                             renderCountUnit, renderByteCount,
                             renderAsText)
import Slap.Display.Info (PatchInfo(..), renderPatchInfo)
import Slap.Display.EmbeddedContent (EmbeddedDepth(..))
import Slap.Display.Primitives (padHex, padNum, padRight, showSigned, hexDump)
import Slap.Display.Glyph (spacePaddedEnDash)
import Slap.Measure (Offset(..), Length(..), Delta(..), SignedOffset(unSignedOffset),
                     byteLength,
                     OffsetRange(..), rangeLastByte, advance, distance, writtenOffsetRange)
import Slap.Status (CursorKind, renderCursorKind)
import Slap.Status.Vocabulary (slapAddressableCeiling)
import Data.Aeson (ToJSON)
import Data.Array (Array, Ix, accumArray, assocs, elems)
import Data.Bits (xor)
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.Char (isDigit)
import Data.Function (on)
import Data.List (find, intercalate, sort, partition)
import Data.List.NonEmpty (NonEmpty(..))
import qualified Data.List.NonEmpty as NonEmpty
import Data.Int (Int64)
import Data.Text (Text)
import qualified Data.Text as Text
import Data.Word (Word8)
import GHC.Generics (Generic, Generically(..))

----------------------------------------------------------------------------
-- Types
----------------------------------------------------------------------------

-- | The analytical pass: what @explain@ shows beyond the cheaper 'Slap.Display.Info.PatchInfo'.
-- Built by each format's @analyze\<Format\>@ in its @Describe@ module;
-- the walk's cost is deferred by the non-strict 'Slap.SomePatch.patchAnalysis' field, which owns the force discipline.
data PatchAnalysis = PatchAnalysis
  { analysisSections :: [AnalysisSection]
  , analysisSummary  :: AnalysisSummary
  }
  deriving (Generic)
  deriving (ToJSON) via Generically PatchAnalysis

data AnalysisSection
  = SectionRegions [AnalysisRegion]
  | SectionLabeled Text [InfoLine]
  | SectionText Text
  deriving (Generic)
  deriving (ToJSON) via Generically AnalysisSection

data AnalysisRegion = AnalysisRegion
  { regionOffset     :: Offset             -- in output or target coordinates, the format's walk decides which
  , regionSize       :: Length
  , regionLabel      :: Text               -- carries its own trailing space
  , regionPayload    :: AnalysisPayload
  , regionAnnotation :: Annotation
  }
  deriving (Generic)
  deriving (ToJSON) via Generically AnalysisRegion

data AnalysisPayload
  = PayloadWrite LiteralWriteBytes
  | PayloadFill !Word8 !Length         -- fill byte + repeat count
  | PayloadCopy CopySource
  | PayloadXOR XORDeltaBytes
  | PayloadMeta
  deriving (Generic)
  deriving (ToJSON) via Generically AnalysisPayload

newtype LiteralWriteBytes = LiteralWriteBytes { unLiteralWriteBytes :: ByteString }
  deriving (ToJSON) via BytesAsBase64

newtype XORDeltaBytes = XORDeltaBytes { unXORDeltaBytes :: ByteString }
  deriving (ToJSON) via BytesAsBase64

data CopySource = FromSource | FromTarget | FromPatch
  deriving (Eq, Show, Generic)
  deriving (ToJSON) via Generically CopySource

data AnalysisSummary
  = SummaryNone
  | Summary !SummaryInfo
  deriving (Generic)
  deriving (ToJSON) via Generically AnalysisSummary

data SummaryInfo = SummaryInfo
  { summaryTally :: !Tally
  , summaryUnit  :: !CountUnit
  , summaryBytes :: !(Maybe ByteCount)
  }
  deriving (Generic)
  deriving (ToJSON) via Generically SummaryInfo

data Annotation
  = AnnotationAt { annotationOffsetKind :: !OffsetKind
                 , annotationOffset     :: !Offset
                 , annotationDetails    :: ![AnnotDetail]
                 }
  deriving (Generic)
  deriving (ToJSON) via Generically Annotation

data OffsetKind = AtOffset | AtOutput
  deriving (Generic)
  deriving (ToJSON) via Generically OffsetKind

data AnnotDetail
  = DetailRLE
  | DetailUndo
  | DetailDelta Delta
  | DetailSkip Length
  | DetailAdd Length            -- bsdiff: bytes summed with the source run
  | DetailCopy Length           -- bsdiff: literal bytes from the extra block
  | DetailSeek Delta            -- bsdiff: signed move of the source cursor
  | DetailSource Offset
  | DetailSourceIndex Int64
  | DetailCRC16 CRC16 CRC16     -- source's, then target's
  | DetailCursorUnderflow CursorKind SignedOffset
  deriving (Generic)
  deriving (ToJSON) via Generically AnnotDetail

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
  [ renderPatchInfo WithPayload info
  , concatMap renderSection (analysisSections analysis)
  , summaryLines (analysisSummary analysis)
  ]
  where
    summaryLines SummaryNone     = []
    summaryLines (Summary summary)  = [renderSummaryLine summary]

    renderSection (SectionRegions regions) =
      zipWith renderRegion [0..] regions

    renderSection (SectionLabeled label fields) =
      label : map renderLabeledField fields

    renderSection (SectionText text) = [text]

    renderLabeledField (InfoLine key value) =
      "  " <> key <> ":" <> Text.replicate (max 1 (18 - Text.length key - 3)) " " <> value

    annotation = renderAnnotation . regionAnnotation

    renderRegion index region = case regionPayload region of
      PayloadWrite (LiteralWriteBytes writeData) ->
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
      PayloadXOR (XORDeltaBytes deltaBytes) ->
        padNum index <> "  " <> regionLabel region <> padRight 10 (renderAsText (unLength (regionSize region)) <> " B")
        <> annotation region
        <> "\n" <> labeledHexDump "delta" deltaBytes
        <> renderResolvedXOR mSource (regionOffset region) deltaBytes
      PayloadMeta ->
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

resolveXOR :: ByteString -> Offset -> ByteString -> ByteString
resolveXOR source deltaOffset deltaBytes =
  ByteString.pack (ByteString.zipWith xor (zeroExtendedBlock deltaOffset (byteLength deltaBytes) source) deltaBytes)

findSourceOffset :: Annotation -> Maybe Offset
findSourceOffset (AnnotationAt _ _ details) = searchDetails details
  where
    searchDetails []                           = Nothing
    searchDetails (DetailSource sourceOffset:_) = Just sourceOffset
    searchDetails (_:remaining)                = searchDetails remaining

renderResolvedXOR :: Maybe ByteString -> Offset -> ByteString -> Text
renderResolvedXOR Nothing _ _ = ""
renderResolvedXOR (Just source) deltaOffset deltaBytes =
  "\n" <> labeledHexDump "resolved" (resolveXOR source deltaOffset deltaBytes)

renderCopySource :: Maybe ByteString -> AnalysisRegion -> Text
renderCopySource Nothing _ = ""
renderCopySource (Just source) region =
  case findSourceOffset (regionAnnotation region) of
    Nothing          -> ""
    Just sourceOffset ->
      "\n" <> labeledHexDump "source data" (viewBytesInRange sourceOffset (regionSize region) source)

----------------------------------------------------------------------------
-- Summary renderer
----------------------------------------------------------------------------

-- | A sparkline column: the summary divides the patched offset range into bucketCount equal columns, and a BucketIndex names one of them.
newtype BucketIndex = BucketIndex { unBucketIndex :: Int }
  deriving stock (Eq, Ord, Show)
  deriving newtype (Ix, Enum)

data ColumnOccupancy = ColumnOccupied | ColumnVacant
  deriving stock (Eq)

instance Semigroup ColumnOccupancy where
  ColumnOccupied <> _              = ColumnOccupied
  ColumnVacant   <> rightOccupancy = rightOccupancy

instance Monoid ColumnOccupancy where
  mempty = ColumnVacant

occupancyGlyph :: ColumnOccupancy -> Char
occupancyGlyph ColumnOccupied = '#'
occupancyGlyph ColumnVacant   = '.'

-- | One sparkline column's contribution: whether any region touches it (this drives the bar and the run detection),
-- plus the records and bytes attributed to it.
data BucketTally = BucketTally
  { tallyOccupancy :: ColumnOccupancy
  , tallyRecords   :: Int
  , tallyBytes     :: Length
  }

instance Semigroup BucketTally where
  BucketTally leftOccupancy leftRecords leftBytes <> BucketTally rightOccupancy rightRecords rightBytes =
    BucketTally (leftOccupancy <> rightOccupancy) (leftRecords + rightRecords) (leftBytes <> rightBytes)

instance Monoid BucketTally where
  mempty = BucketTally mempty 0 mempty

-- | An inclusive run of occupied sparkline columns, carrying the columns it spans.
newtype BucketRun = BucketRun (NonEmpty (BucketIndex, BucketTally))

runFirstBucket, runLastBucket :: BucketRun -> BucketIndex
runFirstBucket (BucketRun columns) = fst (NonEmpty.head columns)
runLastBucket  (BucketRun columns) = fst (NonEmpty.last columns)

runRecords :: BucketRun -> Int
runRecords (BucketRun columns) = sum (fmap (tallyRecords . snd) columns)

runBytes :: BucketRun -> Length
runBytes (BucketRun columns) = foldMap (tallyBytes . snd) columns

-- Returns the upper of the two middles when the length is even.
middleElement :: NonEmpty a -> a
middleElement (firstValue :| laterValues) = seekMiddle firstValue laterValues (firstValue : laterValues)
  where
    seekMiddle _       (nextValue : slower) (_ : _ : faster) = seekMiddle nextValue slower faster
    seekMiddle current _                    _                = current

renderAnalysisSummary :: PatchInfo -> PatchAnalysis -> Maybe ByteString -> Text
renderAnalysisSummary info analysis mSource = Text.unlines $ joinSections
  [ renderPatchInfo WithPayload info
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
    -- Summed at 'Integer': a hand-built patch can carry region sizes that overflow 'Int64' in aggregate,
    -- and the display should show the true total rather than a wrapped one.
    totalModified = sum (map (toInteger . unLength . regionSize) allRegions)
    payloadCounts = foldl' countPayload (PayloadCounts 0 0 0 0 0) allRegions
    countPayload counts region = case regionPayload region of
      PayloadWrite _  -> counts { writeCount = writeCount counts + 1 }
      PayloadFill _ _ -> counts { fillCount  = fillCount  counts + 1 }
      PayloadCopy _   -> counts { copyCount  = copyCount  counts + 1 }
      PayloadXOR _    -> counts { xorCount   = xorCount   counts + 1 }
      PayloadMeta     -> counts { metaCount  = metaCount  counts + 1 }
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

    offsetRange :: Maybe OffsetRange
    offsetRange =
      writtenOffsetRange [ (regionOffset region, regionSize region) | region <- allRegions ]
    -- A patch that covers bytes but has no range reached past what an 'Offset' carries, which is the only other way
    -- 'writtenOffsetRange' declines to state one.
    rangeLine = case offsetRange of
      Nothing
        | all ((== Length 0) . regionSize) allRegions -> ["range:       (empty patch)"]
        | otherwise -> ["range:       (a record reaches past " <> slapAddressableCeiling <> ")"]
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
    bucketCount = 56 :: Int64  -- terminal sparkline width

    -- Column arithmetic runs in Int64; 'BucketIndex' wraps the Int that 'Array' indexing wants, and this pair is the only crossing.
    bucketAtColumn :: Int64 -> BucketIndex
    bucketAtColumn = BucketIndex . fromIntegral

    columnOfBucket :: BucketIndex -> Int64
    columnOfBucket = fromIntegral . unBucketIndex

    -- Ceiling division, so bucketWidth * bucketCount >= rangeLength and every offset in the range lands in a column below bucketCount.
    bucketWidth :: OffsetRange -> Int64
    bucketWidth range = max 1 ((unLength (rangeLength range) + bucketCount - 1) `div` bucketCount)

    -- The column a region's first byte lands in.
    regionStartColumn :: OffsetRange -> AnalysisRegion -> Int64
    regionStartColumn range region = unLength (distance (rangeStart range) (regionOffset region)) `div` bucketWidth range

    spannedColumns :: OffsetRange -> AnalysisRegion -> [BucketIndex]
    spannedColumns range region =
      let endColumn = (unOffset (advance (regionOffset region) (regionSize region)) - 1 - unOffset (rangeStart range))
                      `div` bucketWidth range
      in [ bucketAtColumn column | column <- [max 0 (regionStartColumn range region) .. min (bucketCount - 1) endColumn] ]

    bucketBounds :: (BucketIndex, BucketIndex)
    bucketBounds = (BucketIndex 0, bucketAtColumn (bucketCount - 1))

    emptyBuckets :: Array BucketIndex BucketTally
    emptyBuckets = accumArray (<>) mempty bucketBounds []

    bucketTallies :: Array BucketIndex BucketTally
    bucketTallies = case offsetRange of
      Nothing -> emptyBuckets
      Just range ->
        let occupancyEntries =
              [ (column, BucketTally ColumnOccupied 0 (Length 0)) | region <- allRegions, column <- spannedColumns range region ]
            startEntries =
              [ (bucketAtColumn column, BucketTally ColumnVacant 1 (regionSize region)) | region <- allRegions
              , let column = regionStartColumn range region, column >= 0, column < bucketCount ]
        in accumArray (<>) mempty bucketBounds (occupancyEntries <> startEntries)

    findRuns :: Array BucketIndex BucketTally -> [BucketRun]
    findRuns columnTallies =
      [ BucketRun columns
      | columns <- NonEmpty.groupBy ((==) `on` occupancyOf) (assocs columnTallies)
      , occupancyOf (NonEmpty.head columns) == ColumnOccupied
      ]
      where
        occupancyOf = tallyOccupancy . snd

    regionsBlock = case offsetRange of
      Nothing -> []
      Just range ->
          let width = bucketWidth range
              runs = findRuns bucketTallies
              formatRun run =
                let runStartColumn = columnOfBucket (runFirstBucket run)
                    runEndColumn   = columnOfBucket (runLastBucket run)
                    startOffset = unOffset (rangeStart range) + runStartColumn * width
                    -- The ceiling-rounded last bucket can nominally reach past the range's final byte;
                    -- clamp the shown end to the real last byte.
                    endOffset = min (unOffset (rangeStart range) + (runEndColumn + 1) * width - 1)
                                    (unOffset (rangeLastByte range))
                    recordsInRun = runRecords run
                    bytesInRun   = runBytes run
                    percentage = if totalModified > 0
                          then 100.0 * fromIntegral (unLength bytesInRun) / fromIntegral totalModified :: Double
                          else 0
                in "  0x" <> padHex 6 startOffset <> spacePaddedEnDash <> "0x" <> padHex 6 endOffset
                   <> "   " <> padRight 5 (renderAsText recordsInRun) <> " records"
                   <> "   " <> padRight 10 (commaNum (unLength bytesInRun) <> " B")
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
      (smallest : moreSizes) ->
          let sortedSizes = smallest :| moreSizes
              largest     = NonEmpty.last sortedSizes
              medianSize  = middleElement sortedSizes
              meanSize    = totalModified `div` fromIntegral totalRecords
          in ["record sizes: " <> commaNum smallest <> spacePaddedEnDash
              <> commaNum largest <> " B"
              <> " (median " <> commaNum medianSize
              <> ", mean " <> commaNum meanSize <> ")"]

    -- Sparkline
    sparkline = case offsetRange of
      Nothing -> []
      Just range ->
          let chars = map (occupancyGlyph . tallyOccupancy) (elems bucketTallies)
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
          hasMeta = any (\region -> case regionPayload region of PayloadMeta -> True; _ -> False) allRegions
          hasDelta = hasCopy || hasXOR || hasMeta
      in case (hasDelta, mSource) of
           (True, Just _)  -> ["note: source file provided; use --records to see resolved content"]
           (True, Nothing) -> ["note: patch uses delta/reference operations (requires source file)"]
           _               -> []

-- | Format an integer with comma grouping.
-- The sign is split off the rendered digits rather than negated: @negate minBound@ stays negative, and would loop.
commaNum :: Show number => number -> Text
commaNum number = case Text.stripPrefix "-" (renderAsText number) of
  Just digits -> "-" <> groupFromRight digits
  Nothing     -> groupFromRight (renderAsText number)
  where
    groupFromRight = Text.reverse . insertCommas . Text.reverse
    insertCommas digits
      | Text.null digits = ""
      | otherwise =
          let (group, rest) = Text.splitAt 3 digits
          in group <> if Text.null rest then "" else "," <> insertCommas rest
