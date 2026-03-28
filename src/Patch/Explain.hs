module Patch.Explain
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
  , explainPPF
  , explainIPS
  , explainBPS
  , explainUPS
  , explainVCDIFF
  , explainAPSN64
  , explainAPSGBA
  , explainRUP
  , explainBSDiff
  , explainGDIFF
  , explainXDelta1
  , explainPMSR
  , explainDPS
  , explainNINJA1
  , explainPCHTXT
  ) where

import qualified Patch.PPF.Types as PPF
import qualified Patch.IPS as IPS
import qualified Patch.BPS as BPS
import qualified Patch.UPS as UPS
import qualified Patch.APS.N64 as APSN64
import qualified Patch.APS.GBA as APSGBA
import qualified Patch.RUP as RUP
import qualified Patch.VCDIFF as VCDIFF
import qualified Patch.BSDiff as BSDiff
import qualified Patch.GDIFF as GDIFF
import qualified Patch.XDelta1 as XDelta1
import qualified Patch.PMSR as PMSR
import qualified Patch.DPS as DPS
import qualified Patch.NINJA1 as NINJA1
import qualified Patch.PCHTXT as PCHTXT

import Patch.Format (padHex, padNum, padRight, showSigned, hexDump, renderField)
import Patch.Measure (Offset(..), Length(..), FileSize(..), Delta(..))
import qualified Patch.PPF.Info as PPFInfo

import Data.Array (accumArray, elems)
import Data.Bits (xor)
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Char8 as ByteString8
import Data.Char (isDigit)
import Data.List (mapAccumL, sort, intercalate, partition)
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

----------------------------------------------------------------------------
-- PPF
----------------------------------------------------------------------------

explainPPF :: PPF.Patch -> ExplainData
explainPPF patch = ExplainData
  { explainFormat   = ppfVersionString (PPF.ppfVersion patch)
  , explainHeader   = PPFInfo.ppfMeta patch
  , explainSections = [SectionRegions (zipWith makePPFRegion [1..] (PPF.ppfRecords patch))]
  , explainSummary  = Summary recordCount "records" (Just (totalBytes, BytesTotal))
  , explainNotes    = []
  }
  where
    recordCount = length (PPF.ppfRecords patch)
    totalBytes = sum (map (ByteString.length . PPF.recordData) (PPF.ppfRecords patch))

ppfVersionString :: PPF.Version -> String
ppfVersionString PPF.PPF1 = "PPF1"
ppfVersionString PPF.PPF2 = "PPF2"
ppfVersionString PPF.PPF3 = "PPF3"
ppfVersionString PPF.PPF4 = "PPF4 (Pyriel internal format)"

makePPFRegion :: Int -> PPF.Record -> ExplainRegion
makePPFRegion _ record = ExplainRegion
  { regionOffset     = PPF.recordOffset record
  , regionSize       = Length (ByteString.length (PPF.recordData record))
  , regionLabel      = commandString
  , regionPayload    = PayloadWrite (PPF.recordData record)
  , regionAnnotation = AnnotAt AtOffset (PPF.recordOffset record) undoDetail
  }
  where
    commandString = case PPF.recordCommand record of
      PPF.Replace -> "Write  "
      PPF.Append  -> "Append "
    undoDetail = case PPF.recordUndo record of
      Nothing -> []
      Just _  -> [DetailUndo]

----------------------------------------------------------------------------
-- IPS
----------------------------------------------------------------------------

explainIPS :: IPS.IPSPatch -> ExplainData
explainIPS patch = ExplainData
  { explainFormat   = case IPS.ipsVariant patch of
      IPS.StandardIPS -> case IPS.ipsEBPMeta patch of
        Nothing -> "IPS"
        Just _  -> "IPS (EBP)"
      IPS.IPS32       -> "IPS32"
  , explainHeader   = IPS.ipsMeta patch
  , explainSections = [SectionRegions (map makeIPSRegion (IPS.ipsRecords patch))]
  , explainSummary  = Summary recordCount "records" (Just (totalBytes, BytesTotal))
  , explainNotes    = truncNote
  }
  where
    recordCount = length (IPS.ipsRecords patch)
    totalBytes = sum (map ipsRecordSize (IPS.ipsRecords patch))
    truncNote = case IPS.ipsTruncate patch of
      Nothing         -> []
      Just outputSize -> ["truncate to " ++ show (unFileSize outputSize) ++ " bytes"]

makeIPSRegion :: IPS.IPSRecord -> ExplainRegion
makeIPSRegion (IPS.IPSRecord recordOffset recordPayload) = ExplainRegion
  { regionOffset     = recordOffset
  , regionSize       = Length (ByteString.length recordPayload)
  , regionLabel      = "Write  "
  , regionPayload    = PayloadWrite recordPayload
  , regionAnnotation = AnnotAt AtOffset recordOffset []
  }
makeIPSRegion (IPS.IPSRecordRLE recordOffset fillCount fillByte) = ExplainRegion
  { regionOffset     = recordOffset
  , regionSize       = fillCount
  , regionLabel      = "Fill "
  , regionPayload    = PayloadFill fillByte (unLength fillCount)
  , regionAnnotation = AnnotAt AtOffset recordOffset [DetailRLE]
  }

ipsRecordSize :: IPS.IPSRecord -> Int
ipsRecordSize (IPS.IPSRecord _ recordPayload) = ByteString.length recordPayload
ipsRecordSize (IPS.IPSRecordRLE _ fillCount _) = unLength fillCount

----------------------------------------------------------------------------
-- BPS
----------------------------------------------------------------------------

explainBPS :: BPS.BPSPatch -> ExplainData
explainBPS patch = ExplainData
  { explainFormat   = "BPS"
  , explainHeader   = BPS.bpsMeta patch
  , explainSections = [SectionRegions (snd (mapAccumL makeBPSRegion (0, 0) (BPS.bpsActions patch)))]
  , explainSummary  = Summary actionCount "actions" (Just (fromIntegral (unFileSize (BPS.bpsTargetSize patch)), BytesTotalOutput))
  , explainNotes    = []
  }
  where
    actionCount = length (BPS.bpsActions patch)

makeBPSRegion :: (Int64, Int64) -> BPS.BPSAction -> ((Int64, Int64), ExplainRegion)
makeBPSRegion (outputPosition, sourceRelative) action = case action of
  BPS.SourceRead actionLength ->
    let dataLength = unLength actionLength
    in ( (outputPosition + fromIntegral dataLength, sourceRelative)
       , ExplainRegion (Offset outputPosition) actionLength "SourceRead " (PayloadCopy FromSource)
           (AnnotAt AtOutput (Offset outputPosition) [DetailSource (Offset outputPosition)])
       )
  BPS.TargetRead payload ->
    let dataLength = ByteString.length payload
    in ( (outputPosition + fromIntegral dataLength, sourceRelative)
       , ExplainRegion (Offset outputPosition) (Length dataLength) "TargetRead " (PayloadWrite payload)
           (AnnotAt AtOutput (Offset outputPosition) [])
       )
  BPS.SourceCopy actionLength actionDelta ->
    let dataLength = unLength actionLength
        nextSourceRelative = sourceRelative + unDelta actionDelta
    in ( (outputPosition + fromIntegral dataLength, nextSourceRelative + fromIntegral dataLength)
       , ExplainRegion (Offset outputPosition) actionLength "SourceCopy " (PayloadCopy FromSource)
           (AnnotAt AtOutput (Offset outputPosition) [DetailSource (Offset nextSourceRelative), DetailDelta actionDelta])
       )
  BPS.TargetCopy actionLength actionDelta ->
    let dataLength = unLength actionLength
    in ( (outputPosition + fromIntegral dataLength, sourceRelative)
       , ExplainRegion (Offset outputPosition) actionLength "TargetCopy " (PayloadCopy FromTarget)
           (AnnotAt AtOutput (Offset outputPosition) [DetailDelta actionDelta])
       )

----------------------------------------------------------------------------
-- UPS
----------------------------------------------------------------------------

explainUPS :: UPS.UPSPatch -> ExplainData
explainUPS patch = ExplainData
  { explainFormat   = "UPS"
  , explainHeader   = UPS.upsMeta patch
  , explainSections = [SectionRegions (snd (mapAccumL makeUPSRegion (Offset 0) (UPS.upsBlocks patch)))]
  , explainSummary  = Summary blockCount "blocks" Nothing
  , explainNotes    = []
  }
  where
    blockCount = length (UPS.upsBlocks patch)

makeUPSRegion :: Offset -> UPS.UPSBlock -> (Offset, ExplainRegion)
makeUPSRegion position (UPS.UPSBlock skipDelta deltaBytes) =
  let xorOffset = Offset (unOffset position + unDelta skipDelta)
      dataLength = ByteString.length deltaBytes
      nextPosition = Offset (unOffset xorOffset + fromIntegral dataLength + 1)  -- +1 for 0x00 terminator byte
  in ( nextPosition
     , ExplainRegion xorOffset (Length dataLength) "XOR  " (PayloadXOR (Just deltaBytes))
         (AnnotAt AtOffset xorOffset [DetailSkip skipDelta])
     )

----------------------------------------------------------------------------
-- VCDIFF
----------------------------------------------------------------------------

explainVCDIFF :: VCDIFF.VCDIFFPatch -> ExplainData
explainVCDIFF patch = ExplainData
  { explainFormat   = "VCDIFF" ++ if VCDIFF.vcdiffVersion (VCDIFF.vcdiffHeader patch) == 0x53
                               then " (xdelta3)" else ""
  , explainHeader   = VCDIFF.vcdiffMeta patch
  , explainSections = concat windowSections
  , explainSummary  = Summary totalInstructions "instructions"
                   (Just (fromIntegral totalTarget, BytesTotalOutput))
  , explainNotes    = []
  }
  where
    windows = VCDIFF.vcdiffWindows patch
    totalTarget = sum (map (unFileSize . VCDIFF.vcdiffTargetLength) windows)
    codeTable  = VCDIFF.vcdiffCodeTable patch
    nearSize = VCDIFF.vcdiffNearSize patch
    sameSize = VCDIFF.vcdiffSameSize patch
    decoded    = map (VCDIFF.decodeWindowInstructions codeTable nearSize sameSize) windows
    totalInstructions = sum (map length decoded)
    globalOffsets = map Offset (scanl (+) 0 (map (unFileSize . VCDIFF.vcdiffTargetLength) windows))
    windowSections = [ makeVCDIFFSection index globalOffset window decodedInstructions
                     | (index, (globalOffset, window, decodedInstructions)) <- zip [1..] (zip3 globalOffsets windows decoded) ]

makeVCDIFFSection :: Int -> Offset -> VCDIFF.VCDIFFWindow -> [VCDIFF.VCDIFFDecodedInstruction]
                -> [ExplainSection]
makeVCDIFFSection index globalOffset window instructions =
  [ SectionLabeled ("window " ++ show index ++ ":")
      ( [ ("target size", show (unFileSize (VCDIFF.vcdiffTargetLength window)))
        , ("source segment", show (unFileSize (VCDIFF.vcdiffSourceLength window)) ++ " bytes at 0x"
            ++ padHex 6 (unOffset (VCDIFF.vcdiffSourcePosition window)))
        , ("add/run data", show (ByteString.length (VCDIFF.vcdiffAddRunData window)) ++ " bytes")
        , ("instructions", show (ByteString.length (VCDIFF.vcdiffInstructions window)) ++ " bytes")
        , ("addresses", show (ByteString.length (VCDIFF.vcdiffAddresses window)) ++ " bytes")
        ] ++ adlerPair
      )
  , SectionRegions (map (decodedToRegion globalOffset) instructions)
  ]
  where
    adlerPair = case VCDIFF.vcdiffAdler32 window of
      Nothing      -> []
      Just adler   -> [("adler32", "0x" ++ padHex 8 (fromIntegral adler :: Int64))]

decodedToRegion :: Offset -> VCDIFF.VCDIFFDecodedInstruction -> ExplainRegion
decodedToRegion globalOffset instruction = case instruction of
  VCDIFF.DecodedAdd windowOffset payload -> ExplainRegion
    { regionOffset     = absoluteOffset windowOffset
    , regionSize       = Length (ByteString.length payload)
    , regionLabel      = "Add    "
    , regionPayload    = PayloadWrite payload
    , regionAnnotation = AnnotAt AtOutput (absoluteOffset windowOffset) []
    }
  VCDIFF.DecodedRun windowOffset fillByte count -> ExplainRegion
    { regionOffset     = absoluteOffset windowOffset
    , regionSize       = Length count
    , regionLabel      = "Run  "
    , regionPayload    = PayloadFill fillByte count
    , regionAnnotation = AnnotAt AtOutput (absoluteOffset windowOffset) [DetailRLE]
    }
  VCDIFF.DecodedCopy windowOffset copySize (Just sourceOffset) -> ExplainRegion
    { regionOffset     = absoluteOffset windowOffset
    , regionSize       = Length copySize
    , regionLabel      = "Copy   "
    , regionPayload    = PayloadCopy FromSource
    , regionAnnotation = AnnotAt AtOutput (absoluteOffset windowOffset) [DetailSource (Offset sourceOffset)]
    }
  VCDIFF.DecodedCopy windowOffset copySize Nothing -> ExplainRegion
    { regionOffset     = absoluteOffset windowOffset
    , regionSize       = Length copySize
    , regionLabel      = "Copy   "
    , regionPayload    = PayloadCopy FromTarget
    , regionAnnotation = AnnotAt AtOutput (absoluteOffset windowOffset) []
    }
  where
    absoluteOffset windowOffset = Offset (unOffset globalOffset + windowOffset)

----------------------------------------------------------------------------
-- APS
----------------------------------------------------------------------------

explainAPSN64 :: APSN64.APSN64Patch -> ExplainData
explainAPSN64 patch@(APSN64.APSN64Patch _header records) = ExplainData
  { explainFormat   = "APS (N64)"
  , explainHeader   = APSN64.apsN64Meta patch
  , explainSections = [SectionRegions (map makeN64Region records)]
  , explainSummary  = Summary (length records) "records" Nothing
  , explainNotes    = []
  }

explainAPSGBA :: APSGBA.APSGBAPatch -> ExplainData
explainAPSGBA patch@(APSGBA.APSGBAPatch _header records) = ExplainData
  { explainFormat   = "APS (GBA)"
  , explainHeader   = APSGBA.apsGBAMeta patch
  , explainSections = [SectionRegions (map makeGBARegion records)]
  , explainSummary  = Summary (length records) "blocks" Nothing
  , explainNotes    = []
  }

makeN64Region :: APSN64.APSN64Record -> ExplainRegion
makeN64Region (APSN64.APSN64Normal recordOffset recordPayload) = ExplainRegion
  { regionOffset     = recordOffset
  , regionSize       = Length (ByteString.length recordPayload)
  , regionLabel      = "Write  "
  , regionPayload    = PayloadWrite recordPayload
  , regionAnnotation = AnnotAt AtOffset recordOffset []
  }
makeN64Region (APSN64.APSN64RLE recordOffset fillByte fillCount) = ExplainRegion
  { regionOffset     = recordOffset
  , regionSize       = Length (fromIntegral fillCount)
  , regionLabel      = "Fill "
  , regionPayload    = PayloadFill fillByte (fromIntegral fillCount)
  , regionAnnotation = AnnotAt AtOffset recordOffset [DetailRLE]
  }

makeGBARegion :: APSGBA.APSGBARecord -> ExplainRegion
makeGBARegion record = ExplainRegion
  { regionOffset     = Offset (fromIntegral (APSGBA.apsGbaOffset record))
  , regionSize       = Length 65536
  , regionLabel      = "XOR block  "
  , regionPayload    = PayloadXOR (Just (APSGBA.apsGbaXorData record))
  , regionAnnotation = AnnotAt AtOffset (Offset (fromIntegral (APSGBA.apsGbaOffset record)))
      [DetailCRC16 (fromIntegral (APSGBA.apsGbaSourceCRC record)) (fromIntegral (APSGBA.apsGbaTargetCRC record))]
  }

----------------------------------------------------------------------------
-- RUP
----------------------------------------------------------------------------

explainRUP :: RUP.RUPPatch -> ExplainData
explainRUP patch = ExplainData
  { explainFormat   = "RUP (NINJA2)"
  , explainHeader   = RUP.rupMeta patch
  , explainSections = [SectionRegions (map makeRUPRegion (RUP.rupRecords patch))]
  , explainSummary  = Summary recordCount "records" Nothing
  , explainNotes    = []
  }
  where
    recordCount = length (RUP.rupRecords patch)

makeRUPRegion :: RUP.RUPRecord -> ExplainRegion
makeRUPRegion (RUP.RUPRecord recordOffset deltaBytes) = ExplainRegion
  { regionOffset     = recordOffset
  , regionSize       = Length (ByteString.length deltaBytes)
  , regionLabel      = "XOR  "
  , regionPayload    = PayloadXOR (Just deltaBytes)
  , regionAnnotation = AnnotAt AtOffset recordOffset []
  }

----------------------------------------------------------------------------
-- GDIFF
----------------------------------------------------------------------------

explainGDIFF :: GDIFF.GDiffPatch -> ExplainData
explainGDIFF patch = ExplainData
  { explainFormat   = "GDIFF (W3C)"
  , explainHeader   = GDIFF.gdiffMeta patch
  , explainSections = [SectionRegions (snd (mapAccumL makeGDIFFRegion (Offset 0) (GDIFF.gdiffCommands patch)))]
  , explainSummary  = Summary commandCount "commands" Nothing
  , explainNotes    = []
  }
  where
    commandCount = length (GDIFF.gdiffCommands patch)

makeGDIFFRegion :: Offset -> GDIFF.GDiffCommand -> (Offset, ExplainRegion)
makeGDIFFRegion outputPosition command = case command of
  GDIFF.GDiffData payload ->
    let dataLength = ByteString.length payload
    in ( Offset (unOffset outputPosition + fromIntegral dataLength)
       , ExplainRegion outputPosition (Length dataLength) "DATA  " (PayloadWrite payload)
           (AnnotAt AtOutput outputPosition [])
       )
  GDIFF.GDiffCopy sourceOffset copyLength ->
    ( Offset (unOffset outputPosition + unFileSize copyLength)
    , ExplainRegion outputPosition (Length (fromIntegral (unFileSize copyLength))) "COPY  " (PayloadCopy FromSource)
        (AnnotAt AtOutput outputPosition [DetailSource sourceOffset])
    )

----------------------------------------------------------------------------
-- BSDiff
----------------------------------------------------------------------------

explainBSDiff :: BSDiff.BSDiffPatch -> ExplainData
explainBSDiff patch = ExplainData
  { explainFormat   = "BSDiff / BDF (BSDIFF40)"
  , explainHeader   = BSDiff.bsdiffMeta patch
  , explainSections = if null (BSDiff.bsdiffControls patch)
                 then [SectionText "(control data not decoded)"]
                 else [SectionRegions (snd (mapAccumL makeBSDiffRegion (Offset 0) (BSDiff.bsdiffControls patch)))]
  , explainSummary  = if null (BSDiff.bsdiffControls patch)
                 then SummaryNone
                 else Summary (length (BSDiff.bsdiffControls patch)) "control tuples" Nothing
  , explainNotes    = []
  }

makeBSDiffRegion :: Offset -> BSDiff.BSDiffControl -> (Offset, ExplainRegion)
makeBSDiffRegion outputPosition control =
  let addLength = BSDiff.controlAdd control
      copyLength = BSDiff.controlCopy control
  in ( Offset (unOffset outputPosition + addLength + copyLength)
     , ExplainRegion
       { regionOffset     = outputPosition
       , regionSize       = Length (fromIntegral (addLength + copyLength))
       , regionLabel      = ""
       , regionPayload    = PayloadMeta []
       , regionAnnotation = AnnotBSDiff (FileSize addLength) (FileSize copyLength) (BSDiff.controlSeek control)
       }
     )

----------------------------------------------------------------------------
-- XDelta1
----------------------------------------------------------------------------

explainXDelta1 :: XDelta1.XDelta1Patch -> ExplainData
explainXDelta1 patch = ExplainData
  { explainFormat   = "xdelta1 v" ++ XDelta1.xdelta1Version patch
  , explainHeader   = XDelta1.xdelta1Meta patch
  , explainSections = map makeXDelta1SourceText (zip [0..] (XDelta1.xdelta1Sources patch))
      ++ [SectionText "", SectionText ("instructions: " ++ show instructionCount), SectionText ""]
      ++ [SectionRegions (map makeXDelta1Region (XDelta1.xdelta1Instructions patch))]
  , explainSummary  = Summary instructionCount "instructions" (Just (fromIntegral (unFileSize (XDelta1.xdelta1TargetLength patch)), BytesTotalOutput))
  , explainNotes    = []
  }
  where
    instructionCount = length (XDelta1.xdelta1Instructions patch)

makeXDelta1SourceText :: (Int, XDelta1.XDelta1Source) -> ExplainSection
makeXDelta1SourceText (index, sourceEntry) = SectionText $
  "  [" ++ show index ++ "] " ++ ByteString8.unpack (XDelta1.xdelta1SourceName sourceEntry)
  ++ (if XDelta1.xdelta1SourceIsData sourceEntry then " (data)" else " (file)")
  ++ (if XDelta1.xdelta1SourceSequential sourceEntry then " seq" else "")
  ++ "  " ++ show (unFileSize (XDelta1.xdelta1SourceLength sourceEntry)) ++ " bytes"
  ++ "  MD5:" ++ concatMap (\byte -> padHex 2 (fromIntegral byte)) (ByteString.unpack (XDelta1.xdelta1SourceMD5 sourceEntry))

makeXDelta1Region :: XDelta1.XDelta1Instruction -> ExplainRegion
makeXDelta1Region instruction = ExplainRegion
  { regionOffset     = XDelta1.xdelta1InstructionOffset instruction
  , regionSize       = Length (fromIntegral (unFileSize (XDelta1.xdelta1InstructionLength instruction)))
  , regionLabel      = "Copy  "
  , regionPayload    = PayloadCopy FromSource
  , regionAnnotation = AnnotAt AtOffset (XDelta1.xdelta1InstructionOffset instruction)
      [DetailSourceIndex (XDelta1.xdelta1InstructionIndex instruction)]
  }

----------------------------------------------------------------------------
-- PMSR
----------------------------------------------------------------------------

explainPMSR :: PMSR.PMSRPatch -> ExplainData
explainPMSR patch = ExplainData
  { explainFormat   = "PMSR (Paper Mario Star Rod)"
  , explainHeader   = PMSR.pmsrMeta patch
  , explainSections = [SectionRegions (map makePMSRRegion (PMSR.pmsrRecords patch))]
  , explainSummary  = Summary recordCount "records" (Just (totalBytes, BytesTotal))
  , explainNotes    = []
  }
  where
    recordCount = length (PMSR.pmsrRecords patch)
    totalBytes = sum (map (ByteString.length . PMSR.pmsrData) (PMSR.pmsrRecords patch))

makePMSRRegion :: PMSR.PMSRRecord -> ExplainRegion
makePMSRRegion record = ExplainRegion
  { regionOffset     = PMSR.pmsrOffset record
  , regionSize       = Length (ByteString.length (PMSR.pmsrData record))
  , regionLabel      = "Write  "
  , regionPayload    = PayloadWrite (PMSR.pmsrData record)
  , regionAnnotation = AnnotAt AtOffset (PMSR.pmsrOffset record) []
  }

----------------------------------------------------------------------------
-- DPS
----------------------------------------------------------------------------

explainDPS :: DPS.DPSPatch -> ExplainData
explainDPS patch = ExplainData
  { explainFormat   = "DPS (Deufeufeu Patching System)"
  , explainHeader   = DPS.dpsMeta patch
  , explainSections = [SectionRegions (map makeDPSRegion (DPS.dpsRecords patch))]
  , explainSummary  = Summary recordCount "records" (Just (totalBytes, BytesTotal))
  , explainNotes    = []
  }
  where
    recordCount = length (DPS.dpsRecords patch)
    totalBytes = sum (map recordBytes (DPS.dpsRecords patch))
    recordBytes record = case DPS.dpsRecordPayload record of
      DPS.PayloadData payload     -> ByteString.length payload
      DPS.PayloadCopy _ copyLength -> fromIntegral copyLength

makeDPSRegion :: DPS.DPSRecord -> ExplainRegion
makeDPSRegion record = case DPS.dpsRecordPayload record of
  DPS.PayloadData payload -> ExplainRegion
    { regionOffset     = DPS.dpsRecordOutputOffset record
    , regionSize       = Length (ByteString.length payload)
    , regionLabel      = "Data   "
    , regionPayload    = PayloadWrite payload
    , regionAnnotation = AnnotAt AtOffset (DPS.dpsRecordOutputOffset record) []
    }
  DPS.PayloadCopy sourceOffset copyLength -> ExplainRegion
    { regionOffset     = DPS.dpsRecordOutputOffset record
    , regionSize       = Length (fromIntegral copyLength)
    , regionLabel      = "Copy   "
    , regionPayload    = PayloadCopy FromSource
    , regionAnnotation = AnnotAt AtOffset (DPS.dpsRecordOutputOffset record) [DetailSource (Offset sourceOffset)]
    }

----------------------------------------------------------------------------
-- NINJA1
----------------------------------------------------------------------------

explainNINJA1 :: NINJA1.NINJA1Patch -> ExplainData
explainNINJA1 patch = ExplainData
  { explainFormat   = "NINJA1 (" ++ subFormatString ++ ")"
  , explainHeader   = NINJA1.ninja1Meta patch
  , explainSections = [SectionRegions (map makeNINJA1Region (NINJA1.ninja1Records patch))]
  , explainSummary  = Summary recordCount "records" (Just (totalBytes, BytesTotal))
  , explainNotes    = []
  }
  where
    recordCount = length (NINJA1.ninja1Records patch)
    subFormatString = case NINJA1.ninja1SubFormat patch of
      NINJA1.Ninja1Binary -> "binary"
      NINJA1.Ninja1BinaryCompressed -> "binary, compressed"
      NINJA1.Ninja1Text   -> "text"
      NINJA1.Ninja1TextCompressed   -> "text, compressed"
    totalBytes = sum (map (ByteString.length . NINJA1.ninja1RecordData) (NINJA1.ninja1Records patch))

makeNINJA1Region :: NINJA1.NINJA1Record -> ExplainRegion
makeNINJA1Region (NINJA1.NINJA1Record recordOffset recordPayload) = ExplainRegion
  { regionOffset     = recordOffset
  , regionSize       = Length (ByteString.length recordPayload)
  , regionLabel      = "Write  "
  , regionPayload    = PayloadWrite recordPayload
  , regionAnnotation = AnnotAt AtOffset recordOffset []
  }

----------------------------------------------------------------------------
-- PCHTXT
----------------------------------------------------------------------------

explainPCHTXT :: PCHTXT.PCHTXTPatch -> ExplainData
explainPCHTXT patch = ExplainData
  { explainFormat   = "PCHTXT (Nintendo Switch)"
  , explainHeader   = PCHTXT.pchtxtMeta patch
  , explainSections = map makePCHTXTBlock (zip [1..] (PCHTXT.pchtxtBlocks patch))
  , explainSummary  = Summary (length enabledEntries) "enabled entries" (Just (totalBytes, BytesTotal))
  , explainNotes    = []
  }
  where
    enabledEntries = concatMap PCHTXT.pchtxtBlockEntries
                       (filter PCHTXT.pchtxtBlockEnabled (PCHTXT.pchtxtBlocks patch))
    totalBytes = sum (map (ByteString.length . PCHTXT.pchtxtData) enabledEntries)

makePCHTXTBlock :: (Int, PCHTXT.PCHTXTBlock) -> ExplainSection
makePCHTXTBlock (index, block) =
  SectionBlock label (map makePCHTXTEntry (PCHTXT.pchtxtBlockEntries block))
  where
    status = if PCHTXT.pchtxtBlockEnabled block then "enabled" else "disabled"
    description = maybe "" (" -- " ++) (PCHTXT.pchtxtBlockDescription block)
    label = "block " ++ show index ++ " (" ++ status ++ ")" ++ description

makePCHTXTEntry :: PCHTXT.PCHTXTEntry -> ExplainRegion
makePCHTXTEntry entry = ExplainRegion
  { regionOffset     = PCHTXT.pchtxtOffset entry
  , regionSize       = Length (ByteString.length (PCHTXT.pchtxtData entry))
  , regionLabel      = "Write  "
  , regionPayload    = PayloadWrite (PCHTXT.pchtxtData entry)
  , regionAnnotation = AnnotNone
  }
