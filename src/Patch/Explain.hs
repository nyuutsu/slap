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
  , explainAPS
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
import qualified Patch.APS as APS
import qualified Patch.RUP as RUP
import qualified Patch.VCDIFF as VCDIFF
import qualified Patch.BSDiff as BSDiff
import qualified Patch.GDIFF as GDIFF
import qualified Patch.XDelta1 as XDelta1
import qualified Patch.PMSR as PMSR
import qualified Patch.DPS as DPS
import qualified Patch.NINJA1 as NINJA1
import qualified Patch.PCHTXT as PCHTXT

import Patch.Format (padHex, padNum, padR, showSigned, hexDump, renderField)
import qualified Patch.PPF.Info as PPFInfo

import Data.Bits (xor)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BS8
import Data.Char (isDigit)
import Data.List (mapAccumL, sort, intercalate, partition)
import Data.Int (Int64)
import Data.Word (Word8)

----------------------------------------------------------------------------
-- Types
----------------------------------------------------------------------------

data ExplainData = ExplainData
  { edFormat   :: String              -- "PPF3", "IPS (EBP)", "BPS", etc.
  , edHeader   :: [(String, String)]  -- key-value metadata (key without colon)
  , edSections :: [ExplainSection]    -- grouped content
  , edSummary  :: ExplainSummary      -- structured summary
  , edNotes    :: [String]            -- trailing messages
  }

data ExplainSection
  = SectionRegions [ExplainRegion]              -- flat numbered list
  | SectionBlock String [ExplainRegion]         -- labeled block + entries (PCHTXT)
  | SectionLabeled String [(String, String)]    -- labeled block + kv pairs (VCDIFF)
  | SectionText String                          -- free text line

data ExplainRegion = ExplainRegion
  { erOffset     :: Int64              -- primary offset (output or target)
  , erSize       :: Int                -- bytes affected
  , erLabel      :: String             -- operation label with trailing space
  , erPayload    :: ExplainPayload
  , erAnnotation :: Annotation         -- structured trailing metadata
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
  | AnnotAt OffsetKind Int64 [AnnotDetail]       -- offset display + details
  | AnnotBSDiff Int64 Int64 Int64                -- add, copy, seek

data OffsetKind = AtOffset | AtOutput

data AnnotDetail
  = DetailRLE                   -- "(RLE)"
  | DetailUndo                  -- "(undo data)"
  | DetailDelta Int64           -- "(delta +N)"
  | DetailSkip Int64            -- "(skip N)"
  | DetailSource Int64          -- "(source 0xN)"
  | DetailSourceIndex Int64     -- "from source N" (rendered before offset)
  | DetailCRC16 Int64 Int64     -- "(src CRC16 0xN, tgt CRC16 0xN)"

----------------------------------------------------------------------------
-- Renderer
----------------------------------------------------------------------------

renderExplain :: Maybe ByteString -> ExplainData -> String
renderExplain mSource ed = unlines $
  [ "format:      " ++ edFormat ed ]
  ++ map renderField (edHeader ed)
  ++ [""]
  ++ concatMap renderSection (edSections ed)
  ++ notesLines
  ++ [renderSummaryLine (edSummary ed) | not (isSummaryNone (edSummary ed))]
  where
    notesLines = map (\n -> n) (edNotes ed)

    renderSection (SectionRegions rs) =
      zipWith renderRegion [1..] rs

    renderSection (SectionBlock label rs) =
      label : map renderBlockEntry rs ++ [""]

    renderSection (SectionLabeled label kvs) =
      label : map renderLabeledKV kvs ++ [""]

    renderSection (SectionText t) = [t]

    renderLabeledKV (k, v) =
      "  " ++ k ++ ":" ++ replicate (max 1 (18 - length k - 3)) ' ' ++ v

    renderBlockEntry r =
      "    " ++ padHex 8 (erOffset r) ++ "  " ++ erLabel r
      ++ padR 10 (show (erSize r) ++ " B")
      ++ "\n" ++ hexDump (payloadBytes (erPayload r))

    payloadBytes (PayloadWrite bs) = bs
    payloadBytes _ = BS.empty

    annot = renderAnnotation . erAnnotation

    renderRegion n r = case erPayload r of
      PayloadWrite bs ->
        padNum n ++ "  " ++ erLabel r ++ padR 10 (show (erSize r) ++ " B")
        ++ annot r
        ++ "\n" ++ hexDump bs
      PayloadFill val count ->
        padNum n ++ "  " ++ erLabel r ++ show count ++ " x 0x"
        ++ padHex 2 (fromIntegral val :: Int64)
        ++ annot r
      PayloadCopy _ ->
        padNum n ++ "  " ++ erLabel r ++ padR 10 (show (erSize r) ++ " B")
        ++ annot r
        ++ renderCopySource mSource r
      PayloadXOR (Just xd) ->
        padNum n ++ "  " ++ erLabel r ++ padR 10 (show (erSize r) ++ " B")
        ++ annot r
        ++ "\n" ++ labeledHexDump "delta" xd
        ++ renderResolvedXOR mSource (erOffset r) xd
      PayloadXOR Nothing ->
        padNum n ++ "  " ++ erLabel r ++ padR 10 (show (erSize r) ++ " B")
        ++ annot r
      PayloadMeta _ ->
        padNum n ++ "  " ++ erLabel r ++ annot r

isSummaryNone :: ExplainSummary -> Bool
isSummaryNone SummaryNone = True
isSummaryNone _           = False

renderSummaryLine :: ExplainSummary -> String
renderSummaryLine SummaryNone = ""
renderSummaryLine (Summary count unit Nothing) =
  show count ++ " " ++ unit
renderSummaryLine (Summary count unit (Just (bytes, sfx))) =
  show count ++ " " ++ unit ++ ", " ++ show bytes ++ " " ++ renderBytesSuffix sfx

renderBytesSuffix :: SummaryBytes -> String
renderBytesSuffix BytesTotal       = "bytes total"
renderBytesSuffix BytesTotalOutput = "bytes total output"

renderAnnotation :: Annotation -> String
renderAnnotation AnnotNone = ""
renderAnnotation (AnnotBSDiff add copy seek) =
  "add " ++ padR 10 (show add ++ " B")
  ++ "  copy " ++ padR 10 (show copy ++ " B")
  ++ "  seek " ++ showSigned seek
renderAnnotation (AnnotAt kind off details) =
  srcPrefix ++ "  " ++ kindStr kind ++ "0x" ++ padHex 6 off
  ++ concatMap renderDetail rest
  where
    (srcIdxs, rest) = partition isSrcIdx details
    isSrcIdx (DetailSourceIndex _) = True
    isSrcIdx _                     = False
    srcPrefix = case srcIdxs of
      (DetailSourceIndex i : _) -> "  from source " ++ show i
      _                         -> ""
    kindStr AtOffset = "at "
    kindStr AtOutput = "at output "

renderDetail :: AnnotDetail -> String
renderDetail DetailRLE             = "  (RLE)"
renderDetail DetailUndo            = "  (undo data)"
renderDetail (DetailDelta d)       = "  (delta " ++ showSigned d ++ ")"
renderDetail (DetailSkip s)        = "  (skip " ++ show s ++ ")"
renderDetail (DetailSource off)    = "  (source 0x" ++ padHex 6 off ++ ")"
renderDetail (DetailSourceIndex _) = ""
renderDetail (DetailCRC16 src tgt) =
  "  (src CRC16 " ++ padHex 4 src ++ ", tgt CRC16 " ++ padHex 4 tgt ++ ")"

----------------------------------------------------------------------------
-- Source-aware helpers
----------------------------------------------------------------------------

labeledHexDump :: String -> ByteString -> String
labeledHexDump label bs = "      " ++ label ++ ":\n" ++ hexDump bs

resolveXOR :: ByteString -> Int64 -> ByteString -> ByteString
resolveXOR source off xd =
  let srcSlice = BS.take (BS.length xd) (BS.drop (fromIntegral off) source)
      -- zero-pad if source is shorter
      padded = srcSlice <> BS.replicate (BS.length xd - BS.length srcSlice) 0
  in BS.pack (BS.zipWith xor padded xd)

findSourceOffset :: Annotation -> Maybe Int64
findSourceOffset (AnnotAt _ _ details) = go details
  where
    go []                    = Nothing
    go (DetailSource off:_)  = Just off
    go (_:ds)                = go ds
findSourceOffset _ = Nothing

renderResolvedXOR :: Maybe ByteString -> Int64 -> ByteString -> String
renderResolvedXOR Nothing _ _ = ""
renderResolvedXOR (Just source) off xd =
  "\n" ++ labeledHexDump "resolved" (resolveXOR source off xd)

renderCopySource :: Maybe ByteString -> ExplainRegion -> String
renderCopySource Nothing _ = ""
renderCopySource (Just source) r =
  case findSourceOffset (erAnnotation r) of
    Nothing     -> ""
    Just srcOff ->
      let slice = BS.take (erSize r) (BS.drop (fromIntegral srcOff) source)
      in "\n" ++ labeledHexDump "source data" slice

----------------------------------------------------------------------------
-- Summary renderer
----------------------------------------------------------------------------

renderSummary :: Maybe ByteString -> ExplainData -> String
renderSummary mSource ed = unlines $ filter (not . null) $
  [ "format:      " ++ edFormat ed
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
    allRegions = concatMap sectionRegions (edSections ed)

    totalRecords = length allRegions

    sectionRegions (SectionRegions rs)  = rs
    sectionRegions (SectionBlock _ rs)  = rs
    sectionRegions (SectionLabeled _ _) = []
    sectionRegions (SectionText _)      = []

    -- Modified bytes breakdown
    totalModified = sum (map erSize allRegions)
    payloadCounts = foldl countPayload (0,0,0,0,0) allRegions
    countPayload (!w,!f,!c,!x,!m) r = case erPayload r of
      PayloadWrite _  -> (w+1,f,c,x,m)
      PayloadFill _ _ -> (w,f+1,c,x,m)
      PayloadCopy _   -> (w,f,c+1,x,m)
      PayloadXOR _    -> (w,f,c,x+1,m)
      PayloadMeta _   -> (w,f,c,x,m+1)
    breakdownStr = let (w,f,c,x,m) = payloadCounts
                       parts = filter ((/= 0) . fst)
                         [ (w, "writes"), (f, "fills"), (c, "copies")
                         , (x, "XOR"), (m, "structural") ]
                   in case parts of
                        [] -> ""
                        ps -> " (" ++ intercalate ", "
                                (map (\(n,l) -> commaNum n ++ " " ++ l) ps)
                              ++ ")"
    modifiedLine
      | totalRecords == 0 = []
      | otherwise = ["modified:    " ++ commaNum totalModified
                     ++ " bytes" ++ breakdownStr]

    -- Offset range
    offsets = map erOffset allRegions
    minOff = minimum offsets
    maxEnd = maximum [ erOffset r + fromIntegral (erSize r)
                     | r <- allRegions ]
    rangeLine
      | totalRecords == 0 = ["range:       (empty patch)"]
      | otherwise = ["range:       0x" ++ padHex 6 minOff
                     ++ " \8211 0x" ++ padHex 6 (maxEnd - 1)]

    -- Size change from header
    sizeChangeLine = case (lookupHeader "source size", lookupHeader "target size",
                           lookupHeader "new size") of
      (Just srcS, Just tgtS, _) -> mkSizeLine srcS tgtS
      (Just srcS, _, Just tgtS) -> mkSizeLine srcS tgtS
      _ -> []

    lookupHeader key = lookup key (edHeader ed)

    mkSizeLine srcS tgtS =
      case (parseSize srcS, parseSize tgtS) of
        (Just src, Just tgt) ->
          let diff = tgt - src
              sign = if diff >= 0 then "+" else ""
              truncNote = case lookupHeader "truncation" of
                Just t  -> " (truncation at " ++ t ++ ")"
                Nothing -> ""
          in ["size change: " ++ sign ++ commaNum (fromIntegral diff)
              ++ " bytes" ++ truncNote]
        _ -> []

    parseSize s =
      let digits = filter isDigit (takeWhile (\c -> isDigit c || c == ',') s)
      in case reads digits of
           [(n, "")] -> Just (n :: Int64)
           _         -> Nothing

    -- Bucket-based analysis
    bucketCount = 56 :: Int

    buckets :: [(Int, Int)]  -- (bucketIndex, byteCount)
    buckets
      | totalRecords == 0 = []
      | otherwise =
          let rangeSize = max 1 (maxEnd - minOff)
              bucketSize = max 1 (rangeSize `div` fromIntegral bucketCount)
              toBucket r =
                let startB = fromIntegral ((erOffset r - minOff) `div` bucketSize)
                    endB   = fromIntegral (((erOffset r + fromIntegral (erSize r) - 1) - minOff) `div` bucketSize)
                in [ (b, erSize r) | b <- [max 0 startB .. min (bucketCount-1) endB] ]
          in concatMap toBucket allRegions

    bucketSums :: [Int]
    bucketSums
      | totalRecords == 0 = []
      | otherwise =
          let arr = replicate bucketCount 0
              addTo xs (i, v) = take i xs ++ [xs !! i + v] ++ drop (i+1) xs
          in foldl addTo arr buckets

    -- Contiguous runs of non-empty buckets, as (startIdx, endIdx) pairs
    findRuns :: [Int] -> [(Int, Int)]
    findRuns sums = go 0 Nothing []
      where
        go i (Just s) acc | i >= length sums = reverse ((s, i-1) : acc)
        go i Nothing  acc | i >= length sums = reverse acc
        go i Nothing  acc
          | sums !! i > 0 = go (i+1) (Just i) acc
          | otherwise      = go (i+1) Nothing acc
        go i (Just s) acc
          | sums !! i > 0 = go (i+1) (Just s) acc
          | otherwise      = go (i+1) Nothing ((s, i-1) : acc)

    regionsBlock
      | totalRecords == 0 = []
      | otherwise =
          let rangeSize = max 1 (maxEnd - minOff)
              bucketSize = max 1 (rangeSize `div` fromIntegral bucketCount)
              runs = findRuns bucketSums
              fmt (rStart, rEnd) =
                let sOff = minOff + fromIntegral rStart * bucketSize
                    eOff = minOff + fromIntegral (rEnd + 1) * bucketSize - 1
                    recsInRun = length [ r | r <- allRegions
                                       , let b = fromIntegral ((erOffset r - minOff) `div` bucketSize)
                                       , b >= rStart && b <= rEnd ]
                    bytesInRun = sum [ erSize r | r <- allRegions
                                     , let b = fromIntegral ((erOffset r - minOff) `div` bucketSize)
                                     , b >= rStart && b <= rEnd ]
                    pct = if totalModified > 0
                          then 100.0 * fromIntegral bytesInRun / fromIntegral totalModified :: Double
                          else 0
                in "  0x" ++ padHex 6 sOff ++ " \8211 0x" ++ padHex 6 eOff
                   ++ "   " ++ padR 5 (show recsInRun) ++ " records"
                   ++ "   " ++ padR 10 (commaNum bytesInRun ++ " B")
                   ++ "   " ++ showPct pct
          in case runs of
               [] -> []
               _  -> "regions:" : map fmt runs

    showPct :: Double -> String
    showPct p =
      let s = show (round (p * 10) :: Int)
          (whole, frac) = splitAt (length s - 1) s
          w = if null whole then "0" else whole
      in padR 6 (w ++ "." ++ frac ++ "%")

    -- Record size distribution
    sizes = sort (map erSize allRegions)
    recordSizeLine = case sizes of
      []    -> []
      (s:_) | all (== s) sizes ->
          ["record sizes: " ++ commaNum s ++ " B"]
      (minS:_) ->
          let maxS    = last sizes
              medianS = sizes !! (length sizes `div` 2)
              meanS   = totalModified `div` totalRecords
          in ["record sizes: " ++ commaNum minS ++ " \8211 "
              ++ commaNum maxS ++ " B"
              ++ " (median " ++ commaNum medianS
              ++ ", mean " ++ commaNum meanS ++ ")"]

    -- Sparkline
    sparkline
      | totalRecords == 0 = []
      | otherwise =
          let chars = map (\s -> if s > 0 then '#' else '.') bucketSums
              leftLabel = "0x" ++ padHex 6 minOff
              rightLabel = "0x" ++ padHex 6 (maxEnd - 1)
              barLine = "[" ++ chars ++ "]"
              -- right-align rightLabel to closing bracket
              gap = max 1 (length barLine - length leftLabel - length rightLabel)
              labelLine = " " ++ leftLabel
                          ++ replicate gap ' ' ++ rightLabel
          in [barLine, labelLine]

    -- Capability notes
    capabilityNotes =
      let hasCopy = any (\r -> case erPayload r of PayloadCopy _ -> True; _ -> False) allRegions
          hasXOR  = any (\r -> case erPayload r of PayloadXOR _  -> True; _ -> False) allRegions
          hasMeta = any (\r -> case erPayload r of PayloadMeta _ -> True; _ -> False) allRegions
          hasDelta = hasCopy || hasXOR || hasMeta
      in case (hasDelta, mSource) of
           (True, Just _)  -> ["", "note: source file provided; use --records to see resolved content"]
           (True, Nothing) -> ["", "note: patch uses delta/reference operations (requires source file)"]
           _               -> []

-- | Format an integer with comma grouping.
commaNum :: Int -> String
commaNum n
  | n < 0     = "-" ++ commaNum (negate n)
  | otherwise = reverse (go (reverse (show n)))
  where
    go [] = []
    go xs = let (a, b) = splitAt 3 xs
            in a ++ if null b then "" else "," ++ go b

----------------------------------------------------------------------------
-- PPF
----------------------------------------------------------------------------

explainPPF :: PPF.Patch -> ExplainData
explainPPF p = ExplainData
  { edFormat   = ppfVerStr (PPF.patchVersion p)
  , edHeader   = PPFInfo.ppfMeta p
  , edSections = [SectionRegions (zipWith mkPPFRegion [1..] (PPF.patchRecords p))]
  , edSummary  = Summary nRecs "records" (Just (totalBytes, BytesTotal))
  , edNotes    = []
  }
  where
    nRecs = length (PPF.patchRecords p)
    totalBytes = sum (map (BS.length . PPF.recData) (PPF.patchRecords p))

ppfVerStr :: PPF.Version -> String
ppfVerStr PPF.PPF1 = "PPF1"
ppfVerStr PPF.PPF2 = "PPF2"
ppfVerStr PPF.PPF3 = "PPF3"
ppfVerStr PPF.PPF4 = "PPF4 (Pyriel internal format)"

mkPPFRegion :: Int -> PPF.Record -> ExplainRegion
mkPPFRegion _ r = ExplainRegion
  { erOffset     = PPF.recOffset r
  , erSize       = BS.length (PPF.recData r)
  , erLabel      = cmdStr
  , erPayload    = PayloadWrite (PPF.recData r)
  , erAnnotation = AnnotAt AtOffset (PPF.recOffset r) undoDetail
  }
  where
    cmdStr = case PPF.recCmd r of
      PPF.Replace -> "Write  "
      PPF.Append  -> "Append "
    undoDetail = case PPF.recUndo r of
      Nothing -> []
      Just _  -> [DetailUndo]

----------------------------------------------------------------------------
-- IPS
----------------------------------------------------------------------------

explainIPS :: IPS.IPSPatch -> ExplainData
explainIPS p = ExplainData
  { edFormat   = case IPS.ipsVariant p of
      IPS.StandardIPS -> case IPS.ipsEBPMeta p of
        Nothing -> "IPS"
        Just _  -> "IPS (EBP)"
      IPS.IPS32       -> "IPS32"
  , edHeader   = IPS.ipsMeta p
  , edSections = [SectionRegions (map mkIPSRegion (IPS.ipsRecords p))]
  , edSummary  = Summary nRecs "records" (Just (totalBytes, BytesTotal))
  , edNotes    = truncNote
  }
  where
    nRecs = length (IPS.ipsRecords p)
    totalBytes = sum (map ipsRecSize (IPS.ipsRecords p))
    truncNote = case IPS.ipsTruncate p of
      Nothing -> []
      Just sz -> ["truncate to " ++ show sz ++ " bytes"]

mkIPSRegion :: IPS.IPSRecord -> ExplainRegion
mkIPSRegion (IPS.IPSRecord off dat) = ExplainRegion
  { erOffset     = off
  , erSize       = BS.length dat
  , erLabel      = "Write  "
  , erPayload    = PayloadWrite dat
  , erAnnotation = AnnotAt AtOffset off []
  }
mkIPSRegion (IPS.IPSRecordRLE off count val) = ExplainRegion
  { erOffset     = off
  , erSize       = count
  , erLabel      = "Fill "
  , erPayload    = PayloadFill val count
  , erAnnotation = AnnotAt AtOffset off [DetailRLE]
  }

ipsRecSize :: IPS.IPSRecord -> Int
ipsRecSize (IPS.IPSRecord _ d)       = BS.length d
ipsRecSize (IPS.IPSRecordRLE _ c _)  = c

----------------------------------------------------------------------------
-- BPS
----------------------------------------------------------------------------

explainBPS :: BPS.BPSPatch -> ExplainData
explainBPS p = ExplainData
  { edFormat   = "BPS"
  , edHeader   = BPS.bpsMeta p
  , edSections = [SectionRegions (snd (mapAccumL mkBPSRegion (0, 0) (BPS.bpsActions p)))]
  , edSummary  = Summary nActs "actions" (Just (fromIntegral (BPS.bpsTargetSize p), BytesTotalOutput))
  , edNotes    = []
  }
  where
    nActs = length (BPS.bpsActions p)

mkBPSRegion :: (Int64, Int64) -> BPS.BPSAction -> ((Int64, Int64), ExplainRegion)
mkBPSRegion (outPos, srcRel) act = case act of
  BPS.SourceRead len ->
    ( (outPos + fromIntegral len, srcRel)
    , ExplainRegion outPos len "SourceRead " (PayloadCopy FromSource)
        (AnnotAt AtOutput outPos [DetailSource outPos])
    )
  BPS.TargetRead dat ->
    let len = BS.length dat
    in ( (outPos + fromIntegral len, srcRel)
       , ExplainRegion outPos len "TargetRead " (PayloadWrite dat)
           (AnnotAt AtOutput outPos [])
       )
  BPS.SourceCopy len delta ->
    let srcRel' = srcRel + delta
    in ( (outPos + fromIntegral len, srcRel' + fromIntegral len)
       , ExplainRegion outPos len "SourceCopy " (PayloadCopy FromSource)
           (AnnotAt AtOutput outPos [DetailSource srcRel', DetailDelta delta])
       )
  BPS.TargetCopy len delta ->
    ( (outPos + fromIntegral len, srcRel)
    , ExplainRegion outPos len "TargetCopy " (PayloadCopy FromTarget)
        (AnnotAt AtOutput outPos [DetailDelta delta])
    )

----------------------------------------------------------------------------
-- UPS
----------------------------------------------------------------------------

explainUPS :: UPS.UPSPatch -> ExplainData
explainUPS p = ExplainData
  { edFormat   = "UPS"
  , edHeader   = UPS.upsMeta p
  , edSections = [SectionRegions (snd (mapAccumL mkUPSRegion 0 (UPS.upsBlocks p)))]
  , edSummary  = Summary nBlocks "blocks" Nothing
  , edNotes    = []
  }
  where
    nBlocks = length (UPS.upsBlocks p)

mkUPSRegion :: Int64 -> UPS.UPSBlock -> (Int64, ExplainRegion)
mkUPSRegion pos (UPS.UPSBlock skip xd) =
  let xorOff = pos + skip
      len    = BS.length xd
  in ( xorOff + fromIntegral len + 1  -- +1 for 0x00 terminator byte
     , ExplainRegion xorOff len "XOR  " (PayloadXOR (Just xd))
         (AnnotAt AtOffset xorOff [DetailSkip skip])
     )

----------------------------------------------------------------------------
-- VCDIFF
----------------------------------------------------------------------------

explainVCDIFF :: VCDIFF.VCDIFFPatch -> ExplainData
explainVCDIFF p = ExplainData
  { edFormat   = "VCDIFF" ++ if VCDIFF.vcdVersion (VCDIFF.vcdHeader p) == 0x53
                               then " (xdelta3)" else ""
  , edHeader   = VCDIFF.vcdiffMeta p
  , edSections = concat sections
  , edSummary  = Summary totalInsts "instructions"
                   (Just (fromIntegral totalTgt, BytesTotalOutput))
  , edNotes    = []
  }
  where
    wins = VCDIFF.vcdWindows p
    totalTgt = sum (map VCDIFF.vcdTargetLen wins)
    ct  = VCDIFF.vcdCodeTable p
    nSz = VCDIFF.vcdNearSize p
    sSz = VCDIFF.vcdSameSize p
    decoded    = map (VCDIFF.decodeWindowInstructions ct nSz sSz) wins
    totalInsts = sum (map length decoded)
    globalOffs = scanl (+) 0 (map VCDIFF.vcdTargetLen wins)
    sections   = [ mkVCDIFFSection n gOff w d
                 | (n, (gOff, w, d)) <- zip [1..] (zip3 globalOffs wins decoded) ]

mkVCDIFFSection :: Int -> Int64 -> VCDIFF.VCDIFFWindow -> [VCDIFF.VCDDecodedInst]
                -> [ExplainSection]
mkVCDIFFSection n globalOff w insts =
  [ SectionLabeled ("window " ++ show n ++ ":")
      ( [ ("target size", show (VCDIFF.vcdTargetLen w))
        , ("source segment", show (VCDIFF.vcdSourceLen w) ++ " bytes at 0x"
            ++ padHex 6 (VCDIFF.vcdSourcePos w))
        , ("add/run data", show (BS.length (VCDIFF.vcdAddRunData w)) ++ " bytes")
        , ("instructions", show (BS.length (VCDIFF.vcdInstructions w)) ++ " bytes")
        , ("addresses", show (BS.length (VCDIFF.vcdAddresses w)) ++ " bytes")
        ] ++ adlerKV
      )
  , SectionRegions (map (decodedToRegion globalOff) insts)
  ]
  where
    adlerKV = case VCDIFF.vcdAdler32 w of
      Nothing -> []
      Just a  -> [("adler32", "0x" ++ padHex 8 (fromIntegral a :: Int64))]

decodedToRegion :: Int64 -> VCDIFF.VCDDecodedInst -> ExplainRegion
decodedToRegion globalOff inst = case inst of
  VCDIFF.DAdd winOff dat -> ExplainRegion
    { erOffset     = absOff winOff
    , erSize       = BS.length dat
    , erLabel      = "Add    "
    , erPayload    = PayloadWrite dat
    , erAnnotation = AnnotAt AtOutput (absOff winOff) []
    }
  VCDIFF.DRun winOff val count -> ExplainRegion
    { erOffset     = absOff winOff
    , erSize       = count
    , erLabel      = "Run  "
    , erPayload    = PayloadFill val count
    , erAnnotation = AnnotAt AtOutput (absOff winOff) [DetailRLE]
    }
  VCDIFF.DCopy winOff sz (Just srcOff) -> ExplainRegion
    { erOffset     = absOff winOff
    , erSize       = sz
    , erLabel      = "Copy   "
    , erPayload    = PayloadCopy FromSource
    , erAnnotation = AnnotAt AtOutput (absOff winOff) [DetailSource srcOff]
    }
  VCDIFF.DCopy winOff sz Nothing -> ExplainRegion
    { erOffset     = absOff winOff
    , erSize       = sz
    , erLabel      = "Copy   "
    , erPayload    = PayloadCopy FromTarget
    , erAnnotation = AnnotAt AtOutput (absOff winOff) []
    }
  where
    absOff winOff = globalOff + winOff

----------------------------------------------------------------------------
-- APS
----------------------------------------------------------------------------

explainAPS :: APS.APSPatch -> ExplainData
explainAPS p@(APS.APSPatch variant) = case variant of
  APS.APSN64 _hdr recs -> ExplainData
    { edFormat   = "APS (N64)"
    , edHeader   = APS.apsMeta p
    , edSections = [SectionRegions (map mkN64Region recs)]
    , edSummary  = Summary (length recs) "records" Nothing
    , edNotes    = []
    }
  APS.APSGBA _hdr recs -> ExplainData
    { edFormat   = "APS (GBA)"
    , edHeader   = APS.apsMeta p
    , edSections = [SectionRegions (map mkGBARegion recs)]
    , edSummary  = Summary (length recs) "blocks" Nothing
    , edNotes    = []
    }

mkN64Region :: APS.APSN64Record -> ExplainRegion
mkN64Region (APS.APSN64Normal off dat) = ExplainRegion
  { erOffset     = off
  , erSize       = BS.length dat
  , erLabel      = "Write  "
  , erPayload    = PayloadWrite dat
  , erAnnotation = AnnotAt AtOffset off []
  }
mkN64Region (APS.APSN64RLE off val count) = ExplainRegion
  { erOffset     = off
  , erSize       = fromIntegral count
  , erLabel      = "Fill "
  , erPayload    = PayloadFill val (fromIntegral count)
  , erAnnotation = AnnotAt AtOffset off [DetailRLE]
  }

mkGBARegion :: APS.APSGBARecord -> ExplainRegion
mkGBARegion r = ExplainRegion
  { erOffset     = fromIntegral (APS.gbaOffset r)
  , erSize       = 65536
  , erLabel      = "XOR block  "
  , erPayload    = PayloadXOR (Just (APS.gbaXorData r))
  , erAnnotation = AnnotAt AtOffset (fromIntegral (APS.gbaOffset r))
      [DetailCRC16 (fromIntegral (APS.gbaSourceCRC r)) (fromIntegral (APS.gbaTargetCRC r))]
  }

----------------------------------------------------------------------------
-- RUP
----------------------------------------------------------------------------

explainRUP :: RUP.RUPPatch -> ExplainData
explainRUP p = ExplainData
  { edFormat   = "RUP (NINJA2)"
  , edHeader   = RUP.rupMetaKV p
  , edSections = [SectionRegions (map mkRUPRegion (RUP.rupRecords p))]
  , edSummary  = Summary nRecs "records" Nothing
  , edNotes    = []
  }
  where
    nRecs = length (RUP.rupRecords p)

mkRUPRegion :: RUP.RUPRecord -> ExplainRegion
mkRUPRegion (RUP.RUPRecord off xd) = ExplainRegion
  { erOffset     = off
  , erSize       = BS.length xd
  , erLabel      = "XOR  "
  , erPayload    = PayloadXOR (Just xd)
  , erAnnotation = AnnotAt AtOffset off []
  }

----------------------------------------------------------------------------
-- GDIFF
----------------------------------------------------------------------------

explainGDIFF :: GDIFF.GDiffPatch -> ExplainData
explainGDIFF p = ExplainData
  { edFormat   = "GDIFF (W3C)"
  , edHeader   = GDIFF.gdiffMeta p
  , edSections = [SectionRegions (snd (mapAccumL mkGDIFFRegion 0 (GDIFF.gdiffCmds p)))]
  , edSummary  = Summary nCmds "commands" Nothing
  , edNotes    = []
  }
  where
    nCmds = length (GDIFF.gdiffCmds p)

mkGDIFFRegion :: Int64 -> GDIFF.GDiffCmd -> (Int64, ExplainRegion)
mkGDIFFRegion outPos cmd = case cmd of
  GDIFF.GDiffData dat ->
    let len = BS.length dat
    in ( outPos + fromIntegral len
       , ExplainRegion outPos len "DATA  " (PayloadWrite dat)
           (AnnotAt AtOutput outPos [])
       )
  GDIFF.GDiffCopy off len ->
    ( outPos + len
    , ExplainRegion outPos (fromIntegral len) "COPY  " (PayloadCopy FromSource)
        (AnnotAt AtOutput outPos [DetailSource off])
    )

----------------------------------------------------------------------------
-- BSDiff
----------------------------------------------------------------------------

explainBSDiff :: BSDiff.BSDiffPatch -> ExplainData
explainBSDiff p = ExplainData
  { edFormat   = "BSDiff / BDF (BSDIFF40)"
  , edHeader   = BSDiff.bsdiffMeta p
  , edSections = if null (BSDiff.bsdControls p)
                 then [SectionText "(control data not decoded)"]
                 else [SectionRegions (snd (mapAccumL mkBSDiffRegion 0 (BSDiff.bsdControls p)))]
  , edSummary  = if null (BSDiff.bsdControls p)
                 then SummaryNone
                 else Summary (length (BSDiff.bsdControls p)) "control tuples" Nothing
  , edNotes    = []
  }

mkBSDiffRegion :: Int64 -> BSDiff.BSDiffControl -> (Int64, ExplainRegion)
mkBSDiffRegion outPos ctrl =
  let addLen = BSDiff.ctrlAdd ctrl
      cpLen  = BSDiff.ctrlCopy ctrl
  in ( outPos + addLen + cpLen
     , ExplainRegion
       { erOffset     = outPos
       , erSize       = fromIntegral (addLen + cpLen)
       , erLabel      = ""
       , erPayload    = PayloadMeta []
       , erAnnotation = AnnotBSDiff addLen cpLen (BSDiff.ctrlSeek ctrl)
       }
     )

----------------------------------------------------------------------------
-- XDelta1
----------------------------------------------------------------------------

explainXDelta1 :: XDelta1.XDelta1Patch -> ExplainData
explainXDelta1 p = ExplainData
  { edFormat   = "xdelta1 v" ++ XDelta1.xd1Version p
  , edHeader   = XDelta1.xdelta1Meta p
  , edSections = map mkXD1SourceText (zip [0..] (XDelta1.xd1Sources p))
      ++ [SectionText "", SectionText ("instructions: " ++ show nInsts), SectionText ""]
      ++ [SectionRegions (map mkXD1Region (XDelta1.xd1Instructions p))]
  , edSummary  = Summary nInsts "instructions" (Just (fromIntegral (XDelta1.xd1ToLen p), BytesTotalOutput))
  , edNotes    = []
  }
  where
    nInsts = length (XDelta1.xd1Instructions p)

mkXD1SourceText :: (Int, XDelta1.XD1Source) -> ExplainSection
mkXD1SourceText (n, s) = SectionText $
  "  [" ++ show n ++ "] " ++ BS8.unpack (XDelta1.xd1SrcName s)
  ++ (if XDelta1.xd1SrcIsData s then " (data)" else " (file)")
  ++ (if XDelta1.xd1SrcSequential s then " seq" else "")
  ++ "  " ++ show (XDelta1.xd1SrcLen s) ++ " bytes"
  ++ "  MD5:" ++ concatMap (\b -> padHex 2 (fromIntegral b)) (BS.unpack (XDelta1.xd1SrcMD5 s))

mkXD1Region :: XDelta1.XD1Instruction -> ExplainRegion
mkXD1Region inst = ExplainRegion
  { erOffset     = XDelta1.xd1InstOffset inst
  , erSize       = fromIntegral (XDelta1.xd1InstLength inst)
  , erLabel      = "Copy  "
  , erPayload    = PayloadCopy FromSource
  , erAnnotation = AnnotAt AtOffset (XDelta1.xd1InstOffset inst)
      [DetailSourceIndex (XDelta1.xd1InstIndex inst)]
  }

----------------------------------------------------------------------------
-- PMSR
----------------------------------------------------------------------------

explainPMSR :: PMSR.PMSRPatch -> ExplainData
explainPMSR p = ExplainData
  { edFormat   = "PMSR (Paper Mario Star Rod)"
  , edHeader   = PMSR.pmsrMeta p
  , edSections = [SectionRegions (map mkPMSRRegion (PMSR.pmsrRecords p))]
  , edSummary  = Summary nRecs "records" (Just (totalBytes, BytesTotal))
  , edNotes    = []
  }
  where
    nRecs = length (PMSR.pmsrRecords p)
    totalBytes = sum (map (BS.length . PMSR.pmsrData) (PMSR.pmsrRecords p))

mkPMSRRegion :: PMSR.PMSRRecord -> ExplainRegion
mkPMSRRegion r = ExplainRegion
  { erOffset     = PMSR.pmsrOffset r
  , erSize       = BS.length (PMSR.pmsrData r)
  , erLabel      = "Write  "
  , erPayload    = PayloadWrite (PMSR.pmsrData r)
  , erAnnotation = AnnotAt AtOffset (PMSR.pmsrOffset r) []
  }

----------------------------------------------------------------------------
-- DPS
----------------------------------------------------------------------------

explainDPS :: DPS.DPSPatch -> ExplainData
explainDPS p = ExplainData
  { edFormat   = "DPS (Deufeufeu Patching System)"
  , edHeader   = DPS.dpsMeta p
  , edSections = [SectionRegions (map mkDPSRegion (DPS.dpsRecords p))]
  , edSummary  = Summary nRecs "records" (Just (totalBytes, BytesTotal))
  , edNotes    = []
  }
  where
    nRecs = length (DPS.dpsRecords p)
    totalBytes = sum (map recBytes (DPS.dpsRecords p))
    recBytes r = case DPS.dpsRecPayload r of
      DPS.PayloadData dat    -> BS.length dat
      DPS.PayloadCopy _ len  -> fromIntegral len

mkDPSRegion :: DPS.DPSRecord -> ExplainRegion
mkDPSRegion r = case DPS.dpsRecPayload r of
  DPS.PayloadData dat -> ExplainRegion
    { erOffset     = DPS.dpsRecOutOffset r
    , erSize       = BS.length dat
    , erLabel      = "Data   "
    , erPayload    = PayloadWrite dat
    , erAnnotation = AnnotAt AtOffset (DPS.dpsRecOutOffset r) []
    }
  DPS.PayloadCopy srcOff len -> ExplainRegion
    { erOffset     = DPS.dpsRecOutOffset r
    , erSize       = fromIntegral len
    , erLabel      = "Copy   "
    , erPayload    = PayloadCopy FromSource
    , erAnnotation = AnnotAt AtOffset (DPS.dpsRecOutOffset r) [DetailSource srcOff]
    }

----------------------------------------------------------------------------
-- NINJA1
----------------------------------------------------------------------------

explainNINJA1 :: NINJA1.NINJA1Patch -> ExplainData
explainNINJA1 p = ExplainData
  { edFormat   = "NINJA1 (" ++ subFmtStr ++ ")"
  , edHeader   = NINJA1.ninja1Meta p
  , edSections = [SectionRegions (map mkN1Region (NINJA1.n1Records p))]
  , edSummary  = Summary nRecs "records" (Just (totalBytes, BytesTotal))
  , edNotes    = []
  }
  where
    nRecs = length (NINJA1.n1Records p)
    subFmtStr = case NINJA1.n1SubFormat p of
      NINJA1.N1Binary  -> "binary"
      NINJA1.N1BinaryZ -> "binary, compressed"
      NINJA1.N1Text    -> "text"
      NINJA1.N1TextZ   -> "text, compressed"
    totalBytes = sum (map (BS.length . NINJA1.n1RecData) (NINJA1.n1Records p))

mkN1Region :: NINJA1.NINJA1Record -> ExplainRegion
mkN1Region (NINJA1.NINJA1Record off dat) = ExplainRegion
  { erOffset     = off
  , erSize       = BS.length dat
  , erLabel      = "Write  "
  , erPayload    = PayloadWrite dat
  , erAnnotation = AnnotAt AtOffset off []
  }

----------------------------------------------------------------------------
-- PCHTXT
----------------------------------------------------------------------------

explainPCHTXT :: PCHTXT.PCHTXTPatch -> ExplainData
explainPCHTXT p = ExplainData
  { edFormat   = "PCHTXT (Nintendo Switch)"
  , edHeader   = PCHTXT.pchtxtMeta p
  , edSections = map mkPCHTXTBlock (zip [1..] (PCHTXT.pchtxtBlocks p))
  , edSummary  = Summary (length enabledEntries) "enabled entries" (Just (totalBytes, BytesTotal))
  , edNotes    = []
  }
  where
    enabledEntries = concatMap PCHTXT.pchtxtBlockEntries
                       (filter PCHTXT.pchtxtBlockEnabled (PCHTXT.pchtxtBlocks p))
    totalBytes = sum (map (BS.length . PCHTXT.pchtxtData) enabledEntries)

mkPCHTXTBlock :: (Int, PCHTXT.PCHTXTBlock) -> ExplainSection
mkPCHTXTBlock (n, block) =
  SectionBlock label (map mkPCHTXTEntry (PCHTXT.pchtxtBlockEntries block))
  where
    status = if PCHTXT.pchtxtBlockEnabled block then "enabled" else "disabled"
    desc = maybe "" (" -- " ++) (PCHTXT.pchtxtBlockDesc block)
    label = "block " ++ show n ++ " (" ++ status ++ ")" ++ desc

mkPCHTXTEntry :: PCHTXT.PCHTXTEntry -> ExplainRegion
mkPCHTXTEntry e = ExplainRegion
  { erOffset     = PCHTXT.pchtxtOffset e
  , erSize       = BS.length (PCHTXT.pchtxtData e)
  , erLabel      = "Write  "
  , erPayload    = PayloadWrite (PCHTXT.pchtxtData e)
  , erAnnotation = AnnotNone
  }
