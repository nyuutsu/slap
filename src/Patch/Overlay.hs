module Patch.Overlay
  ( CreateFormat(..)
  , OverlayRecord(..)
  , OverlaySource(..)
  , emptyOverlay
  , extractIPS
  , extractPPF
  , extractNINJA1
  , extractPMSR
  , extractPCHTXT
  , extractAPSN64
  , splitOverlay
  , convertOverlay
  , overlayWarnings
  , createFromMemory
  , fmtExt
  , fmtName
  ) where

import qualified Patch.PPF.Types as PPF
import qualified Patch.PPF.Create as PPF
import qualified Patch.IPS as IPS
import qualified Patch.BPS as BPS
import qualified Patch.UPS as UPS
import qualified Patch.APS as APS
import qualified Patch.RUP as RUP
import qualified Patch.GDIFF as GDIFF
import qualified Patch.PMSR as PMSR
import qualified Patch.DPS as DPS
import qualified Patch.NINJA1 as NINJA1
import qualified Patch.PCHTXT as PCHTXT
import Patch.Format (showCRC, padHex)

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BS8
import Control.Applicative ((<|>))
import Data.Int (Int64)
import Data.Maybe (fromMaybe)
import Data.Word (Word32)

----------------------------------------------------------------------------
-- Types
----------------------------------------------------------------------------

data CreateFormat
  = CfmtBPS | CfmtIPS | CfmtIPS32 | CfmtEBP | CfmtUPS | CfmtPPF3 | CfmtPMSR
  | CfmtNINJA1 | CfmtDPS | CfmtRUP | CfmtAPSN64 | CfmtAPSGBA | CfmtGDIFF | CfmtPCHTXT
  deriving (Show, Eq)

-- | Overlay record: offset + replacement bytes.
data OverlayRecord = OverlayRecord Int64 BS.ByteString

-- | Everything an overlay source carries beyond raw records.
data OverlaySource = OverlaySource
  { osRecords     :: [OverlayRecord]
  , osDescription :: Maybe BS.ByteString   -- 50-byte PPF/APS desc, or raw EBP JSON
  , osValidation  :: Maybe BS.ByteString   -- 1024-byte validation block (PPF2/PPF3)
  , osUndoRecs    :: Maybe [(Int64, BS.ByteString, BS.ByteString)]
      -- (off, new, old) triples — PPF3 with undo only
  , osFileSize    :: Maybe Word32          -- PPF2 patchFileSize
  , osDestSize    :: Maybe Word32          -- APS N64 dest_size
  , osSourceCRC   :: Maybe Word32          -- NINJA1 CRC32
  , osSourceMD5   :: Maybe BS.ByteString   -- NINJA1 MD5 (16 bytes)
  , osSourceSHA1  :: Maybe BS.ByteString   -- NINJA1 SHA1 (20 bytes)
  , osTruncate    :: Maybe Int64           -- IPS truncation marker
  , osEBPMeta     :: Maybe BS.ByteString   -- raw EBP JSON (for EBP→EBP)
  }

----------------------------------------------------------------------------
-- Overlay extraction
----------------------------------------------------------------------------

emptyOverlay :: [OverlayRecord] -> OverlaySource
emptyOverlay recs = OverlaySource
  recs Nothing Nothing Nothing Nothing Nothing Nothing Nothing Nothing Nothing Nothing

extractIPS :: IPS.IPSPatch -> OverlaySource
extractIPS p = (emptyOverlay (map expandIPS (IPS.ipsRecords p)))
  { osTruncate = IPS.ipsTruncate p
  , osEBPMeta  = IPS.ipsEBPMeta p
  }
  where
    expandIPS (IPS.IPSRecord off dat)        = OverlayRecord off dat
    expandIPS (IPS.IPSRecordRLE off cnt val) = OverlayRecord off (BS.replicate cnt val)

extractPPF :: PPF.Patch -> OverlaySource
extractPPF p = (emptyOverlay (map toRec (PPF.patchRecords p)))
  { osDescription = Just (PPF.patchDescription p)
  , osValidation  = fmap PPF.valBlock (PPF.patchValidation p)
  , osUndoRecs    = if PPF.patchHasUndo p
                    then Just [ (PPF.recOffset r, PPF.recData r, fromMaybe BS.empty (PPF.recUndo r))
                              | r <- PPF.patchRecords p ]
                    else Nothing
  , osFileSize    = PPF.patchFileSize p
  }
  where toRec r = OverlayRecord (PPF.recOffset r) (PPF.recData r)

extractNINJA1 :: NINJA1.NINJA1Patch -> OverlaySource
extractNINJA1 p = (emptyOverlay (map toRec (NINJA1.n1Records p)))
  { osSourceCRC  = NINJA1.n1SourceCRC p
  , osSourceMD5  = NINJA1.n1SourceMD5 p
  , osSourceSHA1 = NINJA1.n1SourceSHA1 p
  }
  where toRec r = OverlayRecord (NINJA1.n1RecOffset r) (NINJA1.n1RecData r)

extractPMSR :: PMSR.PMSRPatch -> OverlaySource
extractPMSR p = emptyOverlay
  (map (\r -> OverlayRecord (PMSR.pmsrOffset r) (PMSR.pmsrData r)) (PMSR.pmsrRecords p))

extractPCHTXT :: PCHTXT.PCHTXTPatch -> OverlaySource
extractPCHTXT p = (emptyOverlay recs)
  { osDescription = BS8.pack <$> PCHTXT.pchtxtNsobid p }
  where
    recs = concatMap blockToRecs (filter PCHTXT.pchtxtBlockEnabled (PCHTXT.pchtxtBlocks p))
    blockToRecs block = map (\e -> OverlayRecord (PCHTXT.pchtxtOffset e) (PCHTXT.pchtxtData e))
                            (PCHTXT.pchtxtBlockEntries block)

extractAPSN64 :: APS.APSN64Header -> [APS.APSN64Record] -> OverlaySource
extractAPSN64 hdr recs = (emptyOverlay (map expandAPS recs))
  { osDescription = Just (APS.n64Description hdr)
  , osDestSize    = Just (APS.n64DestSize hdr)
  }
  where
    expandAPS (APS.APSN64Normal off dat)  = OverlayRecord off dat
    expandAPS (APS.APSN64RLE off val cnt) = OverlayRecord off (BS.replicate (fromIntegral cnt) val)

----------------------------------------------------------------------------
-- Overlay conversion
----------------------------------------------------------------------------

-- | Convert overlay records to a target format without needing the source ROM.
convertOverlay :: OverlaySource -> CreateFormat -> String -> Bool -> Bool
               -> Either String (BS.ByteString, [String])
convertOverlay os target desc includeUndo includeValidation =
  let notes = overlayWarnings os target
      intRecs = overlayToIntPairs (osRecords os)
  in case target of
    CfmtIPS     -> checkIPSOffsets os >>= \rs -> Right (IPS.encodeIPS (overlayToIntPairs rs) (osTruncate os), notes)
    CfmtIPS32   -> Right (IPS.encodeIPS32 (splitOverlay 0xFFFF intRecs) (osTruncate os), notes)
    CfmtEBP     -> checkIPSOffsets os >>= \rs ->
      let pairs = overlayToIntPairs rs
      in case if null desc then osEBPMeta os else Nothing of
           Just raw -> Right (IPS.encodeEBPRaw pairs raw, notes)
           Nothing  -> Right (IPS.encodeEBP pairs (osTruncate os) (resolveDesc desc (osEBPMeta os) (osDescription os) ""), notes)
    CfmtPPF3    -> convertToPPF3 os desc includeUndo includeValidation notes
    CfmtNINJA1  -> Right (NINJA1.encodeNINJA1 intRecs (osSourceCRC os) (osSourceMD5 os) (osSourceSHA1 os), notes)
    CfmtPMSR    -> Right (PMSR.encodePMSR intRecs, notes)
    CfmtPCHTXT  -> Right (PCHTXT.encodePCHTXT intRecs (osDescription os), notes)
    CfmtAPSN64  -> case osDestSize os <|> osFileSize os of
                     Just sz -> Right (APS.encodeAPSN64 intRecs sz (resolveDesc desc Nothing (osDescription os) (replicate 50 ' ')), notes)
                     Nothing -> Left "converting to APS (N64) requires target file size\nuse --with SOURCE to compute it"
    CfmtBPS     -> Left (fmtName CfmtBPS ++ " requires source+target diff data\nuse --with SOURCE")
    CfmtUPS     -> Left (fmtName CfmtUPS ++ " requires source+target diff data\nuse --with SOURCE")
    CfmtDPS     -> Left (fmtName CfmtDPS ++ " requires source+target diff data\nuse --with SOURCE")
    CfmtRUP     -> Left (fmtName CfmtRUP ++ " requires source+target diff data\nuse --with SOURCE")
    CfmtAPSGBA  -> Left (fmtName CfmtAPSGBA ++ " requires source+target diff data\nuse --with SOURCE")
    CfmtGDIFF   -> Left (fmtName CfmtGDIFF ++ " requires source+target diff data\nuse --with SOURCE")

-- | Convert overlay records to (Int, ByteString) pairs for module encoders.
overlayToIntPairs :: [OverlayRecord] -> [(Int, BS.ByteString)]
overlayToIntPairs = map (\(OverlayRecord off dat) -> (fromIntegral off, dat))

-- | Check that all overlay offsets fit in 3-byte IPS range.
checkIPSOffsets :: OverlaySource -> Either String [OverlayRecord]
checkIPSOffsets os
  | any (\(OverlayRecord off _) -> off > 0xFFFFFF) (osRecords os) =
      Left "patch has offsets > 16 MB \8212 cannot convert to IPS\nuse --to ips32, or --with SOURCE to re-diff"
  | otherwise = Right (osRecords os)

-- | PPF3 conversion with undo/validate gating.
convertToPPF3 :: OverlaySource -> String -> Bool -> Bool -> [String]
              -> Either String (BS.ByteString, [String])
convertToPPF3 os desc includeUndo includeValidation notes = do
  undoTriples <- if includeUndo
    then case osUndoRecs os of
      Just u  -> Right (Just u)
      Nothing -> Left "source has no undo data\nuse --no-undo, or --with SOURCE to generate it"
    else Right Nothing
  valBlock <- if includeValidation
    then case osValidation os of
      Just v  -> Right (Just v)
      Nothing -> Left "source has no validation block\nuse --no-validate, or --with SOURCE to generate it"
    else Right Nothing
  let descStr = resolveDesc desc Nothing (osDescription os) ""
      ppfRecs = splitOverlay 255 (map (\(OverlayRecord off dat) -> (off, dat)) (osRecords os))
  Right (PPF.encodePPF3 ppfRecs descStr undoTriples valBlock, notes)

-- | Split (offset, ByteString) pairs so each data chunk is ≤ maxSize bytes.
splitOverlay :: Integral a => Int -> [(a, BS.ByteString)] -> [(a, BS.ByteString)]
splitOverlay maxSize = concatMap split1
  where
    split1 (off, dat)
      | BS.length dat <= maxSize = [(off, dat)]
      | otherwise =
          let (h, t) = BS.splitAt maxSize dat
          in (off, h) : split1 (off + fromIntegral maxSize, t)

----------------------------------------------------------------------------
-- Create
----------------------------------------------------------------------------

-- | Create a patch from source and target bytes.
createFromMemory :: CreateFormat -> BS.ByteString -> BS.ByteString -> String -> Bool -> Bool -> Either String BS.ByteString
createFromMemory CfmtBPS  src tgt _ _ _ = Right (BPS.createBPS src tgt)
createFromMemory CfmtUPS  src tgt _ _ _ = Right (UPS.createUPS src tgt)
createFromMemory CfmtPMSR src tgt _ _ _ = Right (PMSR.createPMSR src tgt)
createFromMemory CfmtIPS  src tgt _ _ _ = IPS.createIPS src tgt
createFromMemory CfmtIPS32 src tgt _ _ _ = IPS.createIPS32 src tgt
createFromMemory CfmtEBP  src tgt desc _ _ = IPS.createEBP src tgt desc
createFromMemory CfmtPPF3 src tgt desc undo val =
  Right (PPF.createPatchPure src tgt desc undo val)
createFromMemory CfmtNINJA1 src tgt _ _ _ = Right (NINJA1.createNINJA1 src tgt)
createFromMemory CfmtDPS    src tgt _ _ _ = Right (DPS.createDPS src tgt)
createFromMemory CfmtRUP    src tgt _ _ _ = Right (RUP.createRUP src tgt)
createFromMemory CfmtAPSN64 src tgt _ _ _ = Right (APS.createAPSN64 src tgt)
createFromMemory CfmtAPSGBA src tgt _ _ _ = Right (APS.createAPSGBA src tgt)
createFromMemory CfmtGDIFF  src tgt _ _ _ = Right (GDIFF.createGDIFF src tgt)
createFromMemory CfmtPCHTXT src tgt _ _ _ = Right (PCHTXT.createPCHTXT src tgt)

----------------------------------------------------------------------------
-- Overlay helpers
----------------------------------------------------------------------------

-- | Resolve a description string from CLI flag, source metadata, or default.
resolveDesc :: String -> Maybe BS.ByteString -> Maybe BS.ByteString -> String -> String
resolveDesc cliDesc ebpMeta rawDesc def
  | not (null cliDesc) = cliDesc
  | Just meta <- ebpMeta = extractEBPDesc meta
  | Just d <- rawDesc    = trimNulSpace (BS8.unpack d)
  | otherwise            = def
  where
    -- Extract description from EBP JSON: {"title":"...","author":"...","description":"..."}
    extractEBPDesc bs = case BS8.unpack bs of
      s -> case dropWhile (/= ':') (snd (breakOn "description" s)) of
              (':':'"':rest) -> takeQuoted rest
              _              -> def
    takeQuoted ('"' : _)        = ""
    takeQuoted ('\\' : c : cs)  = c : takeQuoted cs
    takeQuoted (c : cs)         = c : takeQuoted cs
    takeQuoted []               = ""
    breakOn _ [] = ("", "")
    breakOn needle ss@(x:xs)
      | take (length needle) ss == needle = ("", ss)
      | otherwise = let (a, b) = breakOn needle xs in (x:a, b)

-- | Emit info-loss notes for metadata the target format cannot carry.
overlayWarnings :: OverlaySource -> CreateFormat -> [String]
overlayWarnings os target = concat
  [ warnCRC, warnMD5, warnSHA1, warnDesc, warnVal, warnUndo
  , warnFileSize, warnTrunc, warnEBP
  ]
  where
    warnCRC = case osSourceCRC os of
      Just crc | target /= CfmtNINJA1, crc /= 0 ->
        ["note: dropping source CRC32: 0x" ++ showCRC crc]
      _ -> []
    warnMD5 = case osSourceMD5 os of
      Just md5 | target /= CfmtNINJA1, not (BS.all (== 0) md5) ->
        ["note: dropping source MD5: " ++ hexBS md5]
      _ -> []
    warnSHA1 = case osSourceSHA1 os of
      Just sha1 | target /= CfmtNINJA1, not (BS.all (== 0) sha1) ->
        ["note: dropping source SHA1: " ++ hexBS sha1]
      _ -> []
    warnDesc = case osDescription os of
      Just d | target `notElem` [CfmtPPF3, CfmtAPSN64, CfmtEBP, CfmtPCHTXT]
             , not (BS.all (\b -> b == 0x20 || b == 0) d) ->
        ["note: dropping description: \"" ++ trimNulSpace (BS8.unpack d) ++ "\""]
      _ -> []
    warnVal = case osValidation os of
      Just _ | target /= CfmtPPF3 ->
        ["note: dropping 1024-byte validation block"]
      _ -> []
    warnUndo = case osUndoRecs os of
      Just u | target /= CfmtPPF3 ->
        ["note: dropping undo data (" ++ show (length u) ++ " records)"]
      _ -> []
    warnFileSize = case osFileSize os of
      Just sz | target `notElem` [CfmtPPF3, CfmtAPSN64] ->
        ["note: dropping file size: " ++ show sz ++ " bytes"]
      _ -> []
    warnTrunc = case osTruncate os of
      Just _ | target `notElem` [CfmtIPS, CfmtIPS32] ->
        ["note: dropping truncation marker"]
      _ -> []
    warnEBP = case osEBPMeta os of
      Just _ | target /= CfmtEBP ->
        ["note: dropping EBP metadata"]
      _ -> []

hexBS :: BS.ByteString -> String
hexBS = concatMap (\b -> padHex 2 (fromIntegral b)) . BS.unpack

trimNulSpace :: String -> String
trimNulSpace = reverse . dropWhile (\c -> c == ' ' || c == '\0') . reverse

----------------------------------------------------------------------------
-- Format metadata
----------------------------------------------------------------------------

fmtExt :: CreateFormat -> String
fmtExt CfmtBPS    = ".bps"
fmtExt CfmtIPS    = ".ips"
fmtExt CfmtIPS32  = ".ips"
fmtExt CfmtEBP    = ".ebp"
fmtExt CfmtUPS    = ".ups"
fmtExt CfmtPPF3   = ".ppf"
fmtExt CfmtPMSR   = ".pmsr"
fmtExt CfmtNINJA1 = ".rup"
fmtExt CfmtDPS    = ".dps"
fmtExt CfmtRUP    = ".rup"
fmtExt CfmtAPSN64 = ".aps"
fmtExt CfmtAPSGBA = ".aps"
fmtExt CfmtGDIFF  = ".gdiff"
fmtExt CfmtPCHTXT = ".pchtxt"

fmtName :: CreateFormat -> String
fmtName CfmtBPS    = "BPS"
fmtName CfmtIPS    = "IPS"
fmtName CfmtIPS32  = "IPS32"
fmtName CfmtEBP    = "EBP"
fmtName CfmtUPS    = "UPS"
fmtName CfmtPPF3   = "PPF3"
fmtName CfmtPMSR   = "PMSR"
fmtName CfmtNINJA1 = "NINJA1"
fmtName CfmtDPS    = "DPS"
fmtName CfmtRUP    = "RUP"
fmtName CfmtAPSN64 = "APS (N64)"
fmtName CfmtAPSGBA = "APS (GBA)"
fmtName CfmtGDIFF  = "GDIFF"
fmtName CfmtPCHTXT = "PCHTXT"
