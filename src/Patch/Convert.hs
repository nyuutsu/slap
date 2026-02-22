module Patch.Convert
  ( PatchContents(..)
  , CreateFormat(..)
  , PatchField(..)
  , FormatSpec(..)
  , emptyContents
  , provides
  , formatSpec
  , canConvert
  , conversionNotes
  , fieldName
  , convertDirect
  , createFromMemory
  , fmtExt
  , fmtName
  ) where

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
import Data.Int (Int64)
import Data.List (intercalate)
import Data.Maybe (isJust)
import qualified Data.Set as Set
import Data.Word (Word32)

----------------------------------------------------------------------------
-- Types
----------------------------------------------------------------------------

-- | Fields a patch format can provide or require.
data PatchField
  = FRecords
  | FDescription
  | FSourceCRC32
  | FSourceMD5
  | FSourceSHA1
  | FDestSize
  | FUndoData
  | FValidation
  | FTruncation
  | FEBPMeta
  deriving (Eq, Ord, Show)

-- | Declares what a target format requires and can accept.
data FormatSpec = FormatSpec
  { fsRequired :: Set.Set PatchField
  , fsAccepted :: Set.Set PatchField
  }

-- | Universal representation of a direct (overlay) patch's contents.
data PatchContents = PatchContents
  { pcRecords     :: [(Int64, BS.ByteString)]
  , pcDescription :: Maybe BS.ByteString
  , pcSourceCRC32 :: Maybe Word32
  , pcSourceMD5   :: Maybe BS.ByteString
  , pcSourceSHA1  :: Maybe BS.ByteString
  , pcDestSize    :: Maybe Word32
  , pcValidation  :: Maybe BS.ByteString
  , pcUndoData    :: Maybe [(Int64, BS.ByteString, BS.ByteString)]
  , pcTruncation  :: Maybe Int64
  , pcEBPMeta     :: Maybe BS.ByteString
  }

data CreateFormat
  = CfmtBPS | CfmtIPS | CfmtIPS32 | CfmtEBP | CfmtUPS | CfmtPPF3 | CfmtPMSR
  | CfmtNINJA1 | CfmtDPS | CfmtRUP | CfmtAPSN64 | CfmtAPSGBA | CfmtGDIFF | CfmtPCHTXT
  deriving (Show, Eq)

----------------------------------------------------------------------------
-- PatchContents helpers
----------------------------------------------------------------------------

emptyContents :: [(Int64, BS.ByteString)] -> PatchContents
emptyContents recs = PatchContents
  recs Nothing Nothing Nothing Nothing Nothing Nothing Nothing Nothing Nothing

provides :: PatchContents -> Set.Set PatchField
provides pc = Set.fromList $ [FRecords]
  ++ [FDescription  | isJust (pcDescription pc)]
  ++ [FSourceCRC32  | isJust (pcSourceCRC32 pc)]
  ++ [FSourceMD5    | isJust (pcSourceMD5 pc)]
  ++ [FSourceSHA1   | isJust (pcSourceSHA1 pc)]
  ++ [FDestSize     | isJust (pcDestSize pc)]
  ++ [FUndoData     | isJust (pcUndoData pc)]
  ++ [FValidation   | isJust (pcValidation pc)]
  ++ [FTruncation   | isJust (pcTruncation pc)]
  ++ [FEBPMeta      | isJust (pcEBPMeta pc)]

----------------------------------------------------------------------------
-- Format specs
----------------------------------------------------------------------------

formatSpec :: CreateFormat -> Bool -> Bool -> FormatSpec
formatSpec target includeUndo includeValidation = case target of
  CfmtIPS     -> FormatSpec (req []) (acc [FTruncation])
  CfmtIPS32   -> FormatSpec (req []) (acc [FTruncation])
  CfmtEBP     -> FormatSpec (req []) (acc [FDescription, FTruncation, FEBPMeta])
  CfmtPPF3    -> FormatSpec (req $ [FUndoData  | includeUndo]
                                 ++ [FValidation | includeValidation])
                             (acc [FDescription])
  CfmtNINJA1  -> FormatSpec (req [FSourceCRC32, FSourceMD5, FSourceSHA1]) (acc [])
  CfmtPMSR    -> FormatSpec (req []) (acc [])
  CfmtPCHTXT  -> FormatSpec (req []) (acc [FDescription])
  CfmtAPSN64  -> FormatSpec (req [FDestSize]) (acc [FDescription])
  -- Differential formats: specs unused (rejected before contract check)
  _           -> FormatSpec (req []) (acc [])
  where
    req extra = Set.fromList (FRecords : extra)
    acc = Set.fromList

----------------------------------------------------------------------------
-- Contract checking
----------------------------------------------------------------------------

canConvert :: PatchContents -> FormatSpec -> Either (Set.Set PatchField) ()
canConvert pc spec =
  let have = provides pc
      need = fsRequired spec
      missing = need `Set.difference` have
  in if Set.null missing then Right () else Left missing

formatMissing :: CreateFormat -> Set.Set PatchField -> String
formatMissing target missing = header ++ skipHint ++ withHint
  where
    header = "cannot convert to " ++ fmtName target ++ ": source lacks "
          ++ intercalate ", " (map fieldName (Set.toList missing))
    skipHint
      | FUndoData `Set.member` missing, FValidation `Set.member` missing
        = "\nuse --no-undo and --no-validate to skip, or"
      | FUndoData `Set.member` missing
        = "\nuse --no-undo to skip, or"
      | FValidation `Set.member` missing
        = "\nuse --no-validate to skip, or"
      | otherwise = ""
    withHint
      | null skipHint = "\nuse --with SOURCE to provide " ++ pronoun
      | otherwise     = "\n--with SOURCE to provide " ++ pronoun
    pronoun = if Set.size missing == 1 then "it" else "them"

fieldName :: PatchField -> String
fieldName FRecords     = "records"
fieldName FDescription = "description"
fieldName FSourceCRC32 = "source CRC32"
fieldName FSourceMD5   = "source MD5"
fieldName FSourceSHA1  = "source SHA1"
fieldName FDestSize    = "target file size"
fieldName FUndoData    = "undo data"
fieldName FValidation  = "validation block"
fieldName FTruncation  = "truncation marker"
fieldName FEBPMeta     = "EBP metadata"

----------------------------------------------------------------------------
-- Conversion notes (dropped-field warnings)
----------------------------------------------------------------------------

conversionNotes :: PatchContents -> FormatSpec -> [String]
conversionNotes pc spec =
  let have = provides pc
      kept = fsRequired spec `Set.union` fsAccepted spec
      dropped = have `Set.difference` kept `Set.difference` Set.singleton FRecords
  in concatMap (fieldNote pc) (Set.toList dropped)

fieldNote :: PatchContents -> PatchField -> [String]
fieldNote pc field = case field of
  FSourceCRC32
    | Just crc <- pcSourceCRC32 pc, crc /= 0 ->
      ["note: dropping source CRC32: 0x" ++ showCRC crc]
  FSourceMD5
    | Just md5 <- pcSourceMD5 pc, not (BS.all (== 0) md5) ->
      ["note: dropping source MD5: " ++ hexBS md5]
  FSourceSHA1
    | Just sha1 <- pcSourceSHA1 pc, not (BS.all (== 0) sha1) ->
      ["note: dropping source SHA1: " ++ hexBS sha1]
  FDescription
    | Just d <- pcDescription pc
    , not (BS.all (\b -> b == 0x20 || b == 0) d) ->
      ["note: dropping description: \"" ++ trimNulSpace (BS8.unpack d) ++ "\""]
  FUndoData
    | Just u <- pcUndoData pc ->
      ["note: dropping undo data (" ++ show (length u) ++ " records)"]
  FValidation
    | isJust (pcValidation pc) ->
      ["note: dropping 1024-byte validation block"]
  FDestSize
    | Just sz <- pcDestSize pc ->
      ["note: dropping file size: " ++ show sz ++ " bytes"]
  FTruncation
    | isJust (pcTruncation pc) ->
      ["note: dropping truncation marker"]
  FEBPMeta
    | isJust (pcEBPMeta pc) ->
      ["note: dropping EBP metadata"]
  _ -> []

----------------------------------------------------------------------------
-- Direct conversion (overlay → overlay)
----------------------------------------------------------------------------

-- | Convert parsed patch contents to a target format without the source ROM.
convertDirect :: PatchContents -> CreateFormat -> String -> Bool -> Bool
              -> Either String (BS.ByteString, [String])
convertDirect pc target cliDesc includeUndo includeValidation = case target of
  -- Differential formats always need --with
  CfmtBPS    -> Left (diffOnlyMsg CfmtBPS)
  CfmtUPS    -> Left (diffOnlyMsg CfmtUPS)
  CfmtDPS    -> Left (diffOnlyMsg CfmtDPS)
  CfmtRUP    -> Left (diffOnlyMsg CfmtRUP)
  CfmtAPSGBA -> Left (diffOnlyMsg CfmtAPSGBA)
  CfmtGDIFF  -> Left (diffOnlyMsg CfmtGDIFF)
  -- Overlay targets: contract check → offset check → encode
  _ -> do
    let spec = formatSpec target includeUndo includeValidation
    case canConvert pc spec of
      Left missing -> Left (formatMissing target missing)
      Right () -> do
        checkOffsetLimits target (pcRecords pc)
        let notes = conversionNotes pc spec
        Right (encodeDirect pc target cliDesc, notes)

diffOnlyMsg :: CreateFormat -> String
diffOnlyMsg fmt = fmtName fmt ++ " requires source+target diff data\nuse --with SOURCE"

-- | Check that offsets fit in IPS/EBP 24-bit range.
checkOffsetLimits :: CreateFormat -> [(Int64, BS.ByteString)] -> Either String ()
checkOffsetLimits target recs
  | target `elem` [CfmtIPS, CfmtEBP]
  , any (\(off, _) -> off > 0xFFFFFF) recs
  = Left ("patch has offsets > 16 MB \8212 cannot convert to " ++ fmtName target
       ++ "\nuse --to ips32, or --with SOURCE to re-diff")
  | otherwise = Right ()

-- | Encode PatchContents into the target format.
encodeDirect :: PatchContents -> CreateFormat -> String -> BS.ByteString
encodeDirect pc target cliDesc = case target of
  CfmtIPS    -> IPS.encodeIPS intRecs (pcTruncation pc)
  CfmtIPS32  -> IPS.encodeIPS32 (splitRecords 0xFFFF intRecs) (pcTruncation pc)
  CfmtEBP    -> case if null cliDesc then pcEBPMeta pc else Nothing of
                  Just raw -> IPS.encodeEBPRaw intRecs raw
                  Nothing  -> IPS.encodeEBP intRecs (pcTruncation pc) desc
  CfmtPPF3   -> PPF.encodePPF3 (splitRecords 255 (pcRecords pc)) desc
                   (pcUndoData pc) (pcValidation pc)
  CfmtNINJA1 -> case (pcSourceCRC32 pc, pcSourceMD5 pc, pcSourceSHA1 pc) of
                   (Just crc, Just md5v, Just sha1v) ->
                     NINJA1.encodeNINJA1 intRecs crc md5v sha1v
                   _ -> error "unreachable: canConvert verified"
  CfmtPMSR   -> PMSR.encodePMSR intRecs
  CfmtPCHTXT -> PCHTXT.encodePCHTXT intRecs (pcDescription pc)
  CfmtAPSN64 -> case pcDestSize pc of
                  Just sz -> APS.encodeAPSN64 intRecs sz apsDesc
                  Nothing -> error "unreachable: canConvert verified FDestSize"
  -- Differential formats handled in convertDirect, never reach here
  _          -> error "unreachable: differential format in encodeDirect"
  where
    intRecs = toIntPairs (pcRecords pc)
    desc    = resolveDesc cliDesc (pcEBPMeta pc) (pcDescription pc) ""
    apsDesc = resolveDesc cliDesc Nothing (pcDescription pc) (replicate 50 ' ')

----------------------------------------------------------------------------
-- Create
----------------------------------------------------------------------------

-- | Create a patch from source and target bytes.
createFromMemory :: CreateFormat -> BS.ByteString -> BS.ByteString -> String -> Bool -> Bool -> Either String BS.ByteString
createFromMemory CfmtBPS    src tgt _    _    _   = Right (BPS.createBPS src tgt)
createFromMemory CfmtUPS    src tgt _    _    _   = Right (UPS.createUPS src tgt)
createFromMemory CfmtPMSR   src tgt _    _    _   = Right (PMSR.createPMSR src tgt)
createFromMemory CfmtIPS    src tgt _    _    _   = IPS.createIPS src tgt
createFromMemory CfmtIPS32  src tgt _    _    _   = IPS.createIPS32 src tgt
createFromMemory CfmtEBP    src tgt desc _    _   = IPS.createEBP src tgt desc
createFromMemory CfmtPPF3   src tgt desc undo val = Right (PPF.createPatchPure src tgt desc undo val)
createFromMemory CfmtNINJA1 src tgt _    _    _   = Right (NINJA1.createNINJA1 src tgt)
createFromMemory CfmtDPS    src tgt _    _    _   = Right (DPS.createDPS src tgt)
createFromMemory CfmtRUP    src tgt _    _    _   = Right (RUP.createRUP src tgt)
createFromMemory CfmtAPSN64 src tgt _    _    _   = Right (APS.createAPSN64 src tgt)
createFromMemory CfmtAPSGBA src tgt _    _    _   = Right (APS.createAPSGBA src tgt)
createFromMemory CfmtGDIFF  src tgt _    _    _   = Right (GDIFF.createGDIFF src tgt)
createFromMemory CfmtPCHTXT src tgt _    _    _   = Right (PCHTXT.createPCHTXT src tgt)

----------------------------------------------------------------------------
-- Internal helpers
----------------------------------------------------------------------------

-- | Split records so each data chunk is ≤ maxSize bytes.
splitRecords :: (Integral a) => Int -> [(a, BS.ByteString)] -> [(a, BS.ByteString)]
splitRecords maxSize = concatMap split1
  where
    split1 (off, dat)
      | BS.length dat <= maxSize = [(off, dat)]
      | otherwise =
          let (h, t) = BS.splitAt maxSize dat
          in (off, h) : split1 (off + fromIntegral maxSize, t)

-- | Convert Int64 offset pairs to Int pairs for format encoders.
toIntPairs :: [(Int64, BS.ByteString)] -> [(Int, BS.ByteString)]
toIntPairs = map (\(off, dat) -> (fromIntegral off, dat))

-- | Resolve a description from CLI flag, EBP metadata, raw description, or default.
resolveDesc :: String -> Maybe BS.ByteString -> Maybe BS.ByteString -> String -> String
resolveDesc cliDesc ebpMeta rawDesc def
  | not (null cliDesc) = cliDesc
  | Just meta <- ebpMeta = extractEBPDesc meta
  | Just d <- rawDesc    = trimNulSpace (BS8.unpack d)
  | otherwise            = def
  where
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
