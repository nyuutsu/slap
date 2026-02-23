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
import Patch.IPS (jsonPairs, jsonFieldCI)
import qualified Patch.BPS as BPS
import qualified Patch.UPS as UPS
import qualified Patch.APS as APS
import qualified Patch.RUP as RUP
import qualified Patch.GDIFF as GDIFF
import qualified Patch.PMSR as PMSR
import qualified Patch.DPS as DPS
import qualified Patch.NINJA1 as NINJA1
import qualified Patch.PCHTXT as PCHTXT
import Patch.Binary (diffHunks, crc32, md5, sha1)
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

-- | Universal representation of a direct patch's contents.
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
    | Just md5v <- pcSourceMD5 pc, not (BS.all (== 0) md5v) ->
      ["note: dropping source MD5: " ++ hexBS md5v]
  FSourceSHA1
    | Just sha1v <- pcSourceSHA1 pc, not (BS.all (== 0) sha1v) ->
      ["note: dropping source SHA1: " ++ hexBS sha1v]
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
-- Direct conversion (direct → direct)
----------------------------------------------------------------------------

-- | Convert parsed patch contents to a target format without the source ROM.
convertDirect :: PatchContents -> CreateFormat -> String -> String -> String
              -> Bool -> Bool
              -> Either String (BS.ByteString, [String])
convertDirect pc target cliTitle cliAuthor cliDesc includeUndo includeValidation = case target of
  -- Differential formats always need --with
  CfmtBPS    -> Left (diffOnlyMsg CfmtBPS)
  CfmtUPS    -> Left (diffOnlyMsg CfmtUPS)
  CfmtDPS    -> Left (diffOnlyMsg CfmtDPS)
  CfmtRUP    -> Left (diffOnlyMsg CfmtRUP)
  CfmtAPSGBA -> Left (diffOnlyMsg CfmtAPSGBA)
  CfmtGDIFF  -> Left (diffOnlyMsg CfmtGDIFF)
  -- Direct targets: contract check → offset check → encode
  _ -> do
    let spec = formatSpec target includeUndo includeValidation
    case canConvert pc spec of
      Left missing -> Left (formatMissing target missing)
      Right () -> do
        checkOffsetLimits target (pcRecords pc)
        let notes = conversionNotes pc spec
        Right (encodeDirect pc target cliTitle cliAuthor cliDesc, notes)

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
encodeDirect :: PatchContents -> CreateFormat -> String -> String -> String -> BS.ByteString
encodeDirect pc target cliTitle cliAuthor cliDesc = case target of
  CfmtIPS    -> IPS.encodeIPS splitIPS (pcTruncation pc)
  CfmtIPS32  -> IPS.encodeIPS32 (splitRecords 0xFFFF intRecs) (pcTruncation pc)
  CfmtEBP    -> case if null cliDesc && null cliTitle && null cliAuthor
                     then pcEBPMeta pc else Nothing of
                  Just raw -> IPS.encodeEBPRaw splitIPS raw
                  Nothing  -> IPS.encodeEBP splitIPS (pcTruncation pc)
                                ebpTitle ebpAuthor desc
  CfmtPPF3   -> PPF.encodePPF3 (splitRecords 255 (pcRecords pc)) desc
                   (pcUndoData pc) (pcValidation pc)
  CfmtNINJA1 -> case (pcSourceCRC32 pc, pcSourceMD5 pc, pcSourceSHA1 pc) of
                   (Just crc, Just md5v, Just sha1v) ->
                     NINJA1.encodeNINJA1 intRecs crc md5v sha1v
                   _ -> error "unreachable: canConvert verified"
  CfmtPMSR   -> PMSR.encodePMSR intRecs
  CfmtPCHTXT -> PCHTXT.encodePCHTXT intRecs pchtxtDesc
  CfmtAPSN64 -> case pcDestSize pc of
                  Just sz -> APS.encodeAPSN64 intRecs sz apsDesc
                  Nothing -> error "unreachable: canConvert verified FDestSize"
  -- Differential formats handled in convertDirect, never reach here
  _          -> error "unreachable: differential format in encodeDirect"
  where
    intRecs  = toIntPairs (pcRecords pc)
    splitIPS = splitRecords 0xFFFF intRecs
    desc     = resolveDesc cliDesc (pcEBPMeta pc) (pcDescription pc) ""
    apsDesc  = resolveDesc cliDesc Nothing (pcDescription pc) (replicate 50 ' ')
    pchtxtDesc
      | not (null cliDesc) = Just (BS8.pack cliDesc)
      | otherwise          = pcDescription pc
    ebpPairs = maybe [] jsonPairs (pcEBPMeta pc)
    ebpTitle  = resolveField cliTitle ebpPairs "title"
    ebpAuthor = resolveField cliAuthor ebpPairs "author"

----------------------------------------------------------------------------
-- Create
----------------------------------------------------------------------------

-- | Create a patch from source and target bytes.
createFromMemory :: CreateFormat -> BS.ByteString -> BS.ByteString -> String -> String -> String -> Bool -> Bool -> Either String BS.ByteString
createFromMemory fmt src tgt title author desc undo val
  | isDirect fmt =
      let pc = buildContents fmt src tgt undo val
      in checkOffsetLimits fmt (pcRecords pc)
         >> Right (encodeDirect pc fmt title author desc)
  | otherwise = case fmt of
      CfmtBPS    -> Right (BPS.createBPS src tgt)
      CfmtUPS    -> Right (UPS.createUPS src tgt)
      CfmtDPS    -> Right (DPS.createDPS src tgt)
      CfmtRUP    -> Right (RUP.createRUP src tgt)
      CfmtAPSGBA -> Right (APS.createAPSGBA src tgt)
      CfmtGDIFF  -> Right (GDIFF.createGDIFF src tgt)
      _          -> error "unreachable: all formats handled"

-- | Direct formats that go through PatchContents → encodeDirect.
isDirect :: CreateFormat -> Bool
isDirect CfmtIPS    = True
isDirect CfmtIPS32  = True
isDirect CfmtEBP    = True
isDirect CfmtPPF3   = True
isDirect CfmtNINJA1 = True
isDirect CfmtPMSR   = True
isDirect CfmtPCHTXT = True
isDirect CfmtAPSN64 = True
isDirect _          = False

-- | Build PatchContents from source and target bytes for a direct format.
buildContents :: CreateFormat -> BS.ByteString -> BS.ByteString
              -> Bool -> Bool -> PatchContents
buildContents fmt src tgt includeUndo includeValidation = PatchContents
  { pcRecords     = int64Recs
  , pcDescription = Nothing
  , pcSourceCRC32 = if needs FSourceCRC32 then Just (crc32 src) else Nothing
  , pcSourceMD5   = if needs FSourceMD5   then Just (md5 src)   else Nothing
  , pcSourceSHA1  = if needs FSourceSHA1  then Just (sha1 src)  else Nothing
  , pcDestSize    = if needs FDestSize
                    then Just (fromIntegral (BS.length tgt))
                    else Nothing
  , pcValidation  = if needs FValidation && BS.length src > 0x9320 + 1024
                    then Just (BS.take 1024 (BS.drop 0x9320 src))
                    else Nothing
  , pcUndoData    = if needs FUndoData
                    then Just (computeUndo src int64Recs)
                    else Nothing
  , pcTruncation  = if needs FTruncation && BS.length tgt < BS.length src
                    then Just (fromIntegral (BS.length tgt))
                    else Nothing
  , pcEBPMeta     = Nothing
  }
  where
    hunks     = diffHunks src tgt
    int64Recs = map (\(o, d) -> (fromIntegral o, d)) hunks
    spec      = formatSpec fmt includeUndo includeValidation
    allFields = fsRequired spec `Set.union` fsAccepted spec
    needs f   = f `Set.member` allFields

-- | Compute undo triples from source bytes and diff records.
-- Each record is split at 255 bytes (PPF3 record size limit).
computeUndo :: BS.ByteString -> [(Int64, BS.ByteString)]
            -> [(Int64, BS.ByteString, BS.ByteString)]
computeUndo src = concatMap splitUndo
  where
    srcLen = BS.length src
    splitUndo (off, dat)
      | BS.null dat = []
      | BS.length dat <= 255 =
          [(off, dat, oldBytes (fromIntegral off) (BS.length dat))]
      | otherwise =
          let chunk = BS.take 255 dat
              intOff = fromIntegral off
          in (off, chunk, oldBytes intOff 255)
             : splitUndo (off + 255, BS.drop 255 dat)
    oldBytes off len
      | off >= srcLen = BS.replicate len 0
      | off + len > srcLen =
          BS.take (srcLen - off) (BS.drop off src)
          <> BS.replicate (len - (srcLen - off)) 0
      | otherwise = BS.take len (BS.drop off src)

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
  | Just meta <- ebpMeta
  , Just d <- jsonFieldCI (jsonPairs meta) "description"
  , not (null d) = d
  | Just d <- rawDesc    = trimNulSpace (BS8.unpack d)
  | otherwise            = def

-- | Resolve a single EBP field: CLI flag wins, then fall back to source metadata.
resolveField :: String -> [(String, String)] -> String -> String
resolveField cli pairs key
  | not (null cli) = cli
  | Just v <- jsonFieldCI pairs key = v
  | otherwise = ""

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
