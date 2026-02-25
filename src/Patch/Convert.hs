module Patch.Convert
  ( PatchContents(..)
  , CreateFormat(..)
  , CreateMeta(..)
  , defaultMeta
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
  , createDefaultNotes
  , fmtExt
  , fmtName
  ) where

import qualified Patch.PPF.Create as PPF
import Patch.PPF.Types (ImageType(..))
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

import Control.Applicative ((<|>))
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BS8
import Data.Int (Int64)
import Data.List (intercalate)
import Data.Maybe (fromMaybe, isJust)
import qualified Data.Set as Set
import Data.Word (Word8, Word32, Word64)
import Numeric (showHex)

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
  | FRomType
  | FImageType
  | FFileIdDiz
  | FPCHTXTBlocks
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
  , pcRomType     :: Maybe Word8
    -- ^ See cmRomType comment: Word8 is intentional (NINJA1 vs RUP semantics).
  , pcImageType   :: Maybe ImageType
  , pcFileIdDiz   :: Maybe BS.ByteString
  , pcPCHTXTBlocks :: Maybe [PCHTXT.PCHTXTBlock]
  , pcNINJA1Compressed :: Maybe Bool  -- source was BZ/TZ (compressed)
  }

data CreateFormat
  = CfmtBPS | CfmtIPS | CfmtIPS32 | CfmtEBP | CfmtUPS | CfmtPPF3 | CfmtPMSR
  | CfmtNINJA1 | CfmtDPS | CfmtRUP | CfmtAPSN64 | CfmtAPSGBA | CfmtGDIFF | CfmtPCHTXT
  deriving (Show, Eq)

data CreateMeta = CreateMeta
  { cmTitle       :: String
  , cmAuthor      :: String
  , cmDesc        :: String
  , cmVersion     :: String
  , cmUndo        :: Bool
  , cmValidate    :: Bool
  , cmUnstable    :: Bool
  , cmRomType     :: Maybe Word8
    -- ^ Word8, not a sum type: NINJA1 and RUP both carry a ROM type byte
    -- but with different (and for RUP, unspecified) semantics.  NINJA1
    -- converts at its boundary via toNINJA1RomType; RUP passes through raw.
    -- A shared sum type would force NINJA1 labels onto RUP values.
  , cmImageType   :: Maybe ImageType
  , cmBPSMetadata :: Maybe BS.ByteString
  }

defaultMeta :: CreateMeta
defaultMeta = CreateMeta "" "" "" "" False False False Nothing Nothing Nothing

----------------------------------------------------------------------------
-- PatchContents helpers
----------------------------------------------------------------------------

emptyContents :: [(Int64, BS.ByteString)] -> PatchContents
emptyContents recs = PatchContents
  { pcRecords     = recs
  , pcDescription = Nothing
  , pcSourceCRC32 = Nothing
  , pcSourceMD5   = Nothing
  , pcSourceSHA1  = Nothing
  , pcDestSize    = Nothing
  , pcValidation  = Nothing
  , pcUndoData    = Nothing
  , pcTruncation  = Nothing
  , pcEBPMeta     = Nothing
  , pcRomType     = Nothing
  , pcImageType   = Nothing
  , pcFileIdDiz   = Nothing
  , pcPCHTXTBlocks = Nothing
  , pcNINJA1Compressed = Nothing
  }

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
  ++ [FRomType      | isJust (pcRomType pc)]
  ++ [FImageType    | isJust (pcImageType pc)]
  ++ [FFileIdDiz    | isJust (pcFileIdDiz pc)]
  ++ [FPCHTXTBlocks | isJust (pcPCHTXTBlocks pc)]

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
                             (acc [FDescription, FImageType, FFileIdDiz])
  CfmtNINJA1  -> FormatSpec (req [FSourceCRC32, FSourceMD5, FSourceSHA1]) (acc [FRomType])
  CfmtPMSR    -> FormatSpec (req []) (acc [])
  CfmtPCHTXT  -> FormatSpec (req []) (acc [FDescription, FPCHTXTBlocks])
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
fieldName FRomType     = "ROM type"
fieldName FImageType   = "image type"
fieldName FFileIdDiz   = "File_ID.diz"
fieldName FPCHTXTBlocks = "PCHTXT blocks"

----------------------------------------------------------------------------
-- Conversion notes (dropped-field warnings)
----------------------------------------------------------------------------

conversionNotes :: PatchContents -> CreateFormat -> FormatSpec -> CreateMeta -> [String]
conversionNotes pc target spec meta =
  let have = provides pc
      kept = fsRequired spec `Set.union` fsAccepted spec
      dropped = have `Set.difference` kept `Set.difference` Set.singleton FRecords
      droppedNotes = concatMap (fieldNote pc) (Set.toList dropped)
      interopNotes = ebpTruncMetaNote pc target meta
      defaultNotes = defaultAssumptionNotes target meta (pcRomType pc) (pcImageType pc)
  in droppedNotes ++ interopNotes ++ defaultNotes

-- | Warn when EBP output has both truncation and metadata — RomPatcher.js
-- treats them as mutually exclusive.
ebpTruncMetaNote :: PatchContents -> CreateFormat -> CreateMeta -> [String]
ebpTruncMetaNote pc CfmtEBP meta
  | isJust (pcTruncation pc), hasMeta
  = ["note: EBP truncation + metadata together; may not be compatible with RomPatcher.js"]
  where
    hasMeta = isJust (pcEBPMeta pc) || isJust (pcDescription pc)
           || not (null (cmDesc meta)) || not (null (cmTitle meta)) || not (null (cmAuthor meta))
ebpTruncMetaNote _ _ _ = []

-- | Warn when encodeDirect defaults romType or imgType because neither the
-- CLI flags nor the source patch provided a value.
defaultAssumptionNotes :: CreateFormat -> CreateMeta -> Maybe Word8 -> Maybe ImageType -> [String]
defaultAssumptionNotes target meta srcRomType srcImageType = concat
  [ [ "note: assuming raw ROM type (use --rom-type to specify)"
    | target == CfmtNINJA1
    , Nothing <- [cmRomType meta <|> srcRomType] ]
  , [ "note: assuming BIN image type (use --image-type gi for GI disc images)"
    | target == CfmtPPF3
    , Nothing <- [cmImageType meta <|> srcImageType] ]
  ]

-- | Default-assumption notes for the create and --with convert paths,
-- where no source PatchContents is available.
createDefaultNotes :: CreateFormat -> CreateMeta -> [String]
createDefaultNotes target meta = defaultAssumptionNotes target meta Nothing Nothing

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
  FRomType
    | isJust (pcRomType pc) ->
      ["note: dropping ROM type"]
  FImageType
    | isJust (pcImageType pc) ->
      ["note: dropping image type"]
  FFileIdDiz
    | isJust (pcFileIdDiz pc) ->
      ["note: dropping File_ID.diz"]
  FPCHTXTBlocks
    | Just blocks <- pcPCHTXTBlocks pc ->
      let disabled = sum (map (length . PCHTXT.pchtxtBlockEntries)
                              (filter (not . PCHTXT.pchtxtBlockEnabled) blocks))
          hasDescs = any (isJust . PCHTXT.pchtxtBlockDesc) blocks
      in concat
        [ ["note: dropping " ++ show disabled ++ " disabled entries" | disabled > 0]
        , ["note: dropping block descriptions" | hasDescs]
        ]
  _ -> []

----------------------------------------------------------------------------
-- Direct conversion (direct → direct)
----------------------------------------------------------------------------

-- | Convert parsed patch contents to a target format without the source ROM.
convertDirect :: PatchContents -> CreateFormat -> CreateMeta
              -> Either String (BS.ByteString, [String])
convertDirect pc target meta = case target of
  -- Differential formats always need --with
  CfmtBPS    -> Left (diffOnlyMsg CfmtBPS)
  CfmtUPS    -> Left (diffOnlyMsg CfmtUPS)
  CfmtDPS    -> Left (diffOnlyMsg CfmtDPS)
  CfmtRUP    -> Left (diffOnlyMsg CfmtRUP)
  CfmtAPSGBA -> Left (diffOnlyMsg CfmtAPSGBA)
  CfmtGDIFF  -> Left (diffOnlyMsg CfmtGDIFF)
  -- Direct targets: contract check → offset check → sentinel check → encode
  _ -> do
    let spec = formatSpec target (cmUndo meta) (cmValidate meta)
    case canConvert pc spec of
      Left missing -> Left (formatMissing target missing)
      Right () -> do
        checkOffsetLimits target (pcRecords pc)
        checkSentinelCollision target (pcRecords pc)
        let notes = conversionNotes pc target spec meta
        Right (encodeDirect pc BS.empty target meta, notes)

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

-- | Reject direct conversion to IPS/IPS32/EBP when a record starts at the
-- EOF sentinel offset.  Without source bytes, avoidSentinel can't shift the
-- record back safely.
checkSentinelCollision :: CreateFormat -> [(Int64, BS.ByteString)] -> Either String ()
checkSentinelCollision target recs = case sentinel of
    Nothing -> Right ()
    Just s
      | any (\(off, _) -> off == s) recs ->
          Left (fmtName target ++ ": record at offset 0x"
             ++ showHexInt64 s
             ++ " collides with EOF marker; use --with SOURCE to provide source bytes for safe encoding")
      | otherwise -> Right ()
  where
    sentinel = case target of
      CfmtIPS   -> Just 0x454F46
      CfmtEBP   -> Just 0x454F46
      CfmtIPS32 -> Just 0x45454F46
      _         -> Nothing
    showHexInt64 :: Int64 -> String
    showHexInt64 n = showHex (fromIntegral n :: Word64) ""

-- | Encode PatchContents into the target format.
encodeDirect :: PatchContents -> BS.ByteString -> CreateFormat -> CreateMeta -> BS.ByteString
encodeDirect pc src target meta = case target of
  CfmtIPS    -> IPS.encodeIPS src splitIPS (pcTruncation pc)
  CfmtIPS32  -> IPS.encodeIPS32 src (splitRecords 0xFFFF intRecs) (pcTruncation pc)
  CfmtEBP    -> case if null cliDesc && null cliTitle && null cliAuthor
                     then pcEBPMeta pc else Nothing of
                  Just raw -> IPS.encodeEBPRaw src splitIPS (pcTruncation pc) raw
                  Nothing  -> IPS.encodeEBP src splitIPS (pcTruncation pc)
                                ebpTitle ebpAuthor desc
  CfmtPPF3   -> let base = PPF.encodePPF3 (splitRecords 255 (pcRecords pc)) desc
                              (pcUndoData pc) (pcValidation pc) imgType
                 in case pcFileIdDiz pc of
                      Nothing  -> base
                      Just diz -> base <> PPF.encodeFileIdDiz diz
  CfmtNINJA1 -> case (pcSourceCRC32 pc, pcSourceMD5 pc, pcSourceSHA1 pc) of
                   (Just crc, Just md5v, Just sha1v) ->
                     NINJA1.encodeNINJA1 intRecs crc md5v sha1v romType
                       (fromMaybe False (pcNINJA1Compressed pc))
                   _ -> error "unreachable: canConvert verified"
  CfmtPMSR   -> PMSR.encodePMSR intRecs
  CfmtPCHTXT -> case pcPCHTXTBlocks pc of
                   Just blocks -> PCHTXT.encodePCHTXTBlocks blocks pchtxtDesc
                   Nothing     -> PCHTXT.encodePCHTXT intRecs pchtxtDesc
  CfmtAPSN64 -> case pcDestSize pc of
                  Just sz -> APS.encodeAPSN64 intRecs sz apsDesc
                  Nothing -> error "unreachable: canConvert verified FDestSize"
  -- Differential formats handled in convertDirect, never reach here
  _          -> error "unreachable: differential format in encodeDirect"
  where
    cliDesc   = cmDesc meta
    cliTitle  = cmTitle meta
    cliAuthor = cmAuthor meta
    intRecs   = toIntPairs (pcRecords pc)
    splitIPS  = splitRecords 0xFFFF intRecs
    desc      = resolveDesc cliDesc (pcEBPMeta pc) (pcDescription pc) ""
    apsDesc   = resolveDesc cliDesc Nothing (pcDescription pc) (replicate 50 ' ')
    pchtxtDesc
      | not (null cliDesc) = Just (BS8.pack cliDesc)
      | otherwise          = pcDescription pc
    ebpPairs  = maybe [] jsonPairs (pcEBPMeta pc)
    ebpTitle  = resolveField cliTitle ebpPairs "title"
    ebpAuthor = resolveField cliAuthor ebpPairs "author"
    -- CLI flag > PatchContents > format default
    romType   = maybe NINJA1.RomRAW NINJA1.toNINJA1RomType (cmRomType meta <|> pcRomType pc)
    imgType   = fromMaybe BIN (cmImageType meta <|> pcImageType pc)

----------------------------------------------------------------------------
-- Create
----------------------------------------------------------------------------

-- | Create a patch from source and target bytes.
createFromMemory :: CreateFormat -> BS.ByteString -> BS.ByteString -> CreateMeta -> Either String BS.ByteString
createFromMemory fmt src tgt m
  | isDirect fmt =
      let pc = buildContents fmt src tgt m
      in checkOffsetLimits fmt (pcRecords pc)
         >> Right (encodeDirect pc src fmt m)
  | otherwise = case fmt of
      CfmtBPS    -> Right (BPS.createBPS src tgt (fromMaybe BS.empty (cmBPSMetadata m)))
      CfmtUPS    -> Right (UPS.createUPS src tgt)
      CfmtDPS    -> Right (DPS.createDPS src tgt
                     (if null (cmTitle m) then cmDesc m else cmTitle m)
                     (cmAuthor m) (cmVersion m)
                     (if cmUnstable m then DPS.DPSUnstable else DPS.DPSStable))
      CfmtRUP    -> Right (RUP.createRUP src tgt rupInfo (fromMaybe 0 (cmRomType m)))
        where rupInfo = RUP.RUPInfo
                (toMaybe (cmAuthor m)) (toMaybe (cmVersion m))
                (toMaybe (cmTitle m)) Nothing Nothing Nothing Nothing
                (toMaybe (cmDesc m))
              toMaybe s = if null s then Nothing else Just (BS8.pack s)
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
              -> CreateMeta -> PatchContents
buildContents fmt src tgt meta = PatchContents
  { pcRecords     = int64Recs
  , pcDescription = Nothing
  , pcSourceCRC32 = if needs FSourceCRC32 then Just (crc32 hashSrc) else Nothing
  , pcSourceMD5   = if needs FSourceMD5   then Just (md5 hashSrc)   else Nothing
  , pcSourceSHA1  = if needs FSourceSHA1  then Just (sha1 hashSrc)  else Nothing
  , pcDestSize    = if needs FDestSize
                    then Just (fromIntegral (BS.length tgt))
                    else Nothing
  , pcValidation  = if needs FValidation && BS.length src > valOff + 1024
                    then Just (BS.take 1024 (BS.drop valOff src))
                    else Nothing
  , pcUndoData    = if needs FUndoData
                    then Just (computeUndo src int64Recs)
                    else Nothing
  , pcTruncation  = if needs FTruncation && BS.length tgt < BS.length src
                    then Just (fromIntegral (BS.length tgt))
                    else Nothing
  , pcEBPMeta     = Nothing
  , pcRomType     = Nothing
  , pcImageType   = Nothing
  , pcFileIdDiz   = Nothing
  , pcPCHTXTBlocks = Nothing
  , pcNINJA1Compressed = Nothing
  }
  where
    hunks     = case fmt of
      CfmtIPS   -> IPS.optimalIPSRecords 3 src tgt
      CfmtIPS32 -> IPS.optimalIPSRecords 4 src tgt
      CfmtEBP   -> IPS.optimalIPSRecords 3 src tgt
      _         -> diffHunks src tgt
    int64Recs = map (\(o, d) -> (fromIntegral o, d)) hunks
    hashSrc   = case fmt of
      CfmtNINJA1 -> NINJA1.ninja1HashInput src
      _          -> src
    valOff    = case cmImageType meta of
                  Just GI -> 0x80A0
                  _       -> 0x9320
    spec      = formatSpec fmt (cmUndo meta) (cmValidate meta)
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
