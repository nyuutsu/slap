module Patch.Convert
  ( PatchContents(..)
  , CreateFormat(..)
  , CreateMeta(..)
  , defaultMeta
  , PatchField(..)
  , FormatSpecification(..)
  , emptyContents
  , provides
  , formatSpecification
  , canConvert
  , conversionNotes
  , fieldName
  , convertDirect
  , createFromMemory
  , createDefaultNotes
  , formatExtension
  , formatName
  ) where

import qualified Patch.PPF.Create as PPF
import Patch.PPF.Types (ImageType(..))
import qualified Patch.IPS as IPS
import Patch.IPS (jsonPairs, jsonFieldCI)
import qualified Patch.BPS as BPS
import qualified Patch.UPS as UPS
import qualified Patch.APS.N64 as APSN64
import qualified Patch.APS.GBA as APSGBA
import qualified Patch.RUP as RUP
import qualified Patch.GDIFF as GDIFF
import qualified Patch.PMSR as PMSR
import qualified Patch.DPS as DPS
import qualified Patch.NINJA1 as NINJA1
import qualified Patch.PCHTXT as PCHTXT
import Patch.Binary (diffHunks, md5, sha1)
import Patch.FFI (rustyCRC32)
import Patch.Measure (Offset(..), FileSize(..), Hunk(..), UndoHunk(..),
                      EncodedHunk(..), EncodingLimits(..),
                      narrowHunks, narrowHunksUnbounded,
                      ipsLimits, ips32Limits, ebpLimits)
import Patch.Format (showCRC, padHex)

import Control.Applicative ((<|>))
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Char8 as ByteString8
import Data.List (intercalate)
import Data.Maybe (fromMaybe, isJust, isNothing)
import qualified Data.Set as Set
import Data.Word (Word8, Word32)

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
  | FDestinationSize
  | FUndoData
  | FValidation
  | FTruncation
  | FEBPMeta
  | FRomType
  | FImageType
  | FFileIdDiz
  | FPCHTXTBlocks
  | FMetadata
  deriving (Eq, Ord, Show)

-- | Declares what a target format requires and can accept.
data FormatSpecification = FormatSpecification
  { specificationRequired :: Set.Set PatchField
  , specificationAccepted :: Set.Set PatchField
  }

-- | Universal representation of a direct patch's contents.
data PatchContents = PatchContents
  { contentsRecords     :: [Hunk]
  , contentsDescription :: Maybe ByteString.ByteString
  , contentsSourceCRC32 :: Maybe Word32
  , contentsSourceMD5   :: Maybe ByteString.ByteString
  , contentsSourceSHA1  :: Maybe ByteString.ByteString
  , contentsDestinationSize    :: Maybe FileSize
  , contentsValidation  :: Maybe ByteString.ByteString
  , contentsUndoData    :: Maybe [UndoHunk]
  , contentsTruncation  :: Maybe FileSize
  , contentsEBPMeta     :: Maybe ByteString.ByteString
  , contentsRomType     :: Maybe Word8
    -- ^ See metaRomType comment: Word8 is intentional (NINJA1 vs RUP semantics).
  , contentsImageType   :: Maybe ImageType
  , contentsFileIdDiz   :: Maybe ByteString.ByteString
  , contentsPCHTXTBlocks :: Maybe [PCHTXT.PCHTXTBlock]
  , contentsNINJA1Compressed :: Maybe Bool  -- source was BZ/TZ (compressed)
  , contentsMetadata :: Maybe ByteString.ByteString
    -- ^ Arbitrary metadata blob (BPS). Most formats don't carry this.
  }

data CreateFormat
  = CreateBPS | CreateIPS | CreateIPS32 | CreateEBP | CreateUPS | CreatePPF3 | CreatePMSR
  | CreateNINJA1 | CreateDPS | CreateRUP | CreateAPSN64 | CreateAPSGBA | CreateGDIFF | CreatePCHTXT
  deriving (Show, Eq)

data CreateMeta = CreateMeta
  { metaTitle       :: Maybe String
  , metaAuthor      :: Maybe String
  , metaDescription        :: Maybe String
  , metaVersion     :: Maybe String
  , metaUndo        :: Bool
  , metaValidate    :: Bool
  , metaUnstable    :: Bool
  , metaRomType     :: Maybe Word8
    -- ^ Word8, not a sum type: NINJA1 and RUP both carry a ROM type byte
    -- but with different (and for RUP, unspecified) semantics.  NINJA1
    -- converts at its boundary via toNINJA1RomType; RUP passes through raw.
    -- A shared sum type would force NINJA1 labels onto RUP values.
  , metaImageType   :: Maybe ImageType
  , metaBPSMetadata :: Maybe ByteString.ByteString
  }

defaultMeta :: CreateMeta
defaultMeta = CreateMeta
  { metaTitle       = Nothing
  , metaAuthor      = Nothing
  , metaDescription        = Nothing
  , metaVersion     = Nothing
  , metaUndo        = False
  , metaValidate    = False
  , metaUnstable    = False
  , metaRomType     = Nothing
  , metaImageType   = Nothing
  , metaBPSMetadata = Nothing
  }

----------------------------------------------------------------------------
-- PatchContents helpers
----------------------------------------------------------------------------

emptyContents :: [Hunk] -> PatchContents
emptyContents records = PatchContents
  { contentsRecords     = records
  , contentsDescription = Nothing
  , contentsSourceCRC32 = Nothing
  , contentsSourceMD5   = Nothing
  , contentsSourceSHA1  = Nothing
  , contentsDestinationSize    = Nothing
  , contentsValidation  = Nothing
  , contentsUndoData    = Nothing
  , contentsTruncation  = Nothing
  , contentsEBPMeta     = Nothing
  , contentsRomType     = Nothing
  , contentsImageType   = Nothing
  , contentsFileIdDiz   = Nothing
  , contentsPCHTXTBlocks = Nothing
  , contentsNINJA1Compressed = Nothing
  , contentsMetadata = Nothing
  }

provides :: PatchContents -> Set.Set PatchField
provides contents = Set.fromList $ [FRecords]
  ++ [FDescription  | isJust (contentsDescription contents)]
  ++ [FSourceCRC32  | isJust (contentsSourceCRC32 contents)]
  ++ [FSourceMD5    | isJust (contentsSourceMD5 contents)]
  ++ [FSourceSHA1   | isJust (contentsSourceSHA1 contents)]
  ++ [FDestinationSize     | isJust (contentsDestinationSize contents)]
  ++ [FUndoData     | isJust (contentsUndoData contents)]
  ++ [FValidation   | isJust (contentsValidation contents)]
  ++ [FTruncation   | isJust (contentsTruncation contents)]
  ++ [FEBPMeta      | isJust (contentsEBPMeta contents)]
  ++ [FRomType      | isJust (contentsRomType contents)]
  ++ [FImageType    | isJust (contentsImageType contents)]
  ++ [FFileIdDiz    | isJust (contentsFileIdDiz contents)]
  ++ [FPCHTXTBlocks | isJust (contentsPCHTXTBlocks contents)]
  ++ [FMetadata     | isJust (contentsMetadata contents)]

----------------------------------------------------------------------------
-- Format specs
----------------------------------------------------------------------------

formatSpecification :: CreateFormat -> Bool -> Bool -> FormatSpecification
formatSpecification target includeUndo includeValidation = case target of
  CreateIPS     -> FormatSpecification (requiredFields []) (acceptedFields [FTruncation])
  CreateIPS32   -> FormatSpecification (requiredFields []) (acceptedFields [FTruncation])
  CreateEBP     -> FormatSpecification (requiredFields []) (acceptedFields [FDescription, FTruncation, FEBPMeta])
  CreatePPF3    -> FormatSpecification (requiredFields $ [FUndoData  | includeUndo]
                                 ++ [FValidation | includeValidation])
                             (acceptedFields [FDescription, FImageType, FFileIdDiz])
  CreateNINJA1  -> FormatSpecification (requiredFields [FSourceCRC32, FSourceMD5, FSourceSHA1]) (acceptedFields [FRomType])
  CreatePMSR    -> FormatSpecification (requiredFields []) (acceptedFields [])
  CreatePCHTXT  -> FormatSpecification (requiredFields []) (acceptedFields [FDescription, FPCHTXTBlocks])
  CreateAPSN64  -> FormatSpecification (requiredFields [FDestinationSize]) (acceptedFields [FDescription])
  -- Differential formats: specs unused (rejected before contract check)
  _           -> FormatSpecification (requiredFields []) (acceptedFields [])
  where
    requiredFields extra = Set.fromList (FRecords : extra)
    acceptedFields = Set.fromList

----------------------------------------------------------------------------
-- Contract checking
----------------------------------------------------------------------------

canConvert :: PatchContents -> FormatSpecification -> Either (Set.Set PatchField) ()
canConvert contents spec =
  let have = provides contents
      need = specificationRequired spec
      missing = need `Set.difference` have
  in if Set.null missing then Right () else Left missing

formatMissing :: CreateFormat -> Set.Set PatchField -> String
formatMissing target missing = header ++ skipHint ++ withHint
  where
    header = "cannot convert to " ++ formatName target ++ ": source lacks "
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
fieldName FDestinationSize    = "target file size"
fieldName FUndoData    = "undo data"
fieldName FValidation  = "validation block"
fieldName FTruncation  = "truncation marker"
fieldName FEBPMeta     = "EBP metadata"
fieldName FRomType     = "ROM type"
fieldName FImageType   = "image type"
fieldName FFileIdDiz   = "File_ID.diz"
fieldName FPCHTXTBlocks = "PCHTXT blocks"
fieldName FMetadata     = "metadata"

----------------------------------------------------------------------------
-- Conversion notes (dropped-field warnings)
----------------------------------------------------------------------------

conversionNotes :: PatchContents -> CreateFormat -> FormatSpecification -> CreateMeta -> [String]
conversionNotes contents target spec meta =
  let have = provides contents
      kept = specificationRequired spec `Set.union` specificationAccepted spec
      dropped = have `Set.difference` kept `Set.difference` Set.singleton FRecords
      droppedNotes = concatMap (fieldNote contents) (Set.toList dropped)
      interopNotes = ebpTruncMetaNote contents target meta
      defaultNotes = defaultAssumptionNotes target meta (contentsRomType contents) (contentsImageType contents)
  in droppedNotes ++ interopNotes ++ defaultNotes

-- | Warn when EBP output has both truncation and metadata — RomPatcher.js
-- treats them as mutually exclusive.
ebpTruncMetaNote :: PatchContents -> CreateFormat -> CreateMeta -> [String]
ebpTruncMetaNote contents CreateEBP meta
  | isJust (contentsTruncation contents), hasMeta
  = ["note: EBP truncation + metadata together; may not be compatible with RomPatcher.js"]
  where
    hasMeta = isJust (contentsEBPMeta contents) || isJust (contentsDescription contents)
           || isJust (metaDescription meta) || isJust (metaTitle meta) || isJust (metaAuthor meta)
ebpTruncMetaNote _ _ _ = []

-- | Warn when encodeDirect defaults romType or imageType because neither the
-- CLI flags nor the source patch provided a value.
defaultAssumptionNotes :: CreateFormat -> CreateMeta -> Maybe Word8 -> Maybe ImageType -> [String]
defaultAssumptionNotes target meta sourceRomType sourceImageType = concat
  [ [ "note: assuming raw ROM type (use --rom-type to specify)"
    | target == CreateNINJA1
    , Nothing <- [metaRomType meta <|> sourceRomType] ]
  , [ "note: assuming BIN image type (use --image-type gi for GI disc images)"
    | target == CreatePPF3
    , Nothing <- [metaImageType meta <|> sourceImageType] ]
  ]

-- | Default-assumption notes for the create and --with convert paths,
-- where no source PatchContents is available.
createDefaultNotes :: CreateFormat -> CreateMeta -> [String]
createDefaultNotes target meta = defaultAssumptionNotes target meta Nothing Nothing

fieldNote :: PatchContents -> PatchField -> [String]
fieldNote contents field = case field of
  FSourceCRC32
    | Just crc <- contentsSourceCRC32 contents, crc /= 0 ->
      ["note: dropping source CRC32: 0x" ++ showCRC crc]
  FSourceMD5
    | Just md5Hash <- contentsSourceMD5 contents, not (ByteString.all (== 0) md5Hash) ->
      ["note: dropping source MD5: " ++ hexByteString md5Hash]
  FSourceSHA1
    | Just sha1Hash <- contentsSourceSHA1 contents, not (ByteString.all (== 0) sha1Hash) ->
      ["note: dropping source SHA1: " ++ hexByteString sha1Hash]
  FDescription
    | Just description <- contentsDescription contents
    , not (ByteString.all (\byte -> byte == 0x20 || byte == 0) description) ->
      ["note: dropping description: \"" ++ trimNullSpace (ByteString8.unpack description) ++ "\""]
  FUndoData
    | Just undoRecords <- contentsUndoData contents ->
      ["note: dropping undo data (" ++ show (length undoRecords) ++ " records)"]
  FValidation
    | isJust (contentsValidation contents) ->
      ["note: dropping 1024-byte validation block"]
  FDestinationSize
    | Just targetSize <- contentsDestinationSize contents ->
      ["note: dropping file size: " ++ show (unFileSize targetSize) ++ " bytes"]
  FTruncation
    | isJust (contentsTruncation contents) ->
      ["note: dropping truncation marker"]
  FEBPMeta
    | isJust (contentsEBPMeta contents) ->
      ["note: dropping EBP metadata"]
  FRomType
    | isJust (contentsRomType contents) ->
      ["note: dropping ROM type"]
  FImageType
    | isJust (contentsImageType contents) ->
      ["note: dropping image type"]
  FFileIdDiz
    | isJust (contentsFileIdDiz contents) ->
      ["note: dropping File_ID.diz"]
  FPCHTXTBlocks
    | Just blocks <- contentsPCHTXTBlocks contents ->
      let disabled = sum (map (length . PCHTXT.pchtxtBlockEntries)
                              (filter (not . PCHTXT.pchtxtBlockEnabled) blocks))
          hasDescriptions = any (isJust . PCHTXT.pchtxtBlockDescription) blocks
      in concat
        [ ["note: dropping " ++ show disabled ++ " disabled entries" | disabled > 0]
        , ["note: dropping block descriptions" | hasDescriptions]
        ]
  FMetadata
    | Just metadataBlob <- contentsMetadata contents, not (ByteString.null metadataBlob) ->
      ["note: dropping metadata (" ++ show (ByteString.length metadataBlob) ++ " bytes)"]
  _ -> []

----------------------------------------------------------------------------
-- Direct conversion (direct → direct)
----------------------------------------------------------------------------

-- | Convert parsed patch contents to a target format without the source ROM.
convertDirect :: PatchContents -> CreateFormat -> CreateMeta
              -> Either String (ByteString.ByteString, [String])
convertDirect contents target meta = case target of
  -- Differential formats always need --with
  CreateBPS    -> Left (diffOnlyMsg CreateBPS)
  CreateUPS    -> Left (diffOnlyMsg CreateUPS)
  CreateDPS    -> Left (diffOnlyMsg CreateDPS)
  CreateRUP    -> Left (diffOnlyMsg CreateRUP)
  CreateAPSGBA -> Left (diffOnlyMsg CreateAPSGBA)
  CreateGDIFF  -> Left (diffOnlyMsg CreateGDIFF)
  -- Direct targets: contract check → narrow (validates limits) → encode
  _ -> do
    let spec = formatSpecification target (metaUndo meta) (metaValidate meta)
    case canConvert contents spec of
      Left missing -> Left (formatMissing target missing)
      Right () -> do
        _ <- case encodingLimits target of
               Just limits -> narrowHunks limits (contentsRecords contents)
               Nothing     -> Right (narrowHunksUnbounded (contentsRecords contents))
        let notes = conversionNotes contents target spec meta
        Right (encodeDirect contents ByteString.empty target meta, notes)

diffOnlyMsg :: CreateFormat -> String
diffOnlyMsg format = formatName format ++ " requires source+target diff data\nuse --with SOURCE"

-- | Encoding limits for formats with constrained offset ranges and sentinels.
encodingLimits :: CreateFormat -> Maybe EncodingLimits
encodingLimits CreateIPS   = Just ipsLimits
encodingLimits CreateIPS32 = Just ips32Limits
encodingLimits CreateEBP   = Just ebpLimits
encodingLimits _           = Nothing

-- | Encode PatchContents into the target format.
encodeDirect :: PatchContents -> ByteString.ByteString -> CreateFormat -> CreateMeta -> ByteString.ByteString
encodeDirect contents source target meta = case target of
  CreateIPS    -> IPS.encodeIPS source splitIPSRecords (contentsTruncation contents)
  CreateIPS32  -> IPS.encodeIPS32 source (narrowHunksUnbounded (splitHunks 0xFFFF (contentsRecords contents))) (contentsTruncation contents)
  CreateEBP    -> let passthrough = if isNothing cliDescription && isNothing cliTitle && isNothing cliAuthor
                                  then contentsEBPMeta contents else Nothing
                 in case passthrough of
                      Just raw -> IPS.encodeEBPRaw source splitIPSRecords (contentsTruncation contents) raw
                      Nothing  -> IPS.encodeEBP source splitIPSRecords (contentsTruncation contents)
                                    ebpTitle ebpAuthor description
  CreatePPF3   -> let base = PPF.encodePPF3 (splitHunks 255 (contentsRecords contents)) description
                              (contentsUndoData contents) (contentsValidation contents) imageType
                 in case contentsFileIdDiz contents of
                      Nothing  -> base
                      Just diz -> base <> PPF.encodeFileIdDiz diz
  CreateNINJA1 -> case (contentsSourceCRC32 contents, contentsSourceMD5 contents, contentsSourceSHA1 contents) of
                   (Just crc, Just md5Hash, Just sha1Hash) ->
                     NINJA1.encodeNINJA1 encodedRecords crc md5Hash sha1Hash romType
                       (fromMaybe False (contentsNINJA1Compressed contents))
                   _ -> error "unreachable: canConvert verified"
  CreatePMSR   -> PMSR.encodePMSR encodedRecords
  CreatePCHTXT -> case contentsPCHTXTBlocks contents of
                   Just blocks -> PCHTXT.encodePCHTXTBlocks blocks pchtxtDescription
                   Nothing     -> PCHTXT.encodePCHTXT encodedRecords pchtxtDescription
  CreateAPSN64 -> case contentsDestinationSize contents of
                  Just targetSize -> APSN64.encodeAPSN64 encodedRecords (fromIntegral (unFileSize targetSize)) apsDescription
                  Nothing -> error "unreachable: canConvert verified FDestinationSize"
  -- Differential formats handled in convertDirect, never reach here
  _          -> error "unreachable: differential format in encodeDirect"
  where
    cliDescription   = metaDescription meta
    cliTitle  = metaTitle meta
    cliAuthor = metaAuthor meta
    encodedRecords   = narrowHunksUnbounded (contentsRecords contents)
    splitIPSRecords  = narrowHunksUnbounded (splitHunks 0xFFFF (contentsRecords contents))
    description   = resolveDescription cliDescription (contentsEBPMeta contents) (contentsDescription contents) ""
    apsDescription = resolveDescription cliDescription Nothing (contentsDescription contents) (replicate 50 ' ')
    pchtxtDescription = fmap ByteString8.pack cliDescription <|> contentsDescription contents
    ebpFieldPairs = maybe [] jsonPairs (contentsEBPMeta contents)
    ebpTitle  = resolveField cliTitle ebpFieldPairs "title"
    ebpAuthor = resolveField cliAuthor ebpFieldPairs "author"
    -- CLI flag > PatchContents > format default
    romType   = maybe NINJA1.RomRAW NINJA1.toNINJA1RomType (metaRomType meta <|> contentsRomType contents)
    imageType   = fromMaybe BIN (metaImageType meta <|> contentsImageType contents)

----------------------------------------------------------------------------
-- Create
----------------------------------------------------------------------------

-- | Create a patch from source and target bytes.
createFromMemory :: CreateFormat -> ByteString.ByteString -> ByteString.ByteString -> CreateMeta -> Either String ByteString.ByteString
createFromMemory format source target meta
  | isDirect format =
      let contents = buildContents format source target meta
          -- Source bytes available: avoidSentinel handles sentinel collisions
          -- at encode time, so only validate offset limits here.
          offsetLimits = case encodingLimits format of
            Just limits -> narrowHunks (limits { sentinelOffset = Nothing }) (contentsRecords contents)
            Nothing     -> Right (narrowHunksUnbounded (contentsRecords contents))
      in offsetLimits >> Right (encodeDirect contents source format meta)
  | otherwise = case format of
      CreateBPS    -> Right (BPS.createBPS source target (fromMaybe ByteString.empty (metaBPSMetadata meta)))
      CreateUPS    -> Right (UPS.createUPS source target)
      CreateDPS    -> Right (DPS.createDPS source target
                     (fromMaybe "" (metaTitle meta <|> metaDescription meta))
                     (fromMaybe "" (metaAuthor meta)) (fromMaybe "" (metaVersion meta))
                     (if metaUnstable meta then DPS.DPSUnstable else DPS.DPSStable))
      CreateRUP    -> Right (RUP.createRUP source target rupInfo (fromMaybe 0 (metaRomType meta)))
        where rupInfo = RUP.RUPInfo
                { RUP.rupAuthor = fmap ByteString8.pack (metaAuthor meta), RUP.rupVersion = fmap ByteString8.pack (metaVersion meta)
                , RUP.rupTitle = fmap ByteString8.pack (metaTitle meta), RUP.rupGenre = Nothing
                , RUP.rupLanguage = Nothing, RUP.rupDate = Nothing
                , RUP.rupWebsite = Nothing, RUP.rupDescription = fmap ByteString8.pack (metaDescription meta)
                }
      CreateAPSGBA -> Right (APSGBA.createAPSGBA source target)
      CreateGDIFF  -> Right (GDIFF.createGDIFF source target)
      _          -> error "unreachable: all formats handled"

-- | Direct formats that go through PatchContents → encodeDirect.
isDirect :: CreateFormat -> Bool
isDirect CreateIPS    = True
isDirect CreateIPS32  = True
isDirect CreateEBP    = True
isDirect CreatePPF3   = True
isDirect CreateNINJA1 = True
isDirect CreatePMSR   = True
isDirect CreatePCHTXT = True
isDirect CreateAPSN64 = True
isDirect _          = False

-- | Build PatchContents from source and target bytes for a direct format.
buildContents :: CreateFormat -> ByteString.ByteString -> ByteString.ByteString
              -> CreateMeta -> PatchContents
buildContents format source target meta = PatchContents
  { contentsRecords     = patchHunks
  , contentsDescription = Nothing
  , contentsSourceCRC32 = if needs FSourceCRC32 then Just (rustyCRC32 hashSource) else Nothing
  , contentsSourceMD5   = if needs FSourceMD5   then Just (md5 hashSource)   else Nothing
  , contentsSourceSHA1  = if needs FSourceSHA1  then Just (sha1 hashSource)  else Nothing
  , contentsDestinationSize    = if needs FDestinationSize
                    then Just (FileSize (fromIntegral (ByteString.length target)))
                    else Nothing
  , contentsValidation  = if needs FValidation && ByteString.length source > validationOffset + 1024
                    then Just (ByteString.take 1024 (ByteString.drop validationOffset source))
                    else Nothing
  , contentsUndoData    = if needs FUndoData
                    then Just (computeUndo source patchHunks)
                    else Nothing
  , contentsTruncation  = if needs FTruncation && ByteString.length target < ByteString.length source
                    then Just (FileSize (fromIntegral (ByteString.length target)))
                    else Nothing
  , contentsEBPMeta     = Nothing
  , contentsRomType     = Nothing
  , contentsImageType   = Nothing
  , contentsFileIdDiz   = Nothing
  , contentsPCHTXTBlocks = Nothing
  , contentsNINJA1Compressed = Nothing
  , contentsMetadata = Nothing
  }
  where
    encodedToHunk (EncodedHunk hunkOffset hunkPayload) = Hunk (Offset (fromIntegral hunkOffset)) hunkPayload
    patchHunks = case format of
      CreateIPS   -> map encodedToHunk (IPS.optimalIPSRecords 3 source target)
      CreateIPS32 -> map encodedToHunk (IPS.optimalIPSRecords 4 source target)
      CreateEBP   -> map encodedToHunk (IPS.optimalIPSRecords 3 source target)
      _         -> diffHunks source target
    hashSource   = case format of
      CreateNINJA1 -> NINJA1.ninja1HashInput source
      _          -> source
    validationOffset = case metaImageType meta of
                         Just GI -> 0x80A0
                         _       -> 0x9320
    spec      = formatSpecification format (metaUndo meta) (metaValidate meta)
    allFields = specificationRequired spec `Set.union` specificationAccepted spec
    needs field = field `Set.member` allFields

-- | Compute undo hunks from source bytes and diff records.
-- Each record is split at 255 bytes (PPF3 record size limit).
computeUndo :: ByteString.ByteString -> [Hunk] -> [UndoHunk]
computeUndo source = concatMap splitUndo
  where
    sourceLength = ByteString.length source
    splitUndo (Hunk hunkOffset hunkPayload)
      | ByteString.null hunkPayload = []
      | ByteString.length hunkPayload <= 255 =
          [UndoHunk hunkOffset hunkPayload (oldBytes (fromIntegral (unOffset hunkOffset)) (ByteString.length hunkPayload))]
      | otherwise =
          let chunk = ByteString.take 255 hunkPayload
              intOffset = fromIntegral (unOffset hunkOffset)
          in UndoHunk hunkOffset chunk (oldBytes intOffset 255)
             : splitUndo (Hunk (Offset (unOffset hunkOffset + 255)) (ByteString.drop 255 hunkPayload))
    oldBytes position chunkLength
      | position >= sourceLength = ByteString.replicate chunkLength 0
      | position + chunkLength > sourceLength =
          ByteString.take (sourceLength - position) (ByteString.drop position source)
          <> ByteString.replicate (chunkLength - (sourceLength - position)) 0
      | otherwise = ByteString.take chunkLength (ByteString.drop position source)

----------------------------------------------------------------------------
-- Internal helpers
----------------------------------------------------------------------------

-- | Split hunks so each payload is ≤ maxSize bytes.
splitHunks :: Int -> [Hunk] -> [Hunk]
splitHunks maxSize = concatMap splitOne
  where
    splitOne (Hunk hunkOffset hunkPayload)
      | ByteString.length hunkPayload <= maxSize = [Hunk hunkOffset hunkPayload]
      | otherwise =
          let (chunk, rest) = ByteString.splitAt maxSize hunkPayload
              nextOffset = Offset (unOffset hunkOffset + fromIntegral maxSize)
          in Hunk hunkOffset chunk : splitOne (Hunk nextOffset rest)

-- | Resolve a description from CLI flag, EBP metadata, raw description, or default.
resolveDescription :: Maybe String -> Maybe ByteString.ByteString -> Maybe ByteString.ByteString -> String -> String
resolveDescription cliDescription ebpMeta rawDescription fallback
  | Just description <- cliDescription = description
  | Just meta <- ebpMeta
  , Just description <- jsonFieldCI (jsonPairs meta) "description"
  , not (null description) = description
  | Just raw <- rawDescription    = trimNullSpace (ByteString8.unpack raw)
  | otherwise              = fallback

-- | Resolve a single EBP field: CLI flag wins, then fall back to source metadata.
resolveField :: Maybe String -> [(String, String)] -> String -> String
resolveField cliValue pairs key
  | Just provided <- cliValue = provided
  | Just value <- jsonFieldCI pairs key = value
  | otherwise = ""

hexByteString :: ByteString.ByteString -> String
hexByteString = concatMap (\byte -> padHex 2 (fromIntegral byte)) . ByteString.unpack

trimNullSpace :: String -> String
trimNullSpace = reverse . dropWhile (\char -> char == ' ' || char == '\0') . reverse

----------------------------------------------------------------------------
-- Format metadata
----------------------------------------------------------------------------

formatExtension :: CreateFormat -> String
formatExtension CreateBPS    = ".bps"
formatExtension CreateIPS    = ".ips"
formatExtension CreateIPS32  = ".ips"
formatExtension CreateEBP    = ".ebp"
formatExtension CreateUPS    = ".ups"
formatExtension CreatePPF3   = ".ppf"
formatExtension CreatePMSR   = ".pmsr"
formatExtension CreateNINJA1 = ".rup"
formatExtension CreateDPS    = ".dps"
formatExtension CreateRUP    = ".rup"
formatExtension CreateAPSN64 = ".aps"
formatExtension CreateAPSGBA = ".aps"
formatExtension CreateGDIFF  = ".gdiff"
formatExtension CreatePCHTXT = ".pchtxt"

formatName :: CreateFormat -> String
formatName CreateBPS    = "BPS"
formatName CreateIPS    = "IPS"
formatName CreateIPS32  = "IPS32"
formatName CreateEBP    = "EBP"
formatName CreateUPS    = "UPS"
formatName CreatePPF3   = "PPF3"
formatName CreatePMSR   = "PMSR"
formatName CreateNINJA1 = "NINJA1"
formatName CreateDPS    = "DPS"
formatName CreateRUP    = "RUP"
formatName CreateAPSN64 = "APS (N64)"
formatName CreateAPSGBA = "APS (GBA)"
formatName CreateGDIFF  = "GDIFF"
formatName CreatePCHTXT = "PCHTXT"
