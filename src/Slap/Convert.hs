module Slap.Convert
  ( PatchContents(..)
  , DirectCreate(..)
  , DiffCreate(..)
  , CreateFormat(..)
  , CreateMeta(..)
  , defaultMeta
  , FormatSpecification(..)
  , emptyContents
  , provides
  , formatSpecification
  , canConvert
  , conversionNotes
  , convertDirect
  , createFromMemory
  , createDefaultNotes
  , mergeMeta
  , trimNullSpace
  , formatExtension
  , formatName
  , PatchEncoding(..)
  ) where

import qualified Slap.PPF.Create as PPF
import Slap.PPF.Types (ImageType(..))
import qualified Slap.IPS.Create as IPS
import Slap.IPS.Create (splitHunks)
import Slap.IPS.Types (ipsMaxRecordData)
import Slap.IPS.Describe (jsonPairs, jsonFieldCI)
import qualified Slap.BPS.Create as BPS
import qualified Slap.UPS.Create as UPS
import qualified Slap.APSN64.Create as APSN64
import qualified Slap.APSGBA.Create as APSGBA
import Slap.RUP.Types (PatchEncoding(..))
import qualified Slap.RUP.Types as RUP
import qualified Slap.RUP.Create as RUP
import qualified Slap.GDIFF.Create as GDIFF
import qualified Slap.PMSR.Create as PMSR
import qualified Slap.DPS.Types as DPS
import qualified Slap.DPS.Create as DPS
import qualified Slap.NINJA1.Types as NINJA1
import qualified Slap.NINJA1.Create as NINJA1
import qualified Slap.PCHTXT.Types as PCHTXT
import qualified Slap.PCHTXT.Create as PCHTXT
import Slap.Binary (diffHunks, md5, sha1)
import Slap.Checksum (CRC32(..), MD5Hash(..), SHA1Hash(..))
import Slap.FFI (rustyCRC32)
import Slap.Measure (Offset(..), FileSize(..), Length(..), Hunk(..), UndoHunk(..),
                      EncodedHunk(..), EncodingLimits(..),
                      advance, narrowHunks, narrowHunksUnbounded,
                      ipsLimits, ips32Limits, ebpLimits)
import Slap.Error (SlapError(..), SlapWarning(..), DroppedValue(..), CreateResult(..))
import Slap.FormatLabel (FormatLabel(..))
import Slap.PatchField (PatchField(..))

import Slap.TextEncoding (isValidUtf8, decodeLocaleField)

import Control.Applicative ((<|>))
import qualified Data.ByteString as ByteString
import Data.Maybe (fromMaybe, isJust, isNothing)
import qualified Data.Set as Set
import Data.Word (Word8)

----------------------------------------------------------------------------
-- Types
----------------------------------------------------------------------------

-- | Declares what a target format requires and can accept.
data FormatSpecification = FormatSpecification
  { specificationRequired :: Set.Set PatchField
  , specificationAccepted :: Set.Set PatchField
  }

-- | Universal representation of a direct patch's contents.
data PatchContents = PatchContents
  { contentsRecords     :: [Hunk]
  , contentsDescription :: Maybe ByteString.ByteString
  , contentsSourceCRC32 :: Maybe CRC32
  , contentsSourceMD5   :: Maybe MD5Hash
  , contentsSourceSHA1  :: Maybe SHA1Hash
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
  , contentsNINJA1Compressed :: Maybe Bool  -- patch used compressed subformat (BZ/TZ)
  , contentsMetadata :: Maybe ByteString.ByteString
    -- ^ Arbitrary metadata blob (BPS). Most formats don't carry this.
  , contentsPatchEncoding :: Maybe PatchEncoding
    -- ^ Text encoding of description/metadata fields, when the source
    -- format carries an encoding flag (e.g. RUP PATCH_ENC).  Nothing
    -- for formats with opaque byte fields (PPF, DPS, APSN64).
  }

-- | Direct creation target.  Some format families have multiple creation
-- variants: IPS has three (IPS, IPS32, EBP) distinguished by offset width
-- and metadata; PPF exposes only version 3.
data DirectCreate
  = CreateIPS | CreateIPS32 | CreateEBP | CreatePPF3
  | CreateNINJA1 | CreatePMSR | CreatePCHTXT | CreateAPSN64
  deriving (Show, Eq)

-- | Differential creation target.  Formats slap can parse but not yet
-- create (VCDIFF, BSDiff, XDelta1) belong to DiffFormat (the format
-- taxonomy) but not here (slap's current creation capability).
data DiffCreate
  = CreateBPS | CreateUPS | CreateDPS | CreateRUP
  | CreateAPSGBA | CreateGDIFF
  deriving (Show, Eq)

-- | Target format for patch creation or conversion.
data CreateFormat
  = CreateDirect DirectCreate
  | CreateDiff DiffCreate
  deriving (Show, Eq)

data CreateMeta = CreateMeta
  { metaTitle       :: Maybe String
  , metaAuthor      :: Maybe String
  , metaDescription        :: Maybe String
  , metaVersion     :: Maybe String
  , metaUndo        :: Maybe Bool
  , metaValidate    :: Maybe Bool
  , metaUnstable    :: Maybe Bool
  , metaRomType     :: Maybe Word8
    -- ^ Word8, not a sum type: NINJA1 and RUP both carry a ROM type byte
    -- but with different (and for RUP, unspecified) semantics.  NINJA1
    -- converts at its boundary via toNINJA1RomType; RUP passes through raw.
    -- A shared sum type would force NINJA1 labels onto RUP values.
  , metaImageType   :: Maybe ImageType
  , metaGenre       :: Maybe String
  , metaLanguage    :: Maybe String
  , metaDate        :: Maybe String
  , metaWebsite     :: Maybe String
  , metaPatchEncoding :: PatchEncoding
  , metaBPSMetadata :: Maybe ByteString.ByteString
  }

defaultMeta :: CreateMeta
defaultMeta = CreateMeta
  { metaTitle       = Nothing
  , metaAuthor      = Nothing
  , metaDescription        = Nothing
  , metaVersion     = Nothing
  , metaUndo        = Nothing
  , metaValidate    = Nothing
  , metaUnstable    = Nothing
  , metaRomType     = Nothing
  , metaImageType   = Nothing
  , metaGenre       = Nothing
  , metaLanguage    = Nothing
  , metaDate        = Nothing
  , metaWebsite     = Nothing
  , metaPatchEncoding = PatchEncodingUTF8
  , metaBPSMetadata = Nothing
  }

-- | Merge two metadata records: first (CLI) wins for each field, then
-- second (source patch).  For non-Maybe fields like 'metaPatchEncoding',
-- the first argument always wins.
mergeMeta :: CreateMeta -> CreateMeta -> CreateMeta
mergeMeta cli source = CreateMeta
  { metaTitle         = metaTitle cli <|> metaTitle source
  , metaAuthor        = metaAuthor cli <|> metaAuthor source
  , metaDescription   = metaDescription cli <|> metaDescription source
  , metaVersion       = metaVersion cli <|> metaVersion source
  , metaUndo          = metaUndo cli <|> metaUndo source
  , metaValidate      = metaValidate cli <|> metaValidate source
  , metaUnstable      = metaUnstable cli <|> metaUnstable source
  , metaRomType       = metaRomType cli <|> metaRomType source
  , metaImageType     = metaImageType cli <|> metaImageType source
  , metaGenre         = metaGenre cli <|> metaGenre source
  , metaLanguage      = metaLanguage cli <|> metaLanguage source
  , metaDate          = metaDate cli <|> metaDate source
  , metaWebsite       = metaWebsite cli <|> metaWebsite source
  , metaPatchEncoding = metaPatchEncoding cli
  , metaBPSMetadata   = metaBPSMetadata cli <|> metaBPSMetadata source
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
  , contentsPatchEncoding = Nothing
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

formatSpecification :: DirectCreate -> Bool -> Bool -> FormatSpecification
formatSpecification target includeUndo includeValidation = case target of
  CreateIPS     -> FormatSpecification (requiredFields []) (acceptedFields [FTruncation])
  CreateIPS32   -> FormatSpecification (requiredFields []) (acceptedFields [FTruncation])
  CreateEBP     -> FormatSpecification (requiredFields []) (acceptedFields [FDescription, FTruncation, FEBPMeta])
  CreatePPF3    -> FormatSpecification (requiredFields $ [FUndoData  | includeUndo]
                                 ++ [FValidation | includeValidation])
                             (acceptedFields [FDescription, FImageType, FFileIdDiz])
  CreateNINJA1  -> FormatSpecification (requiredFields []) (acceptedFields [FSourceCRC32, FSourceMD5, FSourceSHA1, FRomType])
  CreatePMSR    -> FormatSpecification (requiredFields []) (acceptedFields [])
  CreatePCHTXT  -> FormatSpecification (requiredFields []) (acceptedFields [FDescription, FPCHTXTBlocks])
  CreateAPSN64  -> FormatSpecification (requiredFields [FDestinationSize]) (acceptedFields [FDescription])
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

----------------------------------------------------------------------------
-- Conversion notes (dropped-field warnings)
----------------------------------------------------------------------------

conversionNotes :: PatchContents -> DirectCreate -> FormatSpecification -> CreateMeta -> [SlapWarning]
conversionNotes contents target spec meta =
  let have = provides contents
      kept = specificationRequired spec `Set.union` specificationAccepted spec
      dropped = have `Set.difference` kept `Set.difference` Set.singleton FRecords
      droppedNotes = concatMap (fieldNote contents) (Set.toList dropped)
      interopNotes = ebpTruncMetaNote contents target meta
      defaultNotes = defaultAssumptionNotes target meta (contentsRomType contents) (contentsImageType contents)
      hashNotes = ninja1HashNotes contents target
      encodingNotes = encodingGapNotes contents target
  in droppedNotes ++ interopNotes ++ defaultNotes ++ hashNotes ++ encodingNotes

-- | Warn when converting from a format with known text encoding to one
-- without an encoding flag.  The bytes are copied unchanged — but the
-- target has no way to record what encoding they are.
encodingGapNotes :: PatchContents -> DirectCreate -> [SlapWarning]
encodingGapNotes contents target = case contentsPatchEncoding contents of
  Just _ | isJust (contentsDescription contents)
         , target `elem` [CreatePPF3, CreateAPSN64]
         -> [EncodingGap LabelRUP (directLabel target)]
  _ -> []

-- | Warn when EBP output has both truncation and metadata — RomPatcher.js
-- treats them as mutually exclusive.
ebpTruncMetaNote :: PatchContents -> DirectCreate -> CreateMeta -> [SlapWarning]
ebpTruncMetaNote contents CreateEBP meta
  | isJust (contentsTruncation contents), hasMeta
  = [EBPTruncationMetaConflict]
  where
    hasMeta = isJust (contentsEBPMeta contents) || isJust (contentsDescription contents)
           || isJust (metaDescription meta) || isJust (metaTitle meta) || isJust (metaAuthor meta)
ebpTruncMetaNote _ _ _ = []

-- | Warn when encodeDirect defaults romType or imageType because neither the
-- CLI flags nor the source patch provided a value.
defaultAssumptionNotes :: DirectCreate -> CreateMeta -> Maybe Word8 -> Maybe ImageType -> [SlapWarning]
defaultAssumptionNotes target meta sourceRomType sourceImageType = concat
  [ [ DefaultRomType LabelNINJA1
    | target == CreateNINJA1
    , Nothing <- [metaRomType meta <|> sourceRomType] ]
  , [ DefaultImageType LabelPPF3
    | target == CreatePPF3
    , Nothing <- [metaImageType meta <|> sourceImageType] ]
  ]

-- | Default-assumption notes for the create and --with convert paths,
-- where no source PatchContents is available.
createDefaultNotes :: CreateFormat -> CreateMeta -> [SlapWarning]
createDefaultNotes (CreateDirect target) meta = defaultAssumptionNotes target meta Nothing Nothing
  ++ undoValidateNotes target meta
createDefaultNotes (CreateDiff CreateRUP) meta = snd (prepareRUP meta)
createDefaultNotes (CreateDiff _) _ = []

-- | Build a RUPInfo from CreateMeta and compute its truncation warnings.
-- Single source of truth for RUPInfo construction — used by both the create
-- path (which needs the RUPInfo) and the notes path (which needs the warnings).
prepareRUP :: CreateMeta -> (RUP.RUPInfo, [SlapWarning])
prepareRUP meta = (rupInfo, RUP.rupTruncationNotes patchEncoding rupInfo)
  where
    patchEncoding = metaPatchEncoding meta
    encode = RUP.encodeRUPString patchEncoding
    rupInfo = RUP.RUPInfo
      { RUP.rupAuthor      = fmap encode (metaAuthor meta)
      , RUP.rupVersion     = fmap encode (metaVersion meta)
      , RUP.rupTitle       = fmap encode (metaTitle meta)
      , RUP.rupGenre       = fmap encode (metaGenre meta)
      , RUP.rupLanguage    = fmap encode (metaLanguage meta)
      , RUP.rupDate        = fmap encode (metaDate meta)
      , RUP.rupWebsite     = fmap encode (metaWebsite meta)
      , RUP.rupDescription = fmap encode (metaDescription meta)
      }

-- | Warn when undo/validation are included by default (no CLI flag, no
-- inherited source value).  Same pattern as rom-type defaulting to RAW.
undoValidateNotes :: DirectCreate -> CreateMeta -> [SlapWarning]
undoValidateNotes CreatePPF3 meta = concat
  [ [ IncludingUndoByDefault | Nothing <- [metaUndo meta] ]
  , [ IncludingValidationByDefault | Nothing <- [metaValidate meta] ]
  ]
undoValidateNotes _ _ = []

-- | Note when converting to NINJA1 without source verification hashes.
ninja1HashNotes :: PatchContents -> DirectCreate -> [SlapWarning]
ninja1HashNotes contents CreateNINJA1
  | isNothing (contentsSourceCRC32 contents)
    || isNothing (contentsSourceMD5 contents)
    || isNothing (contentsSourceSHA1 contents)
  = [SourceHashesMissing LabelNINJA1]
ninja1HashNotes _ _ = []

fieldNote :: PatchContents -> PatchField -> [SlapWarning]
fieldNote contents field = case field of
  FSourceCRC32
    | Just crc <- contentsSourceCRC32 contents, crc /= CRC32 0 ->
      [FieldDropped FSourceCRC32 (DroppedCRC crc)]
  FSourceMD5
    | Just hash <- contentsSourceMD5 contents, not (ByteString.all (== 0) (unMD5Hash hash)) ->
      [FieldDropped FSourceMD5 (DroppedMD5 hash)]
  FSourceSHA1
    | Just hash <- contentsSourceSHA1 contents, not (ByteString.all (== 0) (unSHA1Hash hash)) ->
      [FieldDropped FSourceSHA1 (DroppedSHA1 hash)]
  FDescription
    | Just description <- contentsDescription contents
    , not (ByteString.all (\byte -> byte == 0x20 || byte == 0) description) ->
      [FieldDropped FDescription (DroppedDescription (trimNullSpace (decodeLocaleField description)))]
  FUndoData
    | Just undoRecords <- contentsUndoData contents ->
      [UndoDataDropped (length undoRecords)]
  FValidation
    | isJust (contentsValidation contents) ->
      [ValidationBlockDropped]
  FDestinationSize
    | Just targetSize <- contentsDestinationSize contents ->
      [FieldDropped FDestinationSize (DroppedSize targetSize)]
  FTruncation
    | isJust (contentsTruncation contents) ->
      [FieldDropped FTruncation DroppedEmpty]
  FEBPMeta
    | isJust (contentsEBPMeta contents) ->
      [FieldDropped FEBPMeta DroppedEmpty]
  FRomType
    | isJust (contentsRomType contents) ->
      [FieldDropped FRomType DroppedEmpty]
  FImageType
    | isJust (contentsImageType contents) ->
      [FieldDropped FImageType DroppedEmpty]
  FFileIdDiz
    | isJust (contentsFileIdDiz contents) ->
      [FieldDropped FFileIdDiz DroppedEmpty]
  FPCHTXTBlocks
    | Just blocks <- contentsPCHTXTBlocks contents ->
      let disabled = sum (map (length . PCHTXT.pchtxtBlockEntries)
                              (filter (not . PCHTXT.pchtxtBlockEnabled) blocks))
          hasDescriptions = any (isJust . PCHTXT.pchtxtBlockDescription) blocks
      in concat
        [ [DisabledEntriesDropped disabled | disabled > 0]
        , [BlockDescriptionsDropped | hasDescriptions]
        ]
  FMetadata
    | Just metadataBlob <- contentsMetadata contents, not (ByteString.null metadataBlob) ->
      [MetadataDropped (ByteString.length metadataBlob)]
  _ -> []

----------------------------------------------------------------------------
-- Direct conversion (direct → direct)
----------------------------------------------------------------------------

-- | Convert parsed patch contents to a target format without the source ROM.
convertDirect :: PatchContents -> CreateFormat -> CreateMeta
              -> Either SlapError CreateResult
convertDirect _ (CreateDiff target) _ = Left (DiffRequiresSource (diffLabel target))
convertDirect contents (CreateDirect target) meta = do
  let includeUndo = fromMaybe (isJust (contentsUndoData contents)) (metaUndo meta)
      includeValidation = fromMaybe (isJust (contentsValidation contents)) (metaValidate meta)
      spec = formatSpecification target includeUndo includeValidation
  case canConvert contents spec of
    Left missing -> Left (MissingRequiredField (directLabel target) (Set.findMin missing))
    Right () -> do
      -- Full limits including sentinel: convertDirect has no source bytes,
      -- so avoidSentinel can't fix collisions at encode time.
      let notes = conversionNotes contents target spec meta
      encoded <- encodeDirect contents ByteString.empty target meta (encodingLimits target)
      Right CreateResult
        { resultBytes    = resultBytes encoded
        , resultWarnings = notes ++ resultWarnings encoded
        }

-- | Encoding limits for formats with constrained offset ranges and sentinels.
encodingLimits :: DirectCreate -> Maybe EncodingLimits
encodingLimits CreateIPS   = Just ipsLimits
encodingLimits CreateIPS32 = Just ips32Limits
encodingLimits CreateEBP   = Just ebpLimits
encodingLimits _           = Nothing

-- | Encode PatchContents into the target format.
-- Validation (offset range, sentinel collision) runs after format-specific
-- splitting, so split-induced sentinel collisions are caught.
encodeDirect :: PatchContents -> ByteString.ByteString -> DirectCreate -> CreateMeta
             -> Maybe EncodingLimits -> Either SlapError CreateResult
encodeDirect contents source target meta limits = case target of
  CreateIPS -> do
    records <- narrow (splitHunks ipsMaxRecordData (contentsRecords contents))
    Right (CreateResult (IPS.encodeIPS source records (contentsTruncation contents)) [])
  CreateIPS32 -> do
    records <- narrow (splitHunks ipsMaxRecordData (contentsRecords contents))
    Right (CreateResult (IPS.encodeIPS32 source records (contentsTruncation contents)) [])
  CreateEBP -> do
    records <- narrow (splitHunks ipsMaxRecordData (contentsRecords contents))
    -- Pass through raw EBP JSON when metadata values match what the JSON
    -- already provides.  This detects CLI overrides: if the user changed
    -- a field, the values diverge and we rebuild the JSON.
    let passthrough = case contentsEBPMeta contents of
          Nothing -> Nothing
          Just raw ->
            let pairs = jsonPairs raw
                normalizeEmpty (Just value) = if null value then Nothing else Just value
                normalizeEmpty Nothing  = Nothing
            in if cliDescription == normalizeEmpty (jsonFieldCI pairs "description")
                  && cliTitle == normalizeEmpty (jsonFieldCI pairs "title")
                  && cliAuthor == normalizeEmpty (jsonFieldCI pairs "author")
               then Just raw
               else Nothing
    Right $ case passthrough of
      Just raw -> CreateResult (IPS.encodeEBPRaw source records (contentsTruncation contents) raw) []
      Nothing  -> CreateResult (IPS.encodeEBP source records (contentsTruncation contents)
                    ebpTitle ebpAuthor description) []
  CreatePPF3 ->
    -- PPF3 has no encoding limits and takes [Hunk] directly.
    let ppfResult = PPF.encodePPF3 (splitHunks 255 (contentsRecords contents)) description
                      (contentsUndoData contents) (contentsValidation contents) imageType
    in Right $ case contentsFileIdDiz contents of
         Nothing  -> ppfResult
         Just diz -> ppfResult { resultBytes = resultBytes ppfResult <> PPF.encodeFileIdDiz diz }
  CreateNINJA1 -> do
    records <- narrow (contentsRecords contents)
    let crc      = fromMaybe (CRC32 0) (contentsSourceCRC32 contents)
        md5Hash  = unMD5Hash (fromMaybe (MD5Hash (ByteString.replicate 16 0)) (contentsSourceMD5 contents))
        sha1Hash = unSHA1Hash (fromMaybe (SHA1Hash (ByteString.replicate 20 0)) (contentsSourceSHA1 contents))
    Right (CreateResult (NINJA1.encodeNINJA1 records crc md5Hash sha1Hash romType
             (fromMaybe False (contentsNINJA1Compressed contents))) [])
  CreatePMSR -> do
    records <- narrow (contentsRecords contents)
    Right (CreateResult (PMSR.encodePMSR records) [])
  CreatePCHTXT -> case contentsPCHTXTBlocks contents of
    Just blocks -> Right (CreateResult (PCHTXT.encodePCHTXTBlocks blocks pchtxtDescription) [])
    Nothing -> do
      records <- narrow (contentsRecords contents)
      Right (CreateResult (PCHTXT.encodePCHTXT records pchtxtDescription) [])
  CreateAPSN64 -> do
    records <- narrow (contentsRecords contents)
    case contentsDestinationSize contents of
      Just targetSize ->
        Right (APSN64.encodeAPSN64 records (fromIntegral (unFileSize targetSize)) apsDescription)
      Nothing -> error "unreachable: canConvert verified FDestinationSize"
  where
    narrow :: [Hunk] -> Either SlapError [EncodedHunk]
    narrow = case limits of
      Nothing  -> Right . narrowHunksUnbounded
      Just lim -> wrapNarrow . narrowHunks lim
    wrapNarrow :: Either String a -> Either SlapError a
    wrapNarrow (Right value) = Right value
    wrapNarrow (Left errorMessage) = Left (ParseError (directLabel target) errorMessage)
    cliDescription   = metaDescription meta
    cliTitle  = metaTitle meta
    cliAuthor = metaAuthor meta
    description   = resolveDescription cliDescription (contentsEBPMeta contents) (contentsDescription contents) ""
    apsDescription = resolveDescription cliDescription Nothing (contentsDescription contents) (replicate 50 ' ')
    pchtxtDescription = cliDescription <|> fmap decodeLocaleField (contentsDescription contents)
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
-- The optional 'PatchContents' carries structural data from the source patch
-- (EBP JSON, File_ID.diz, PCHTXT blocks, NINJA1 compression flag) for
-- inheritance in the @--with@ conversion path.
createFromMemory :: CreateFormat -> ByteString.ByteString -> ByteString.ByteString
                 -> CreateMeta -> Maybe PatchContents -> Either SlapError CreateResult
createFromMemory (CreateDirect format) source target meta sourceContents =
  let contents = buildContents format source target meta sourceContents
      -- Source bytes available: avoidSentinel handles sentinel collisions
      -- at encode time, so only validate offset ranges here (sentinel stripped).
      strippedLimits = fmap (\lim -> lim { sentinelOffset = Nothing }) (encodingLimits format)
  in encodeDirect contents source format meta strippedLimits
createFromMemory (CreateDiff format) source target meta sourceContents = case format of
  CreateBPS    -> Right (CreateResult (BPS.createBPS source target (fromMaybe ByteString.empty (metaBPSMetadata meta))) [])
  CreateUPS    -> Right (CreateResult (UPS.createUPS source target) [])
  CreateDPS    -> Right (DPS.createDPS source target
                       (fromMaybe "" (metaTitle meta <|> metaDescription meta))
                       (fromMaybe "" (metaAuthor meta)) (fromMaybe "" (metaVersion meta))
                       (if fromMaybe False (metaUnstable meta) then DPS.DPSUnstable else DPS.DPSStable))
  CreateRUP    ->
    let -- When source patch has opaque description bytes, detect encoding
        -- via isValidUtf8: valid → PATCH_ENC=1, invalid → PATCH_ENC=0.
        -- If source already has known encoding, respect it.
        detectedEncoding = case sourceContents >>= contentsPatchEncoding of
          Just patchEncoding -> patchEncoding
          Nothing  -> case sourceContents >>= contentsDescription of
            Just descBytes | not (isValidUtf8 descBytes) -> PatchEncodingSystem
            _ -> metaPatchEncoding meta
        adjustedMeta = meta { metaPatchEncoding = detectedEncoding }
        (rupInfo, truncWarnings) = prepareRUP adjustedMeta
    in Right (CreateResult (RUP.createRUP source target rupInfo (fromMaybe 0 (metaRomType adjustedMeta)) detectedEncoding)
              truncWarnings)
  CreateAPSGBA -> Right (CreateResult (APSGBA.createAPSGBA source target) [])
  CreateGDIFF  -> Right (CreateResult (GDIFF.createGDIFF source target) [])

-- | Build PatchContents from source and target bytes for a direct format.
-- The optional source 'PatchContents' carries structural data (EBP JSON,
-- File_ID.diz, PCHTXT blocks, NINJA1 compression flag) from the original
-- patch for inheritance during @--with@ conversion.
buildContents :: DirectCreate -> ByteString.ByteString -> ByteString.ByteString
              -> CreateMeta -> Maybe PatchContents -> PatchContents
buildContents format source target meta sourceContents = PatchContents
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
  -- Structural inheritance: preserve format-specific data from the source patch
  , contentsEBPMeta          = sourceContents >>= contentsEBPMeta
  , contentsFileIdDiz        = sourceContents >>= contentsFileIdDiz
  , contentsPCHTXTBlocks     = sourceContents >>= contentsPCHTXTBlocks
  , contentsNINJA1Compressed = sourceContents >>= contentsNINJA1Compressed
  , contentsRomType     = Nothing
  , contentsImageType   = Nothing
  , contentsMetadata    = Nothing
  , contentsPatchEncoding = Nothing
  }
  where
    encodedToHunk (EncodedHunk hunkOffset hunkPayload) = Hunk hunkOffset hunkPayload
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
    includeUndo = fromMaybe False (metaUndo meta)
    includeValidation = fromMaybe False (metaValidate meta)
    spec      = formatSpecification format includeUndo includeValidation
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
             : splitUndo (Hunk (advance hunkOffset (Length 255)) (ByteString.drop 255 hunkPayload))
    oldBytes position chunkLength
      | position >= sourceLength = ByteString.replicate chunkLength 0
      | position + chunkLength > sourceLength =
          ByteString.take (sourceLength - position) (ByteString.drop position source)
          <> ByteString.replicate (chunkLength - (sourceLength - position)) 0
      | otherwise = ByteString.take chunkLength (ByteString.drop position source)

----------------------------------------------------------------------------
-- Internal helpers
----------------------------------------------------------------------------

-- | Resolve a description from CLI flag, EBP metadata, raw description, or default.
resolveDescription :: Maybe String -> Maybe ByteString.ByteString -> Maybe ByteString.ByteString -> String -> String
resolveDescription cliDescription ebpMeta rawDescription fallback
  | Just description <- cliDescription = description
  | Just meta <- ebpMeta
  , Just description <- jsonFieldCI (jsonPairs meta) "description"
  , not (null description) = description
  | Just raw <- rawDescription    = trimNullSpace (decodeLocaleField raw)
  | otherwise              = fallback

-- | Resolve a single EBP field: CLI flag wins, then fall back to source metadata.
resolveField :: Maybe String -> [(String, String)] -> String -> String
resolveField cliValue pairs key
  | Just provided <- cliValue = provided
  | Just value <- jsonFieldCI pairs key = value
  | otherwise = ""

trimNullSpace :: String -> String
trimNullSpace = reverse . dropWhile (\char -> char == ' ' || char == '\0') . reverse

----------------------------------------------------------------------------
-- Format metadata
----------------------------------------------------------------------------

formatExtension :: CreateFormat -> String
formatExtension (CreateDirect format) = directExtension format
formatExtension (CreateDiff format) = diffExtension format

formatName :: CreateFormat -> String
formatName (CreateDirect format) = directName format
formatName (CreateDiff format) = diffName format

directExtension :: DirectCreate -> String
directExtension CreateIPS    = ".ips"
directExtension CreateIPS32  = ".ips"
directExtension CreateEBP    = ".ebp"
directExtension CreatePPF3   = ".ppf"
directExtension CreateNINJA1 = ".rup"
directExtension CreatePMSR   = ".pmsr"
directExtension CreatePCHTXT = ".pchtxt"
directExtension CreateAPSN64 = ".aps"

diffExtension :: DiffCreate -> String
diffExtension CreateBPS    = ".bps"
diffExtension CreateUPS    = ".ups"
diffExtension CreateDPS    = ".dps"
diffExtension CreateRUP    = ".rup"
diffExtension CreateAPSGBA = ".aps"
diffExtension CreateGDIFF  = ".gdiff"

directName :: DirectCreate -> String
directName CreateIPS    = "IPS"
directName CreateIPS32  = "IPS32"
directName CreateEBP    = "EBP"
directName CreatePPF3   = "PPF3"
directName CreateNINJA1 = "NINJA1"
directName CreatePMSR   = "PMSR"
directName CreatePCHTXT = "PCHTXT"
directName CreateAPSN64 = "APS (N64)"

diffName :: DiffCreate -> String
diffName CreateBPS    = "BPS"
diffName CreateUPS    = "UPS"
diffName CreateDPS    = "DPS"
diffName CreateRUP    = "RUP"
diffName CreateAPSGBA = "APS (GBA)"
diffName CreateGDIFF  = "GDIFF"

directLabel :: DirectCreate -> FormatLabel
directLabel CreateIPS    = LabelIPS
directLabel CreateIPS32  = LabelIPS32
directLabel CreateEBP    = LabelEBP
directLabel CreatePPF3   = LabelPPF3
directLabel CreateNINJA1 = LabelNINJA1
directLabel CreatePMSR   = LabelPMSR
directLabel CreatePCHTXT = LabelPCHTXT
directLabel CreateAPSN64 = LabelAPSN64

diffLabel :: DiffCreate -> FormatLabel
diffLabel CreateBPS    = LabelBPS
diffLabel CreateUPS    = LabelUPS
diffLabel CreateDPS    = LabelDPS
diffLabel CreateRUP    = LabelRUP
diffLabel CreateAPSGBA = LabelAPSGBA
diffLabel CreateGDIFF  = LabelGDIFF
