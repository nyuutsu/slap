module Slap.SomePatch
  ( SomePatch(..)
  , RecordSummary(..)
  , ApplyStrategy(..)
  , UndoStrategy(..)
  , Verification(..)
  , BlockCheck(..)
  , ValidationBlock(..)
  , WindowCheck(..)
  , ByteCheck(..)
  , noVerification
  , parseSome
  ) where

import Slap.Types (PatchFormat(..), DirectFormat(..), DiffFormat(..))
import Slap.Detect (detectFormat)
import Slap.Convert (PatchContents(..), emptyContents, CreateMeta(..), defaultMeta, trimNullSpace)
import Slap.TextEncoding (decodeLocaleField, encodeUtf8Field)
import Slap.Measure (Offset(..), Length(..), FileSize(..), Hunk(..), UndoHunk(..))
import qualified Slap.PPF.Types as PPF
import qualified Slap.PPF.Parse as PPF
import qualified Slap.PPF.Apply as PPF
import qualified Slap.PPF.Describe as PPF
import qualified Slap.IPS.Apply as IPS
import qualified Slap.IPS.Describe as IPS
import qualified Slap.IPS.Parse as IPS
import qualified Slap.IPS.Types as IPS
import qualified Slap.BPS.Apply as BPS
import qualified Slap.BPS.Describe as BPS
import qualified Slap.BPS.Parse as BPS
import qualified Slap.BPS.Types as BPS
import qualified Slap.UPS.Apply as UPS
import qualified Slap.UPS.Describe as UPS
import qualified Slap.UPS.Parse as UPS
import qualified Slap.UPS.Types as UPS
import qualified Slap.VCDIFF.Types as VCDIFF
import qualified Slap.VCDIFF.Parse as VCDIFF
import qualified Slap.VCDIFF.Apply as VCDIFF
import qualified Slap.VCDIFF.Describe as VCDIFF
import qualified Slap.APSN64.Types as APSN64
import qualified Slap.APSN64.Parse as APSN64
import qualified Slap.APSN64.Apply as APSN64
import qualified Slap.APSN64.Describe as APSN64
import qualified Slap.APSGBA.Types as APSGBA
import qualified Slap.APSGBA.Parse as APSGBA
import qualified Slap.APSGBA.Apply as APSGBA
import qualified Slap.APSGBA.Describe as APSGBA
import qualified Slap.RUP.Types as RUP
import qualified Slap.RUP.Parse as RUP
import qualified Slap.RUP.Apply as RUP
import qualified Slap.RUP.Describe as RUP
import qualified Slap.BSDiff.Types as BSDiff
import qualified Slap.BSDiff.Parse as BSDiff
import qualified Slap.BSDiff.Apply as BSDiff
import qualified Slap.BSDiff.Describe as BSDiff
import qualified Slap.GDIFF.Types as GDIFF
import qualified Slap.GDIFF.Parse as GDIFF
import qualified Slap.GDIFF.Apply as GDIFF
import qualified Slap.GDIFF.Describe as GDIFF
import qualified Slap.XDelta1.Types as XDelta1
import qualified Slap.XDelta1.Parse as XDelta1
import qualified Slap.XDelta1.Apply as XDelta1
import qualified Slap.XDelta1.Describe as XDelta1
import qualified Slap.PMSR.Types as PMSR
import qualified Slap.PMSR.Parse as PMSR
import qualified Slap.PMSR.Apply as PMSR
import qualified Slap.PMSR.Describe as PMSR
import qualified Slap.PCHTXT.Types as PCHTXT
import qualified Slap.PCHTXT.Parse as PCHTXT
import qualified Slap.PCHTXT.Apply as PCHTXT
import qualified Slap.PCHTXT.Describe as PCHTXT
import qualified Slap.DPS.Types as DPS
import qualified Slap.DPS.Parse as DPS
import qualified Slap.DPS.Apply as DPS
import qualified Slap.DPS.Describe as DPS
import qualified Slap.NINJA1.Types as NINJA1
import qualified Slap.NINJA1.Parse as NINJA1
import qualified Slap.NINJA1.Apply as NINJA1
import qualified Slap.NINJA1.Create as NINJA1
import qualified Slap.NINJA1.Describe as NINJA1
import Slap.Explain (ExplainData(..))
import Slap.Error (SlapError(..), SlapWarning(..))
import Slap.FormatLabel (FormatLabel(..))
import qualified Slap.Yay0 as Yay0

import qualified Data.ByteString as ByteString
import Data.Maybe (fromMaybe, isJust)
import Slap.Checksum (CRC32, CRC16, Adler32, MD5Hash(..), SHA1Hash(..))

----------------------------------------------------------------------------
-- Types
----------------------------------------------------------------------------

-- | Strategy for applying a patch.
--
-- Every format takes source bytes in memory and returns target bytes.
-- Direct formats (IPS, PPF, etc.) overlay records onto a copy of the
-- source; differential formats (BPS, UPS, VCDIFF, etc.) compute the
-- target from source bytes and patch instructions.
newtype ApplyStrategy = InMemory
  { inMemoryApply :: ByteString.ByteString -> IO (Either SlapError ByteString.ByteString) }

-- | Verification data extracted from a parsed patch.
-- All fields are optional; formats populate whichever they carry.
data Verification = Verification
  { verifySourceCRC32  :: Maybe CRC32
  , verifySourceMD5    :: Maybe MD5Hash
  , verifySourceSHA1   :: Maybe SHA1Hash
  , verifyTargetCRC32  :: Maybe CRC32
  , verifyTargetMD5    :: Maybe MD5Hash
  , verifySourceBlocks  :: [BlockCheck]
  , verifyTargetBlocks  :: [BlockCheck]
  , verifyPPFBlock      :: Maybe ValidationBlock
  , verifyFileSize      :: Maybe FileSize
  , verifyWindowAdler32 :: [WindowCheck]
  , verifySourceBytes   :: [ByteCheck]
  , verifySourcePreHash :: ByteString.ByteString -> ByteString.ByteString -- transform source before hashing (NINJA1 sampling)
  }

-- | Per-block CRC16 check (APS-GBA).
data BlockCheck = BlockCheck
  { blockCheckOffset :: !Offset
  , blockCheckCRC16  :: !CRC16
  } deriving (Show)

-- | Validation block comparison (PPF).
data ValidationBlock = ValidationBlock
  { validationBlockOffset :: !Offset
  , validationBlockData   :: !ByteString.ByteString
  } deriving (Show)

-- | Per-window Adler32 check (VCDIFF).
data WindowCheck = WindowCheck
  { windowCheckOffset   :: !Offset
  , windowCheckLength   :: !Length
  , windowCheckExpected :: !Adler32
  } deriving (Show)

-- | Advisory byte-range comparison (APS-N64 cart ID, country, CRC).
data ByteCheck = ByteCheck
  { byteCheckOffset   :: !Offset
  , byteCheckExpected :: !ByteString.ByteString
  , byteCheckLabel    :: !String
  } deriving (Show)

noVerification :: Verification
noVerification = Verification
  { verifySourceCRC32 = Nothing, verifySourceMD5 = Nothing, verifySourceSHA1 = Nothing
  , verifyTargetCRC32 = Nothing, verifyTargetMD5 = Nothing
  , verifySourceBlocks = [], verifyTargetBlocks = []
  , verifyPPFBlock = Nothing, verifyFileSize = Nothing
  , verifyWindowAdler32 = [], verifySourceBytes = []
  , verifySourcePreHash = id
  }

-- | Strategy for undoing a patch.
-- The undo function takes modified bytes and returns the original.
-- For self-inverse formats like UPS (XOR-based), the apply function
-- itself serves as the undo, so UndoInMemory simply wraps it.
newtype UndoStrategy = UndoInMemory (ByteString.ByteString -> ByteString.ByteString)

-- | Record count and unit label for display.
data RecordSummary = RecordSummary
  { recordCount :: !Int
  , recordUnit  :: !String       -- "records", "actions", "commands", etc.
  } deriving (Show)

-- | A parsed patch with all operations pre-bound as closures.
-- The only dispatch point is 'parseSome'; every consumer works
-- through these fields, never inspecting the underlying format.
data SomePatch = SomePatch
  { patchFormat         :: FormatLabel
  , patchExplain        :: ExplainData
  , patchIsDifferential :: Bool
  , patchApply          :: ApplyStrategy
  , patchUndo           :: Maybe UndoStrategy
  , patchVerification   :: Verification
  , patchWarnings       :: [SlapWarning]
  , patchRecordSummary  :: RecordSummary
  , patchContents       :: Maybe PatchContents
  , patchSourceNotes    :: [SlapWarning]
  , patchMetadata       :: Maybe ByteString.ByteString  -- ^ Arbitrary metadata blob (BPS)
  , patchExtractedMeta  :: CreateMeta  -- ^ Text metadata extracted at parse time for conversion
  }

----------------------------------------------------------------------------
-- Parse dispatch — the single point where format-specific types exist
----------------------------------------------------------------------------

parseSome :: ByteString.ByteString -> Either SlapError SomePatch
parseSome patchBytes = case detectFormat patchBytes of
  Nothing
    | Yay0.isYay0 patchBytes -> parseYay0Container patchBytes
    | otherwise -> Left UnrecognizedFormat

  Just (PatchDirect FormatPPF) -> do
    patch <- PPF.parsePatch patchBytes
    let records = PPF.ppfRecords patch
        hasAppend = any (\record -> PPF.recordCommand record == PPF.Append) records
        ppfVerification = noVerification
            { verifyPPFBlock = case PPF.ppfValidation patch of
                Just validation -> Just (ValidationBlock (PPF.validationOffset (PPF.validationImageType validation)) (PPF.validationBlock validation))
                Nothing  -> Nothing
            , verifyFileSize = PPF.ppfFileSize patch
            }
    Right SomePatch
        { patchFormat         = ppfLabel (PPF.ppfVersion patch)
        , patchExplain        = PPF.explainPPF patch
        , patchIsDifferential = False
        , patchApply          = InMemory
            { inMemoryApply = \source -> pure (Right (PPF.applyPatchMemory patch source)) }
        , patchUndo           = if PPF.ppfHasUndo patch
                                 then Just (UndoInMemory $ PPF.undoPatchMemory patch)
                                 else Nothing
        , patchVerification   = ppfVerification
        , patchWarnings       = [EmptyPatch (ppfLabel (PPF.ppfVersion patch)) "records" | null records]
        , patchRecordSummary  = RecordSummary (length records) "records"
        , patchSourceNotes    = []
        , patchMetadata       = Nothing
        , patchExtractedMeta  = let description = trimNullSpace (decodeLocaleField (PPF.ppfDescription patch))
                                in defaultMeta
                                  { metaDescription = if null description then Nothing else Just description
                                  , metaImageType   = PPF.ppfImageType patch
                                  , metaUndo        = if PPF.ppfHasUndo patch then Just True else Nothing
                                  , metaValidate    = if isJust (PPF.ppfValidation patch) then Just True else Nothing
                                  }
        , patchContents  = if hasAppend then Nothing else Just PatchContents
            { contentsRecords     = map (\record -> Hunk (PPF.recordOffset record) (PPF.recordData record)) records
            , contentsDescription = Just (PPF.ppfDescription patch)
            , contentsSourceCRC32 = Nothing
            , contentsSourceMD5   = Nothing
            , contentsSourceSHA1  = Nothing
            , contentsDestinationSize    = PPF.ppfFileSize patch
            , contentsValidation  = fmap PPF.validationBlock (PPF.ppfValidation patch)
            , contentsUndoData    = if PPF.ppfHasUndo patch
                              then Just [ UndoHunk (PPF.recordOffset record) (PPF.recordData record) (fromMaybe ByteString.empty (PPF.recordUndo record))
                                        | record <- records ]
                              else Nothing
            , contentsTruncation  = Nothing
            , contentsEBPMeta     = Nothing
            , contentsRomType     = Nothing
            , contentsImageType   = PPF.ppfImageType patch
            , contentsFileIdDiz   = fmap PPF.fileIdContent (PPF.ppfFileId patch)
            , contentsPCHTXTBlocks = Nothing
            , contentsNINJA1Compressed = Nothing
            , contentsMetadata = Nothing
            , contentsPatchEncoding = Nothing
            }
        }

  Just (PatchDirect FormatIPS) -> do
    patch <- IPS.parseIPS patchBytes
    let records = IPS.ipsRecords patch
        expandIPS (IPS.IPSRecord recordOffset recordPayload) = Hunk recordOffset recordPayload
        expandIPS (IPS.IPSRecordRLE recordOffset fillCount fillByte) = Hunk recordOffset (ByteString.replicate (unLength fillCount) fillByte)
        label = case (IPS.ipsVariant patch, IPS.ipsEBPMeta patch) of
          (IPS.StandardIPS, Nothing) -> LabelIPS
          (IPS.StandardIPS, Just _)  -> LabelEBP
          (IPS.IPS32, _)             -> LabelIPS32
        warnings = concat
          [ [NoEOFMarker label | not (IPS.ipsCleanEOF patch)]
          , [EmptyPatch label "records" | null records]
          ]
        ebpPairs = maybe [] IPS.jsonPairs (IPS.ipsEBPMeta patch)
        nonEmptyField decoded = if null decoded then Nothing else Just decoded
        ebpMeta = defaultMeta
          { metaTitle       = IPS.jsonFieldCI ebpPairs "title" >>= nonEmptyField
          , metaAuthor      = IPS.jsonFieldCI ebpPairs "author" >>= nonEmptyField
          , metaDescription = IPS.jsonFieldCI ebpPairs "description" >>= nonEmptyField
          }
    Right SomePatch
      { patchFormat         = label
      , patchExplain        = IPS.explainIPS patch
      , patchIsDifferential = False
      , patchApply          = InMemory
            { inMemoryApply = \source -> pure (Right (IPS.applyIPSMemory patch source)) }
      , patchUndo           = Nothing
      , patchVerification   = noVerification
      , patchWarnings       = warnings
      , patchRecordSummary  = RecordSummary (length records) "records"
      , patchSourceNotes    = []
      , patchMetadata       = Nothing
      , patchExtractedMeta  = ebpMeta
      , patchContents  = Just (emptyContents (map expandIPS records))
          { contentsTruncation = IPS.ipsTruncate patch
          , contentsEBPMeta    = IPS.ipsEBPMeta patch
          }
      }

  Just (PatchDiff FormatBPS) -> do
    patch <- BPS.parseBPS patchBytes
    let actions = BPS.bpsActions patch
        bpsMetaBlob = if ByteString.null (BPS.bpsMetadata patch) then Nothing
                      else Just (BPS.bpsMetadata patch)
    Right SomePatch
      { patchFormat         = LabelBPS
      , patchExplain        = BPS.explainBPS patch
      , patchIsDifferential = True
      , patchApply          = InMemory
          { inMemoryApply     = \source -> pure (Right (BPS.applyBPS patch source)) }
      , patchUndo           = Nothing
      , patchVerification   = noVerification
          { verifySourceCRC32 = Just (BPS.bpsSourceCRC patch)
          , verifyTargetCRC32 = Just (BPS.bpsTargetCRC patch)
          }
      , patchWarnings       = [EmptyPatch LabelBPS "actions" | null actions]
      , patchRecordSummary  = RecordSummary (length actions) "actions"
      , patchSourceNotes    = []
      , patchMetadata       = bpsMetaBlob
      , patchExtractedMeta  = defaultMeta { metaBPSMetadata = bpsMetaBlob }
      , patchContents  = Nothing
      }

  Just (PatchDiff FormatUPS) -> do
    patch <- UPS.parseUPS patchBytes
    let blocks = UPS.upsBlocks patch
    Right SomePatch
      { patchFormat         = LabelUPS
      , patchExplain        = UPS.explainUPS patch
      , patchIsDifferential = True
      , patchApply          = InMemory
          { inMemoryApply     = \source -> pure (Right (UPS.applyUPS patch source)) }
      , patchUndo           = Just (UndoInMemory $ UPS.applyUPS patch)
      , patchVerification   = noVerification
          { verifySourceCRC32 = Just (UPS.upsSourceCRC patch)
          , verifyTargetCRC32 = Just (UPS.upsTargetCRC patch)
          }
      , patchWarnings       = [EmptyPatch LabelUPS "blocks" | null blocks]
      , patchRecordSummary  = RecordSummary (length blocks) "blocks"
      , patchSourceNotes    = []
      , patchMetadata       = Nothing
      , patchExtractedMeta  = defaultMeta
      , patchContents  = Nothing
      }

  Just (PatchDiff FormatVCDIFF) -> do
    patch <- VCDIFF.parseVCDIFF patchBytes
    let windows = VCDIFF.vcdiffWindows patch
        windowOffsets = scanl (+) 0 (map (unFileSize . VCDIFF.vcdiffTargetLength) windows)
        adlerChecks =
          [ WindowCheck (Offset windowOffset) (Length (fromIntegral (unFileSize (VCDIFF.vcdiffTargetLength window)))) checksum
          | (window, windowOffset) <- zip windows windowOffsets
          , Just checksum <- [VCDIFF.vcdiffAdler32 window]
          ]
    Right SomePatch
      { patchFormat         = LabelVCDIFF
      , patchExplain        = VCDIFF.explainVCDIFF patch
      , patchIsDifferential = True
      , patchApply          = InMemory
          { inMemoryApply     = \source -> pure (VCDIFF.applyVCDIFF patch source) }
      , patchUndo           = Nothing
      , patchVerification   = noVerification { verifyWindowAdler32 = adlerChecks }
      , patchWarnings       = [EmptyPatch LabelVCDIFF "windows" | null windows]
      , patchRecordSummary  = RecordSummary (length windows) "windows"
      , patchSourceNotes    = []
      , patchMetadata       = Nothing
      , patchExtractedMeta  = defaultMeta
      , patchContents  = Nothing
      }

  -- APS N64 and APS GBA are unrelated formats by different authors who
  -- both used "APS" as the name.  detectFormat dispatches on magic, but
  -- "APS10" (N64) collides with "APS1" + source size when size mod 256 == 48.
  -- Disambiguate via GBA's fixed record structure (12 + N*65544 bytes,
  -- 64KB-aligned offsets).
  Just (PatchDirect FormatAPSN64)
    | apsGbaStructure patchBytes -> parseAPSGBABlock patchBytes
    | otherwise -> do
    patch@(APSN64.APSN64Patch header records) <- APSN64.parseAPSN64 patchBytes
    let expandN64 (APSN64.APSN64Normal recordOffset recordPayload) = Hunk recordOffset recordPayload
        expandN64 (APSN64.APSN64RLE recordOffset fillValue fillCount) = Hunk recordOffset (ByteString.replicate (fromIntegral fillCount) fillValue)
    Right SomePatch
      { patchFormat         = LabelAPSN64
      , patchExplain        = APSN64.explainAPSN64 patch
      , patchIsDifferential = False
      , patchApply          = InMemory
            { inMemoryApply = \source -> pure (Right (APSN64.applyAPSN64Memory patch source)) }
      , patchUndo           = Nothing
      , patchVerification   = noVerification
            { verifySourceBytes = concat
                [ maybe [] (\cartId -> [ByteCheck (Offset 0x3C) cartId "N64 cart ID"]) (APSN64.apsN64CartId header)
                , maybe [] (\country -> [ByteCheck (Offset 0x3E) (ByteString.singleton country) "N64 country"]) (APSN64.apsN64Country header)
                , maybe [] (\crc -> [ByteCheck (Offset 0x10) crc "N64 CRC"]) (APSN64.apsN64Crc header)
                ]
            }
      , patchWarnings       = [EmptyPatch LabelAPSN64 "records" | null records]
      , patchRecordSummary  = RecordSummary (length records) "records"
      , patchSourceNotes    = []
      , patchMetadata       = Nothing
      , patchExtractedMeta  = let description = trimNullSpace (decodeLocaleField (APSN64.apsN64Description header))
                              in defaultMeta
                                { metaDescription = if null description then Nothing else Just description }
      , patchContents  = Just (emptyContents (map expandN64 records))
            { contentsDescription = Just (APSN64.apsN64Description header)
            , contentsDestinationSize    = Just (APSN64.apsN64DestinationSize header)
            }
      }

  Just (PatchDiff FormatAPSGBA) -> parseAPSGBABlock patchBytes

  Just (PatchDiff FormatRUP) -> do
    patch <- RUP.parseRUP patchBytes
    let filterZeroMD5 (Just hashValue) | ByteString.all (== 0) hashValue = Nothing
        filterZeroMD5 other = fmap MD5Hash other
    Right SomePatch
      { patchFormat         = LabelRUP
      , patchExplain        = RUP.explainRUP patch
      , patchIsDifferential = True
      , patchApply          = InMemory
            { inMemoryApply = \source -> pure (Right (RUP.applyRUPMemory patch source)) }
      , patchUndo           = Nothing
      , patchVerification   = noVerification
          { verifySourceMD5 = filterZeroMD5 (RUP.rupSourceMD5 patch)
          , verifyTargetMD5 = filterZeroMD5 (RUP.rupTargetMD5 patch)
          }
      , patchWarnings       = [EmptyPatch LabelRUP "records" | null (RUP.rupRecords patch)]
      , patchRecordSummary  = RecordSummary (length (RUP.rupRecords patch)) "records"
      , patchSourceNotes    = []
      , patchMetadata       = Nothing
      , patchExtractedMeta  = let decode = RUP.decodeRUPField (RUP.rupPatchEncoding patch)
                                  nonEmptyField fieldBytes = let decoded = decode fieldBytes
                                                              in if null decoded then Nothing else Just decoded
                                  info = RUP.rupHeader patch
                              in defaultMeta
                                { metaTitle       = RUP.rupTitle info >>= nonEmptyField
                                , metaAuthor      = RUP.rupAuthor info >>= nonEmptyField
                                , metaVersion     = RUP.rupVersion info >>= nonEmptyField
                                , metaGenre       = RUP.rupGenre info >>= nonEmptyField
                                , metaLanguage    = RUP.rupLanguage info >>= nonEmptyField
                                , metaDate        = RUP.rupDate info >>= nonEmptyField
                                , metaWebsite     = RUP.rupWebsite info >>= nonEmptyField
                                , metaDescription = RUP.rupDescription info >>= nonEmptyField
                                , metaRomType     = Just (RUP.rupRomType patch)
                                }
      , patchContents  = Nothing
      }

  Just (PatchDirect FormatNINJA1) -> do
    patch <- NINJA1.parseNINJA1 patchBytes
    let records = NINJA1.ninja1Records patch
        warnings = concat
          [ [NoEOFMarker LabelNINJA1 | not (NINJA1.ninja1CleanEOF patch)]
          , [EmptyPatch LabelNINJA1 "records" | null records]
          ]
        compressed = NINJA1.ninja1SubFormat patch `elem` [NINJA1.Ninja1BinaryCompressed, NINJA1.Ninja1TextCompressed]
        sourceNotes = case NINJA1.ninja1SubFormat patch of
          NINJA1.Ninja1Text  -> [SubformatConverted LabelNINJA1 "text (T)" "binary (B)"]
          NINJA1.Ninja1TextCompressed -> [SubformatConverted LabelNINJA1 "text (TZ)" "compressed binary (BZ)"]
          _              -> []
    Right SomePatch
      { patchFormat         = LabelNINJA1
      , patchExplain        = NINJA1.explainNINJA1 patch
      , patchIsDifferential = False
      , patchApply          = InMemory
            { inMemoryApply = \source -> pure (Right (NINJA1.applyNINJA1Memory patch source)) }
      , patchUndo           = Nothing
      , patchVerification   = noVerification
          { verifySourceCRC32  = NINJA1.ninja1SourceCRC patch
          , verifySourceMD5    = NINJA1.ninja1SourceMD5 patch
          , verifySourceSHA1   = NINJA1.ninja1SourceSHA1 patch
          , verifySourcePreHash = NINJA1.ninja1HashInput
          }
      , patchWarnings       = warnings
      , patchRecordSummary  = RecordSummary (length records) "records"
      , patchSourceNotes    = sourceNotes
      , patchMetadata       = Nothing
      , patchExtractedMeta  = defaultMeta
          { metaRomType = Just (NINJA1.fromNINJA1RomType (NINJA1.ninja1RomType patch)) }
      , patchContents  = Just (emptyContents (map (\record -> Hunk (NINJA1.ninja1RecordOffset record) (NINJA1.ninja1RecordData record)) records))
          { contentsSourceCRC32 = NINJA1.ninja1SourceCRC patch
          , contentsSourceMD5   = NINJA1.ninja1SourceMD5 patch
          , contentsSourceSHA1  = NINJA1.ninja1SourceSHA1 patch
          , contentsRomType     = Just (NINJA1.fromNINJA1RomType (NINJA1.ninja1RomType patch))
          , contentsNINJA1Compressed = Just compressed
          }
      }

  Just (PatchDiff FormatBSDiff) -> do
    patch <- BSDiff.parseBSDiff patchBytes
    Right SomePatch
      { patchFormat         = LabelBSDiff
      , patchExplain        = BSDiff.explainBSDiff patch
      , patchIsDifferential = True
      , patchApply          = InMemory
          { inMemoryApply     = \source -> pure (BSDiff.applyBSDiff patch source) }
      , patchUndo           = Nothing
      , patchVerification   = noVerification
      , patchWarnings       = [EmptyPatch LabelBSDiff "control tuples" | null (BSDiff.bsdiffControls patch)]
      , patchRecordSummary  = RecordSummary (length (BSDiff.bsdiffControls patch)) "control tuples"
      , patchSourceNotes    = []
      , patchMetadata       = Nothing
      , patchExtractedMeta  = defaultMeta
      , patchContents  = Nothing
      }

  Just (PatchDiff FormatGDIFF) -> do
    patch <- GDIFF.parseGDIFF patchBytes
    Right SomePatch
      { patchFormat         = LabelGDIFF
      , patchExplain        = GDIFF.explainGDIFF patch
      , patchIsDifferential = True
      , patchApply          = InMemory
          { inMemoryApply     = \source -> pure (Right (GDIFF.applyGDIFF patch source)) }
      , patchUndo           = Nothing
      , patchVerification   = noVerification
      , patchWarnings       = [EmptyPatch LabelGDIFF "commands" | null (GDIFF.gdiffCommands patch)]
      , patchRecordSummary  = RecordSummary (length (GDIFF.gdiffCommands patch)) "commands"
      , patchSourceNotes    = []
      , patchMetadata       = Nothing
      , patchExtractedMeta  = defaultMeta
      , patchContents  = Nothing
      }

  Just (PatchDiff FormatXDelta1) -> do
    patch <- XDelta1.parseXDelta1 patchBytes
    let fileSources = filter (\entry -> XDelta1.xdelta1SourceKind entry == XDelta1.FileSource) (XDelta1.xdelta1Sources patch)
        xdeltaVerification = noVerification
          { verifySourceMD5 = case fileSources of
              (entry:_) -> Just (XDelta1.xdelta1SourceMD5 entry)
              []        -> Nothing
          , verifyTargetMD5 = Just (XDelta1.xdelta1ToMD5 patch)
          }
    Right SomePatch
      { patchFormat         = LabelXDelta1
      , patchExplain        = XDelta1.explainXDelta1 patch
      , patchIsDifferential = True
      , patchApply          = InMemory
          { inMemoryApply     = \source -> pure (XDelta1.applyXDelta1 patch source) }
      , patchUndo           = Nothing
      , patchVerification   = xdeltaVerification
      , patchWarnings       = [EmptyPatch LabelXDelta1 "instructions" | null (XDelta1.xdelta1Instructions patch)]
      , patchRecordSummary  = RecordSummary (length (XDelta1.xdelta1Instructions patch)) "instructions"
      , patchSourceNotes    = []
      , patchMetadata       = Nothing
      , patchExtractedMeta  = defaultMeta
      , patchContents  = Nothing
      }

  Just (PatchDirect FormatPMSR) -> do
    patch <- PMSR.parsePMSR patchBytes
    let records = PMSR.pmsrRecords patch
    Right SomePatch
      { patchFormat         = LabelPMSR
      , patchExplain        = PMSR.explainPMSR patch
      , patchIsDifferential = False
      , patchApply          = InMemory
            { inMemoryApply = \source -> pure (Right (PMSR.applyPMSRMemory patch source)) }
      , patchUndo           = Nothing
      , patchVerification   = noVerification
      , patchWarnings       = [EmptyPatch LabelPMSR "records" | null records]
      , patchRecordSummary  = RecordSummary (length records) "records"
      , patchSourceNotes    = []
      , patchMetadata       = Nothing
      , patchExtractedMeta  = defaultMeta
      , patchContents  = Just (emptyContents
          (map (\record -> Hunk (PMSR.pmsrOffset record) (PMSR.pmsrData record)) records))
      }

  Just (PatchDirect FormatPCHTXT) -> do
    patch <- PCHTXT.parsePCHTXT patchBytes
    let allBlocks = PCHTXT.pchtxtBlocks patch
        enabledBlocks = filter PCHTXT.pchtxtBlockEnabled allBlocks
        entries = concatMap PCHTXT.pchtxtBlockEntries enabledBlocks
        contentRecords = map (\entry -> Hunk (PCHTXT.pchtxtOffset entry) (PCHTXT.pchtxtData entry)) entries
        sourceNotes = [OffsetShiftApplied | PCHTXT.pchtxtHasShift patch]
    Right SomePatch
      { patchFormat         = LabelPCHTXT
      , patchExplain        = PCHTXT.explainPCHTXT patch
      , patchIsDifferential = False
      , patchApply          = InMemory
            { inMemoryApply = \source -> pure (Right (PCHTXT.applyPCHTXTMemory patch source)) }
      , patchUndo           = Nothing
      , patchVerification   = noVerification
      , patchWarnings       = [EmptyPatch LabelPCHTXT "entries" | null entries]
      , patchRecordSummary  = RecordSummary (length entries) "entries"
      , patchSourceNotes    = sourceNotes
      , patchMetadata       = Nothing
      , patchExtractedMeta  = defaultMeta
      , patchContents  = Just (emptyContents contentRecords)
          { contentsDescription = encodeUtf8Field <$> PCHTXT.pchtxtNsobid patch
          , contentsPCHTXTBlocks = Just allBlocks
          }
      }

  Just (PatchDiff FormatDPS) -> parseDPSBlock patchBytes

----------------------------------------------------------------------------
-- Helpers
----------------------------------------------------------------------------

parseDPSBlock :: ByteString.ByteString -> Either SlapError SomePatch
parseDPSBlock input = case DPS.parseDPS input of
  Left slapError -> Left slapError
  Right patch  ->
    let records = DPS.dpsRecords patch
    in Right SomePatch
      { patchFormat         = LabelDPS
      , patchExplain        = DPS.explainDPS patch
      , patchIsDifferential = True
      , patchApply          = InMemory
          { inMemoryApply     = \source -> pure (Right (DPS.applyDPS patch source)) }
      , patchVerification   = noVerification
      , patchUndo           = Nothing
      , patchWarnings       = [EmptyPatch LabelDPS "records" | null records]
      , patchRecordSummary  = RecordSummary (length records) "records"
      , patchSourceNotes    = []
      , patchContents  = Nothing
      , patchMetadata       = Nothing
      , patchExtractedMeta  = let nonEmpty fieldBytes = let decoded = trimNullSpace (decodeLocaleField fieldBytes)
                                                       in if null decoded then Nothing else Just decoded
                              in defaultMeta
                                { metaTitle    = nonEmpty (DPS.dpsName patch)
                                , metaAuthor   = nonEmpty (DPS.dpsAuthor patch)
                                , metaVersion  = nonEmpty (DPS.dpsVersion patch)
                                , metaUnstable = case DPS.dpsStability patch of
                                                   DPS.DPSUnstable -> Just True
                                                   DPS.DPSStable   -> Nothing
                                }
      }

-- | Yay0 is a compression container (Nintendo LZSS), not a patch format.
-- Decompress the envelope and recurse into parseSome on the inner bytes.
parseYay0Container :: ByteString.ByteString -> Either SlapError SomePatch
parseYay0Container input = case Yay0.decompressYay0 input of
  Left errorMessage   -> Left (Yay0DecompressionFailed errorMessage)
  Right decompressedBytes -> case parseSome decompressedBytes of
    Left slapError -> Left slapError
    Right parsed -> Right parsed
      { patchExplain = (patchExplain parsed)
          { explainFormat = explainFormat (patchExplain parsed) ++ "/Yay0" }
      }

parseAPSGBABlock :: ByteString.ByteString -> Either SlapError SomePatch
parseAPSGBABlock input = do
  patch@(APSGBA.APSGBAPatch header records) <- APSGBA.parseAPSGBA input
  Right SomePatch
    { patchFormat         = LabelAPSGBA
    , patchExplain        = APSGBA.explainAPSGBA patch
    , patchIsDifferential = True
    , patchApply          = InMemory
          { inMemoryApply = \source -> pure (Right (APSGBA.applyAPSGBAMemory patch source)) }
    , patchUndo           = Nothing
    , patchVerification   = noVerification
          { verifySourceBlocks = map (\record -> BlockCheck (APSGBA.apsGbaOffset record) (APSGBA.apsGbaSourceCRC record)) records
          , verifyTargetBlocks = map (\record -> BlockCheck (APSGBA.apsGbaOffset record) (APSGBA.apsGbaTargetCRC record)) records
          , verifyFileSize = Just (APSGBA.apsGbaSourceSize header)
          }
    , patchWarnings       = [EmptyPatch LabelAPSGBA "blocks" | null records]
    , patchRecordSummary  = RecordSummary (length records) "blocks"
    , patchSourceNotes    = []
    , patchMetadata       = Nothing
    , patchExtractedMeta  = defaultMeta
    , patchContents  = Nothing
    }

-- | Structural check for APS-GBA: 12-byte header + N * 65544-byte records,
-- each record offset 64KB-aligned.  Used to disambiguate "APS10" (N64) from
-- "APS1" + source_size when size mod 256 == 48.
apsGbaStructure :: ByteString.ByteString -> Bool
apsGbaStructure input =
  let dataLength = ByteString.length input - 12
      recordCount = dataLength `div` 65544
  in dataLength == 0
     || (dataLength >= 65544 && dataLength `mod` 65544 == 0
         && all (\index -> let position = 12 + index * 65544
                       in ByteString.index input position == 0 && ByteString.index input (position + 1) == 0)
                [0 .. recordCount - 1])

-- | Map PPF version to format label.
ppfLabel :: PPF.Version -> FormatLabel
ppfLabel PPF.PPF1 = LabelPPF1
ppfLabel PPF.PPF2 = LabelPPF2
ppfLabel PPF.PPF3 = LabelPPF3
ppfLabel PPF.PPF4 = LabelPPF4
