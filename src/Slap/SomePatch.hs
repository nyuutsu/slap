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

import Slap.FileContents (SourceFileContents(..), TargetFileContents(..), PatchFileContents(..))
import Slap.Types (PatchFormat(..), DirectFormat(..), DiffFormat(..))
import Slap.Detect (detectFormat)
import Slap.Convert (PatchContents(..), emptyContents, CreateMeta(..), defaultMeta, trimNullSpace)
import Slap.TextEncoding (decodeLocaleField, encodeUtf8Field)
import Slap.JSON (jsonPairs, jsonFieldCI)
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
import qualified Slap.NINJA2.Types as NINJA2
import qualified Slap.NINJA2.Parse as NINJA2
import qualified Slap.NINJA2.Apply as NINJA2
import qualified Slap.NINJA2.Describe as NINJA2
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
import Slap.Platform (ninja1ToPlatform, ninja2ToPlatform)
import Slap.Explain (ExplainData(..))
import Slap.Error (SlapError(..), SlapWarning(..))
import Slap.FormatLabel (FormatLabel(..))
import qualified Slap.Yay0 as Yay0

import qualified Data.ByteString as ByteString
import qualified Data.Vector as Vector
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
  { inMemoryApply :: SourceFileContents -> IO (Either SlapError TargetFileContents) }

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
    -- | Advisory file-size check for formats that have a stronger
    -- integrity gate (e.g. CRC32).  Mismatch emits a warning but does
    -- not fail the apply — the CRC will catch real corruption.
  , verifyFileSizeAdvisory :: Maybe FileSize
    -- | Required file-size check for formats where file size is the
    -- only integrity gate (no CRC, no hash).  Mismatch fails the
    -- apply unless @--no-verify@ is set.
  , verifyFileSizeRequired :: Maybe FileSize
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
  , verifyPPFBlock = Nothing, verifyFileSizeAdvisory = Nothing, verifyFileSizeRequired = Nothing
  , verifyWindowAdler32 = [], verifySourceBytes = []
  , verifySourcePreHash = id
  }

-- | Strategy for undoing a patch.
-- The undo function takes the modified file contents and returns the
-- original. Returns 'Left' on malformed undo data (bounds violations,
-- negative offsets). For self-inverse formats like UPS (XOR-based),
-- the apply function itself serves as the undo.
newtype UndoStrategy = UndoInMemory
  (TargetFileContents -> Either SlapError SourceFileContents)

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

parseSome :: PatchFileContents -> Either SlapError SomePatch
parseSome patchContents = case detectFormat patchContents of
  Nothing
    | Yay0.isYay0 rawBytes -> parseYay0Container patchContents
    | otherwise -> Left UnrecognizedFormat

  Just (PatchDirect FormatPPF) -> do
    patch <- PPF.parsePatch patchContents
    let records = PPF.ppfRecords patch
        hasAppend = any (\record -> PPF.recordCommand record == PPF.Append) records
        ppfVerification = noVerification
            { verifyPPFBlock = case PPF.ppfValidation patch of
                Just validation -> Just (ValidationBlock (PPF.validationOffset (PPF.validationImageType validation)) (PPF.validationBlock validation))
                Nothing  -> Nothing
            , verifyFileSizeAdvisory = PPF.ppfFileSize patch
            }
    Right SomePatch
        { patchFormat         = PPF.ppfVersionLabel (PPF.ppfVersion patch)
        , patchExplain        = PPF.explainPPF patch
        , patchIsDifferential = False
        , patchApply          = InMemory
            { inMemoryApply = \source -> pure (PPF.applyPatchMemory patch source) }
        , patchUndo           = if PPF.ppfHasUndo patch
                                 then Just (UndoInMemory $ PPF.undoPatchMemory patch)
                                 else Nothing
        , patchVerification   = ppfVerification
        , patchWarnings       = [EmptyPatch (PPF.ppfVersionLabel (PPF.ppfVersion patch)) "records" | null records]
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

  Just (PatchDirect FormatIPS) ->
    let expandIPSRecord (IPS.IPSRecordCopy { ipsCopyOffset = recordOffset
                                           , ipsCopyPayload = recordPayload }) =
          Hunk recordOffset recordPayload
        expandIPSRecord (IPS.IPSRecordRLE { ipsRleOffset = recordOffset
                                          , ipsRleCount = fillCount
                                          , ipsRleFill = fillByte }) =
          Hunk recordOffset (ByteString.replicate (unLength fillCount) fillByte)
    in case IPS.parseIPS patchContents of
      -- Get-monad failure: the body was too truncated to decode even
      -- one record or EOF marker.  Return a 0-record patch with a
      -- NoEOFMarker warning so recognised-but-truncated IPS files
      -- still produce useful output from info/explain.
      Left (ParseError LabelIPS _) ->
        let truncatedFallback = IPS.IPSPatch
              { IPS.ipsVariant             = IPS.StandardIPS
              , IPS.ipsRecords             = Vector.empty
              , IPS.ipsTruncatedTargetSize = Nothing
              }
        in Right SomePatch
          { patchFormat         = LabelIPS
          , patchExplain        = IPS.explainIPS truncatedFallback
          , patchIsDifferential = False
          , patchApply          = InMemory
                { inMemoryApply = \source -> pure (IPS.applyIPS source truncatedFallback) }
          , patchUndo           = Nothing
          , patchVerification   = noVerification
          , patchWarnings       = [NoEOFMarker LabelIPS, EmptyPatch LabelIPS "records"]
          , patchRecordSummary  = RecordSummary 0 "records"
          , patchSourceNotes    = []
          , patchMetadata       = Nothing
          , patchExtractedMeta  = defaultMeta
          , patchContents       = Just (emptyContents [])
              { contentsTruncation = Nothing
              , contentsEBPMeta    = Nothing
              }
          }
      Left otherError -> Left otherError
      Right parseResult -> case parseResult of
        Left ipsPatch ->
          let records = IPS.ipsRecords ipsPatch
              label = case IPS.ipsVariant ipsPatch of
                IPS.StandardIPS -> LabelIPS
                IPS.IPS32       -> LabelIPS32
          in Right SomePatch
            { patchFormat         = label
            , patchExplain        = IPS.explainIPS ipsPatch
            , patchIsDifferential = False
            , patchApply          = InMemory
                  { inMemoryApply = \source -> pure (IPS.applyIPS source ipsPatch) }
            , patchUndo           = Nothing
            , patchVerification   = noVerification
            , patchWarnings       = [EmptyPatch label "records" | Vector.null records]
            , patchRecordSummary  = RecordSummary (Vector.length records) "records"
            , patchSourceNotes    = []
            , patchMetadata       = Nothing
            , patchExtractedMeta  = defaultMeta
            , patchContents  = Just (emptyContents (map expandIPSRecord (Vector.toList records)))
                { contentsTruncation = IPS.ipsTruncatedTargetSize ipsPatch
                , contentsEBPMeta    = Nothing
                }
            }
        Right ebpPatch ->
          let basePatch = IPS.ebpBasePatch ebpPatch
              records = IPS.ipsRecords basePatch
              ebpPairs = jsonPairs (IPS.unEBPMetadata (IPS.ebpMetadata ebpPatch))
              nonEmptyField decoded = if null decoded then Nothing else Just decoded
              extractedMeta = defaultMeta
                { metaTitle       = jsonFieldCI ebpPairs "title" >>= nonEmptyField
                , metaAuthor      = jsonFieldCI ebpPairs "author" >>= nonEmptyField
                , metaDescription = jsonFieldCI ebpPairs "description" >>= nonEmptyField
                }
          in Right SomePatch
            { patchFormat         = LabelEBP
            , patchExplain        = IPS.explainEBP ebpPatch
            , patchIsDifferential = False
            , patchApply          = InMemory
                  { inMemoryApply = \source -> pure (IPS.applyIPS source basePatch) }
            , patchUndo           = Nothing
            , patchVerification   = noVerification
            , patchWarnings       = [EmptyPatch LabelEBP "records" | Vector.null records]
            , patchRecordSummary  = RecordSummary (Vector.length records) "records"
            , patchSourceNotes    = []
            , patchMetadata       = Nothing
            , patchExtractedMeta  = extractedMeta
            , patchContents  = Just (emptyContents (map expandIPSRecord (Vector.toList records)))
                { contentsTruncation = IPS.ipsTruncatedTargetSize basePatch
                , contentsEBPMeta    = Just (IPS.unEBPMetadata (IPS.ebpMetadata ebpPatch))
                }
            }

  Just (PatchDiff FormatBPS) -> do
    patch <- BPS.parseBPS patchContents
    let actions = BPS.bpsActions patch
        bpsMetaBlob = if ByteString.null (BPS.bpsMetadata patch) then Nothing
                      else Just (BPS.bpsMetadata patch)
    Right SomePatch
      { patchFormat         = LabelBPS
      , patchExplain        = BPS.explainBPS patch
      , patchIsDifferential = True
      , patchApply          = InMemory
          { inMemoryApply     = \source -> pure (BPS.applyBPS patch source) }
      , patchUndo           = Nothing
      , patchVerification   = noVerification
          { verifySourceCRC32 = Just (BPS.bpsSourceCRC patch)
          , verifyTargetCRC32 = Just (BPS.bpsTargetCRC patch)
          -- The BPS spec declares source-size in the header and says
          -- the source checksum "verifies that the input file is
          -- correct". The spec doesn't mandate rejection on size
          -- mismatch (only CRC rejection), so we populate the size
          -- for warn-level diagnostics without changing the fatal-
          -- error semantics. A wrong-size source still fails via
          -- the source CRC check; the size warning just makes the
          -- diagnostic more specific before the CRC hard-errors.
          , verifyFileSizeAdvisory = Just (BPS.bpsSourceSize patch)
          }
      , patchWarnings       = [EmptyPatch LabelBPS "actions" | Vector.null actions]
      , patchRecordSummary  = RecordSummary (Vector.length actions) "actions"
      , patchSourceNotes    = []
      , patchMetadata       = bpsMetaBlob
      , patchExtractedMeta  = defaultMeta { metaBPSMetadata = bpsMetaBlob }
      , patchContents  = Nothing
      }

  Just (PatchDiff FormatUPS) -> do
    patch <- UPS.parseUPS patchContents
    let blocks = UPS.upsBlocks patch
    Right SomePatch
      { patchFormat         = LabelUPS
      , patchExplain        = UPS.explainUPS patch
      , patchIsDifferential = True
      , patchApply          = InMemory
          { inMemoryApply     = \source -> pure (UPS.applyUPS patch source) }
      , patchUndo           = Just $ UndoInMemory $ \(TargetFileContents modified) ->
          -- UPS is self-inverse (XOR-based): applying the patch to the
          -- target recovers the source. For a well-parsed patch this
          -- reapplication cannot fail.
          case UPS.applyUPS patch (SourceFileContents modified) of
            Right (TargetFileContents reverted) -> Right (SourceFileContents reverted)
            Left err -> Left err
      , patchVerification   = noVerification
          { verifySourceCRC32 = Just (UPS.upsSourceCRC patch)
          , verifyTargetCRC32 = Just (UPS.upsTargetCRC patch)
          -- See the BPS branch above for the reasoning: UPS spec
          -- declares source-size in the header but doesn't mandate
          -- size-based rejection. Populate for warn-level diagnostics
          -- on the forward-apply path. The undo/reverse-apply path
          -- bypasses the Verification layer entirely in Main.doUndo,
          -- so this doesn't interfere with UPS's self-inverse
          -- property — undoing a patch where the "source" actually
          -- has target-size still works because undo never consults
          -- verifyFileSizeAdvisory.
          , verifyFileSizeAdvisory = Just (UPS.upsSourceSize patch)
          }
      , patchWarnings       = [EmptyPatch LabelUPS "blocks" | Vector.null blocks]
      , patchRecordSummary  = RecordSummary (Vector.length blocks) "blocks"
      , patchSourceNotes    = []
      , patchMetadata       = Nothing
      , patchExtractedMeta  = defaultMeta
      , patchContents  = Nothing
      }

  Just (PatchDiff FormatVCDIFF) -> do
    patch <- VCDIFF.parseVCDIFF patchContents
    let windows = VCDIFF.vcdiffWindows patch
        windowOffsets = scanl (+) 0 (map (unFileSize . VCDIFF.vcdiffTargetLength) windows)
        adlerChecks =
          [ WindowCheck (Offset windowOffset) (Length (unFileSize (VCDIFF.vcdiffTargetLength window))) checksum
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
    | apsGbaStructure rawBytes -> parseAPSGBABlock patchContents
    | otherwise -> do
    patch@(APSN64.APSN64Patch header records) <- APSN64.parseAPSN64 patchContents
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

  Just (PatchDiff FormatAPSGBA) -> parseAPSGBABlock patchContents

  Just (PatchDiff FormatNINJA2) -> do
    patch <- NINJA2.parseNINJA2 patchContents
    let filterZeroMD5 (Just hashValue) | ByteString.all (== 0) hashValue = Nothing
        filterZeroMD5 other = fmap MD5Hash other
        (platformType, platformWarnings) = ninja2ToPlatform (NINJA2.ninja2RomType patch)
    Right SomePatch
      { patchFormat         = LabelNINJA2
      , patchExplain        = NINJA2.explainNINJA2 patch
      , patchIsDifferential = True
      , patchApply          = InMemory
            { inMemoryApply = \source -> pure (Right (NINJA2.applyNINJA2Memory patch source)) }
      , patchUndo           = Nothing
      , patchVerification   = noVerification
          { verifySourceMD5 = filterZeroMD5 (NINJA2.ninja2SourceMD5 patch)
          , verifyTargetMD5 = filterZeroMD5 (NINJA2.ninja2TargetMD5 patch)
          }
      , patchWarnings       = [EmptyPatch LabelNINJA2 "records" | null (NINJA2.ninja2Records patch)]
                               ++ platformWarnings
      , patchRecordSummary  = RecordSummary (length (NINJA2.ninja2Records patch)) "records"
      , patchSourceNotes    = []
      , patchMetadata       = Nothing
      , patchExtractedMeta  = let decode = NINJA2.decodeNINJA2Field (NINJA2.ninja2PatchEncoding patch)
                                  nonEmptyField fieldBytes = let decoded = decode fieldBytes
                                                              in if null decoded then Nothing else Just decoded
                                  info = NINJA2.ninja2Header patch
                              in defaultMeta
                                { metaTitle       = NINJA2.ninja2Title info >>= nonEmptyField
                                , metaAuthor      = NINJA2.ninja2Author info >>= nonEmptyField
                                , metaVersion     = NINJA2.ninja2Version info >>= nonEmptyField
                                , metaGenre       = NINJA2.ninja2Genre info >>= nonEmptyField
                                , metaLanguage    = NINJA2.ninja2Language info >>= nonEmptyField
                                , metaDate        = NINJA2.ninja2Date info >>= nonEmptyField
                                , metaWebsite     = NINJA2.ninja2Website info >>= nonEmptyField
                                , metaDescription = NINJA2.ninja2Description info >>= nonEmptyField
                                , metaRomType     = Just platformType
                                }
      , patchContents  = Nothing
      }

  Just (PatchDirect FormatNINJA1) -> do
    patch <- NINJA1.parseNINJA1 patchContents
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
          { metaRomType = Just (ninja1ToPlatform (NINJA1.ninja1RomType patch)) }
      , patchContents  = Just (emptyContents (map (\record -> Hunk (NINJA1.ninja1RecordOffset record) (NINJA1.ninja1RecordData record)) records))
          { contentsSourceCRC32 = NINJA1.ninja1SourceCRC patch
          , contentsSourceMD5   = NINJA1.ninja1SourceMD5 patch
          , contentsSourceSHA1  = NINJA1.ninja1SourceSHA1 patch
          , contentsRomType     = Just (ninja1ToPlatform (NINJA1.ninja1RomType patch))
          , contentsNINJA1Compressed = Just compressed
          }
      }

  Just (PatchDiff FormatBSDiff) -> do
    patch <- BSDiff.parseBSDiff patchContents
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
    patch <- GDIFF.parseGDIFF patchContents
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
    patch <- XDelta1.parseXDelta1 patchContents
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
    patch <- PMSR.parsePMSR patchContents
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
    patch <- PCHTXT.parsePCHTXT patchContents
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

  Just (PatchDiff FormatDPS) -> parseDPSBlock patchContents
  where
    rawBytes = unPatchFileContents patchContents

----------------------------------------------------------------------------
-- Helpers
----------------------------------------------------------------------------

parseDPSBlock :: PatchFileContents -> Either SlapError SomePatch
parseDPSBlock patchContents = case DPS.parseDPS patchContents of
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
parseYay0Container :: PatchFileContents -> Either SlapError SomePatch
parseYay0Container (PatchFileContents input) = case Yay0.decompressYay0 input of
  Left errorMessage   -> Left (Yay0DecompressionFailed errorMessage)
  Right decompressedBytes -> case parseSome (PatchFileContents decompressedBytes) of
    Left slapError -> Left slapError
    Right parsed -> Right parsed
      { patchExplain = (patchExplain parsed)
          { explainFormat = explainFormat (patchExplain parsed) ++ "/Yay0" }
      }

parseAPSGBABlock :: PatchFileContents -> Either SlapError SomePatch
parseAPSGBABlock patchContents = do
  patch@(APSGBA.APSGBAPatch header records) <- APSGBA.parseAPSGBA patchContents
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
          , verifyFileSizeAdvisory = Just (APSGBA.apsGbaSourceSize header)
          }
    , patchWarnings       = [EmptyPatch LabelAPSGBA "blocks" | null records]
    , patchRecordSummary  = RecordSummary (length records) "blocks"
    , patchSourceNotes    = []
    , patchMetadata       = Nothing
    , patchExtractedMeta  = defaultMeta
    , patchContents  = Nothing
    }

-- | Structural check for APS-GBA: header + N * 65544-byte records,
-- each record offset 64KB-aligned.  Used to disambiguate "APS10" (N64) from
-- "APS1" + source_size when size mod 256 == 48.
apsGbaStructure :: ByteString.ByteString -> Bool
apsGbaStructure input =
  let dataLength = ByteString.length input - APSGBA.apsGbaHeaderSize
      recordCount = dataLength `div` APSGBA.apsGbaRecordSize
  in dataLength == 0
     || (dataLength >= APSGBA.apsGbaRecordSize && dataLength `mod` APSGBA.apsGbaRecordSize == 0
         && all (\index -> let position = APSGBA.apsGbaHeaderSize + index * APSGBA.apsGbaRecordSize
                       in ByteString.index input position == 0 && ByteString.index input (position + 1) == 0)
                [0 .. recordCount - 1])

