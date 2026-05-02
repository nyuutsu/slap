module Slap.SomePatch
  ( SomePatch(..)
  , PatchKind(..)
  , RecordSummary(..)
  , ApplyStrategy(..)
  , UndoStrategy(..)
  , Verification(..)
  , BlockCheck(..)
  , ValidationBlock(..)
  , WindowCheck(..)
  , ByteCheck(..)
  , AdvisoryExpectedBytes(..)
  , noVerification
  , parseSome
  ) where

import Slap.FileContents (SourceFileContents(..), TargetFileContents(..), PatchFileContents(..))
import Slap.Types (PatchFormat(..), DirectFormat(..), DiffFormat(..))
import Slap.Detect (detectFormat)
import Slap.Convert (PatchContents(..), emptyContents, RequestedPatchMetadata(..),
                     UndoInclusion(..), ValidationInclusion(..), PatchStability(..),
                     noMetadataRequested, trimNullSpace)
import Slap.TextEncoding (decodeLocaleField, encodeUtf8Field)
import Slap.JSON (jsonPairs, jsonFieldCI)
import Slap.Measure (Offset(..), Length(..), FileSize(..), Hunk(..), UndoHunk(..))
import qualified Slap.PPF.Types as PPF
import qualified Slap.PPF1.Parse as PPF1
import qualified Slap.PPF2.Parse as PPF2
import qualified Slap.PPF3.Parse as PPF3
import qualified Slap.PPF4.Parse as PPF4
import qualified Slap.PPF4.Types as PPF4
import qualified Slap.PPF4.Apply as PPF4
import qualified Slap.PPF4.Describe as PPF4
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
import Slap.Error (SlapError(..), SlapWarning(..), Parsed(..),
                   Outcome(..), noWarnings)
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
newtype ApplyStrategy = ApplyStrategy
  { runApply :: SourceFileContents -> IO (Either SlapError (Outcome TargetFileContents)) }

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
  , validationBlockData   :: !PPF.ValidationBlockBytes
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
  , byteCheckExpected :: !AdvisoryExpectedBytes
  , byteCheckLabel    :: !String
  } deriving (Show)

-- | The bytes an advisory 'ByteCheck' expects to find at its offset in
-- the source file.  Advisory, not required: a mismatch emits a warning
-- and the apply proceeds.  The newtype distinguishes these bytes from
-- every other 'ByteString' that flows through verification (block CRCs,
-- validation blocks, hash digests) at the byte boundary.
newtype AdvisoryExpectedBytes = AdvisoryExpectedBytes
  { unAdvisoryExpectedBytes :: ByteString.ByteString }
  deriving (Show, Eq)

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
newtype UndoStrategy = UndoStrategy
  { runUndo :: TargetFileContents -> Either SlapError (Outcome SourceFileContents) }

-- | Record count and unit label for display.
data RecordSummary = RecordSummary
  { recordCount :: !Int
  , recordUnit  :: !String       -- "records", "actions", "commands", etc.
  } deriving (Show)

-- | How the patch's records relate to the target file.
--
-- 'Direct' patches carry replacement bytes that get written into the
-- target. 'Differential' patches carry delta instructions that need
-- the source file to apply. The kind drives whether source-less
-- conversion is structurally possible: 'Differential' patches always
-- need the source to convert; 'Direct' patches usually don't, though
-- specific 'Direct' patches can carry features that prevent
-- conversion (e.g. PPF with Append commands).
data PatchKind = Direct | Differential
  deriving (Show, Eq)

-- | A parsed patch with all operations pre-bound as closures.
-- The only dispatch point is 'parseSome'; every consumer works
-- through these fields, never inspecting the underlying format.
data SomePatch = SomePatch
  { patchFormat         :: FormatLabel
  , patchExplain        :: ExplainData
  , patchKind           :: PatchKind
  , patchApply          :: ApplyStrategy
  , patchUndo           :: Maybe UndoStrategy
  , patchVerification   :: Verification
  , patchWarnings       :: [SlapWarning]
  , patchRecordSummary  :: RecordSummary
  , patchContents       :: Maybe PatchContents
  , patchSourceNotes    :: [SlapWarning]
  , patchMetadata       :: Maybe ByteString.ByteString  -- ^ Arbitrary metadata blob (BPS)
  , patchExtractedMeta  :: RequestedPatchMetadata  -- ^ Text metadata extracted at parse time for conversion
  }

----------------------------------------------------------------------------
-- Parse dispatch — the single point where format-specific types exist
----------------------------------------------------------------------------

parseSome :: PatchFileContents -> Either SlapError SomePatch
parseSome patchContents = case detectFormat patchContents of
  Nothing
    | Yay0.isYay0 rawBytes -> parseYay0Container patchContents
    | otherwise -> Left UnrecognizedFormat

  Just (PatchDirect FormatPPF1) -> PPF1.parsePPF1 patchContents >>= parseSomePatchFromPPF
  Just (PatchDirect FormatPPF2) -> PPF2.parsePPF2 patchContents >>= parseSomePatchFromPPF
  Just (PatchDirect FormatPPF3) -> PPF3.parsePPF3 patchContents >>= parseSomePatchFromPPF
  Just (PatchDirect FormatPPF4) -> PPF4.parsePPF4 patchContents >>= parseSomePatchFromPPF4

  Just (PatchDirect (FormatIPS variant)) ->
    let label = case variant of
          IPS.StandardIPS -> LabelIPS
          IPS.IPS32       -> LabelIPS32
        expandIPSRecord (IPS.IPSRecordCopy { ipsCopyOffset = recordOffset
                                           , ipsCopyPayload = recordPayload }) =
          Hunk recordOffset recordPayload
        expandIPSRecord (IPS.IPSRecordRLE { ipsRleOffset = recordOffset
                                          , ipsRleCount = fillCount
                                          , ipsRleFill = fillByte }) =
          Hunk recordOffset (ByteString.replicate (unLength fillCount) fillByte)
    in case IPS.parseIPS patchContents of
      Left slapError -> Left slapError
      Right (Parsed parseResult parseWarnings) -> case parseResult of
        IPS.IPSParseCleanIPS ipsPatch ->
          let records = IPS.ipsRecords ipsPatch
          in Right SomePatch
            { patchFormat         = label
            , patchExplain        = IPS.explainIPS ipsPatch
            , patchKind           = Direct
            , patchApply          = ApplyStrategy
                  { runApply = \source -> pure (IPS.applyIPS source ipsPatch) }
            , patchUndo           = Nothing
            , patchVerification   = noVerification
            , patchWarnings       = parseWarnings
                                    ++ [EmptyPatch label "records" | Vector.null records]
            , patchRecordSummary  = RecordSummary (Vector.length records) "records"
            , patchSourceNotes    = []
            , patchMetadata       = Nothing
            , patchExtractedMeta  = noMetadataRequested
            , patchContents  = Just (emptyContents (map expandIPSRecord (Vector.toList records)))
                { contentsTruncation = IPS.ipsTruncatedTargetSize ipsPatch
                , contentsEBPMeta    = Nothing
                }
            }
        IPS.IPSParseCleanEBP ebpPatch ->
          let basePatch = IPS.ebpBasePatch ebpPatch
              records = IPS.ipsRecords basePatch
              ebpPairs = jsonPairs (IPS.unEBPMetadata (IPS.ebpMetadata ebpPatch))
              nonEmptyField decoded = if null decoded then Nothing else Just decoded
              extractedMeta = noMetadataRequested
                { requestedTitle       = jsonFieldCI ebpPairs "title" >>= nonEmptyField
                , requestedAuthor      = jsonFieldCI ebpPairs "author" >>= nonEmptyField
                , requestedDescription = jsonFieldCI ebpPairs "description" >>= nonEmptyField
                }
          in Right SomePatch
            { patchFormat         = LabelEBP
            , patchExplain        = IPS.explainEBP ebpPatch
            , patchKind           = Direct
            , patchApply          = ApplyStrategy
                  { runApply = \source -> pure (IPS.applyIPS source basePatch) }
            , patchUndo           = Nothing
            , patchVerification   = noVerification
            , patchWarnings       = parseWarnings
                                    ++ [EmptyPatch LabelEBP "records" | Vector.null records]
            , patchRecordSummary  = RecordSummary (Vector.length records) "records"
            , patchSourceNotes    = []
            , patchMetadata       = Nothing
            , patchExtractedMeta  = extractedMeta
            , patchContents  = Just (emptyContents (map expandIPSRecord (Vector.toList records)))
                { contentsTruncation = IPS.ipsTruncatedTargetSize basePatch
                , contentsEBPMeta    = Just (IPS.unEBPMetadata (IPS.ebpMetadata ebpPatch))
                }
            }
        IPS.IPSParseTruncated _variant records ->
          let truncatedPatch = IPS.IPSPatch
                { IPS.ipsVariant             = variant
                , IPS.ipsRecords             = records
                , IPS.ipsTruncatedTargetSize = Nothing
                }
          in Right SomePatch
            { patchFormat         = label
            , patchExplain        = IPS.explainIPS truncatedPatch
            , patchKind           = Direct
            , patchApply          = ApplyStrategy
                  { runApply = \source -> pure (IPS.applyIPS source truncatedPatch) }
            , patchUndo           = Nothing
            , patchVerification   = noVerification
            , patchWarnings       = parseWarnings
                                    ++ [EmptyPatch label "records" | Vector.null records]
            , patchRecordSummary  = RecordSummary (Vector.length records) "records"
            , patchSourceNotes    = []
            , patchMetadata       = Nothing
            , patchExtractedMeta  = noMetadataRequested
            , patchContents  = Just (emptyContents (map expandIPSRecord (Vector.toList records)))
                { contentsTruncation = Nothing
                , contentsEBPMeta    = Nothing
                }
            }

  Just (PatchDiff FormatBPS) -> do
    Parsed patch parseWarnings <- BPS.parseBPS patchContents
    let actions = BPS.bpsActions patch
        metadataBytes = BPS.unBPSMetadata (BPS.bpsMetadata patch)
        bpsMetaBlob = if ByteString.null metadataBytes then Nothing
                      else Just metadataBytes
    Right SomePatch
      { patchFormat         = LabelBPS
      , patchExplain        = BPS.explainBPS patch
      , patchKind           = Differential
      , patchApply          = ApplyStrategy
          { runApply     = \source -> pure (fmap noWarnings (BPS.applyBPS patch source)) }
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
      , patchWarnings       = parseWarnings
                              ++ [EmptyPatch LabelBPS "actions" | Vector.null actions]
      , patchRecordSummary  = RecordSummary (Vector.length actions) "actions"
      , patchSourceNotes    = []
      , patchMetadata       = bpsMetaBlob
      , patchExtractedMeta  = noMetadataRequested { requestedEmbeddedBlob = bpsMetaBlob }
      , patchContents  = Nothing
      }

  Just (PatchDiff FormatUPS) -> do
    Parsed patch parseWarnings <- UPS.parseUPS patchContents
    let blocks = UPS.upsBlocks patch
    Right SomePatch
      { patchFormat         = LabelUPS
      , patchExplain        = UPS.explainUPS patch
      , patchKind           = Differential
      , patchApply          = ApplyStrategy
          { runApply     = \source -> pure (fmap noWarnings (UPS.applyUPS patch source)) }
      , patchUndo           = Just $ UndoStrategy $ \(TargetFileContents modified) ->
          -- UPS is self-inverse (XOR-based): applying the patch to the
          -- target recovers the source. For a well-parsed patch this
          -- reapplication cannot fail.
          case UPS.applyUPS patch (SourceFileContents modified) of
            Right (TargetFileContents reverted) ->
              Right (noWarnings (SourceFileContents reverted))
            Left slapError -> Left slapError
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
      , patchWarnings       = parseWarnings
                              ++ [EmptyPatch LabelUPS "blocks" | Vector.null blocks]
                              ++ UPS.detectOOBBlocks patch
      , patchRecordSummary  = RecordSummary (Vector.length blocks) "blocks"
      , patchSourceNotes    = []
      , patchMetadata       = Nothing
      , patchExtractedMeta  = noMetadataRequested
      , patchContents  = Nothing
      }

  Just (PatchDiff FormatVCDIFF) -> do
    Parsed patch parseWarnings <- VCDIFF.parseVCDIFF patchContents
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
      , patchKind           = Differential
      , patchApply          = ApplyStrategy
          { runApply     = \source -> pure (fmap noWarnings (VCDIFF.applyVCDIFF patch source)) }
      , patchUndo           = Nothing
      , patchVerification   = noVerification { verifyWindowAdler32 = adlerChecks }
      , patchWarnings       = parseWarnings
                              ++ [EmptyPatch LabelVCDIFF "windows" | null windows]
      , patchRecordSummary  = RecordSummary (length windows) "windows"
      , patchSourceNotes    = []
      , patchMetadata       = Nothing
      , patchExtractedMeta  = noMetadataRequested
      , patchContents  = Nothing
      }

  -- APS N64 and APS GBA are unrelated formats by different authors who
  -- both used "APS" as the name.  detectFormat dispatches on magic, but
  -- "APS10" (N64) collides with "APS1" + source size when size mod 256 == 48.
  -- Disambiguate via GBA's fixed record structure (12 + N*65544 bytes,
  -- 64KB-aligned offsets).
  Just (PatchDirect FormatAPSN64)
    | APSGBA.apsGbaStructure rawBytes -> parseAPSGBABlock patchContents
    | otherwise -> do
    Parsed patch@(APSN64.APSN64Patch header records) parseWarnings <- APSN64.parseAPSN64 patchContents
    let expandN64 (APSN64.APSN64Normal recordOffset recordPayload) = Hunk recordOffset recordPayload
        expandN64 (APSN64.APSN64RLE recordOffset fillValue fillCount) = Hunk recordOffset (ByteString.replicate (fromIntegral fillCount) fillValue)
    Right SomePatch
      { patchFormat         = LabelAPSN64
      , patchExplain        = APSN64.explainAPSN64 patch
      , patchKind           = Direct
      , patchApply          = ApplyStrategy
            { runApply = \source -> pure (fmap noWarnings (APSN64.applyAPSN64 patch source)) }
      , patchUndo           = Nothing
      , patchVerification   = noVerification
            { verifySourceBytes = concat
                [ maybe [] (\cartId -> [ByteCheck (Offset 0x3C) (AdvisoryExpectedBytes (APSN64.unN64CartId cartId)) "N64 cart ID"]) (APSN64.apsN64CartId header)
                , maybe [] (\country -> [ByteCheck (Offset 0x3E) (AdvisoryExpectedBytes (ByteString.singleton (APSN64.fromAPSN64Country country))) "N64 country"]) (APSN64.apsN64Country header)
                , maybe [] (\crc -> [ByteCheck (Offset 0x10) (AdvisoryExpectedBytes (APSN64.unN64ChecksumPair crc)) "N64 CRC"]) (APSN64.apsN64Crc header)
                ]
            }
      , patchWarnings       = parseWarnings
                              ++ [EmptyPatch LabelAPSN64 "records" | Vector.null records]
      , patchRecordSummary  = RecordSummary (Vector.length records) "records"
      , patchSourceNotes    = []
      , patchMetadata       = Nothing
      , patchExtractedMeta  = let description = trimNullSpace (decodeLocaleField (APSN64.apsN64Description header))
                              in noMetadataRequested
                                { requestedDescription = if null description then Nothing else Just description }
      , patchContents  = Just (emptyContents (Vector.toList (Vector.map expandN64 records)))
            { contentsDescription = Just (APSN64.apsN64Description header)
            , contentsDestinationSize    = Just (APSN64.apsN64DestinationSize header)
            }
      }

  Just (PatchDiff FormatAPSGBA) -> parseAPSGBABlock patchContents

  Just (PatchDiff FormatNINJA2) -> do
    Parsed patch parseWarnings <- NINJA2.parseNINJA2 patchContents
    let filterZeroMD5 (Just hash@(MD5Hash bytes))
          | ByteString.all (== 0) bytes = Nothing
          | otherwise                   = Just hash
        filterZeroMD5 Nothing = Nothing
        openNewFile = NINJA2.ninja2OpenNewFile patch
        romTypeForPlatformConversion = case openNewFile of
          Just open -> NINJA2.openNewFileRomType open
          Nothing   -> NINJA2.Ninja2Raw
        (platformType, platformWarnings) = ninja2ToPlatform romTypeForPlatformConversion
    Right SomePatch
      { patchFormat         = LabelNINJA2
      , patchExplain        = NINJA2.explainNINJA2 patch
      , patchKind           = Differential
      , patchApply          = ApplyStrategy
            { runApply = \source -> pure (fmap noWarnings (NINJA2.applyNINJA2 patch source)) }
      , patchUndo           = Nothing
      , patchVerification   = noVerification
          { verifySourceMD5 = filterZeroMD5 (fmap NINJA2.openNewFileSourceMD5 openNewFile)
          , verifyTargetMD5 = filterZeroMD5 (fmap NINJA2.openNewFileTargetMD5 openNewFile)
          }
      , patchWarnings       = parseWarnings
                               ++ [EmptyPatch LabelNINJA2 "records" | null (NINJA2.ninja2Records patch)]
                               ++ platformWarnings
      , patchRecordSummary  = RecordSummary (length (NINJA2.ninja2Records patch)) "records"
      , patchSourceNotes    = []
      , patchMetadata       = Nothing
      , patchExtractedMeta  = let decode = NINJA2.decodeNINJA2Field (NINJA2.ninja2PatchEncoding patch)
                                  nonEmptyField fieldBytes = let decoded = decode fieldBytes
                                                              in if null decoded then Nothing else Just decoded
                                  info = NINJA2.ninja2Header patch
                              in noMetadataRequested
                                { requestedTitle       = NINJA2.ninja2Title       info >>= nonEmptyField
                                , requestedAuthor      = NINJA2.ninja2Author      info >>= nonEmptyField
                                , requestedVersion     = NINJA2.ninja2Version     info >>= nonEmptyField
                                , requestedGenre       = NINJA2.ninja2Genre       info >>= nonEmptyField
                                , requestedLanguage    = NINJA2.ninja2Language    info >>= nonEmptyField
                                , requestedDate        = NINJA2.ninja2Date        info >>= nonEmptyField
                                , requestedWebsite     = NINJA2.ninja2Website     info >>= nonEmptyField
                                , requestedDescription = NINJA2.ninja2Description info >>= nonEmptyField
                                , requestedRomType     = Just platformType
                                }
      , patchContents  = Nothing
      }

  Just (PatchDirect FormatNINJA1) -> do
    Parsed patch parseWarnings <- NINJA1.parseNINJA1 patchContents
    let records = NINJA1.ninja1Records patch
        warnings = concat
          [ parseWarnings
          , [NoEOFMarker LabelNINJA1 | not (NINJA1.ninja1CleanEOF patch)]
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
      , patchKind           = Direct
      , patchApply          = ApplyStrategy
            { runApply = \source -> pure (fmap noWarnings (NINJA1.applyNINJA1 patch source)) }
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
      , patchExtractedMeta  = noMetadataRequested
          { requestedRomType = Just (ninja1ToPlatform (NINJA1.ninja1RomType patch)) }
      , patchContents  = Just (emptyContents (map (\record -> Hunk (NINJA1.ninja1RecordOffset record) (NINJA1.ninja1RecordData record)) records))
          { contentsSourceCRC32 = NINJA1.ninja1SourceCRC patch
          , contentsSourceMD5   = NINJA1.ninja1SourceMD5 patch
          , contentsSourceSHA1  = NINJA1.ninja1SourceSHA1 patch
          , contentsRomType     = Just (ninja1ToPlatform (NINJA1.ninja1RomType patch))
          , contentsNINJA1Compressed = Just compressed
          }
      }

  Just (PatchDiff FormatBSDiff) -> do
    Parsed patch parseWarnings <- BSDiff.parseBSDiff patchContents
    Right SomePatch
      { patchFormat         = LabelBSDiff
      , patchExplain        = BSDiff.explainBSDiff patch
      , patchKind           = Differential
      , patchApply          = ApplyStrategy
          { runApply     = \source -> pure (fmap noWarnings (BSDiff.applyBSDiff patch source)) }
      , patchUndo           = Nothing
      , patchVerification   = noVerification
      , patchWarnings       = parseWarnings
                              ++ [EmptyPatch LabelBSDiff "control tuples" | null (BSDiff.bsdiffControls patch)]
      , patchRecordSummary  = RecordSummary (length (BSDiff.bsdiffControls patch)) "control tuples"
      , patchSourceNotes    = []
      , patchMetadata       = Nothing
      , patchExtractedMeta  = noMetadataRequested
      , patchContents  = Nothing
      }

  Just (PatchDiff FormatGDIFF) -> do
    Parsed patch parseWarnings <- GDIFF.parseGDIFF patchContents
    Right SomePatch
      { patchFormat         = LabelGDIFF
      , patchExplain        = GDIFF.explainGDIFF patch
      , patchKind           = Differential
      , patchApply          = ApplyStrategy
          { runApply     = \source -> pure (fmap noWarnings (GDIFF.applyGDIFF patch source)) }
      , patchUndo           = Nothing
      , patchVerification   = noVerification
      , patchWarnings       = parseWarnings
                              ++ [EmptyPatch LabelGDIFF "commands" | null (GDIFF.gdiffCommands patch)]
      , patchRecordSummary  = RecordSummary (length (GDIFF.gdiffCommands patch)) "commands"
      , patchSourceNotes    = []
      , patchMetadata       = Nothing
      , patchExtractedMeta  = noMetadataRequested
      , patchContents  = Nothing
      }

  Just (PatchDiff FormatXDelta1) -> do
    Parsed patch parseWarnings <- XDelta1.parseXDelta1 patchContents
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
      , patchKind           = Differential
      , patchApply          = ApplyStrategy
          { runApply     = \source -> pure (fmap noWarnings (XDelta1.applyXDelta1 patch source)) }
      , patchUndo           = Nothing
      , patchVerification   = xdeltaVerification
      , patchWarnings       = parseWarnings
                              ++ [EmptyPatch LabelXDelta1 "instructions" | null (XDelta1.xdelta1Instructions patch)]
      , patchRecordSummary  = RecordSummary (length (XDelta1.xdelta1Instructions patch)) "instructions"
      , patchSourceNotes    = []
      , patchMetadata       = Nothing
      , patchExtractedMeta  = noMetadataRequested
      , patchContents  = Nothing
      }

  Just (PatchDirect FormatPMSR) -> do
    Parsed patch parseWarnings <- PMSR.parsePMSR patchContents
    let records = PMSR.pmsrRecords patch
    Right SomePatch
      { patchFormat         = LabelPMSR
      , patchExplain        = PMSR.explainPMSR patch
      , patchKind           = Direct
      , patchApply          = ApplyStrategy
            { runApply = \source -> pure (fmap noWarnings (PMSR.applyPMSR patch source)) }
      , patchUndo           = Nothing
      , patchVerification   = noVerification
      , patchWarnings       = parseWarnings
                              ++ [EmptyPatch LabelPMSR "records" | null records]
      , patchRecordSummary  = RecordSummary (length records) "records"
      , patchSourceNotes    = []
      , patchMetadata       = Nothing
      , patchExtractedMeta  = noMetadataRequested
      , patchContents  = Just (emptyContents
          (map (\record -> Hunk (PMSR.pmsrOffset record) (PMSR.pmsrData record)) records))
      }

  Just (PatchDirect FormatPCHTXT) -> do
    Parsed patch parseWarnings <- PCHTXT.parsePCHTXT patchContents
    let allBlocks = PCHTXT.pchtxtBlocks patch
        enabledBlocks = filter PCHTXT.pchtxtBlockEnabled allBlocks
        entries = concatMap PCHTXT.pchtxtBlockEntries enabledBlocks
        contentRecords = map (\entry -> Hunk (PCHTXT.pchtxtOffset entry) (PCHTXT.pchtxtData entry)) entries
        sourceNotes = [OffsetShiftApplied | PCHTXT.pchtxtHasShift patch]
    Right SomePatch
      { patchFormat         = LabelPCHTXT
      , patchExplain        = PCHTXT.explainPCHTXT patch
      , patchKind           = Direct
      , patchApply          = ApplyStrategy
            { runApply = \source -> pure (fmap noWarnings (PCHTXT.applyPCHTXT patch source)) }
      , patchUndo           = Nothing
      , patchVerification   = noVerification
      , patchWarnings       = parseWarnings
                              ++ [EmptyPatch LabelPCHTXT "entries" | null entries]
      , patchRecordSummary  = RecordSummary (length entries) "entries"
      , patchSourceNotes    = sourceNotes
      , patchMetadata       = Nothing
      , patchExtractedMeta  = noMetadataRequested
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

-- | Build a 'SomePatch' from a parsed PPF1/2/3 patch. The three
-- published-spec PPF versions share a single parsed type
-- ('PPF.PPFPatch') and route through this helper. PPF4, which has its
-- own type with a two-phase shape, has a peer helper
-- 'parseSomePatchFromPPF4'.
parseSomePatchFromPPF :: Parsed PPF.PPFPatch -> Either SlapError SomePatch
parseSomePatchFromPPF (Parsed patch parseWarnings) =
  let records = PPF.ppfRecords patch
      ppfVerification = noVerification
          { verifyPPFBlock = case PPF.ppfValidation patch of
              Just validation -> Just (ValidationBlock (PPF.validationOffset (PPF.validationImageType validation)) (PPF.validationBlock validation))
              Nothing  -> Nothing
          , verifyFileSizeAdvisory = PPF.ppfFileSize patch
          }
  in Right SomePatch
      { patchFormat         = PPF.ppfVersionLabel (PPF.ppfVersion patch)
      , patchExplain        = PPF.explainPPF patch
      , patchKind           = Direct
      , patchApply          = ApplyStrategy
          { runApply = \source -> pure (fmap noWarnings (PPF.applyPPF patch source)) }
      , patchUndo           = if PPF.ppfHasUndo patch
                               then Just (UndoStrategy (fmap noWarnings . PPF.undoPPF patch))
                               else Nothing
      , patchVerification   = ppfVerification
      , patchWarnings       = parseWarnings
                              ++ [EmptyPatch (PPF.ppfVersionLabel (PPF.ppfVersion patch)) "records" | null records]
      , patchRecordSummary  = RecordSummary (length records) "records"
      , patchSourceNotes    = []
      , patchMetadata       = Nothing
      , patchExtractedMeta  = let description = trimNullSpace (decodeLocaleField (PPF.ppfDescription patch))
                              in noMetadataRequested
                                { requestedDescription         = if null description then Nothing else Just description
                                , requestedImageType           = PPF.ppfImageType patch
                                , requestedUndoInclusion       = if PPF.ppfHasUndo patch then Just IncludeUndoData else Nothing
                                , requestedValidationInclusion = if isJust (PPF.ppfValidation patch) then Just IncludeValidationBlock else Nothing
                                }
      , patchContents  = Just PatchContents
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
          , contentsFileIdDiz   = PPF.ppfFileId patch
          , contentsPCHTXTBlocks = Nothing
          , contentsNINJA1Compressed = Nothing
          , contentsMetadata = Nothing
          , contentsPatchEncoding = Nothing
          }
      }

-- | Build a 'SomePatch' from a parsed PPF4 patch. PPF4 is a two-phase
-- format (Replace records, then Append records) with no validation
-- block, no undo, no image type, and no File_ID.diz trailer — none of
-- the metadata that 'parseSomePatchFromPPF' carries for PPF1/2/3.
-- Source-less conversion is structurally possible only when the patch
-- has no Append records (Appends carry no meaningful offset, and so
-- can't be expressed as 'Hunk's).
parseSomePatchFromPPF4 :: Parsed PPF4.PPF4Patch -> Either SlapError SomePatch
parseSomePatchFromPPF4 (Parsed patch parseWarnings) =
  let replaces = PPF4.ppf4Replaces patch
      appends  = PPF4.ppf4Appends patch
      totalRecords = length replaces + length appends
  in Right SomePatch
      { patchFormat         = LabelPPF4
      , patchExplain        = PPF4.explainPPF4 patch
      , patchKind           = Direct
      , patchApply          = ApplyStrategy
          { runApply = \source -> pure (fmap noWarnings (PPF4.applyPPF4 patch source)) }
      , patchUndo           = Nothing
      , patchVerification   = noVerification
      , patchWarnings       = parseWarnings
                              ++ [EmptyPatch LabelPPF4 "records" | totalRecords == 0]
      , patchRecordSummary  = RecordSummary totalRecords "records"
      , patchSourceNotes    = []
      , patchMetadata       = Nothing
      , patchExtractedMeta  = let description = trimNullSpace (decodeLocaleField (PPF4.ppf4Description patch))
                              in noMetadataRequested
                                { requestedDescription = if null description then Nothing else Just description
                                }
      , patchContents       = if null appends
                                then Just (emptyContents (map (\replace -> Hunk (PPF4.replaceOffset replace) (PPF4.replaceData replace)) replaces))
                                       { contentsDescription = Just (PPF4.ppf4Description patch) }
                                else Nothing
      }

parseDPSBlock :: PatchFileContents -> Either SlapError SomePatch
parseDPSBlock patchContents = case DPS.parseDPS patchContents of
  Left slapError -> Left slapError
  Right (Parsed patch parseWarnings) ->
    let records = DPS.dpsRecords patch
    in Right SomePatch
      { patchFormat         = LabelDPS
      , patchExplain        = DPS.explainDPS patch
      , patchKind           = Differential
      , patchApply          = ApplyStrategy
          { runApply     = \source -> pure (fmap noWarnings (DPS.applyDPS patch source)) }
      , patchVerification   = noVerification
            { verifyFileSizeRequired = Just (DPS.dpsOriginalSize patch) }
      , patchUndo           = Nothing
      , patchWarnings       = parseWarnings
                              ++ [EmptyPatch LabelDPS "records" | null records]
      , patchRecordSummary  = RecordSummary (length records) "records"
      , patchSourceNotes    = []
      , patchContents  = Nothing
      , patchMetadata       = Nothing
      , patchExtractedMeta  = let nonEmpty fieldBytes = let decoded = trimNullSpace (decodeLocaleField fieldBytes)
                                                       in if null decoded then Nothing else Just decoded
                              in noMetadataRequested
                                { requestedTitle     = nonEmpty (DPS.dpsName    patch)
                                , requestedAuthor    = nonEmpty (DPS.dpsAuthor  patch)
                                , requestedVersion   = nonEmpty (DPS.dpsVersion patch)
                                , requestedStability = case DPS.dpsStability patch of
                                                         DPS.DPSUnstable -> Just UnstablePatch
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
  Parsed patch@(APSGBA.APSGBAPatch header records) parseWarnings <- APSGBA.parseAPSGBA patchContents
  Right SomePatch
    { patchFormat         = LabelAPSGBA
    , patchExplain        = APSGBA.explainAPSGBA patch
    , patchKind           = Differential
    , patchApply          = ApplyStrategy
          { runApply = \source -> pure (fmap noWarnings (APSGBA.applyAPSGBA patch source)) }
    , patchUndo           = Nothing
    , patchVerification   = noVerification
          { verifySourceBlocks = map (\record -> BlockCheck (APSGBA.apsGbaOffset record) (APSGBA.apsGbaSourceCRC record)) records
          , verifyTargetBlocks = map (\record -> BlockCheck (APSGBA.apsGbaOffset record) (APSGBA.apsGbaTargetCRC record)) records
          , verifyFileSizeAdvisory = Just (APSGBA.apsGbaSourceSize header)
          }
    , patchWarnings       = parseWarnings
                            ++ [EmptyPatch LabelAPSGBA "blocks" | null records]
    , patchRecordSummary  = RecordSummary (length records) "blocks"
    , patchSourceNotes    = []
    , patchMetadata       = Nothing
    , patchExtractedMeta  = noMetadataRequested
    , patchContents  = Nothing
    }

