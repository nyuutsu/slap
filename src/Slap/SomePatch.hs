{-# LANGUAGE OverloadedStrings #-}

module Slap.SomePatch
  ( SomePatch(..)
  , PatchKind(..)
  , ApplyStrategy(..)
  , UndoStrategy(..)
  , Verification(..)
  , BlockCheck(..)
  , ValidationBlock(..)
  , WindowCheck(..)
  , ByteCheck(..)
  , AdvisoryExpectedBytes(..)
  , FileSizeCheck(..)
  , ExpectedN64ByteOrder(..)
  , SourcePreHash(..)
  , applySourcePreHash
  , noVerification
  , parseSome
  ) where

import Slap.FileContents (InputFileContents(..), OutputFileContents(..), PatchFileContents(..))
import Slap.PatchFormat (PatchFormat(..), DirectFormat(..), DifferentialFormat(..))
import Slap.Detect (detectFormat)
import Slap.Convert (PatchContents(..), emptyContents, RequestedPatchMetadata(..),
                     UndoInclusion(..), VerificationInclusion(..), PatchStability(..),
                     RequestedDialects(..), NINJA1Compression(..),
                     noMetadataRequested)
import Slap.Text (EncodedText, EncodingName, encodedTextContent)
import Data.Text (Text)
import qualified Data.Text as Text
import Slap.Measure (Offset(..), Length(..), FileSize(..), Hunk(..),
                     Cursor(..), splitUndoHunkFromParsed)
import qualified Slap.PPF1.Apply as PPF1
import qualified Slap.PPF1.Describe as PPF1
import qualified Slap.PPF1.Parse as PPF1
import qualified Slap.PPF1.Types as PPF1
import qualified Slap.PPF2.Apply as PPF2
import qualified Slap.PPF2.Describe as PPF2
import qualified Slap.PPF2.Parse as PPF2
import qualified Slap.PPF2.Types as PPF2
import qualified Slap.PPF3.Apply as PPF3
import qualified Slap.PPF3.Describe as PPF3
import qualified Slap.PPF3.Parse as PPF3
import qualified Slap.PPF3.Types as PPF3
import qualified Slap.PPF4.Parse as PPF4
import qualified Slap.PPF4.Types as PPF4
import qualified Slap.PPF4.Apply as PPF4
import qualified Slap.PPF4.Describe as PPF4
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
import qualified Slap.VCDIFF.Parse as VCDIFF
import qualified Slap.VCDIFF.Apply as VCDIFF
import qualified Slap.VCDIFF.Types as VCDIFF
import qualified Slap.VCDIFF.Describe as VCDIFFDescribe
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
import Slap.Display.Analysis (PatchAnalysis(..))
import Slap.Display.Common (FormatHeader(..),
                             Tally(..), CountUnit(..), ByteCount(..))
import Slap.Display.Info (PatchInfo(..))
import Slap.Status (SlapError(..), SlapAdvisory(..), DecompressionFailure(..),
                   Parsed(..), Outcome(..), noAdvisories,
                   EmptyUnit(..), NINJA1SubformatConversion(..))
import Slap.FormatLabel (FormatLabel(..))
import qualified Slap.Compression.Yay0 as Yay0
import qualified Slap.Compression.Stream as Stream

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.Vector as Vector
import Data.List (partition)
import Data.Maybe (catMaybes, fromMaybe, isJust, mapMaybe)
import Slap.Checksum (CRC32, CRC16, Adler32, MD5Hash(..), SHA1Hash(..))

----------------------------------------------------------------------------
-- Types
----------------------------------------------------------------------------

-- | Every format takes source bytes and returns target bytes.
-- Direct formats (IPS, PPF, etc.) overlay records onto a copy of the source;
-- differential formats (BPS, UPS, VCDIFF, etc.) compute the target from source bytes and patch instructions.
newtype ApplyStrategy = ApplyStrategy
  { runApply :: InputFileContents -> IO (Either SlapError (Outcome OutputFileContents)) }

-- | How the source bytes are transformed before the source hashes are
-- computed — data, not a bare function, so 'Verification' stays
-- inspectable. 'HashNINJA1Sample' is NINJA1's large-file sampling rule
-- (see 'Slap.NINJA1.Create.ninja1HashInput'); 'HashWholeSource' is the
-- default for every other format.
data SourcePreHash = HashWholeSource | HashNINJA1Sample
  deriving (Eq, Show)

applySourcePreHash :: SourcePreHash -> ByteString -> ByteString
applySourcePreHash HashWholeSource  = id
applySourcePreHash HashNINJA1Sample = NINJA1.ninja1HashInput

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
    -- | File-size check, when the format declares an expected source
    -- size. The 'FileSizeCheck' carries its own severity: 'AdvisorySize'
    -- for formats with a stronger gate (a CRC32, say), where a mismatch
    -- only warns; 'RequiredSize' for formats where the declared size is
    -- the sole gate, where a mismatch fails the apply unless
    -- @--no-verify@ is set.
  , verifyFileSize :: Maybe FileSizeCheck
  , verifyWindowAdler32 :: [WindowCheck]
  , verifySourceBytes   :: [ByteCheck]
  , verifySourcePreHash :: SourcePreHash
    -- | 'Just' the format when the patch's ROM-type byte is unrecognized,
    -- 'Nothing' otherwise (set by the NINJA parsers). Drives the
    -- 'UnrecognizedRomTypeWithoutChecksum' refusal.
  , verifyRomTypeUnrecognized :: Maybe FormatLabel
    -- | Set for an APS-N64 Type-1 source; gates its byte-order on apply, 'Nothing' otherwise.
  , verifyN64ByteOrder :: Maybe ExpectedN64ByteOrder
  }

-- | The N64 image byte-order an APS-N64 Type-1 patch was built against.
-- Its record offsets assume one order, so applying to a source in the other would corrupt it;
-- the format distinguishes only V64 (the byteswapped "Doctor" image) from everything else.
data ExpectedN64ByteOrder = SourceMustBeV64 | SourceMustNotBeV64
  deriving (Show, Eq)

-- | Per-block CRC16 check (APS-GBA).
data BlockCheck = BlockCheck !Offset !CRC16
  deriving (Show)

-- | Validation block comparison (PPF2 and PPF3). The bytes are
-- carried as a raw 'ByteString' at this cross-cutting layer; each
-- format wraps them in its own role newtype during parse and emit.
data ValidationBlock = ValidationBlock !Offset !ByteString
  deriving (Show)

-- | Per-window Adler32 check (VCDIFF).
data WindowCheck = WindowCheck !Offset !Length !Adler32
  deriving (Show)

-- | Advisory byte-range comparison (APS-N64 cart ID, country, CRC).
-- The trailing 'Text' field is the check's label.
data ByteCheck = ByteCheck !Offset !AdvisoryExpectedBytes !Text
  deriving (Show)

-- | The bytes an advisory 'ByteCheck' expects to find at its offset in
-- the source file.  Advisory, not required: a mismatch emits a warning
-- and the apply proceeds.  The newtype distinguishes these bytes from
-- every other 'ByteString' that flows through verification (block CRCs,
-- validation blocks, hash digests) at the byte boundary.
newtype AdvisoryExpectedBytes = AdvisoryExpectedBytes
  { unAdvisoryExpectedBytes :: ByteString }
  deriving (Show, Eq)

-- | A declared file-size expectation paired with how a mismatch is
-- treated. File size is the one verification check whose severity
-- varies by format, so the severity rides on the value here rather than
-- on which field carries it: the apply-time verifier matches the
-- constructor to route 'AdvisorySize' to a warning and 'RequiredSize'
-- to a policy-gated failure.
data FileSizeCheck
  = AdvisorySize !FileSize
    -- ^ The format has a stronger integrity gate (e.g. a CRC32), so a
    -- size mismatch only warns; the stronger check catches real
    -- corruption.
  | RequiredSize !FileSize
    -- ^ The declared size is the format's only integrity gate, so a
    -- mismatch fails the apply unless @--no-verify@ is set.
  deriving (Show, Eq)

noVerification :: Verification
noVerification = Verification
  { verifySourceCRC32 = Nothing, verifySourceMD5 = Nothing, verifySourceSHA1 = Nothing
  , verifyTargetCRC32 = Nothing, verifyTargetMD5 = Nothing
  , verifySourceBlocks = [], verifyTargetBlocks = []
  , verifyPPFBlock = Nothing, verifyFileSize = Nothing
  , verifyWindowAdler32 = [], verifySourceBytes = []
  , verifySourcePreHash = HashWholeSource
  , verifyRomTypeUnrecognized = Nothing
  , verifyN64ByteOrder = Nothing
  }

-- | Takes the modified file and returns the original, or 'Left' on malformed undo data (bounds violations, negative offsets).
-- For self-inverse formats like UPS (XOR-based), the apply function itself serves as the undo.
newtype UndoStrategy = UndoStrategy
  { runUndo :: OutputFileContents -> Either SlapError (Outcome InputFileContents) }

-- | How the patch's records relate to the target file.
--
-- 'Direct' patches carry replacement bytes that get written into the target;
-- the @'Maybe' 'PatchContents'@ payload is the universal direct-patch bag when the format's data is bag-shaped,
-- or 'Nothing' when a structural feature prevents the bag from being constructed
-- (e.g. PPF4 with Append commands: Appends carry no meaningful offset, so they can't be expressed as 'Hunk's).
-- 'Differential' patches carry delta instructions whose meaning depends on the source file,
-- so they have no universal bag to publish.
-- The kind drives whether source-less conversion is structurally possible:
-- only @'Direct' ('Just' _)@ can convert without source.
data PatchKind
  = Direct (Maybe PatchContents)
  | Differential

-- | A parsed patch with all operations pre-bound as closures.
-- The only dispatch point is 'parseSome'; every consumer works
-- through these fields, never inspecting the underlying format.
data SomePatch = SomePatch
  { patchFormat         :: FormatLabel
  , patchAnalysis       :: PatchAnalysis
    -- ^ The analytical-pass carrier consumed by @slap explain@. The
    -- field is non-strict on purpose: @slap info@ and @slap apply@
    -- never force it, so the per-record analytical work each
    -- 'analyze\<Format\>' producer encodes is paid only when
    -- 'renderAnalysisFull' or 'renderAnalysisSummary' actually walks the
    -- 'analysisSections' / 'analysisSummary'. Code that runs on
    -- every parse must not force this field.
  , patchKind           :: PatchKind
  , patchApply          :: ApplyStrategy
  , patchUndo           :: Maybe UndoStrategy
  , patchVerification   :: Verification
  , patchAdvisories       :: [SlapAdvisory]
  , patchInfo           :: PatchInfo
    -- ^ Cheap display carrier consumed by @slap info@ and @slap apply@.
    -- Populated at parse time without per-record analytical work.
    -- The expensive analytical carrier is 'patchAnalysis'.
  , patchSourceAdvisories    :: [SlapAdvisory]
  , patchMetadata       :: Maybe ByteString  -- ^ Opaque embedded metadata blob (BPS metadata / xdelta3 appheader)
  , patchExtractedMeta  :: RequestedPatchMetadata  -- ^ Text metadata extracted at parse time for conversion
  }

----------------------------------------------------------------------------
-- Parse dispatch — the single point where format-specific types exist
----------------------------------------------------------------------------

parseSome :: RequestedDialects -> EncodingName -> PatchFileContents -> Either SlapError SomePatch
parseSome dialects metadataEncoding patchContents = case detectFormat patchContents of
  Nothing
    | Yay0.isYay0 rawBytes -> parseSomePatchFromYay0 dialects metadataEncoding patchContents
    | otherwise            -> Left UnrecognizedFormat

  Just (PatchDirect       FormatPPF1)           -> PPF1.parsePPF1 (requestedPPF1Origin dialects) metadataEncoding patchContents >>= parseSomePatchFromPPF1
  Just (PatchDirect       FormatPPF2)           -> PPF2.parsePPF2 metadataEncoding patchContents >>= parseSomePatchFromPPF2
  Just (PatchDirect       FormatPPF3)           -> PPF3.parsePPF3 metadataEncoding patchContents >>= parseSomePatchFromPPF3
  Just (PatchDirect       FormatPPF4)           -> parseSomePatchFromPPF4 metadataEncoding patchContents
  Just (PatchDirect       (FormatIPS variant))  -> parseSomePatchFromIPS variant patchContents
  Just (PatchDirect       FormatAPSN64)         -> parseSomePatchFromAPSN64 metadataEncoding patchContents
  Just (PatchDirect       FormatNINJA1)         -> parseSomePatchFromNINJA1 patchContents
  Just (PatchDirect       FormatPMSR)           -> parseSomePatchFromPMSR patchContents
  Just (PatchDifferential FormatBPS)            -> parseSomePatchFromBPS metadataEncoding patchContents
  Just (PatchDifferential FormatUPS)            -> parseSomePatchFromUPS patchContents
  Just (PatchDifferential FormatVCDIFF)         -> parseSomePatchFromVCDIFF metadataEncoding patchContents
  Just (PatchDifferential FormatAPSGBA)         -> parseSomePatchFromAPSGBA patchContents
  Just (PatchDifferential FormatNINJA2)         -> parseSomePatchFromNINJA2 metadataEncoding patchContents
  Just (PatchDifferential FormatBSDiff)         -> parseSomePatchFromBSDiff patchContents
  Just (PatchDifferential FormatGDIFF)          -> parseSomePatchFromGDIFF patchContents
  Just (PatchDifferential FormatXDelta1)        -> parseSomePatchFromXDelta1 metadataEncoding patchContents
  Just (PatchDifferential FormatDPS)            -> parseSomePatchFromDPS metadataEncoding patchContents
  where
    rawBytes = unPatchFileContents patchContents

----------------------------------------------------------------------------
-- Helpers
----------------------------------------------------------------------------

-- | A parsed metadata field as a value the producer supplied, or
-- 'Nothing' when the field was blank. Fields arrive trimmed to their
-- content at parse, so a blank one means the producer gave no value —
-- which must read as absent metadata downstream, never as a deliberately
-- empty value.
presentField :: EncodedText -> Maybe EncodedText
presentField field
  | Text.null (encodedTextContent field) = Nothing
  | otherwise                            = Just field

-- | PPF1 carries no validation block, no undo data, no file-size advisory, and no FILE_ID.DIZ — the simplest of the four PPF dispatchers.
parseSomePatchFromPPF1 :: Parsed PPF1.PPF1Patch -> Either SlapError SomePatch
parseSomePatchFromPPF1 (Parsed patch parseAdvisories) =
  let records = PPF1.ppf1Records patch
  in Right SomePatch
      { patchFormat         = LabelPPF1
      , patchAnalysis       = PPF1.analyzePPF1 patch
      , patchKind           = Direct (Just (emptyContents (map hunkOf records))
          { contentsDescription = Just (PPF1.ppf1Description patch) })
      , patchApply          = ApplyStrategy
          { runApply = \source -> pure (PPF1.applyPPF1 patch source) }
      , patchUndo           = Nothing
      , patchVerification   = noVerification
      , patchAdvisories       = parseAdvisories
                              ++ [EmptyPatch LabelPPF1 EmptyRecords | null records]
      , patchInfo           = PatchInfo
          { infoFormat   = FormatHeader LabelPPF1 Nothing
          , infoLines    = PPF1.ppf1Meta patch
          , infoEmbedded = []
          , infoTally    = Tally (length records)
          , infoUnit     = Records
          , infoBytes    = Just (TotalPayloadBytes (Length
              (sum (map (ByteString.length . PPF1.ppf1RecordPayload) records))))
          , infoRange    = PPF1.ppf1RecordsRange records
          }
      , patchSourceAdvisories    = []
      , patchMetadata       = Nothing
      , patchExtractedMeta  = noMetadataRequested
            { requestedDescription = presentField (PPF1.ppf1Description patch) }
      }
  where
    hunkOf ppf1Record = Hunk (PPF1.ppf1RecordOffset ppf1Record) (PPF1.ppf1RecordPayload ppf1Record)

-- | PPF2 adds the declared source-file-size field and the 1024-byte validation block (BIN-only at offset 0x9320).
-- It also carries an optional FILE_ID.DIZ trailer.
parseSomePatchFromPPF2 :: Parsed PPF2.PPF2Patch -> Either SlapError SomePatch
parseSomePatchFromPPF2 (Parsed patch parseAdvisories) =
  let records = PPF2.ppf2Records patch
      validationBytes = PPF2.unPPF2ValidationBlock (PPF2.ppf2ValidationBlock patch)
      sourceFileSize = FileSize (fromIntegral (PPF2.unPPF2SourceSize (PPF2.ppf2SourceFileSize patch)))
      ppfVerification = noVerification
          { verifyPPFBlock = Just (ValidationBlock PPF2.ppf2ValidationOffset validationBytes)
          , verifyFileSize = Just (AdvisorySize sourceFileSize)
          }
  in Right SomePatch
      { patchFormat         = LabelPPF2
      , patchAnalysis       = PPF2.analyzePPF2 patch
      , patchKind           = Direct (Just (emptyContents (map hunkOf records))
          { contentsDescription     = Just (PPF2.ppf2Description patch)
          , contentsDestinationSize = Just sourceFileSize
          , contentsValidation      = Just validationBytes
          , contentsFileIdDiz       = fmap PPF2.unPPF2FileId (PPF2.ppf2FileId patch)
          })
      , patchApply          = ApplyStrategy
          { runApply = \source -> pure (PPF2.applyPPF2 patch source) }
      , patchUndo           = Nothing
      , patchVerification   = ppfVerification
      , patchAdvisories       = parseAdvisories
                              ++ [EmptyPatch LabelPPF2 EmptyRecords | null records]
      , patchInfo           = PatchInfo
          { infoFormat   = FormatHeader LabelPPF2 Nothing
          , infoLines    = PPF2.ppf2Meta patch
          , infoEmbedded = PPF2.ppf2EmbeddedContent patch
          , infoTally    = Tally (length records)
          , infoUnit     = Records
          , infoBytes    = Just (TotalPayloadBytes (Length
              (sum (map (ByteString.length . PPF2.ppf2RecordPayload) records))))
          , infoRange    = PPF2.ppf2RecordsRange records
          }
      , patchSourceAdvisories    = []
      , patchMetadata       = Nothing
      , patchExtractedMeta  = noMetadataRequested
            { requestedDescription           = presentField (PPF2.ppf2Description patch)
            , requestedVerificationInclusion = Just IncludeVerification
            }
      }
  where
    hunkOf ppf2Record = Hunk (PPF2.ppf2RecordOffset ppf2Record) (PPF2.ppf2RecordPayload ppf2Record)

-- | PPF3 adds the image-type byte (BIN/GI, choosing the validation offset), per-record undo bytes, and a 2-byte-length FILE_ID.DIZ trailer.
parseSomePatchFromPPF3 :: Parsed PPF3.PPF3Patch -> Either SlapError SomePatch
parseSomePatchFromPPF3 (Parsed patch parseAdvisories) =
  let records = PPF3.ppf3Records patch
      validationBlockBytes = fmap PPF3.unPPF3ValidationBlock (PPF3.ppf3ValidationBlock patch)
      ppfVerification = noVerification
          { verifyPPFBlock = case validationBlockBytes of
              Just blockBytes -> Just (ValidationBlock
                                         (PPF3.ppf3ValidationOffset (PPF3.ppf3ImageType patch))
                                         blockBytes)
              Nothing -> Nothing
          }
  in Right SomePatch
      { patchFormat         = LabelPPF3
      , patchAnalysis       = PPF3.analyzePPF3 patch
      , patchKind           = Direct (Just (emptyContents (map hunkOf records))
          { contentsDescription = Just (PPF3.ppf3Description patch)
          , contentsValidation  = validationBlockBytes
          , contentsUndoData    = if PPF3.ppf3HasUndo patch
                            then Just [ splitUndoHunkFromParsed
                                          (PPF3.ppf3RecordOffset record)
                                          (PPF3.ppf3RecordPayload record)
                                          (fromMaybe ByteString.empty (PPF3.ppf3RecordUndo record))
                                      | record <- records ]
                            else Nothing
          , contentsImageType   = Just (PPF3.ppf3ImageType patch)
          , contentsFileIdDiz   = fmap PPF3.unPPF3FileId (PPF3.ppf3FileId patch)
          })
      , patchApply          = ApplyStrategy
          { runApply = \source -> pure (PPF3.applyPPF3 patch source) }
      , patchUndo           = if PPF3.ppf3HasUndo patch
                               then Just (UndoStrategy (fmap noAdvisories . PPF3.undoPPF3 patch))
                               else Nothing
      , patchVerification   = ppfVerification
      , patchAdvisories       = parseAdvisories
                              ++ [EmptyPatch LabelPPF3 EmptyRecords | null records]
      , patchInfo           = PatchInfo
          { infoFormat   = FormatHeader LabelPPF3 Nothing
          , infoLines    = PPF3.ppf3Meta patch
          , infoEmbedded = PPF3.ppf3EmbeddedContent patch
          , infoTally    = Tally (length records)
          , infoUnit     = Records
          , infoBytes    = Just (TotalPayloadBytes (Length
              (sum (map (ByteString.length . PPF3.ppf3RecordPayload) records))))
          , infoRange    = PPF3.ppf3RecordsRange records
          }
      , patchSourceAdvisories    = []
      , patchMetadata       = Nothing
      , patchExtractedMeta  = noMetadataRequested
            { requestedDescription           = presentField (PPF3.ppf3Description patch)
            , requestedImageType             = Just (PPF3.ppf3ImageType patch)
            , requestedUndoInclusion         = if PPF3.ppf3HasUndo patch then Just IncludeUndoData else Nothing
            , requestedVerificationInclusion = if isJust (PPF3.ppf3ValidationBlock patch) then Just IncludeVerification else Nothing
            }
      }
  where
    hunkOf ppf3Record = Hunk (PPF3.ppf3RecordOffset ppf3Record) (PPF3.ppf3RecordPayload ppf3Record)

-- | PPF4 is a two-phase format: Replace records, then Append records.
-- It carries none of PPF1/2/3's metadata — no validation block, no undo, no image type, no FILE_ID.DIZ trailer.
-- Source-less conversion is structurally possible only when the patch has no Append records.
-- Appends carry no meaningful offset, so they can't be expressed as 'Hunk's.
parseSomePatchFromPPF4 :: EncodingName -> PatchFileContents -> Either SlapError SomePatch
parseSomePatchFromPPF4 metadataEncoding patchContents = do
  Parsed patch parseAdvisories <- PPF4.parsePPF4 metadataEncoding patchContents
  let replaces = PPF4.ppf4Replaces patch
      appends  = PPF4.ppf4Appends patch
      totalRecords = length replaces + length appends
      hunkOf replaceRecord = Hunk (PPF4.replaceOffset replaceRecord) (PPF4.replaceData replaceRecord)
      directContents
        | null appends = Just (emptyContents (map hunkOf replaces))
                           { contentsDescription = Just (PPF4.ppf4Description patch) }
        | otherwise    = Nothing
  Right SomePatch
      { patchFormat         = LabelPPF4
      , patchAnalysis       = PPF4.analyzePPF4 patch
      , patchKind           = Direct directContents
      , patchApply          = ApplyStrategy
          { runApply = \source -> pure (fmap noAdvisories (PPF4.applyPPF4 patch source)) }
      , patchUndo           = Nothing
      , patchVerification   = noVerification
      , patchAdvisories       = parseAdvisories
                              ++ [EmptyPatch LabelPPF4 EmptyRecords | totalRecords == 0]
      , patchInfo           = PatchInfo
          { infoFormat   = FormatHeader LabelPPF4 (Just " (Pyriel internal format)")
          , infoLines    = PPF4.ppf4Meta patch
          , infoEmbedded = []
          , infoTally    = Tally totalRecords
          , infoUnit     = Records
          , infoBytes    = Just (TotalPayloadBytes (Length
              ( sum (map (ByteString.length . PPF4.replaceData) replaces)
              + sum (map (ByteString.length . PPF4.appendData) appends) )))
          , infoRange    = PPF4.ppf4ReplacesRange replaces
          }
      , patchSourceAdvisories    = []
      , patchMetadata       = Nothing
      , patchExtractedMeta  = noMetadataRequested
            { requestedDescription = presentField (PPF4.ppf4Description patch) }
      }

parseSomePatchFromIPS :: IPS.IPSVariant -> PatchFileContents -> Either SlapError SomePatch
parseSomePatchFromIPS variant patchContents = do
  Parsed parseResult parseAdvisories <- IPS.parseIPS patchContents
  let label = case variant of
        IPS.StandardIPS -> LabelIPS
        IPS.IPS32       -> LabelIPS32
      -- A record's writes become a hunk. A zero-count RLE record
      -- writes nothing and must expand to no hunk: an empty hunk
      -- carried to an IPS-family target re-encodes as a size-0
      -- record, which is the RLE sentinel on the wire, desyncing
      -- every record after it.
      expandIPSRecord (IPS.IPSRecordCopy { ipsCopyOffset = recordOffset
                                         , ipsCopyPayload = recordPayload }) =
        Just (Hunk recordOffset recordPayload)
      expandIPSRecord (IPS.IPSRecordRLE { ipsRleOffset = recordOffset
                                        , ipsRleCount = fillCount
                                        , ipsRleFill = fillByte })
        | unLength fillCount == 0 = Nothing
        | otherwise =
            Just (Hunk recordOffset (ByteString.replicate (unLength fillCount) fillByte))
  case parseResult of
    IPS.IPSParseCleanIPS ipsPatch ->
      let records = IPS.ipsRecords ipsPatch
      in Right SomePatch
        { patchFormat         = label
        , patchAnalysis       = IPS.analyzeIPS ipsPatch
        , patchKind           = Direct (Just (emptyContents (mapMaybe expandIPSRecord (Vector.toList records)))
            { contentsTruncation = IPS.ipsTruncatedTargetSize ipsPatch
            , contentsEBPMetadata = Nothing
            })
        , patchApply          = ApplyStrategy
              { runApply = \source -> pure (IPS.applyIPS source ipsPatch) }
        , patchUndo           = Nothing
        , patchVerification   = noVerification
        , patchAdvisories       = parseAdvisories
                                ++ [EmptyPatch label EmptyRecords | Vector.null records]
        , patchInfo           = PatchInfo
            { infoFormat   = FormatHeader label Nothing
            , infoLines    = IPS.ipsMeta ipsPatch
            , infoEmbedded = []
            , infoTally    = Tally (Vector.length records)
            , infoUnit     = Records
            , infoBytes    = Nothing
            , infoRange    = IPS.ipsRecordsRange records
            }
        , patchSourceAdvisories    = []
        , patchMetadata       = Nothing
        , patchExtractedMeta  = noMetadataRequested
        }
    IPS.IPSParseCleanEBP ebpPatch ->
      let basePatch = IPS.ebpBasePatch ebpPatch
          records = IPS.ipsRecords basePatch
          metadata = IPS.ebpMetadata ebpPatch
          extractedMeta = noMetadataRequested
            { requestedTitle       = IPS.ebpMetadataTitle       metadata >>= presentField
            , requestedAuthor      = IPS.ebpMetadataAuthor      metadata >>= presentField
            , requestedDescription = IPS.ebpMetadataDescription metadata >>= presentField
            }
      in Right SomePatch
        { patchFormat         = LabelEBP
        , patchAnalysis       = IPS.analyzeEBP ebpPatch
        , patchKind           = Direct (Just (emptyContents (mapMaybe expandIPSRecord (Vector.toList records)))
            { contentsTruncation = IPS.ipsTruncatedTargetSize basePatch
            , contentsEBPMetadata = Just metadata
            })
        , patchApply          = ApplyStrategy
              { runApply = \source -> pure (IPS.applyIPS source basePatch) }
        , patchUndo           = Nothing
        , patchVerification   = noVerification
        , patchAdvisories       = parseAdvisories
                                ++ [EmptyPatch LabelEBP EmptyRecords | Vector.null records]
        , patchInfo           = PatchInfo
            { infoFormat   = FormatHeader LabelEBP Nothing
            , infoLines    = IPS.ebpMeta ebpPatch
            , infoEmbedded = []
            , infoTally    = Tally (Vector.length records)
            , infoUnit     = Records
            , infoBytes    = Nothing
            , infoRange    = IPS.ipsRecordsRange records
            }
        , patchSourceAdvisories    = []
        , patchMetadata       = Nothing
        , patchExtractedMeta  = extractedMeta
        }
    IPS.IPSParseTruncated _variant records ->
      let truncatedPatch = IPS.IPSPatch
            { IPS.ipsVariant             = variant
            , IPS.ipsRecords             = records
            , IPS.ipsTruncatedTargetSize = Nothing
            }
      in Right SomePatch
        { patchFormat         = label
        , patchAnalysis       = IPS.analyzeIPS truncatedPatch
        , patchKind           = Direct (Just (emptyContents (mapMaybe expandIPSRecord (Vector.toList records)))
            { contentsTruncation = Nothing
            , contentsEBPMetadata = Nothing
            })
        , patchApply          = ApplyStrategy
              { runApply = \source -> pure (IPS.applyIPS source truncatedPatch) }
        , patchUndo           = Nothing
        , patchVerification   = noVerification
        , patchAdvisories       = parseAdvisories
                                ++ [EmptyPatch label EmptyRecords | Vector.null records]
        , patchInfo           = PatchInfo
            { infoFormat   = FormatHeader label Nothing
            , infoLines    = IPS.ipsMeta truncatedPatch
            , infoEmbedded = []
            , infoTally    = Tally (Vector.length records)
            , infoUnit     = Records
            , infoBytes    = Nothing
            , infoRange    = IPS.ipsRecordsRange records
            }
        , patchSourceAdvisories    = []
        , patchMetadata       = Nothing
        , patchExtractedMeta  = noMetadataRequested
        }

parseSomePatchFromBPS :: EncodingName -> PatchFileContents -> Either SlapError SomePatch
parseSomePatchFromBPS metadataEncoding patchContents = do
  Parsed patch parseAdvisories <- BPS.parseBPS patchContents
  let actions = BPS.bpsActions patch
      metadataBytes = BPS.unBPSMetadata (BPS.bpsMetadata patch)
      bpsMetaBlob = if ByteString.null metadataBytes then Nothing
                    else Just metadataBytes
  Right SomePatch
    { patchFormat         = LabelBPS
    , patchAnalysis       = BPS.analyzeBPS patch
    , patchKind           = Differential
    , patchApply          = ApplyStrategy
        { runApply     = \source -> pure (fmap noAdvisories (BPS.applyBPS patch source)) }
    , patchUndo           = Nothing
    , patchVerification   = noVerification
        { verifySourceCRC32 = Just (BPS.bpsSourceCRC patch)
        , verifyTargetCRC32 = Just (BPS.bpsTargetCRC patch)
        -- The spec leaves both checksum and size mismatch unspecified
        -- (fatal or advisory). Slap's policy makes the source CRC fatal
        -- and the declared size advisory, so a wrong-size source still
        -- hard-fails via the source CRC.
        , verifyFileSize = Just (AdvisorySize (BPS.bpsSourceSize patch))
        }
    , patchAdvisories       = parseAdvisories
                            ++ [EmptyPatch LabelBPS EmptyActions | Vector.null actions]
                            ++ BPS.bpsMetadataNotes patch
    , patchInfo           = PatchInfo
        { infoFormat   = FormatHeader LabelBPS Nothing
        , infoLines    = BPS.bpsMeta patch
        , infoEmbedded = BPS.bpsEmbeddedContent metadataEncoding patch
        , infoTally    = Tally (Vector.length actions)
        , infoUnit     = Actions
        , infoBytes    = Just (TotalOutputBytes (BPS.bpsTargetSize patch))
        , infoRange    = Nothing
        }
    , patchSourceAdvisories    = []
    , patchMetadata       = bpsMetaBlob
    , patchExtractedMeta  = noMetadataRequested { requestedEmbeddedBlob = bpsMetaBlob }
    }

parseSomePatchFromUPS :: PatchFileContents -> Either SlapError SomePatch
parseSomePatchFromUPS patchContents = do
  Parsed patch parseAdvisories <- UPS.parseUPS patchContents
  let blocks = UPS.upsBlocks patch
  Right SomePatch
    { patchFormat         = LabelUPS
    , patchAnalysis       = UPS.analyzeUPS patch
    , patchKind           = Differential
    , patchApply          = ApplyStrategy
        { runApply     = \source -> pure (UPS.applyUPS patch source) }
    , patchUndo           = Just $ UndoStrategy (UPS.undoUPS patch)
        -- UPS is self-inverse (XOR): walking the same block stream
        -- against the target reconstructs the source. The only
        -- direction-dependent choice is the output buffer size, and
        -- 'undoUPS' passes sourceSize instead of targetSize so
        -- size-changing patches round-trip.
    , patchVerification   = noVerification
        { verifySourceCRC32 = Just (UPS.upsSourceCRC patch)
        , verifyTargetCRC32 = Just (UPS.upsTargetCRC patch)
        -- Advisory like BPS's: the size doesn't gate rejection.
        -- Undo bypasses the Verification layer (Main.doUndo), so it
        -- never consults verifyFileSize.
        , verifyFileSize = Just (AdvisorySize (UPS.upsSourceSize patch))
        }
    , patchAdvisories       = parseAdvisories
                            ++ [EmptyPatch LabelUPS EmptyBlocks | Vector.null blocks]
    , patchInfo           = PatchInfo
        { infoFormat   = FormatHeader LabelUPS Nothing
        , infoLines    = UPS.upsMeta patch
        , infoEmbedded = []
        , infoTally    = Tally (Vector.length blocks)
        , infoUnit     = Blocks
        , infoBytes    = Just (TotalOutputBytes (UPS.upsTargetSize patch))
        , infoRange    = Nothing
        }
    , patchSourceAdvisories    = []
    , patchMetadata       = Nothing
    , patchExtractedMeta  = noMetadataRequested
    }

-- | The flavor surfaces through the format header's qualifier slot ('vcdiffFlavorQualifier'), so @slap info@ answers "which flavor" on its first line.
-- An xdelta3 patch's per-window Adler32 checksums are lifted into 'verifyWindowAdler32', the way the BPS seam lifts its CRCs;
-- 'Slap.VCDIFF.Describe' gives the analytical and info carriers their voice.
parseSomePatchFromVCDIFF :: EncodingName -> PatchFileContents -> Either SlapError SomePatch
parseSomePatchFromVCDIFF metadataEncoding patchContents = do
  Parsed patch parseAdvisories <- VCDIFF.parseVCDIFF patchContents
  let windows         = VCDIFF.patchWindows patch
      windowCount     = Vector.length windows
      totalOutputSize = FileSize
        (Vector.sum (Vector.map (unFileSize . VCDIFF.windowTargetSize) windows))
      appHeaderBlob   = case VCDIFF.vcdiffAppHeader patch of
                          Just bytes | not (ByteString.null bytes) -> Just bytes
                          _                                        -> Nothing
  Right SomePatch
    { patchFormat       = LabelVCDIFF
    , patchAnalysis     = VCDIFFDescribe.analyzeVCDIFF patch
    , patchKind         = Differential
    , patchApply        = ApplyStrategy
        { runApply = \source -> pure (fmap noAdvisories (VCDIFF.applyVCDIFF patch source)) }
    , patchUndo         = Nothing
    , patchVerification = noVerification
        { verifyWindowAdler32 = vcdiffWindowChecks patch }
    , patchAdvisories   = parseAdvisories
                        ++ [EmptyPatch LabelVCDIFF EmptyWindows | windowCount == 0]
    , patchInfo         = PatchInfo
        { infoFormat   = FormatHeader LabelVCDIFF (vcdiffFlavorQualifier patch)
        , infoLines    = VCDIFFDescribe.vcdiffMeta patch
        , infoEmbedded = VCDIFFDescribe.vcdiffEmbeddedContent metadataEncoding patch
        , infoTally    = Tally windowCount
        , infoUnit     = Windows
        , infoBytes    = Just (TotalOutputBytes totalOutputSize)
        , infoRange    = Nothing
        }
    , patchSourceAdvisories = []
    , patchMetadata     = appHeaderBlob
    , patchExtractedMeta = noMetadataRequested { requestedEmbeddedBlob = appHeaderBlob }
    }

-- | The flavor verdict as a format-header qualifier, in the
-- 'Slap.Display.Common.formatExtra' register (leading separator
-- included). CoreOnly is the unqualified case — the patch decodes
-- identically under either flavor, so the bare label is the whole
-- truth.
vcdiffFlavorQualifier :: VCDIFF.VCDIFFPatch -> Maybe Text
vcdiffFlavorQualifier vcdiffPatch = case vcdiffPatch of
  VCDIFF.PatchCoreOnly _  -> Nothing
  VCDIFF.PatchRFC      _ _ -> Just " (RFC 3284)"
  VCDIFF.PatchXDelta3  _ _ -> Just " (xdelta3)"

-- | The per-window Adler32 checks a patch carries, lifted to the shared
-- verification boundary: each present checksum covers its window's slice
-- of the final target — the window's base offset, its output length, and
-- the stored sum. Reads the flavor-flattened window list
-- ('VCDIFF.patchWindowsWithChecksums'), so it is itself flavor-blind: a
-- core-only or RFC window pairs with no checksum and 'catMaybes' drops
-- it, exactly as the absence of an xdelta3 window's checksum does.
vcdiffWindowChecks :: VCDIFF.VCDIFFPatch -> [WindowCheck]
vcdiffWindowChecks vcdiffPatch =
    catMaybes (zipWith windowCheckAt windowBases pairedWindows)
  where
    pairedWindows = Vector.toList (VCDIFF.patchWindowsWithChecksums vcdiffPatch)
    windowBases   = scanl advance (Offset 0)
                      (map (VCDIFF.windowOutputLength . VCDIFF.windowWithChecksumBody) pairedWindows)
    windowCheckAt windowBase pairedWindow =
      WindowCheck windowBase (VCDIFF.windowOutputLength (VCDIFF.windowWithChecksumBody pairedWindow))
        <$> VCDIFF.windowWithChecksumAdler32 pairedWindow

-- APS N64 and APS GBA are unrelated formats by different authors who both used "APS" as the name.
-- detectFormat dispatches on magic, but "APS10" (N64) collides with "APS1" + source size when size mod 256 == 48.
-- detectFormat resolves the collision via GBA's fixed record structure (12 + N*65544 bytes, 64KB-aligned offsets),
-- routing structurally-GBA inputs to 'FormatAPSGBA'.
parseSomePatchFromAPSN64 :: EncodingName -> PatchFileContents -> Either SlapError SomePatch
parseSomePatchFromAPSN64 metadataEncoding patchContents = do
  Parsed patch@(APSN64.APSN64Patch header records) parseAdvisories <- APSN64.parseAPSN64 metadataEncoding patchContents
  let expandN64 (APSN64.APSN64Normal recordOffset recordPayload) = Hunk recordOffset recordPayload
      expandN64 (APSN64.APSN64RLE recordOffset fillValue fillCount) = Hunk recordOffset (ByteString.replicate (fromIntegral fillCount) fillValue)
  Right SomePatch
    { patchFormat         = LabelAPSN64
    , patchAnalysis       = APSN64.analyzeAPSN64 patch
    , patchKind           = Direct (Just (emptyContents (Vector.toList (Vector.map expandN64 records)))
          { contentsDescription = Just (APSN64.apsN64Description header)
          -- ^ APSN64's description field is typed 'EncodedText';
          -- the parse-time decode (and any substitution advisories) lives inside 'parseAPSN64'.
          , contentsDestinationSize    = Just (APSN64.apsN64DestinationSizeAsFileSize (APSN64.apsN64DestinationSize header))
          , contentsAPSN64ImageFormat = APSN64.apsN64ImageFormat header
          })
    , patchApply          = ApplyStrategy
          { runApply = \source -> pure (fmap noAdvisories (APSN64.applyAPSN64 patch source)) }
    , patchUndo           = Nothing
    , patchVerification   = noVerification
          { verifySourceBytes = concat
              [ maybe [] (\cartId -> [ByteCheck (Offset 0x3C) (AdvisoryExpectedBytes (APSN64.unN64CartId cartId)) "N64 cart ID"]) (APSN64.apsN64CartId header)
              , maybe [] (\country -> [ByteCheck (Offset 0x3E) (AdvisoryExpectedBytes (ByteString.singleton (APSN64.fromAPSN64Country country))) "N64 country"]) (APSN64.apsN64Country header)
              , maybe [] (\crc -> [ByteCheck (Offset 0x10) (AdvisoryExpectedBytes (APSN64.unN64ChecksumPair crc)) "N64 CRC"]) (APSN64.apsN64Crc header)
              ]
          , verifyN64ByteOrder = case APSN64.apsN64ImageFormat header of
              Just APSN64.V64Format -> Just SourceMustBeV64
              Just APSN64.Z64Format -> Just SourceMustNotBeV64
              _                     -> Nothing
          }
    , patchAdvisories       = parseAdvisories
                            ++ [EmptyPatch LabelAPSN64 EmptyRecords | Vector.null records]
    , patchInfo           = PatchInfo
        { infoFormat   = FormatHeader LabelAPSN64 Nothing
        , infoLines    = APSN64.apsN64Meta patch
        , infoEmbedded = []
        , infoTally    = Tally (Vector.length records)
        , infoUnit     = Records
        , infoBytes    = Just (TotalOutputBytes (APSN64.apsN64DestinationSizeAsFileSize (APSN64.apsN64DestinationSize header)))
        , infoRange    = Nothing
        }
    , patchSourceAdvisories    = []
    , patchMetadata       = Nothing
    , patchExtractedMeta  = noMetadataRequested
        { requestedDescription = presentField (APSN64.apsN64Description header) }
    }

parseSomePatchFromNINJA2 :: EncodingName -> PatchFileContents -> Either SlapError SomePatch
parseSomePatchFromNINJA2 metadataEncoding patchContents = do
  Parsed patch parseAdvisories <- NINJA2.parseNINJA2 metadataEncoding patchContents
  let filterZeroMD5 (Just hash@(MD5Hash bytes))
        | ByteString.all (== 0) bytes = Nothing
        | otherwise                   = Just hash
      filterZeroMD5 Nothing = Nothing
      openNewFile = NINJA2.ninja2OpenNewFile patch
      romTypeForPlatformConversion = case openNewFile of
        Just open -> NINJA2.openNewFileRomType open
        Nothing   -> NINJA2.NINJA2Raw
      (platformType, platformAdvisories) = ninja2ToPlatform romTypeForPlatformConversion
      romTypeAdvisories = case romTypeForPlatformConversion of
        NINJA2.NINJA2Raw                 -> []
        NINJA2.NINJA2UnknownRomType byte -> [UnrecognizedRomType LabelNINJA2 byte]
        romType
          | NINJA2.ninja2RomTypeNeedsNormalization romType ->
              [RomTypeNormalizationUnsupported LabelNINJA2 platformType]
          | otherwise ->
              [RomTypeWithoutNormalization LabelNINJA2 platformType]
      romTypeUnrecognized = case romTypeForPlatformConversion of
        NINJA2.NINJA2UnknownRomType _ -> Just LabelNINJA2
        _                             -> Nothing
  Right SomePatch
    { patchFormat         = LabelNINJA2
    , patchAnalysis       = NINJA2.analyzeNINJA2 patch
    , patchKind           = Differential
    , patchApply          = ApplyStrategy
          { runApply = \source -> pure (fmap noAdvisories (NINJA2.applyNINJA2 patch source)) }
    , patchUndo           = Nothing
    , patchVerification   = noVerification
        { verifySourceMD5 = filterZeroMD5 (fmap NINJA2.openNewFileSourceMD5 openNewFile)
        , verifyTargetMD5 = filterZeroMD5 (fmap NINJA2.openNewFileTargetMD5 openNewFile)
        , verifyRomTypeUnrecognized = romTypeUnrecognized
        }
    , patchAdvisories       = parseAdvisories
                             ++ [EmptyPatch LabelNINJA2 EmptyRecords | null (NINJA2.ninja2Records patch)]
                             ++ platformAdvisories
                             ++ romTypeAdvisories
    , patchInfo           = PatchInfo
        { infoFormat   = FormatHeader LabelNINJA2 Nothing
        , infoLines    = NINJA2.ninja2Meta patch
        , infoEmbedded = []
        , infoTally    = Tally (length (NINJA2.ninja2Records patch))
        , infoUnit     = Records
        , infoBytes    = Nothing
        , infoRange    = Nothing
        }
    , patchSourceAdvisories    = []
    , patchMetadata       = Nothing
    , patchExtractedMeta  =
        let info = NINJA2.ninja2Header patch
        in noMetadataRequested
            { requestedTitle       = NINJA2.ninja2Title       info
            , requestedAuthor      = NINJA2.ninja2Author      info
            , requestedVersion     = NINJA2.ninja2Version     info
            , requestedGenre       = NINJA2.ninja2Genre       info
            , requestedLanguage    = NINJA2.ninja2Language    info
            , requestedDate        = NINJA2.ninja2Date        info
            , requestedWebsite     = NINJA2.ninja2Website     info
            , requestedDescription = NINJA2.ninja2Description info
            , requestedRomType     = Just platformType
            }
    }

parseSomePatchFromNINJA1 :: PatchFileContents -> Either SlapError SomePatch
parseSomePatchFromNINJA1 patchContents = do
  Parsed patch parseAdvisories <- NINJA1.parseNINJA1 patchContents
  let records = NINJA1.ninja1Records patch
      hunkOf ninja1Record = Hunk (NINJA1.ninja1RecordOffset ninja1Record) (NINJA1.ninja1RecordData ninja1Record)
      romTypeAdvisories = case NINJA1.ninja1RomType patch of
        NINJA1.RomRAW          -> []
        NINJA1.RomUnknown byte -> [UnrecognizedRomType LabelNINJA1 byte]
        NINJA1.RomUnknownName name -> [UnrecognizedRomTypeName LabelNINJA1 name]
        romType
          | NINJA1.ninja1RomTypeNeedsNormalization romType ->
              [RomTypeNormalizationUnsupported LabelNINJA1 (ninja1ToPlatform romType)]
          | otherwise ->
              [RomTypeWithoutNormalization LabelNINJA1 (ninja1ToPlatform romType)]
      romTypeUnrecognized = case NINJA1.ninja1RomType patch of
        NINJA1.RomUnknown _     -> Just LabelNINJA1
        NINJA1.RomUnknownName _ -> Just LabelNINJA1
        _                       -> Nothing
      warnings = concat
        [ parseAdvisories
        , [EmptyPatch LabelNINJA1 EmptyRecords | null records]
        , romTypeAdvisories
        ]
      compressed = NINJA1.ninja1SubFormat patch `elem` [NINJA1.NINJA1BinaryCompressed, NINJA1.NINJA1TextCompressed]
      sourceAdvisories = case NINJA1.ninja1SubFormat patch of
        NINJA1.NINJA1Text  -> [SubformatConverted NINJA1TextToBinary]
        NINJA1.NINJA1TextCompressed -> [SubformatConverted NINJA1CompressedTextToCompressedBinary]
        _              -> []
  Right SomePatch
    { patchFormat         = LabelNINJA1
    , patchAnalysis       = NINJA1.analyzeNINJA1 patch
    , patchKind           = Direct (Just (emptyContents (map hunkOf records))
        { contentsSourceCRC32 = NINJA1.ninja1SourceCRC patch
        , contentsSourceMD5   = NINJA1.ninja1SourceMD5 patch
        , contentsSourceSHA1  = NINJA1.ninja1SourceSHA1 patch
        , contentsRomType     = Just (ninja1ToPlatform (NINJA1.ninja1RomType patch))
        , contentsNINJA1Compression = Just (if compressed then NINJA1Compressed else NINJA1Uncompressed)
        })
    , patchApply          = ApplyStrategy
          { runApply = \source -> pure (fmap noAdvisories (NINJA1.applyNINJA1 patch source)) }
    , patchUndo           = Nothing
    , patchVerification   = noVerification
        { verifySourceCRC32  = NINJA1.ninja1SourceCRC patch
        , verifySourceMD5    = NINJA1.ninja1SourceMD5 patch
        , verifySourceSHA1   = NINJA1.ninja1SourceSHA1 patch
        , verifySourcePreHash = HashNINJA1Sample
        , verifyRomTypeUnrecognized = romTypeUnrecognized
        }
    , patchAdvisories       = warnings
    , patchInfo           = PatchInfo
        { infoFormat   = FormatHeader LabelNINJA1
            (Just (" (" <> NINJA1.subFormatName (NINJA1.ninja1SubFormat patch) <> ")"))
        , infoLines    = NINJA1.ninja1Meta patch
        , infoEmbedded = []
        , infoTally    = Tally (length records)
        , infoUnit     = Records
        , infoBytes    = Just (TotalPayloadBytes (Length
            (sum (map (ByteString.length . NINJA1.ninja1RecordData) records))))
        , infoRange    = NINJA1.ninja1RecordsRange records
        }
    , patchSourceAdvisories    = sourceAdvisories
    , patchMetadata       = Nothing
    , patchExtractedMeta  = noMetadataRequested
        { requestedRomType = Just (ninja1ToPlatform (NINJA1.ninja1RomType patch)) }
    }

parseSomePatchFromBSDiff :: PatchFileContents -> Either SlapError SomePatch
parseSomePatchFromBSDiff patchContents = do
  Parsed patch parseAdvisories <- BSDiff.parseBSDiff patchContents
  Right SomePatch
    { patchFormat         = LabelBSDiff
    , patchAnalysis       = BSDiff.analyzeBSDiff patch
    , patchKind           = Differential
    , patchApply          = ApplyStrategy
        { runApply     = \source -> pure (fmap noAdvisories (BSDiff.applyBSDiff patch source)) }
    , patchUndo           = Nothing
    , patchVerification   = noVerification
    , patchAdvisories       = parseAdvisories
                            ++ [EmptyPatch LabelBSDiff EmptyInstructions | null (BSDiff.bsdiffInstructions patch)]
    , patchInfo           = PatchInfo
        { infoFormat   = FormatHeader LabelBSDiff Nothing
        , infoLines    = BSDiff.bsdiffMeta patch
        , infoEmbedded = []
        , infoTally    = Tally (length (BSDiff.bsdiffInstructions patch))
        , infoUnit     = Instructions
        , infoBytes    = Just (TotalOutputBytes (BSDiff.bsdiffTargetSize patch))
        , infoRange    = Nothing
        }
    , patchSourceAdvisories    = []
    , patchMetadata       = Nothing
    , patchExtractedMeta  = noMetadataRequested
    }

parseSomePatchFromGDIFF :: PatchFileContents -> Either SlapError SomePatch
parseSomePatchFromGDIFF patchContents = do
  Parsed patch parseAdvisories <- GDIFF.parseGDIFF patchContents
  Right SomePatch
    { patchFormat         = LabelGDIFF
    , patchAnalysis       = GDIFF.analyzeGDIFF patch
    , patchKind           = Differential
    , patchApply          = ApplyStrategy
        { runApply     = \source -> pure (fmap noAdvisories (GDIFF.applyGDIFF patch source)) }
    , patchUndo           = Nothing
    , patchVerification   = noVerification
    , patchAdvisories       = parseAdvisories
                            ++ [EmptyPatch LabelGDIFF EmptyCommands | null (GDIFF.gdiffCommands patch)]
    , patchInfo           = PatchInfo
        { infoFormat   = FormatHeader LabelGDIFF Nothing
        , infoLines    = GDIFF.gdiffMeta patch
        , infoEmbedded = []
        , infoTally    = Tally (length (GDIFF.gdiffCommands patch))
        , infoUnit     = Commands
        , infoBytes    = Nothing
        , infoRange    = Nothing
        }
    , patchSourceAdvisories    = []
    , patchMetadata       = Nothing
    , patchExtractedMeta  = noMetadataRequested
    }

parseSomePatchFromXDelta1 :: EncodingName -> PatchFileContents -> Either SlapError SomePatch
parseSomePatchFromXDelta1 metadataEncoding patchContents = do
  Parsed patch parseAdvisories <- XDelta1.parseXDelta1 metadataEncoding patchContents
  let xdeltaVerification = case XDelta1.xdelta1Verification patch of
        XDelta1.VerifyAgainstStoredMD5s targetMD5 -> noVerification
          { verifySourceMD5 = XDelta1.xdelta1SourceMD5 patch
          , verifyTargetMD5 = Just targetMD5
          }
        XDelta1.CreatorOptedOutOfVerification -> noVerification
      -- The data-record-name is a display label, not anything apply
      -- consults, so its divergence is routed to the notice lane
      -- rather than the warning lane.
      (dataNameNotices, otherWarnings) = partition isXDelta1DataNameNotice parseAdvisories
  Right SomePatch
    { patchFormat         = LabelXDelta1
    , patchAnalysis       = XDelta1.analyzeXDelta1 patch
    , patchKind           = Differential
    , patchApply          = ApplyStrategy
        { runApply     = \source -> pure (fmap noAdvisories (XDelta1.applyXDelta1 patch source)) }
    , patchUndo           = Nothing
    , patchVerification   = xdeltaVerification
    , patchAdvisories       = otherWarnings
                            ++ [EmptyPatch LabelXDelta1 EmptyInstructions | null (XDelta1.xdelta1Instructions patch)]
    , patchInfo           = PatchInfo
        { infoFormat   = FormatHeader LabelXDelta1 Nothing
        , infoLines    = XDelta1.xdelta1Meta patch
        , infoEmbedded = []
        , infoTally    = Tally (length (XDelta1.xdelta1Instructions patch))
        , infoUnit     = Instructions
        , infoBytes    = Just (TotalOutputBytes (XDelta1.xdelta1TargetLength patch))
        , infoRange    = Nothing
        }
    , patchSourceAdvisories    = dataNameNotices
    , patchMetadata       = Nothing
    , patchExtractedMeta  = noMetadataRequested
        -- An xdelta1 source patch carries both display labels in its
        -- header; threading them through 'requestedXDelta1*Name' lets
        -- 'mergeRequestedMetadata' inherit them across an
        -- xdelta1@→@xdelta1 convert without round-tripping through
        -- the locale-decode layer (the bytes are opaque on the wire
        -- and we keep them opaque here, typed as 'XDelta1FromName' /
        -- 'XDelta1ToName' so the merge can't transpose).
        { requestedXDelta1FromName = Just (XDelta1.xdelta1FromName patch)
        , requestedXDelta1ToName   = Just (XDelta1.xdelta1ToName   patch)
        }
    }
  where
    isXDelta1DataNameNotice XDelta1DataRecordNameDiverges{} = True
    isXDelta1DataNameNotice _                               = False

parseSomePatchFromPMSR :: PatchFileContents -> Either SlapError SomePatch
parseSomePatchFromPMSR patchContents = do
  Parsed patch parseAdvisories <- PMSR.parsePMSR patchContents
  let records = PMSR.pmsrRecords patch
  Right SomePatch
    { patchFormat         = LabelPMSR
    , patchAnalysis       = PMSR.analyzePMSR patch
    , patchKind           = Direct (Just (emptyContents
        (map recordToHunk (Vector.toList records))))
    , patchApply          = ApplyStrategy
          { runApply = \source -> pure (fmap noAdvisories (PMSR.applyPMSR patch source)) }
    , patchUndo           = Nothing
    , patchVerification   = noVerification
    , patchAdvisories       = parseAdvisories
                            ++ [EmptyPatch LabelPMSR EmptyRecords | Vector.null records]
    , patchInfo           = PatchInfo
        { infoFormat   = FormatHeader LabelPMSR Nothing
        , infoLines    = PMSR.pmsrMeta patch
        , infoEmbedded = []
        , infoTally    = Tally (Vector.length records)
        , infoUnit     = Records
        , infoBytes    = Just (TotalPayloadBytes (Length
            (Vector.foldl' (\runningTotal record ->
                              runningTotal + ByteString.length (PMSR.pmsrData record)) 0 records)))
        , infoRange    = PMSR.pmsrRecordsRange records
        }
    , patchSourceAdvisories    = []
    , patchMetadata       = Nothing
    , patchExtractedMeta  = noMetadataRequested
    }
  where
    recordToHunk pmsrRecord = Hunk (PMSR.pmsrOffset pmsrRecord) (PMSR.pmsrData pmsrRecord)


parseSomePatchFromAPSGBA :: PatchFileContents -> Either SlapError SomePatch
parseSomePatchFromAPSGBA patchContents = do
  Parsed patch@(APSGBA.APSGBAPatch header records) parseAdvisories <- APSGBA.parseAPSGBA patchContents
  Right SomePatch
    { patchFormat         = LabelAPSGBA
    , patchAnalysis       = APSGBA.analyzeAPSGBA patch
    , patchKind           = Differential
    , patchApply          = ApplyStrategy
          { runApply = \source -> pure (fmap noAdvisories (APSGBA.applyAPSGBA patch source)) }
    , patchUndo           = Nothing
    , patchVerification   = noVerification
          { verifySourceBlocks = map (\record -> BlockCheck (APSGBA.apsGbaOffset record) (APSGBA.apsGbaSourceCRC record)) records
          , verifyTargetBlocks = map (\record -> BlockCheck (APSGBA.apsGbaOffset record) (APSGBA.apsGbaTargetCRC record)) records
          , verifyFileSize = Just (AdvisorySize (APSGBA.apsGbaSourceSize header))
          }
    , patchAdvisories       = parseAdvisories
                            ++ [EmptyPatch LabelAPSGBA EmptyBlocks | null records]
    , patchInfo           = PatchInfo
        { infoFormat   = FormatHeader LabelAPSGBA Nothing
        , infoLines    = APSGBA.apsGBAMeta patch
        , infoEmbedded = []
        , infoTally    = Tally (length records)
        , infoUnit     = Blocks
        , infoBytes    = Just (TotalOutputBytes (APSGBA.apsGbaTargetSize header))
        , infoRange    = Nothing
        }
    , patchSourceAdvisories    = []
    , patchMetadata       = Nothing
    , patchExtractedMeta  = noMetadataRequested
    }

parseSomePatchFromDPS :: EncodingName -> PatchFileContents -> Either SlapError SomePatch
parseSomePatchFromDPS metadataEncoding patchContents = do
  Parsed patch parseAdvisories <- DPS.parseDPS metadataEncoding patchContents
  let records = DPS.dpsRecords patch
  Right SomePatch
    { patchFormat         = LabelDPS
    , patchAnalysis       = DPS.analyzeDPS patch
    , patchKind           = Differential
    , patchApply          = ApplyStrategy
        { runApply     = \source -> pure (fmap noAdvisories (DPS.applyDPS patch source)) }
    , patchVerification   = noVerification
          { verifyFileSize = Just (RequiredSize (DPS.dpsSourceSizeAsFileSize (DPS.dpsOriginalSize patch))) }
    , patchUndo           = Nothing
    , patchAdvisories       = parseAdvisories
                            ++ [EmptyPatch LabelDPS EmptyRecords | null records]
    , patchInfo           = PatchInfo
        { infoFormat   = FormatHeader LabelDPS Nothing
        , infoLines    = DPS.dpsMeta patch
        , infoEmbedded = []
        , infoTally    = Tally (length records)
        , infoUnit     = Records
        , infoBytes    = Nothing
        , infoRange    = Nothing
        }
    , patchSourceAdvisories    = []
    , patchMetadata       = Nothing
    , patchExtractedMeta  = noMetadataRequested
             { requestedTitle     = presentField (DPS.dpsName    patch)
             , requestedAuthor    = presentField (DPS.dpsAuthor  patch)
             , requestedVersion   = presentField (DPS.dpsVersion patch)
             , requestedStability = case DPS.dpsStability patch of
                                      DPS.DPSUnstable -> Just UnstablePatch
                                      DPS.DPSStable   -> Nothing
             }
    }

-- | Yay0 is a compression container (Nintendo LZSS), not a patch format.
-- Decompress the envelope and recurse into parseSome on the inner bytes.
-- The format suffix @"\/Yay0"@ is appended to 'patchInfo' so the user can see the envelope at a glance.
parseSomePatchFromYay0 :: RequestedDialects -> EncodingName -> PatchFileContents -> Either SlapError SomePatch
parseSomePatchFromYay0 dialects metadataEncoding (PatchFileContents input) = case Stream.yay0Decompress input of
  Left cause              -> Left (DecompressionFailed (Yay0WrapperFailed cause))
  Right decompressedBytes -> case parseSome dialects metadataEncoding (PatchFileContents decompressedBytes) of
    Left slapError -> Left slapError
    Right parsed ->
      let innerHeader = infoFormat (patchInfo parsed)
          wrappedExtra = Just (maybe "/Yay0" (<> "/Yay0") (formatExtra innerHeader))
      in Right parsed
        { patchInfo = (patchInfo parsed)
            { infoFormat = innerHeader { formatExtra = wrappedExtra } }
        }
