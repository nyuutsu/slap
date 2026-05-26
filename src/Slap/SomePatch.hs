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
  , noVerification
  , parseSome
  ) where

import Slap.FileContents (InputFileContents(..), OutputFileContents(..), PatchFileContents(..))
import Slap.PatchFormat (PatchFormat(..), DirectFormat(..), DifferentialFormat(..))
import Slap.Detect (detectFormat)
import Slap.Convert (PatchContents(..), emptyContents, RequestedPatchMetadata(..),
                     UndoInclusion(..), VerificationInclusion(..), PatchStability(..),
                     RequestedDialects(..),
                     noMetadataRequested)
import Slap.Text (EncodedText, encodedTextContent)
import Data.Text (Text)
import qualified Data.Text as Text
import Slap.Measure (Offset(..), Length(..), FileSize(..), Hunk(..),
                     splitUndoHunkFromParsed)
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
import Slap.Display.Analysis (PatchAnalysis)
import Slap.Display.Common (FormatHeader(..),
                             Tally(..), CountUnit(..), ByteCount(..))
import Slap.Display.Info (PatchInfo(..))
import Slap.Status (SlapError(..), SlapAdvisory(..), DecompressionFailure(..),
                   Parsed(..), Outcome(..), noAdvisories,
                   EmptyUnit(..), NINJA1SubformatConversion(..))
import Slap.FormatLabel (FormatLabel(..))
import qualified Slap.Compression.Yay0 as Yay0
import qualified Slap.Compression.Stream as Stream

import qualified Data.ByteString as ByteString
import qualified Data.Vector as Vector
import Data.List (partition)
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
  { runApply :: InputFileContents -> IO (Either SlapError (Outcome OutputFileContents)) }

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
data BlockCheck = BlockCheck !Offset !CRC16
  deriving (Show)

-- | Validation block comparison (PPF2 and PPF3). The bytes are
-- carried as a raw 'ByteString' at this cross-cutting layer; each
-- format wraps them in its own role newtype during parse and emit.
data ValidationBlock = ValidationBlock !Offset !ByteString.ByteString
  deriving (Show)

-- | Per-window Adler32 check (VCDIFF).
data WindowCheck = WindowCheck !Offset !Length !Adler32
  deriving (Show)

-- | Advisory byte-range comparison (APS-N64 cart ID, country, CRC).
-- Three fields in order: source-file offset, expected bytes, label.
data ByteCheck = ByteCheck !Offset !AdvisoryExpectedBytes !Text
  deriving (Show)

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
  { runUndo :: OutputFileContents -> Either SlapError (Outcome InputFileContents) }

-- | How the patch's records relate to the target file.
--
-- 'Direct' patches carry replacement bytes that get written into the
-- target; the @'Maybe' 'PatchContents'@ payload is the universal
-- direct-patch bag when the format's data is bag-shaped, or 'Nothing'
-- when a structural feature prevents the bag from being constructed
-- (e.g. PPF4 with Append commands — Appends carry no meaningful
-- offset, so they can't be expressed as 'Hunk's). 'Differential'
-- patches carry delta instructions whose meaning depends on the
-- source file, so they have no universal bag to publish and the
-- constructor is nullary. The kind drives whether source-less
-- conversion is structurally possible: only @'Direct' ('Just' _)@
-- can convert without source.
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
  , patchMetadata       :: Maybe ByteString.ByteString  -- ^ Arbitrary metadata blob (BPS)
  , patchExtractedMeta  :: RequestedPatchMetadata  -- ^ Text metadata extracted at parse time for conversion
  }

----------------------------------------------------------------------------
-- Parse dispatch — the single point where format-specific types exist
----------------------------------------------------------------------------

parseSome :: RequestedDialects -> PatchFileContents -> Either SlapError SomePatch
parseSome dialects patchContents = case detectFormat patchContents of
  Nothing
    | Yay0.isYay0 rawBytes -> parseSomePatchFromYay0 dialects patchContents
    | otherwise            -> Left UnrecognizedFormat

  Just (PatchDirect       FormatPPF1)           -> PPF1.parsePPF1 (requestedPPF1Origin dialects) patchContents >>= parseSomePatchFromPPF1
  Just (PatchDirect       FormatPPF2)           -> PPF2.parsePPF2 patchContents >>= parseSomePatchFromPPF2
  Just (PatchDirect       FormatPPF3)           -> PPF3.parsePPF3 patchContents >>= parseSomePatchFromPPF3
  Just (PatchDirect       FormatPPF4)           -> parseSomePatchFromPPF4 patchContents
  Just (PatchDirect       (FormatIPS variant))  -> parseSomePatchFromIPS variant patchContents
  Just (PatchDirect       FormatAPSN64)         -> parseSomePatchFromAPSN64 patchContents
  Just (PatchDirect       FormatNINJA1)         -> parseSomePatchFromNINJA1 patchContents
  Just (PatchDirect       FormatPMSR)           -> parseSomePatchFromPMSR patchContents
  Just (PatchDifferential FormatBPS)            -> parseSomePatchFromBPS patchContents
  Just (PatchDifferential FormatUPS)            -> parseSomePatchFromUPS patchContents
  Just (PatchDifferential FormatVCDIFF)         -> parseSomePatchFromVCDIFF patchContents
  Just (PatchDifferential FormatAPSGBA)         -> parseSomePatchFromAPSGBA patchContents
  Just (PatchDifferential FormatNINJA2)         -> parseSomePatchFromNINJA2 patchContents
  Just (PatchDifferential FormatBSDiff)         -> parseSomePatchFromBSDiff patchContents
  Just (PatchDifferential FormatGDIFF)          -> parseSomePatchFromGDIFF patchContents
  Just (PatchDifferential FormatXDelta1)        -> parseSomePatchFromXDelta1 patchContents
  Just (PatchDifferential FormatDPS)            -> parseSomePatchFromDPS patchContents
  where
    rawBytes = unPatchFileContents patchContents

----------------------------------------------------------------------------
-- Helpers
----------------------------------------------------------------------------

-- | Pass through an 'EncodedText'-shaped header field as a
-- 'RequestedPatchMetadata.requestedDescription' value, or 'Nothing'
-- if the wire field was entirely blank padding (space or null on
-- both ends). The pre-migration shape unpacked to 'String' for the
-- emptiness check; the migration keeps the value typed and runs the
-- check on the decoded codepoints directly.
extractedDescription :: EncodedText -> Maybe EncodedText
extractedDescription field
  | Text.null trimmed = Nothing
  | otherwise         = Just field
  where
    trimmed = Text.dropAround (\c -> c == ' ' || c == '\NUL') (encodedTextContent field)

-- | Build a 'SomePatch' from a parsed PPF1 patch. PPF1 carries no
-- validation block, no undo data, no file-size advisory, and no
-- FILE_ID.DIZ — the simplest of the four PPF dispatchers.
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
          { infoFormat = FormatHeader LabelPPF1 Nothing
          , infoLines  = PPF1.ppf1Meta patch
          , infoTally  = Tally (length records)
          , infoUnit   = Records
          , infoBytes  = Just (TotalPayloadBytes (Length
              (sum (map (ByteString.length . PPF1.ppf1RecordPayload) records))))
          , infoRange  = PPF1.ppf1RecordsRange records
          }
      , patchSourceAdvisories    = []
      , patchMetadata       = Nothing
      , patchExtractedMeta  = noMetadataRequested
            { requestedDescription = extractedDescription (PPF1.ppf1Description patch) }
      }
  where
    hunkOf record = Hunk (PPF1.ppf1RecordOffset record) (PPF1.ppf1RecordPayload record)

-- | Build a 'SomePatch' from a parsed PPF2 patch. PPF2 adds the
-- declared source-file-size field and the 1024-byte validation
-- block (BIN-only at offset 0x9320), plus an optional FILE_ID.DIZ
-- trailer.
parseSomePatchFromPPF2 :: Parsed PPF2.PPF2Patch -> Either SlapError SomePatch
parseSomePatchFromPPF2 (Parsed patch parseAdvisories) =
  let records = PPF2.ppf2Records patch
      validationBytes = PPF2.unPPF2ValidationBlock (PPF2.ppf2ValidationBlock patch)
      sourceFileSize = FileSize (fromIntegral (PPF2.unPPF2SourceSize (PPF2.ppf2SourceFileSize patch)))
      ppfVerification = noVerification
          { verifyPPFBlock = Just (ValidationBlock PPF2.ppf2ValidationOffset validationBytes)
          , verifyFileSizeAdvisory = Just sourceFileSize
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
          { infoFormat = FormatHeader LabelPPF2 Nothing
          , infoLines  = PPF2.ppf2Meta patch
          , infoTally  = Tally (length records)
          , infoUnit   = Records
          , infoBytes  = Just (TotalPayloadBytes (Length
              (sum (map (ByteString.length . PPF2.ppf2RecordPayload) records))))
          , infoRange  = PPF2.ppf2RecordsRange records
          }
      , patchSourceAdvisories    = []
      , patchMetadata       = Nothing
      , patchExtractedMeta  = noMetadataRequested
            { requestedDescription           = extractedDescription (PPF2.ppf2Description patch)
            , requestedVerificationInclusion = Just IncludeVerification
            }
      }
  where
    hunkOf record = Hunk (PPF2.ppf2RecordOffset record) (PPF2.ppf2RecordPayload record)

-- | Build a 'SomePatch' from a parsed PPF3 patch. PPF3 adds the
-- image-type byte (BIN/GI, choosing the validation offset),
-- per-record undo bytes, and a 2-byte-length FILE_ID.DIZ
-- trailer.
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
          { infoFormat = FormatHeader LabelPPF3 Nothing
          , infoLines  = PPF3.ppf3Meta patch
          , infoTally  = Tally (length records)
          , infoUnit   = Records
          , infoBytes  = Just (TotalPayloadBytes (Length
              (sum (map (ByteString.length . PPF3.ppf3RecordPayload) records))))
          , infoRange  = PPF3.ppf3RecordsRange records
          }
      , patchSourceAdvisories    = []
      , patchMetadata       = Nothing
      , patchExtractedMeta  = noMetadataRequested
            { requestedDescription           = extractedDescription (PPF3.ppf3Description patch)
            , requestedImageType             = Just (PPF3.ppf3ImageType patch)
            , requestedUndoInclusion         = if PPF3.ppf3HasUndo patch then Just IncludeUndoData else Nothing
            , requestedVerificationInclusion = if isJust (PPF3.ppf3ValidationBlock patch) then Just IncludeVerification else Nothing
            }
      }
  where
    hunkOf record = Hunk (PPF3.ppf3RecordOffset record) (PPF3.ppf3RecordPayload record)

-- | Build a 'SomePatch' from a parsed PPF4 patch. PPF4 is a two-phase
-- format (Replace records, then Append records) with no validation
-- block, no undo, no image type, and no File_ID.diz trailer — none of
-- the metadata that 'parseSomePatchFromPPF' carries for PPF1/2/3.
-- Source-less conversion is structurally possible only when the patch
-- has no Append records (Appends carry no meaningful offset, and so
-- can't be expressed as 'Hunk's).
parseSomePatchFromPPF4 :: PatchFileContents -> Either SlapError SomePatch
parseSomePatchFromPPF4 patchContents = do
  Parsed patch parseAdvisories <- PPF4.parsePPF4 patchContents
  let replaces = PPF4.ppf4Replaces patch
      appends  = PPF4.ppf4Appends patch
      totalRecords = length replaces + length appends
  Right SomePatch
      { patchFormat         = LabelPPF4
      , patchAnalysis       = PPF4.analyzePPF4 patch
      , patchKind           = Direct (if null appends
                                then Just (emptyContents (map (\replace -> Hunk (PPF4.replaceOffset replace) (PPF4.replaceData replace)) replaces))
                                       { contentsDescription = Just (PPF4.ppf4Description patch) }
                                else Nothing)
      , patchApply          = ApplyStrategy
          { runApply = \source -> pure (fmap noAdvisories (PPF4.applyPPF4 patch source)) }
      , patchUndo           = Nothing
      , patchVerification   = noVerification
      , patchAdvisories       = parseAdvisories
                              ++ [EmptyPatch LabelPPF4 EmptyRecords | totalRecords == 0]
      , patchInfo           = PatchInfo
          { infoFormat = FormatHeader LabelPPF4 (Just " (Pyriel internal format)")
          , infoLines  = PPF4.ppf4Meta patch
          , infoTally  = Tally totalRecords
          , infoUnit   = Records
          , infoBytes  = Just (TotalPayloadBytes (Length
              ( sum (map (ByteString.length . PPF4.replaceData) replaces)
              + sum (map (ByteString.length . PPF4.appendData) appends) )))
          , infoRange  = PPF4.ppf4ReplacesRange replaces
          }
      , patchSourceAdvisories    = []
      , patchMetadata       = Nothing
      , patchExtractedMeta  = noMetadataRequested
            { requestedDescription = extractedDescription (PPF4.ppf4Description patch) }
      }

parseSomePatchFromIPS :: IPS.IPSVariant -> PatchFileContents -> Either SlapError SomePatch
parseSomePatchFromIPS variant patchContents = do
  Parsed parseResult parseAdvisories <- IPS.parseIPS patchContents
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
  case parseResult of
    IPS.IPSParseCleanIPS ipsPatch ->
      let records = IPS.ipsRecords ipsPatch
      in Right SomePatch
        { patchFormat         = label
        , patchAnalysis       = IPS.analyzeIPS ipsPatch
        , patchKind           = Direct (Just (emptyContents (map expandIPSRecord (Vector.toList records)))
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
            { infoFormat = FormatHeader label Nothing
            , infoLines  = IPS.ipsMeta ipsPatch
            , infoTally  = Tally (Vector.length records)
            , infoUnit   = Records
            , infoBytes  = Nothing
            , infoRange  = IPS.ipsRecordsRange records
            }
        , patchSourceAdvisories    = []
        , patchMetadata       = Nothing
        , patchExtractedMeta  = noMetadataRequested
        }
    IPS.IPSParseCleanEBP ebpPatch ->
      let basePatch = IPS.ebpBasePatch ebpPatch
          records = IPS.ipsRecords basePatch
          metadata = IPS.ebpMetadata ebpPatch
          -- The JSON parser already tags extracted values 'EncodingUtf8';
          -- this collapse just drops empty strings so an EBP patch with
          -- blank fields reads as "no metadata requested" downstream
          -- rather than as "empty values explicitly requested".
          nonEmpty encoded
            | Text.null (encodedTextContent encoded) = Nothing
            | otherwise                              = Just encoded
          extractedMeta = noMetadataRequested
            { requestedTitle       = IPS.ebpMetadataTitle       metadata >>= nonEmpty
            , requestedAuthor      = IPS.ebpMetadataAuthor      metadata >>= nonEmpty
            , requestedDescription = IPS.ebpMetadataDescription metadata >>= nonEmpty
            }
      in Right SomePatch
        { patchFormat         = LabelEBP
        , patchAnalysis       = IPS.analyzeEBP ebpPatch
        , patchKind           = Direct (Just (emptyContents (map expandIPSRecord (Vector.toList records)))
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
            { infoFormat = FormatHeader LabelEBP Nothing
            , infoLines  = IPS.ebpMeta ebpPatch
            , infoTally  = Tally (Vector.length records)
            , infoUnit   = Records
            , infoBytes  = Nothing
            , infoRange  = IPS.ipsRecordsRange records
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
        , patchKind           = Direct (Just (emptyContents (map expandIPSRecord (Vector.toList records)))
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
            { infoFormat = FormatHeader label Nothing
            , infoLines  = IPS.ipsMeta truncatedPatch
            , infoTally  = Tally (Vector.length records)
            , infoUnit   = Records
            , infoBytes  = Nothing
            , infoRange  = IPS.ipsRecordsRange records
            }
        , patchSourceAdvisories    = []
        , patchMetadata       = Nothing
        , patchExtractedMeta  = noMetadataRequested
        }

parseSomePatchFromBPS :: PatchFileContents -> Either SlapError SomePatch
parseSomePatchFromBPS patchContents = do
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
    , patchAdvisories       = parseAdvisories
                            ++ [EmptyPatch LabelBPS EmptyActions | Vector.null actions]
    , patchInfo           = PatchInfo
        { infoFormat = FormatHeader LabelBPS Nothing
        , infoLines  = BPS.bpsMeta patch
        , infoTally  = Tally (Vector.length actions)
        , infoUnit   = Actions
        , infoBytes  = Just (TotalOutputBytes (BPS.bpsTargetSize patch))
        , infoRange  = Nothing
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
        -- UPS is self-inverse (XOR-based): walking the same block
        -- stream against the target reconstructs the source. The
        -- only direction-dependent choice is the output buffer
        -- size — 'undoUPS' handles that internally by passing
        -- sourceSize instead of targetSize to the shared walker,
        -- which is what makes size-changing UPS patches round-trip
        -- correctly (a reapply-forward path would have produced a
        -- target-sized buffer regardless of direction, silently
        -- wrong for growth patches). Each direction's 'Outcome'
        -- also carries its own 'ApplyOOBBlocksSkipped' advisory
        -- measured against that direction's output size — apply
        -- against 'upsTargetSize', undo against 'upsSourceSize' —
        -- so the user sees a direction-correct OOB summary instead
        -- of one frozen at parse time against the target.
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
    , patchAdvisories       = parseAdvisories
                            ++ [EmptyPatch LabelUPS EmptyBlocks | Vector.null blocks]
    , patchInfo           = PatchInfo
        { infoFormat = FormatHeader LabelUPS Nothing
        , infoLines  = UPS.upsMeta patch
        , infoTally  = Tally (Vector.length blocks)
        , infoUnit   = Blocks
        , infoBytes  = Just (TotalOutputBytes (UPS.upsTargetSize patch))
        , infoRange  = Nothing
        }
    , patchSourceAdvisories    = []
    , patchMetadata       = Nothing
    , patchExtractedMeta  = noMetadataRequested
    }

parseSomePatchFromVCDIFF :: PatchFileContents -> Either SlapError SomePatch
parseSomePatchFromVCDIFF patchContents = do
  Parsed patch parseAdvisories <- VCDIFF.parseVCDIFF patchContents
  let windows = VCDIFF.vcdiffWindows patch
      windowOffsets = scanl (+) 0 (map (unFileSize . VCDIFF.vcdiffTargetLength) windows)
      adlerChecks =
        [ WindowCheck (Offset windowOffset) (Length (unFileSize (VCDIFF.vcdiffTargetLength window))) checksum
        | (window, windowOffset) <- zip windows windowOffsets
        , Just checksum <- [VCDIFF.vcdiffAdler32 window]
        ]
  Right SomePatch
    { patchFormat         = LabelVCDIFF
    , patchAnalysis       = VCDIFF.analyzeVCDIFF patch
    , patchKind           = Differential
    , patchApply          = ApplyStrategy
        { runApply     = \source -> pure (fmap noAdvisories (VCDIFF.applyVCDIFF patch source)) }
    , patchUndo           = Nothing
    , patchVerification   = noVerification { verifyWindowAdler32 = adlerChecks }
    , patchAdvisories       = parseAdvisories
                            ++ [EmptyPatch LabelVCDIFF EmptyWindows | null windows]
    , patchInfo           = PatchInfo
        { infoFormat = FormatHeader LabelVCDIFF (case VCDIFF.vcdiffVersion (VCDIFF.vcdiffHeader patch) of
                                                   VCDIFF.VCDIFFXDelta3  -> Just " (xdelta3)"
                                                   VCDIFF.VCDIFFStandard -> Nothing)
        , infoLines  = VCDIFF.vcdiffMeta patch
        , infoTally  = Tally (length windows)
        , infoUnit   = Windows
        , infoBytes  = Just (TotalOutputBytes (FileSize
            (sum (map (unFileSize . VCDIFF.vcdiffTargetLength) windows))))
        , infoRange  = Nothing
        }
    , patchSourceAdvisories    = []
    , patchMetadata       = Nothing
    , patchExtractedMeta  = noMetadataRequested
    }

-- APS N64 and APS GBA are unrelated formats by different authors who
-- both used "APS" as the name.  detectFormat dispatches on magic, but
-- "APS10" (N64) collides with "APS1" + source size when size mod 256 == 48.
-- detectFormat disambiguates via GBA's fixed record structure (12 +
-- N*65544 bytes, 64KB-aligned offsets) and re-routes structurally-GBA
-- inputs to 'FormatAPSGBA' upstream of this function, so by the time
-- 'parseSomePatchFromAPSN64' runs the bytes really are APSN64.
parseSomePatchFromAPSN64 :: PatchFileContents -> Either SlapError SomePatch
parseSomePatchFromAPSN64 patchContents = do
  Parsed patch@(APSN64.APSN64Patch header records) parseAdvisories <- APSN64.parseAPSN64 patchContents
  let expandN64 (APSN64.APSN64Normal recordOffset recordPayload) = Hunk recordOffset recordPayload
      expandN64 (APSN64.APSN64RLE recordOffset fillValue fillCount) = Hunk recordOffset (ByteString.replicate (fromIntegral fillCount) fillValue)
  Right SomePatch
    { patchFormat         = LabelAPSN64
    , patchAnalysis       = APSN64.analyzeAPSN64 patch
    , patchKind           = Direct (Just (emptyContents (Vector.toList (Vector.map expandN64 records)))
          { contentsDescription = Just (APSN64.apsN64Description header)
          -- ^ APSN64's description field is typed 'EncodedText' under
          -- stage 3b; the parse-time decode (and any substitution
          -- advisories) lives inside 'parseAPSN64'.
          , contentsDestinationSize    = Just (APSN64.apsN64DestinationSize header)
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
          }
    , patchAdvisories       = parseAdvisories
                            ++ [EmptyPatch LabelAPSN64 EmptyRecords | Vector.null records]
    , patchInfo           = PatchInfo
        { infoFormat = FormatHeader LabelAPSN64 Nothing
        , infoLines  = APSN64.apsN64Meta patch
        , infoTally  = Tally (Vector.length records)
        , infoUnit   = Records
        , infoBytes  = Just (TotalOutputBytes (APSN64.apsN64DestinationSize header))
        , infoRange  = Nothing
        }
    , patchSourceAdvisories    = []
    , patchMetadata       = Nothing
    , patchExtractedMeta  =
        let description       = APSN64.apsN64Description header
            descriptionText   = encodedTextContent description
            trimmedText       = Text.dropAround (\c -> c == ' ' || c == '\NUL') descriptionText
        in noMetadataRequested
             { requestedDescription =
                 if Text.null trimmedText
                   then Nothing
                   else Just description
             }
    }

parseSomePatchFromNINJA2 :: PatchFileContents -> Either SlapError SomePatch
parseSomePatchFromNINJA2 patchContents = do
  Parsed patch parseAdvisories <- NINJA2.parseNINJA2 patchContents
  let filterZeroMD5 (Just hash@(MD5Hash bytes))
        | ByteString.all (== 0) bytes = Nothing
        | otherwise                   = Just hash
      filterZeroMD5 Nothing = Nothing
      openNewFile = NINJA2.ninja2OpenNewFile patch
      romTypeForPlatformConversion = case openNewFile of
        Just open -> NINJA2.openNewFileRomType open
        Nothing   -> NINJA2.NINJA2Raw
      (platformType, platformAdvisories) = ninja2ToPlatform romTypeForPlatformConversion
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
        }
    , patchAdvisories       = parseAdvisories
                             ++ [EmptyPatch LabelNINJA2 EmptyRecords | null (NINJA2.ninja2Records patch)]
                             ++ platformAdvisories
    , patchInfo           = PatchInfo
        { infoFormat = FormatHeader LabelNINJA2 Nothing
        , infoLines  = NINJA2.ninja2Meta patch
        , infoTally  = Tally (length (NINJA2.ninja2Records patch))
        , infoUnit   = Records
        , infoBytes  = Nothing
        , infoRange  = Nothing
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
      warnings = concat
        [ parseAdvisories
        , [NoEOFMarker LabelNINJA1 | not (NINJA1.ninja1CleanEOF patch)]
        , [EmptyPatch LabelNINJA1 EmptyRecords | null records]
        ]
      compressed = NINJA1.ninja1SubFormat patch `elem` [NINJA1.NINJA1BinaryCompressed, NINJA1.NINJA1TextCompressed]
      sourceAdvisories = case NINJA1.ninja1SubFormat patch of
        NINJA1.NINJA1Text  -> [SubformatConverted NINJA1TextToBinary]
        NINJA1.NINJA1TextCompressed -> [SubformatConverted NINJA1CompressedTextToCompressedBinary]
        _              -> []
  Right SomePatch
    { patchFormat         = LabelNINJA1
    , patchAnalysis       = NINJA1.analyzeNINJA1 patch
    , patchKind           = Direct (Just (emptyContents (map (\record -> Hunk (NINJA1.ninja1RecordOffset record) (NINJA1.ninja1RecordData record)) records))
        { contentsSourceCRC32 = NINJA1.ninja1SourceCRC patch
        , contentsSourceMD5   = NINJA1.ninja1SourceMD5 patch
        , contentsSourceSHA1  = NINJA1.ninja1SourceSHA1 patch
        , contentsRomType     = Just (ninja1ToPlatform (NINJA1.ninja1RomType patch))
        , contentsNINJA1Compressed = Just compressed
        })
    , patchApply          = ApplyStrategy
          { runApply = \source -> pure (fmap noAdvisories (NINJA1.applyNINJA1 patch source)) }
    , patchUndo           = Nothing
    , patchVerification   = noVerification
        { verifySourceCRC32  = NINJA1.ninja1SourceCRC patch
        , verifySourceMD5    = NINJA1.ninja1SourceMD5 patch
        , verifySourceSHA1   = NINJA1.ninja1SourceSHA1 patch
        , verifySourcePreHash = NINJA1.ninja1HashInput
        }
    , patchAdvisories       = warnings
    , patchInfo           = PatchInfo
        { infoFormat = FormatHeader LabelNINJA1
            (Just (" (" <> NINJA1.subFormatName (NINJA1.ninja1SubFormat patch) <> ")"))
        , infoLines  = NINJA1.ninja1Meta patch
        , infoTally  = Tally (length records)
        , infoUnit   = Records
        , infoBytes  = Just (TotalPayloadBytes (Length
            (sum (map (ByteString.length . NINJA1.ninja1RecordData) records))))
        , infoRange  = NINJA1.ninja1RecordsRange records
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
        { infoFormat = FormatHeader LabelBSDiff Nothing
        , infoLines  = BSDiff.bsdiffMeta patch
        , infoTally  = Tally (length (BSDiff.bsdiffInstructions patch))
        , infoUnit   = Instructions
        , infoBytes  = Just (TotalOutputBytes (BSDiff.bsdiffTargetSize patch))
        , infoRange  = Nothing
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
        { infoFormat = FormatHeader LabelGDIFF Nothing
        , infoLines  = GDIFF.gdiffMeta patch
        , infoTally  = Tally (length (GDIFF.gdiffCommands patch))
        , infoUnit   = Commands
        , infoBytes  = Nothing
        , infoRange  = Nothing
        }
    , patchSourceAdvisories    = []
    , patchMetadata       = Nothing
    , patchExtractedMeta  = noMetadataRequested
    }

parseSomePatchFromXDelta1 :: PatchFileContents -> Either SlapError SomePatch
parseSomePatchFromXDelta1 patchContents = do
  Parsed patch parseAdvisories <- XDelta1.parseXDelta1 patchContents
  let xdeltaVerification = case XDelta1.xdelta1Verification patch of
        XDelta1.VerifyAgainstStoredMD5s targetMD5 -> noVerification
          { verifySourceMD5 = XDelta1.xdelta1SourceMD5 patch
          , verifyTargetMD5 = Just targetMD5
          }
        XDelta1.CreatorOptedOutOfVerification -> noVerification
      -- The data-record-name divergence is an informational note —
      -- the field is a display label, not anything apply consults
      -- (see 'XDelta1DataRecordNameDiverges'). Split it off the
      -- warning lane so the porcelain emits it through the @slap:@-
      -- prefixed notice path instead of the @warning:@ lane.
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
        { infoFormat = FormatHeader LabelXDelta1 Nothing
        , infoLines  = XDelta1.xdelta1Meta patch
        , infoTally  = Tally (length (XDelta1.xdelta1Instructions patch))
        , infoUnit   = Instructions
        , infoBytes  = Just (TotalOutputBytes (XDelta1.xdelta1TargetLength patch))
        , infoRange  = Nothing
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
        { infoFormat = FormatHeader LabelPMSR Nothing
        , infoLines  = PMSR.pmsrMeta patch
        , infoTally  = Tally (Vector.length records)
        , infoUnit   = Records
        , infoBytes  = Just (TotalPayloadBytes (Length
            (Vector.foldl' (\runningTotal record ->
                              runningTotal + ByteString.length (PMSR.pmsrData record)) 0 records)))
        , infoRange  = PMSR.pmsrRecordsRange records
        }
    , patchSourceAdvisories    = []
    , patchMetadata       = Nothing
    , patchExtractedMeta  = noMetadataRequested
    }
  where
    recordToHunk record = Hunk (PMSR.pmsrOffset record) (PMSR.pmsrData record)


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
          , verifyFileSizeAdvisory = Just (APSGBA.apsGbaSourceSize header)
          }
    , patchAdvisories       = parseAdvisories
                            ++ [EmptyPatch LabelAPSGBA EmptyBlocks | null records]
    , patchInfo           = PatchInfo
        { infoFormat = FormatHeader LabelAPSGBA Nothing
        , infoLines  = APSGBA.apsGBAMeta patch
        , infoTally  = Tally (length records)
        , infoUnit   = Blocks
        , infoBytes  = Just (TotalOutputBytes (APSGBA.apsGbaTargetSize header))
        , infoRange  = Nothing
        }
    , patchSourceAdvisories    = []
    , patchMetadata       = Nothing
    , patchExtractedMeta  = noMetadataRequested
    }

parseSomePatchFromDPS :: PatchFileContents -> Either SlapError SomePatch
parseSomePatchFromDPS patchContents = do
  Parsed patch parseAdvisories <- DPS.parseDPS patchContents
  let records = DPS.dpsRecords patch
  Right SomePatch
    { patchFormat         = LabelDPS
    , patchAnalysis       = DPS.analyzeDPS patch
    , patchKind           = Differential
    , patchApply          = ApplyStrategy
        { runApply     = \source -> pure (fmap noAdvisories (DPS.applyDPS patch source)) }
    , patchVerification   = noVerification
          { verifyFileSizeRequired = Just (DPS.dpsSourceSizeAsFileSize (DPS.dpsOriginalSize patch)) }
    , patchUndo           = Nothing
    , patchAdvisories       = parseAdvisories
                            ++ [EmptyPatch LabelDPS EmptyRecords | null records]
    , patchInfo           = PatchInfo
        { infoFormat = FormatHeader LabelDPS Nothing
        , infoLines  = DPS.dpsMeta patch
        , infoTally  = Tally (length records)
        , infoUnit   = Records
        , infoBytes  = Nothing
        , infoRange  = Nothing
        }
    , patchSourceAdvisories    = []
    , patchMetadata       = Nothing
    , patchExtractedMeta  =
        let nonEmpty field =
              let trimmed = Text.dropAround (\c -> c == ' ' || c == '\NUL')
                                            (encodedTextContent field)
              in if Text.null trimmed then Nothing else Just field
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
-- The format suffix @"\/Yay0"@ is appended to 'patchInfo' so the user
-- can see the envelope at a glance — the analytical carrier
-- 'patchAnalysis' no longer carries a format-name field, since
-- 'renderAnalysisFull' and 'renderAnalysisSummary' read the format-name
-- straight off 'patchInfo' now.
parseSomePatchFromYay0 :: RequestedDialects -> PatchFileContents -> Either SlapError SomePatch
parseSomePatchFromYay0 dialects (PatchFileContents input) = case Stream.yay0Decompress input of
  Left cause              -> Left (DecompressionFailed (Yay0WrapperFailed cause))
  Right decompressedBytes -> case parseSome dialects (PatchFileContents decompressedBytes) of
    Left slapError -> Left slapError
    Right parsed ->
      let innerHeader = infoFormat (patchInfo parsed)
          wrappedExtra = Just (maybe "/Yay0" (<> "/Yay0") (formatExtra innerHeader))
      in Right parsed
        { patchInfo = (patchInfo parsed)
            { infoFormat = innerHeader { formatExtra = wrappedExtra } }
        }
