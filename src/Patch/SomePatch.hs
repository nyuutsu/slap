module Patch.SomePatch
  ( SomePatch(..)
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

import Patch.Types (PatchFormat(..))
import Patch.Detect (detectFormat)
import Patch.Format (padHex)
import Patch.Convert (PatchContents(..), emptyContents)
import Patch.Measure (Offset(..), Length(..), FileSize(..), Delta(..), Hunk(..), UndoHunk(..))
import qualified Patch.PPF.Types as PPF
import qualified Patch.PPF.Parse as PPF
import qualified Patch.PPF.Apply as PPF
import qualified Patch.PPF.Info as PPF
import qualified Patch.IPS as IPS
import qualified Patch.BPS as BPS
import qualified Patch.UPS as UPS
import qualified Patch.VCDIFF as VCDIFF
import qualified Patch.APS.N64 as APSN64
import qualified Patch.APS.GBA as APSGBA
import qualified Patch.RUP as RUP
import qualified Patch.BSDiff as BSDiff
import qualified Patch.GDIFF as GDIFF
import qualified Patch.XDelta1 as XDelta1
import qualified Patch.PMSR as PMSR
import qualified Patch.PCHTXT as PCHTXT
import qualified Patch.DPS as DPS
import qualified Patch.NINJA1 as NINJA1
import qualified Patch.Explain as Explain
import Patch.Explain (ExplainData(..))
import qualified Patch.Yay0 as Yay0

import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Char8 as ByteString8
import Data.Maybe (fromMaybe)
import Data.Word (Word16, Word32)

----------------------------------------------------------------------------
-- Types
----------------------------------------------------------------------------

-- | Strategy for applying a patch to a target file.
--
-- The two constructors map to a real domain distinction:
--
-- __Direct formats__ (IPS, PPF, NINJA1, PMSR, PCHTXT, APS) say "write
-- these bytes at offset X." They don't need to read the source file —
-- they open the target, seek, write, repeat. The format module receives
-- a file handle and mutates it. This is 'InPlace'.
--
-- __Differential formats__ (BPS, UPS, VCDIFF, XDelta1, BSDiff, GDIFF,
-- DPS, RUP) say "given source bytes and these instructions, compute
-- target bytes." They need the entire source in memory. The output is
-- a fresh ByteString, constructed atomically. This is 'InMemory'.
--
-- The error handling asymmetry follows from this distinction:
--
-- * 'InMemory' returns @Either String ByteString@ because failure is
--   clean — nothing was written. Errors are domain-level: "BPS: source
--   CRC mismatch", "VCDIFF: negative window target size."
--
-- * 'InPlace' returns @IO ()@ and throws on IO failure because mutation
--   is non-atomic. If write 7 of 12 succeeds and write 8 fails, the file
--   is partially modified. Main.hs handles this with a single @try@ at
--   the call site and an honest error message. Wrapping every format's
--   apply loop in Either boilerplate would add noise without improving
--   the failure mode.
--
-- Main.hs mitigates the mutation risk by copying the source to the
-- output path first (default) or offering @--backup@ (for @--in-place@).
-- The format module doesn't know or care whether it's mutating the
-- original or a copy.
data ApplyStrategy
  = InPlace (FilePath -> IO ())
    -- ^ Seek-and-write into a mutable file.
  | InMemory
      { inMemoryApply :: ByteString.ByteString -> IO (Either String ByteString.ByteString) }
    -- ^ Delta: takes source bytes, returns target bytes.

-- | Verification data extracted from a parsed patch.
-- All fields are optional; formats populate whichever they carry.
data Verification = Verification
  { verifySourceCRC32  :: Maybe Word32
  , verifySourceMD5    :: Maybe ByteString.ByteString
  , verifySourceSHA1   :: Maybe ByteString.ByteString
  , verifyTargetCRC32  :: Maybe Word32
  , verifyTargetMD5    :: Maybe ByteString.ByteString
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
  , blockCheckCRC16  :: !Word16
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
  , windowCheckExpected :: !Word32
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
data UndoStrategy
  = UndoInPlace (FilePath -> IO (Either String Int))
  | UndoInMemory (ByteString.ByteString -> ByteString.ByteString)

-- | A parsed patch with all operations pre-bound as closures.
-- The only dispatch point is 'parseSome'; every consumer works
-- through these fields, never inspecting the underlying format.
data SomePatch = SomePatch
  { patchFormat         :: String
  , patchInfo           :: String
  , patchExplain        :: ExplainData
  , patchIsDifferential :: Bool
  , patchApply          :: ApplyStrategy
  , patchUndo           :: Maybe UndoStrategy
  , patchVerification   :: Verification
  , patchVerboseLines   :: [String]
  , patchWarnings       :: [String]
  , patchRecordCount    :: Int
  , patchRecordUnit     :: String
  , patchContents       :: Maybe PatchContents
  , patchSourceNotes    :: [String]  -- ^ Conversion warnings about source-side data loss
  , patchMetadata       :: Maybe ByteString.ByteString  -- ^ Arbitrary metadata blob (BPS)
  }

----------------------------------------------------------------------------
-- Parse dispatch — the single point where format-specific types exist
----------------------------------------------------------------------------

parseSome :: ByteString.ByteString -> Either String SomePatch
parseSome patchBytes = case detectFormat patchBytes of
  Nothing
    -- Yay0 container: decompress and retry (Star Rod .mod files)
    | Yay0.isYay0 patchBytes -> case Yay0.decompressYay0 patchBytes of
        Left errorMessage   -> Left ("Yay0 decompression failed: " ++ errorMessage)
        Right decompressedBytes -> case parseSome decompressedBytes of
          Left errorMessage -> Left errorMessage
          Right parsed -> Right parsed
            { patchFormat  = patchFormat parsed ++ "/Yay0"
            , patchInfo    = replaceFirst "PMSR" "PMSR/Yay0" (patchInfo parsed)
            , patchExplain = (patchExplain parsed)
                { explainFormat = explainFormat (patchExplain parsed) ++ "/Yay0" }
            }
    -- DPS: no magic bytes, heuristic detection
    | DPS.isDPS patchBytes -> case DPS.parseDPS patchBytes of
        Left errorMessage -> Left errorMessage
        Right patch  ->
          let records = DPS.dpsRecords patch
          in Right SomePatch
            { patchFormat         = "DPS"
            , patchInfo           = DPS.dpsInfo patch
            , patchExplain        = Explain.explainDPS patch
            , patchIsDifferential = True
            , patchApply          = InMemory
                { inMemoryApply     = \source -> pure (DPS.applyDPS patch source) }
            , patchVerification   = noVerification
            , patchUndo           = Nothing
            , patchVerboseLines   = numbered records $ \record -> case DPS.dpsRecordPayload record of
                DPS.PayloadData payload ->
                  "Write " ++ show (ByteString.length payload) ++ " bytes at 0x"
                  ++ padHex 8 (unOffset (DPS.dpsRecordOutputOffset record))
                DPS.PayloadCopy sourceOffset dataLength ->
                  "Copy " ++ show dataLength ++ " bytes from 0x"
                  ++ padHex 8 sourceOffset ++ " to 0x"
                  ++ padHex 8 (unOffset (DPS.dpsRecordOutputOffset record))
            , patchWarnings       = ["empty patch (0 records)" | null records]
            , patchRecordCount    = length records
            , patchRecordUnit     = "records"
            , patchSourceNotes    = []
            , patchContents  = Nothing
            , patchMetadata       = Nothing
            }
    | otherwise -> Left "unknown patch format"

  Just FormatPPF -> case PPF.parsePatch patchBytes of
    Left errorMessage -> Left errorMessage
    Right patch  ->
      let records = PPF.ppfRecords patch
          hasAppend = any (\record -> PPF.recordCommand record == PPF.Append) records
          ppfVerification = noVerification
            { verifyPPFBlock = case PPF.ppfValidation patch of
                Just validation -> Just (ValidationBlock (PPF.validationOffset (PPF.validationImageType validation)) (PPF.validationBlock validation))
                Nothing  -> Nothing
            , verifyFileSize = fmap (FileSize . fromIntegral) (PPF.ppfFileSize patch)
            }
      in Right SomePatch
        { patchFormat         = "PPF"
        , patchInfo           = PPF.ppfInfo patch
        , patchExplain        = Explain.explainPPF patch
        , patchIsDifferential = False
        , patchApply          = InMemory
            { inMemoryApply = \source -> pure (Right (PPF.applyPatchMemory patch source)) }
        , patchUndo           = Just (UndoInPlace $ PPF.undoPatch patch)
        , patchVerification   = ppfVerification
        , patchVerboseLines   = numbered records $ \record ->
            "Write " ++ show (ByteString.length (PPF.recordData record)) ++ " bytes at 0x"
            ++ padHex 8 (unOffset (PPF.recordOffset record))
        , patchWarnings       = ["empty patch (0 records)" | null records]
        , patchRecordCount    = length records
        , patchRecordUnit     = "records"
        , patchSourceNotes    = []
        , patchMetadata       = Nothing
        , patchContents  = if hasAppend then Nothing else Just PatchContents
            { contentsRecords     = map (\record -> Hunk (PPF.recordOffset record) (PPF.recordData record)) records
            , contentsDescription = Just (PPF.ppfDescription patch)
            , contentsSourceCRC32 = Nothing
            , contentsSourceMD5   = Nothing
            , contentsSourceSHA1  = Nothing
            , contentsDestinationSize    = fmap (FileSize . fromIntegral) (PPF.ppfFileSize patch)
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
            }
        }

  Just FormatIPS -> do
    patch <- IPS.parseIPS patchBytes
    let records = IPS.ipsRecords patch
        expandIPS (IPS.IPSRecord recordOffset recordPayload) = Hunk recordOffset recordPayload
        expandIPS (IPS.IPSRecordRLE recordOffset fillCount fillByte) = Hunk recordOffset (ByteString.replicate (unLength fillCount) fillByte)
        name = case (IPS.ipsVariant patch, IPS.ipsEBPMeta patch) of
          (IPS.StandardIPS, Nothing) -> "IPS"
          (IPS.StandardIPS, Just _)  -> "EBP"
          (IPS.IPS32, _)             -> "IPS32"
        warnings = concat
          [ ["no EOF marker (patch may be truncated)" | not (IPS.ipsCleanEOF patch)]
          , ["empty patch (0 records)" | null records]
          ]
    Right SomePatch
      { patchFormat         = name
      , patchInfo           = IPS.ipsInfo patch
      , patchExplain        = Explain.explainIPS patch
      , patchIsDifferential = False
      , patchApply          = InMemory
            { inMemoryApply = \source -> pure (Right (IPS.applyIPSMemory patch source)) }
      , patchUndo           = Nothing
      , patchVerification   = noVerification
      , patchVerboseLines   = numbered records describeIPS
      , patchWarnings       = warnings
      , patchRecordCount    = length records
      , patchRecordUnit     = "records"
      , patchSourceNotes    = []
      , patchMetadata       = Nothing
      , patchContents  = Just (emptyContents (map expandIPS records))
          { contentsTruncation = IPS.ipsTruncate patch
          , contentsEBPMeta    = IPS.ipsEBPMeta patch
          }
      }

  Just FormatBPS -> do
    patch <- BPS.parseBPS patchBytes
    let actions = BPS.bpsActions patch
    Right SomePatch
      { patchFormat         = "BPS"
      , patchInfo           = BPS.bpsInfo patch
      , patchExplain        = Explain.explainBPS patch
      , patchIsDifferential = True
      , patchApply          = InMemory
          { inMemoryApply     = \source -> pure (BPS.applyBPS patch source) }
      , patchUndo           = Nothing
      , patchVerification   = noVerification
          { verifySourceCRC32 = Just (BPS.bpsSourceCRC patch)
          , verifyTargetCRC32 = Just (BPS.bpsTargetCRC patch)
          }
      , patchVerboseLines   = numbered actions describeBPS
      , patchWarnings       = ["empty patch (0 actions)" | null actions]
      , patchRecordCount    = length actions
      , patchRecordUnit     = "actions"
      , patchSourceNotes    = []
      , patchMetadata       = if ByteString.null (BPS.bpsMetadata patch) then Nothing
                           else Just (BPS.bpsMetadata patch)
      , patchContents  = Nothing
      }

  Just FormatUPS -> do
    patch <- UPS.parseUPS patchBytes
    let blocks = UPS.upsBlocks patch
    Right SomePatch
      { patchFormat         = "UPS"
      , patchInfo           = UPS.upsInfo patch
      , patchExplain        = Explain.explainUPS patch
      , patchIsDifferential = True
      , patchApply          = InMemory
          { inMemoryApply     = \source -> pure (Right (UPS.applyUPS patch source)) }
      , patchUndo           = Just (UndoInMemory $ UPS.applyUPS patch)
      , patchVerification   = noVerification
          { verifySourceCRC32 = Just (UPS.upsSourceCRC patch)
          , verifyTargetCRC32 = Just (UPS.upsTargetCRC patch)
          }
      , patchVerboseLines   = numbered blocks $ \block ->
          "XOR " ++ show (ByteString.length (UPS.upsXorData block))
          ++ " bytes (skip " ++ show (unDelta (UPS.upsSkip block)) ++ ")"
      , patchWarnings       = ["empty patch (0 blocks)" | null blocks]
      , patchRecordCount    = length blocks
      , patchRecordUnit     = "blocks"
      , patchSourceNotes    = []
      , patchMetadata       = Nothing
      , patchContents  = Nothing
      }

  Just FormatVCDIFF -> do
    patch <- VCDIFF.parseVCDIFF patchBytes
    let windows = VCDIFF.vcdiffWindows patch
        windowOffsets = scanl (+) 0 (map (unFileSize . VCDIFF.vcdiffTargetLength) windows)
        adlerChecks =
          [ WindowCheck (Offset windowOffset) (Length (fromIntegral (unFileSize (VCDIFF.vcdiffTargetLength window)))) checksum
          | (window, windowOffset) <- zip windows windowOffsets
          , Just checksum <- [VCDIFF.vcdiffAdler32 window]
          ]
    Right SomePatch
      { patchFormat         = "VCDIFF"
      , patchInfo           = VCDIFF.vcdiffInfo patch
      , patchExplain        = Explain.explainVCDIFF patch
      , patchIsDifferential = True
      , patchApply          = InMemory
          { inMemoryApply     = \source -> pure (VCDIFF.applyVCDIFF patch source) }
      , patchUndo           = Nothing
      , patchVerification   = noVerification { verifyWindowAdler32 = adlerChecks }
      , patchVerboseLines   = numbered windows $ \window ->
          "Window " ++ show (unFileSize (VCDIFF.vcdiffTargetLength window)) ++ " bytes target"
      , patchWarnings       = ["empty patch (0 windows)" | null windows]
      , patchRecordCount    = length windows
      , patchRecordUnit     = "windows"
      , patchSourceNotes    = []
      , patchMetadata       = Nothing
      , patchContents  = Nothing
      }

  -- APS N64 and APS GBA are unrelated formats by different authors who
  -- both used "APS" as the name.  detectFormat dispatches on magic, but
  -- "APS10" (N64) collides with "APS1" + source size when size mod 256 == 48.
  -- Disambiguate via GBA's fixed record structure (12 + N*65544 bytes,
  -- 64KB-aligned offsets).
  Just FormatAPSN64
    | apsGbaStructure patchBytes -> parseAPSGBABlock patchBytes
    | otherwise -> do
    patch@(APSN64.APSN64Patch header records) <- APSN64.parseAPSN64 patchBytes
    let expandN64 (APSN64.APSN64Normal recordOffset recordPayload) = Hunk recordOffset recordPayload
        expandN64 (APSN64.APSN64RLE recordOffset fillByte fillCount) = Hunk recordOffset (ByteString.replicate (fromIntegral fillCount) fillByte)
    Right SomePatch
      { patchFormat         = "APS (N64)"
      , patchInfo           = APSN64.apsN64Info patch
      , patchExplain        = Explain.explainAPSN64 patch
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
      , patchVerboseLines   = []
      , patchWarnings       = ["empty patch (0 records)" | null records]
      , patchRecordCount    = length records
      , patchRecordUnit     = "records"
      , patchSourceNotes    = []
      , patchMetadata       = Nothing
      , patchContents  = Just (emptyContents (map expandN64 records))
            { contentsDescription = Just (APSN64.apsN64Description header)
            , contentsDestinationSize    = Just (FileSize (fromIntegral (APSN64.apsN64DestinationSize header)))
            }
      }

  Just FormatAPSGBA -> parseAPSGBABlock patchBytes

  Just FormatRUP -> do
    patch <- RUP.parseRUP patchBytes
    let filterZero (Just hashValue) | ByteString.all (== 0) hashValue = Nothing
        filterZero other = other
    Right SomePatch
      { patchFormat         = "RUP"
      , patchInfo           = RUP.rupInfo patch
      , patchExplain        = Explain.explainRUP patch
      , patchIsDifferential = True
      , patchApply          = InMemory
            { inMemoryApply = \source -> pure (Right (RUP.applyRUPMemory patch source)) }
      , patchUndo           = Nothing
      , patchVerification   = noVerification
          { verifySourceMD5 = filterZero (RUP.rupSourceMD5 patch)
          , verifyTargetMD5 = filterZero (RUP.rupTargetMD5 patch)
          }
      , patchVerboseLines   = []
      , patchWarnings       = ["empty patch (0 records)" | null (RUP.rupRecords patch)]
      , patchRecordCount    = length (RUP.rupRecords patch)
      , patchRecordUnit     = "records"
      , patchSourceNotes    = []
      , patchMetadata       = Nothing
      , patchContents  = Nothing
      }

  Just FormatNINJA1 -> do
    patch <- NINJA1.parseNINJA1 patchBytes
    let records = NINJA1.ninja1Records patch
        warnings = concat
          [ ["no EOF marker (patch may be truncated)" | not (NINJA1.ninja1CleanEOF patch)]
          , ["empty patch (0 records)" | null records]
          ]
        compressed = NINJA1.ninja1SubFormat patch `elem` [NINJA1.Ninja1BinaryCompressed, NINJA1.Ninja1TextCompressed]
        sourceNotes = case NINJA1.ninja1SubFormat patch of
          NINJA1.Ninja1Text  -> ["note: NINJA1 text subformat converted to binary (B)"]
          NINJA1.Ninja1TextCompressed -> ["note: NINJA1 text subformat converted to compressed binary (BZ)"]
          _              -> []
    Right SomePatch
      { patchFormat         = "NINJA1"
      , patchInfo           = NINJA1.ninja1Info patch
      , patchExplain        = Explain.explainNINJA1 patch
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
      , patchVerboseLines   = numbered records $ \record ->
          "Write " ++ show (ByteString.length (NINJA1.ninja1RecordData record)) ++ " bytes at 0x"
          ++ padHex 8 (unOffset (NINJA1.ninja1RecordOffset record))
      , patchWarnings       = warnings
      , patchRecordCount    = length records
      , patchRecordUnit     = "records"
      , patchSourceNotes    = sourceNotes
      , patchMetadata       = Nothing
      , patchContents  = Just (emptyContents (map (\record -> Hunk (NINJA1.ninja1RecordOffset record) (NINJA1.ninja1RecordData record)) records))
          { contentsSourceCRC32 = NINJA1.ninja1SourceCRC patch
          , contentsSourceMD5   = NINJA1.ninja1SourceMD5 patch
          , contentsSourceSHA1  = NINJA1.ninja1SourceSHA1 patch
          , contentsRomType     = Just (NINJA1.fromNINJA1RomType (NINJA1.ninja1RomType patch))
          , contentsNINJA1Compressed = Just compressed
          }
      }

  Just FormatBSDiff -> do
    patch <- BSDiff.parseBSDiff patchBytes
    Right SomePatch
      { patchFormat         = "BSDiff"
      , patchInfo           = BSDiff.bsdiffInfo patch
      , patchExplain        = Explain.explainBSDiff patch
      , patchIsDifferential = True
      , patchApply          = InMemory
          { inMemoryApply     = \source -> pure (BSDiff.applyBSDiff patch source) }
      , patchUndo           = Nothing
      , patchVerification   = noVerification
      , patchVerboseLines   = []
      , patchWarnings       = ["empty patch (0 control tuples)" | null (BSDiff.bsdiffControls patch)]
      , patchRecordCount    = length (BSDiff.bsdiffControls patch)
      , patchRecordUnit     = "control tuples"
      , patchSourceNotes    = []
      , patchMetadata       = Nothing
      , patchContents  = Nothing
      }

  Just FormatGDIFF -> do
    patch <- GDIFF.parseGDIFF patchBytes
    Right SomePatch
      { patchFormat         = "GDIFF"
      , patchInfo           = GDIFF.gdiffInfo patch
      , patchExplain        = Explain.explainGDIFF patch
      , patchIsDifferential = True
      , patchApply          = InMemory
          { inMemoryApply     = \source -> pure (GDIFF.applyGDIFF patch source) }
      , patchUndo           = Nothing
      , patchVerification   = noVerification
      , patchVerboseLines   = []
      , patchWarnings       = ["empty patch (0 commands)" | null (GDIFF.gdiffCommands patch)]
      , patchRecordCount    = length (GDIFF.gdiffCommands patch)
      , patchRecordUnit     = "commands"
      , patchSourceNotes    = []
      , patchMetadata       = Nothing
      , patchContents  = Nothing
      }

  Just FormatXDelta1 -> do
    patch <- XDelta1.parseXDelta1 patchBytes
    let fileSources = filter (not . XDelta1.xdelta1SourceIsData) (XDelta1.xdelta1Sources patch)
        xdeltaVerification = noVerification
          { verifySourceMD5 = case fileSources of
              (entry:_) -> Just (XDelta1.xdelta1SourceMD5 entry)
              []        -> Nothing
          , verifyTargetMD5 = Just (XDelta1.xdelta1ToMD5 patch)
          }
    Right SomePatch
      { patchFormat         = "xdelta1"
      , patchInfo           = XDelta1.xdelta1Info patch
      , patchExplain        = Explain.explainXDelta1 patch
      , patchIsDifferential = True
      , patchApply          = InMemory
          { inMemoryApply     = \source -> pure (XDelta1.applyXDelta1 patch source) }
      , patchUndo           = Nothing
      , patchVerification   = xdeltaVerification
      , patchVerboseLines   = []
      , patchWarnings       = ["empty patch (0 instructions)" | null (XDelta1.xdelta1Instructions patch)]
      , patchRecordCount    = length (XDelta1.xdelta1Instructions patch)
      , patchRecordUnit     = "instructions"
      , patchSourceNotes    = []
      , patchMetadata       = Nothing
      , patchContents  = Nothing
      }

  Just FormatPMSR -> do
    patch <- PMSR.parsePMSR patchBytes
    let records = PMSR.pmsrRecords patch
    Right SomePatch
      { patchFormat         = "PMSR"
      , patchInfo           = PMSR.pmsrInfo patch
      , patchExplain        = Explain.explainPMSR patch
      , patchIsDifferential = False
      , patchApply          = InMemory
            { inMemoryApply = \source -> pure (Right (PMSR.applyPMSRMemory patch source)) }
      , patchUndo           = Nothing
      , patchVerification   = noVerification
      , patchVerboseLines   = numbered records $ \record ->
          "Write " ++ show (ByteString.length (PMSR.pmsrData record)) ++ " bytes at 0x"
          ++ padHex 8 (unOffset (PMSR.pmsrOffset record))
      , patchWarnings       = ["empty patch (0 records)" | null records]
      , patchRecordCount    = length records
      , patchRecordUnit     = "records"
      , patchSourceNotes    = []
      , patchMetadata       = Nothing
      , patchContents  = Just (emptyContents
          (map (\record -> Hunk (PMSR.pmsrOffset record) (PMSR.pmsrData record)) records))
      }

  Just FormatPCHTXT -> do
    patch <- PCHTXT.parsePCHTXT patchBytes
    let allBlocks = PCHTXT.pchtxtBlocks patch
        enabledBlocks = filter PCHTXT.pchtxtBlockEnabled allBlocks
        entries = concatMap PCHTXT.pchtxtBlockEntries enabledBlocks
        contentRecords = map (\entry -> Hunk (PCHTXT.pchtxtOffset entry) (PCHTXT.pchtxtData entry)) entries
        sourceNotes = ["PCHTXT: offset_shift applied to absolute offsets (no @flag directive in output)"
                   | PCHTXT.pchtxtHasShift patch]
    Right SomePatch
      { patchFormat         = "PCHTXT"
      , patchInfo           = PCHTXT.pchtxtInfo patch
      , patchExplain        = Explain.explainPCHTXT patch
      , patchIsDifferential = False
      , patchApply          = InMemory
            { inMemoryApply = \source -> pure (Right (PCHTXT.applyPCHTXTMemory patch source)) }
      , patchUndo           = Nothing
      , patchVerification   = noVerification
      , patchVerboseLines   = numbered entries $ \entry ->
          "Write " ++ show (ByteString.length (PCHTXT.pchtxtData entry)) ++ " bytes at 0x"
          ++ padHex 8 (unOffset (PCHTXT.pchtxtOffset entry))
      , patchWarnings       = ["empty patch (0 entries)" | null entries]
      , patchRecordCount    = length entries
      , patchRecordUnit     = "entries"
      , patchSourceNotes    = sourceNotes
      , patchMetadata       = Nothing
      , patchContents  = Just (emptyContents contentRecords)
          { contentsDescription = ByteString8.pack <$> PCHTXT.pchtxtNsobid patch
          , contentsPCHTXTBlocks = Just allBlocks
          }
      }

----------------------------------------------------------------------------
-- Helpers
----------------------------------------------------------------------------

parseAPSGBABlock :: ByteString.ByteString -> Either String SomePatch
parseAPSGBABlock input = do
  patch@(APSGBA.APSGBAPatch header records) <- APSGBA.parseAPSGBA input
  Right SomePatch
    { patchFormat         = "APS (GBA)"
    , patchInfo           = APSGBA.apsGBAInfo patch
    , patchExplain        = Explain.explainAPSGBA patch
    , patchIsDifferential = True
    , patchApply          = InMemory
          { inMemoryApply = \source -> pure (Right (APSGBA.applyAPSGBAMemory patch source)) }
    , patchUndo           = Nothing
    , patchVerification   = noVerification
          { verifySourceBlocks = map (\record -> BlockCheck (Offset (fromIntegral (APSGBA.apsGbaOffset record))) (APSGBA.apsGbaSourceCRC record)) records
          , verifyTargetBlocks = map (\record -> BlockCheck (Offset (fromIntegral (APSGBA.apsGbaOffset record))) (APSGBA.apsGbaTargetCRC record)) records
          , verifyFileSize = Just (FileSize (fromIntegral (APSGBA.apsGbaSourceSize header)))
          }
    , patchVerboseLines   = []
    , patchWarnings       = ["empty patch (0 blocks)" | null records]
    , patchRecordCount    = length records
    , patchRecordUnit     = "blocks"
    , patchSourceNotes    = []
    , patchMetadata       = Nothing
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

describeIPS :: IPS.IPSRecord -> String
describeIPS (IPS.IPSRecord recordOffset recordPayload) =
  "Write " ++ show (ByteString.length recordPayload) ++ " bytes at 0x" ++ padHex 6 (unOffset recordOffset)
describeIPS (IPS.IPSRecordRLE recordOffset fillCount fillByte) =
  "Fill " ++ show (unLength fillCount) ++ " x 0x" ++ padHex 2 (fromIntegral fillByte) ++ " at 0x" ++ padHex 6 (unOffset recordOffset)

describeBPS :: BPS.BPSAction -> String
describeBPS (BPS.SourceRead actionLength) = "SourceRead " ++ show (unLength actionLength) ++ " bytes"
describeBPS (BPS.TargetRead payload) = "TargetRead " ++ show (ByteString.length payload) ++ " bytes"
describeBPS (BPS.SourceCopy actionLength _) = "SourceCopy " ++ show (unLength actionLength) ++ " bytes"
describeBPS (BPS.TargetCopy actionLength _) = "TargetCopy " ++ show (unLength actionLength) ++ " bytes"

-- | Pre-render verbose lines with "[i/n]" prefixes.
numbered :: [a] -> (a -> String) -> [String]
numbered items formatItem = zipWith render [(1::Int)..] items
  where
    total = length items
    render index item = "[" ++ show index ++ "/" ++ show total ++ "] " ++ formatItem item

-- | Replace the first occurrence of a substring.  O(n*m) but only called
-- once for Yay0 format string rewriting, so it doesn't matter.
replaceFirst :: String -> String -> String -> String
replaceFirst _ _ [] = []
replaceFirst needle replacement haystack@(char:rest)
  | take (length needle) haystack == needle =
      replacement ++ drop (length needle) haystack
  | otherwise = char : replaceFirst needle replacement rest
