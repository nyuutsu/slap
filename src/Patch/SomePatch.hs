module Patch.SomePatch
  ( SomePatch(..)
  , ApplyStrategy(..)
  , UndoStrategy(..)
  , Verification(..)
  , noVerification
  , parseSome
  ) where

import Patch.Types (PatchFormat(..))
import Patch.Detect (detectFormat)
import Patch.Format (padHex)
import Patch.Convert (PatchContents(..), emptyContents)
import qualified Patch.PPF.Types as PPF
import qualified Patch.PPF.Parse as PPF
import qualified Patch.PPF.Apply as PPF
import qualified Patch.PPF.Info as PPF
import qualified Patch.IPS as IPS
import qualified Patch.BPS as BPS
import qualified Patch.UPS as UPS
import qualified Patch.VCDIFF as VCDIFF
import qualified Patch.APS as APS
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

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BS8
import Data.Int (Int64)
import Data.Maybe (fromMaybe)
import Data.Word (Word16, Word32)
import System.IO (hPutStrLn, stderr)

----------------------------------------------------------------------------
-- Types
----------------------------------------------------------------------------

-- | Strategy for applying a patch to a target.
data ApplyStrategy
  = InPlace (FilePath -> IO ())
    -- ^ Seek-and-write into a mutable file.
  | InMemory
      { imApply :: BS.ByteString -> IO (Either String BS.ByteString) }
    -- ^ Delta: takes source bytes, returns target bytes.

-- | Verification data extracted from a parsed patch.
-- All fields are optional; formats populate whichever they carry.
data Verification = Verification
  { vSourceCRC32  :: Maybe Word32
  , vSourceMD5    :: Maybe BS.ByteString
  , vSourceSHA1   :: Maybe BS.ByteString
  , vTargetCRC32  :: Maybe Word32
  , vTargetMD5    :: Maybe BS.ByteString
  , vSourceBlocks :: [(Int, Word16)]     -- APS-GBA per-block CRC16
  , vTargetBlocks :: [(Int, Word16)]     -- APS-GBA per-block CRC16
  , vPPFBlock     :: Maybe (Int64, BS.ByteString)  -- PPF validation block
  , vFileSize     :: Maybe Word32                  -- PPF2 expected target file size (advisory)
  , vWindowAdler32 :: [(Int, Int, Word32)]         -- VCDIFF per-window (offset, length, expected)
  }

noVerification :: Verification
noVerification = Verification Nothing Nothing Nothing Nothing Nothing [] [] Nothing Nothing []

-- | Strategy for undoing a patch.
data UndoStrategy
  = UndoInPlace (FilePath -> IO (Either String Int))
  | UndoInMemory (BS.ByteString -> BS.ByteString)

-- | A parsed patch with all operations pre-bound as closures.
-- The only dispatch point is 'parseSome'; every consumer works
-- through these fields, never inspecting the underlying format.
data SomePatch = SomePatch
  { spFormat         :: String
  , spInfo           :: String
  , spExplain        :: ExplainData
  , spIsDifferential :: Bool
  , spApply          :: ApplyStrategy
  , spUndo           :: Maybe UndoStrategy
  , spVerification   :: Verification
  , spVerboseLines   :: [String]
  , spWarnings       :: [String]
  , spRecordCount    :: Int
  , spRecordUnit     :: String
  , spContents       :: Maybe PatchContents
  , spSourceNotes    :: [String]  -- ^ Conversion warnings about source-side data loss
  }

----------------------------------------------------------------------------
-- Parse dispatch — the single point where format-specific types exist
----------------------------------------------------------------------------

parseSome :: BS.ByteString -> Either String SomePatch
parseSome bs = case detectFormat bs of
  Nothing
    -- Yay0 container: decompress and retry (Star Rod .mod files)
    | Yay0.isYay0 bs -> case Yay0.decompressYay0 bs of
        Left err    -> Left ("Yay0 decompression failed: " ++ err)
        Right inner -> case parseSome inner of
          Left err -> Left err
          Right sp -> Right sp
            { spFormat  = spFormat sp ++ "/Yay0"
            , spInfo    = replaceFirst "PMSR" "PMSR/Yay0" (spInfo sp)
            , spExplain = (spExplain sp)
                { edFormat = edFormat (spExplain sp) ++ "/Yay0" }
            }
    -- DPS: no magic bytes, heuristic detection
    | DPS.isDPS bs -> case DPS.parseDPS bs of
        Left err -> Left err
        Right p  ->
          let recs = DPS.dpsRecords p
          in Right SomePatch
            { spFormat         = "DPS"
            , spInfo           = DPS.dpsInfo p
            , spExplain        = Explain.explainDPS p
            , spIsDifferential = True
            , spApply          = InMemory
                { imApply     = \source -> pure (DPS.applyDPS p source) }
            , spVerification   = noVerification
            , spUndo           = Nothing
            , spVerboseLines   = numbered recs $ \r -> case DPS.dpsRecPayload r of
                DPS.PayloadData dat ->
                  "Write " ++ show (BS.length dat) ++ " bytes at 0x"
                  ++ padHex 8 (DPS.dpsRecOutOffset r)
                DPS.PayloadCopy srcOff len ->
                  "Copy " ++ show len ++ " bytes from 0x"
                  ++ padHex 8 srcOff ++ " to 0x"
                  ++ padHex 8 (DPS.dpsRecOutOffset r)
            , spWarnings       = ["empty patch (0 records)" | null recs]
            , spRecordCount    = length recs
            , spRecordUnit     = "records"
            , spSourceNotes    = []
            , spContents  = Nothing
            }
    | otherwise -> Left "unknown patch format"

  Just FmtPPF -> case PPF.parsePatch bs of
    Left err -> Left err
    Right p  ->
      let recs = PPF.patchRecords p
          hasAppend = any (\r -> PPF.recCmd r == PPF.Append) recs
          ppfV = noVerification
            { vPPFBlock = case PPF.patchValidation p of
                Just val -> Just (PPF.validationOffset (PPF.valImageType val), PPF.valBlock val)
                Nothing  -> Nothing
            , vFileSize = PPF.patchFileSize p
            }
          srcNotes = ["PPF: File_ID.diz dropped (not representable in target format)"
                     | Just _ <- [PPF.patchFileId p]]
      in Right SomePatch
        { spFormat         = "PPF"
        , spInfo           = PPF.showInfo p
        , spExplain        = Explain.explainPPF p
        , spIsDifferential = False
        , spApply          = InPlace $ \fp -> do
            (warnings, _) <- PPF.applyPatch p fp
            mapM_ (hPutStrLn stderr) warnings
        , spUndo           = Just (UndoInPlace $ PPF.undoPatch p)
        , spVerification   = ppfV
        , spVerboseLines   = numbered recs $ \r ->
            "Write " ++ show (BS.length (PPF.recData r)) ++ " bytes at 0x"
            ++ padHex 8 (PPF.recOffset r)
        , spWarnings       = ["empty patch (0 records)" | null recs]
        , spRecordCount    = length recs
        , spRecordUnit     = "records"
        , spSourceNotes    = srcNotes
        , spContents  = if hasAppend then Nothing else Just PatchContents
            { pcRecords     = map (\r -> (PPF.recOffset r, PPF.recData r)) recs
            , pcDescription = Just (PPF.patchDescription p)
            , pcSourceCRC32 = Nothing
            , pcSourceMD5   = Nothing
            , pcSourceSHA1  = Nothing
            , pcDestSize    = PPF.patchFileSize p
            , pcValidation  = fmap PPF.valBlock (PPF.patchValidation p)
            , pcUndoData    = if PPF.patchHasUndo p
                              then Just [ (PPF.recOffset r, PPF.recData r, fromMaybe BS.empty (PPF.recUndo r))
                                        | r <- recs ]
                              else Nothing
            , pcTruncation  = Nothing
            , pcEBPMeta     = Nothing
            , pcRomType     = Nothing
            , pcImageType   = PPF.patchImageType p
            }
        }

  Just FmtIPS -> do
    p <- IPS.parseIPS bs
    let recs = IPS.ipsRecords p
        expandIPS (IPS.IPSRecord off dat)        = (off, dat)
        expandIPS (IPS.IPSRecordRLE off cnt val) = (off, BS.replicate cnt val)
        name = case (IPS.ipsVariant p, IPS.ipsEBPMeta p) of
          (IPS.StandardIPS, Nothing) -> "IPS"
          (IPS.StandardIPS, Just _)  -> "EBP"
          (IPS.IPS32, _)             -> "IPS32"
        warns = concat
          [ ["no EOF marker (patch may be truncated)" | not (IPS.ipsCleanEOF p)]
          , ["empty patch (0 records)" | null recs]
          ]
    Right SomePatch
      { spFormat         = name
      , spInfo           = IPS.ipsInfo p
      , spExplain        = Explain.explainIPS p
      , spIsDifferential = False
      , spApply          = InPlace $ \fp -> IPS.applyIPS p fp >> pure ()
      , spUndo           = Nothing
      , spVerification   = noVerification
      , spVerboseLines   = numbered recs describeIPS
      , spWarnings       = warns
      , spRecordCount    = length recs
      , spRecordUnit     = "records"
      , spSourceNotes    = []
      , spContents  = Just (emptyContents (map expandIPS recs))
          { pcTruncation = IPS.ipsTruncate p
          , pcEBPMeta    = IPS.ipsEBPMeta p
          }
      }

  Just FmtBPS -> do
    p <- BPS.parseBPS bs
    let acts = BPS.bpsActions p
    Right SomePatch
      { spFormat         = "BPS"
      , spInfo           = BPS.bpsInfo p
      , spExplain        = Explain.explainBPS p
      , spIsDifferential = True
      , spApply          = InMemory
          { imApply     = \source -> pure (BPS.applyBPS p source) }
      , spUndo           = Nothing
      , spVerification   = noVerification
          { vSourceCRC32 = Just (BPS.bpsSourceCRC p)
          , vTargetCRC32 = Just (BPS.bpsTargetCRC p)
          }
      , spVerboseLines   = numbered acts describeBPS
      , spWarnings       = ["empty patch (0 actions)" | null acts]
      , spRecordCount    = length acts
      , spRecordUnit     = "actions"
      , spSourceNotes    = []
      , spContents  = Nothing
      }

  Just FmtUPS -> do
    p <- UPS.parseUPS bs
    let blks = UPS.upsBlocks p
    Right SomePatch
      { spFormat         = "UPS"
      , spInfo           = UPS.upsInfo p
      , spExplain        = Explain.explainUPS p
      , spIsDifferential = True
      , spApply          = InMemory
          { imApply     = \source -> pure (Right (UPS.applyUPS p source)) }
      , spUndo           = Just (UndoInMemory $ UPS.applyUPS p)
      , spVerification   = noVerification
          { vSourceCRC32 = Just (UPS.upsSourceCRC p)
          , vTargetCRC32 = Just (UPS.upsTargetCRC p)
          }
      , spVerboseLines   = numbered blks $ \b ->
          "XOR " ++ show (BS.length (UPS.upsXorData b))
          ++ " bytes (skip " ++ show (UPS.upsSkip b) ++ ")"
      , spWarnings       = ["empty patch (0 blocks)" | null blks]
      , spRecordCount    = length blks
      , spRecordUnit     = "blocks"
      , spSourceNotes    = []
      , spContents  = Nothing
      }

  Just FmtVCDIFF -> do
    p <- VCDIFF.parseVCDIFF bs
    let wins = VCDIFF.vcdWindows p
        winOffsets = scanl (+) 0 (map VCDIFF.vcdTargetLen wins)
        adlerChecks =
          [ (fromIntegral off, fromIntegral (VCDIFF.vcdTargetLen w), a)
          | (w, off) <- zip wins winOffsets
          , Just a <- [VCDIFF.vcdAdler32 w]
          ]
    Right SomePatch
      { spFormat         = "VCDIFF"
      , spInfo           = VCDIFF.vcdiffInfo p
      , spExplain        = Explain.explainVCDIFF p
      , spIsDifferential = True
      , spApply          = InMemory
          { imApply     = \source -> pure (VCDIFF.applyVCDIFF p source) }
      , spUndo           = Nothing
      , spVerification   = noVerification { vWindowAdler32 = adlerChecks }
      , spVerboseLines   = numbered wins $ \w ->
          "Window " ++ show (VCDIFF.vcdTargetLen w) ++ " bytes target"
      , spWarnings       = ["empty patch (0 windows)" | null wins]
      , spRecordCount    = length wins
      , spRecordUnit     = "windows"
      , spSourceNotes    = []
      , spContents  = Nothing
      }

  Just FmtAPS -> do
    p <- APS.parseAPS bs
    let expandAPS (APS.APSN64Normal off dat)  = (off, dat)
        expandAPS (APS.APSN64RLE off val n)   = (off, BS.replicate (fromIntegral n) val)
        (cnt, contents, verif) = case p of
          APS.APSPatch (APS.APSN64 hdr recs) ->
            ( length recs
            , Just (emptyContents (map expandAPS recs))
                { pcDescription = Just (APS.n64Description hdr)
                , pcDestSize    = Just (APS.n64DestSize hdr)
                }
            , noVerification
            )
          APS.APSPatch (APS.APSGBA _ recs) ->
            ( length recs
            , Nothing
            , noVerification
                { vSourceBlocks = map (\r -> (fromIntegral (APS.gbaOffset r), APS.gbaSourceCRC r)) recs
                , vTargetBlocks = map (\r -> (fromIntegral (APS.gbaOffset r), APS.gbaTargetCRC r)) recs
                }
            )
    Right SomePatch
      { spFormat         = "APS"
      , spInfo           = APS.apsInfo p
      , spExplain        = Explain.explainAPS p
      , spIsDifferential = False
      , spApply          = InPlace $ \fp -> APS.applyAPS p fp >> pure ()
      , spUndo           = Nothing
      , spVerification   = verif
      , spVerboseLines   = []
      , spWarnings       = ["empty patch (0 records)" | cnt == 0]
      , spRecordCount    = cnt
      , spRecordUnit     = "records"
      , spSourceNotes    = []
      , spContents  = contents
      }

  Just FmtRUP -> do
    p <- RUP.parseRUP bs
    let filterZero (Just h) | BS.all (== 0) h = Nothing
        filterZero x = x
    Right SomePatch
      { spFormat         = "RUP"
      , spInfo           = RUP.rupInfo p
      , spExplain        = Explain.explainRUP p
      , spIsDifferential = False
      , spApply          = InPlace $ \fp -> RUP.applyRUP p fp >> pure ()
      , spUndo           = Nothing
      , spVerification   = noVerification
          { vSourceMD5 = filterZero (RUP.rupSourceMD5 p)
          , vTargetMD5 = filterZero (RUP.rupTargetMD5 p)
          }
      , spVerboseLines   = []
      , spWarnings       = ["empty patch (0 records)" | null (RUP.rupRecords p)]
      , spRecordCount    = length (RUP.rupRecords p)
      , spRecordUnit     = "records"
      , spSourceNotes    = []
      , spContents  = Nothing
      }

  Just FmtNINJA1 -> do
    p <- NINJA1.parseNINJA1 bs
    let recs = NINJA1.n1Records p
        warns = concat
          [ ["no EOF marker (patch may be truncated)" | not (NINJA1.n1CleanEOF p)]
          , ["empty patch (0 records)" | null recs]
          ]
    Right SomePatch
      { spFormat         = "NINJA1"
      , spInfo           = NINJA1.ninja1Info p
      , spExplain        = Explain.explainNINJA1 p
      , spIsDifferential = False
      , spApply          = InPlace $ \fp -> NINJA1.applyNINJA1 p fp >> pure ()
      , spUndo           = Nothing
      , spVerification   = noVerification
          { vSourceCRC32 = NINJA1.n1SourceCRC p
          , vSourceMD5   = NINJA1.n1SourceMD5 p
          , vSourceSHA1  = NINJA1.n1SourceSHA1 p
          }
      , spVerboseLines   = numbered recs $ \r ->
          "Write " ++ show (BS.length (NINJA1.n1RecData r)) ++ " bytes at 0x"
          ++ padHex 8 (NINJA1.n1RecOffset r)
      , spWarnings       = warns
      , spRecordCount    = length recs
      , spRecordUnit     = "records"
      , spSourceNotes    = []
      , spContents  = Just (emptyContents (map (\r -> (NINJA1.n1RecOffset r, NINJA1.n1RecData r)) recs))
          { pcSourceCRC32 = NINJA1.n1SourceCRC p
          , pcSourceMD5   = NINJA1.n1SourceMD5 p
          , pcSourceSHA1  = NINJA1.n1SourceSHA1 p
          , pcRomType     = Just (NINJA1.fromNINJA1RomType (NINJA1.n1RomType p))
          }
      }

  Just FmtBSDiff -> do
    p <- BSDiff.parseBSDiff bs
    Right SomePatch
      { spFormat         = "BSDiff"
      , spInfo           = BSDiff.bsdiffInfo p
      , spExplain        = Explain.explainBSDiff p
      , spIsDifferential = True
      , spApply          = InMemory
          { imApply     = \source -> pure (BSDiff.applyBSDiff p source) }
      , spUndo           = Nothing
      , spVerification   = noVerification
      , spVerboseLines   = []
      , spWarnings       = ["empty patch (0 control tuples)" | null (BSDiff.bsdControls p)]
      , spRecordCount    = length (BSDiff.bsdControls p)
      , spRecordUnit     = "control tuples"
      , spSourceNotes    = []
      , spContents  = Nothing
      }

  Just FmtGDIFF -> do
    p <- GDIFF.parseGDIFF bs
    Right SomePatch
      { spFormat         = "GDIFF"
      , spInfo           = GDIFF.gdiffInfo p
      , spExplain        = Explain.explainGDIFF p
      , spIsDifferential = True
      , spApply          = InMemory
          { imApply     = \source -> pure (GDIFF.applyGDIFF p source) }
      , spUndo           = Nothing
      , spVerification   = noVerification
      , spVerboseLines   = []
      , spWarnings       = ["empty patch (0 commands)" | null (GDIFF.gdiffCmds p)]
      , spRecordCount    = length (GDIFF.gdiffCmds p)
      , spRecordUnit     = "commands"
      , spSourceNotes    = []
      , spContents  = Nothing
      }

  Just FmtXDelta1 -> do
    p <- XDelta1.parseXDelta1 bs
    let fileSrc = filter (not . XDelta1.xd1SrcIsData) (XDelta1.xd1Sources p)
        xd1V = noVerification
          { vSourceMD5 = case fileSrc of
              (s:_) -> Just (XDelta1.xd1SrcMD5 s)
              []    -> Nothing
          , vTargetMD5 = Just (XDelta1.xd1ToMD5 p)
          }
    Right SomePatch
      { spFormat         = "xdelta1"
      , spInfo           = XDelta1.xdelta1Info p
      , spExplain        = Explain.explainXDelta1 p
      , spIsDifferential = True
      , spApply          = InMemory
          { imApply     = \source -> pure (XDelta1.applyXDelta1 p source) }
      , spUndo           = Nothing
      , spVerification   = xd1V
      , spVerboseLines   = []
      , spWarnings       = ["empty patch (0 instructions)" | null (XDelta1.xd1Instructions p)]
      , spRecordCount    = length (XDelta1.xd1Instructions p)
      , spRecordUnit     = "instructions"
      , spSourceNotes    = []
      , spContents  = Nothing
      }

  Just FmtPMSR -> do
    p <- PMSR.parsePMSR bs
    let recs = PMSR.pmsrRecords p
    Right SomePatch
      { spFormat         = "PMSR"
      , spInfo           = PMSR.pmsrInfo p
      , spExplain        = Explain.explainPMSR p
      , spIsDifferential = False
      , spApply          = InPlace $ \fp -> PMSR.applyPMSR p fp >> pure ()
      , spUndo           = Nothing
      , spVerification   = noVerification
      , spVerboseLines   = numbered recs $ \r ->
          "Write " ++ show (BS.length (PMSR.pmsrData r)) ++ " bytes at 0x"
          ++ padHex 8 (PMSR.pmsrOffset r)
      , spWarnings       = ["empty patch (0 records)" | null recs]
      , spRecordCount    = length recs
      , spRecordUnit     = "records"
      , spSourceNotes    = []
      , spContents  = Just (emptyContents
          (map (\r -> (PMSR.pmsrOffset r, PMSR.pmsrData r)) recs))
      }

  Just FmtPCHTXT -> do
    p <- PCHTXT.parsePCHTXT bs
    let allBlocks = PCHTXT.pchtxtBlocks p
        enabledBlocks = filter PCHTXT.pchtxtBlockEnabled allBlocks
        disabledBlocks = filter (not . PCHTXT.pchtxtBlockEnabled) allBlocks
        disabledCount = sum (map (length . PCHTXT.pchtxtBlockEntries) disabledBlocks)
        hasDescs = any (\b -> case PCHTXT.pchtxtBlockDesc b of Just _ -> True; Nothing -> False) allBlocks
        entries = concatMap PCHTXT.pchtxtBlockEntries enabledBlocks
        pcRecs = map (\e -> (PCHTXT.pchtxtOffset e, PCHTXT.pchtxtData e)) entries
        srcNotes = concat
          [ ["PCHTXT: " ++ show disabledCount ++ " disabled entries dropped" | disabledCount > 0]
          , ["PCHTXT: block descriptions dropped" | hasDescs]
          , ["PCHTXT: offset_shift applied to absolute offsets (no @flag directive in output)"
            | PCHTXT.pchtxtHasShift p]
          ]
    Right SomePatch
      { spFormat         = "PCHTXT"
      , spInfo           = PCHTXT.pchtxtInfo p
      , spExplain        = Explain.explainPCHTXT p
      , spIsDifferential = False
      , spApply          = InPlace $ \fp -> PCHTXT.applyPCHTXT p fp >> pure ()
      , spUndo           = Nothing
      , spVerification   = noVerification
      , spVerboseLines   = numbered entries $ \e ->
          "Write " ++ show (BS.length (PCHTXT.pchtxtData e)) ++ " bytes at 0x"
          ++ padHex 8 (PCHTXT.pchtxtOffset e)
      , spWarnings       = ["empty patch (0 entries)" | null entries]
      , spRecordCount    = length entries
      , spRecordUnit     = "entries"
      , spSourceNotes    = srcNotes
      , spContents  = Just (emptyContents pcRecs)
          { pcDescription = BS8.pack <$> PCHTXT.pchtxtNsobid p }
      }

----------------------------------------------------------------------------
-- Helpers
----------------------------------------------------------------------------

describeIPS :: IPS.IPSRecord -> String
describeIPS (IPS.IPSRecord off dat) =
  "Write " ++ show (BS.length dat) ++ " bytes at 0x" ++ padHex 6 off
describeIPS (IPS.IPSRecordRLE off count val) =
  "Fill " ++ show count ++ " x 0x" ++ padHex 2 (fromIntegral val) ++ " at 0x" ++ padHex 6 off

describeBPS :: BPS.BPSAction -> String
describeBPS (BPS.SourceRead len) = "SourceRead " ++ show len ++ " bytes"
describeBPS (BPS.TargetRead dat) = "TargetRead " ++ show (BS.length dat) ++ " bytes"
describeBPS (BPS.SourceCopy len _) = "SourceCopy " ++ show len ++ " bytes"
describeBPS (BPS.TargetCopy len _) = "TargetCopy " ++ show len ++ " bytes"

-- | Pre-render verbose lines with "[i/n]" prefixes.
numbered :: [a] -> (a -> String) -> [String]
numbered xs f = zipWith fmt [(1::Int)..] xs
  where
    total = length xs
    fmt i x = "[" ++ show i ++ "/" ++ show total ++ "] " ++ f x

-- | Replace the first occurrence of a substring.
replaceFirst :: String -> String -> String -> String
replaceFirst _ _ [] = []
replaceFirst needle replacement haystack@(x:xs)
  | take (length needle) haystack == needle =
      replacement ++ drop (length needle) haystack
  | otherwise = x : replaceFirst needle replacement xs
