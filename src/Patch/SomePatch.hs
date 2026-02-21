module Patch.SomePatch
  ( SomePatch(..)
  , ApplyStrategy(..)
  , UndoStrategy(..)
  , parseSome
  ) where

import Patch.Types (PatchFormat(..))
import Patch.Detect (detectFormat)
import Patch.Format (padHex)
import Patch.Overlay (OverlaySource, extractIPS, extractPPF, extractNINJA1,
                      extractPMSR, extractAPSN64)
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
import qualified Patch.DPS as DPS
import qualified Patch.NINJA1 as NINJA1
import qualified Patch.Explain as Explain
import qualified Patch.Yay0 as Yay0

import qualified Data.ByteString as BS
import Data.Word (Word32)
import System.IO (hPutStrLn, stderr)

----------------------------------------------------------------------------
-- Types
----------------------------------------------------------------------------

-- | Strategy for applying a patch to a target.
data ApplyStrategy
  = InPlace (FilePath -> IO ())
    -- ^ Seek-and-write into a mutable file.
  | InMemory
      { imApply     :: BS.ByteString -> IO (Either String BS.ByteString)
      , imSourceCRC :: Maybe Word32  -- checked before apply
      , imTargetCRC :: Maybe Word32  -- checked after apply
      }
    -- ^ Delta: takes source bytes, returns target bytes.

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
  , spExplain        :: String
  , spIsDifferential :: Bool
  , spApply          :: ApplyStrategy
  , spUndo           :: Maybe UndoStrategy
  , spVerboseLines   :: [String]
  , spWarnings       :: [String]
  , spRecordCount    :: Int
  , spRecordUnit     :: String
  , spDirectConvert  :: Maybe OverlaySource
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
            , spExplain = replaceFirst "PMSR" "PMSR/Yay0" (spExplain sp)
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
                { imApply     = \source -> pure (DPS.applyDPS p source)
                , imSourceCRC = Nothing
                , imTargetCRC = Nothing
                }
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
            , spDirectConvert  = Nothing
            }
    | otherwise -> Left "unknown patch format"

  Just FmtPPF -> case PPF.parsePatch bs of
    Left err -> Left err
    Right p  ->
      let recs = PPF.patchRecords p
      in Right SomePatch
        { spFormat         = "PPF"
        , spInfo           = PPF.showInfo p
        , spExplain        = Explain.explainPPF p
        , spIsDifferential = False
        , spApply          = InPlace $ \fp -> do
            (warnings, _) <- PPF.applyPatch p fp
            mapM_ (hPutStrLn stderr) warnings
        , spUndo           = Just (UndoInPlace $ PPF.undoPatch p)
        , spVerboseLines   = numbered recs $ \r ->
            "Write " ++ show (BS.length (PPF.recData r)) ++ " bytes at 0x"
            ++ padHex 8 (PPF.recOffset r)
        , spWarnings       = ["empty patch (0 records)" | null recs]
        , spRecordCount    = length recs
        , spRecordUnit     = "records"
        , spDirectConvert  = Just (extractPPF p)
        }

  Just FmtIPS -> do
    p <- IPS.parseIPS bs
    let recs = IPS.ipsRecords p
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
      , spVerboseLines   = numbered recs describeIPS
      , spWarnings       = warns
      , spRecordCount    = length recs
      , spRecordUnit     = "records"
      , spDirectConvert  = Just (extractIPS p)
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
          { imApply     = \source -> pure (BPS.applyBPS p source)
          , imSourceCRC = Just (BPS.bpsSourceCRC p)
          , imTargetCRC = Just (BPS.bpsTargetCRC p)
          }
      , spUndo           = Nothing
      , spVerboseLines   = numbered acts describeBPS
      , spWarnings       = ["empty patch (0 actions)" | null acts]
      , spRecordCount    = length acts
      , spRecordUnit     = "actions"
      , spDirectConvert  = Nothing
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
          { imApply     = \source -> pure (Right (UPS.applyUPS p source))
          , imSourceCRC = Just (UPS.upsSourceCRC p)
          , imTargetCRC = Just (UPS.upsTargetCRC p)
          }
      , spUndo           = Just (UndoInMemory $ UPS.applyUPS p)
      , spVerboseLines   = numbered blks $ \b ->
          "XOR " ++ show (BS.length (UPS.upsXorData b))
          ++ " bytes (skip " ++ show (UPS.upsSkip b) ++ ")"
      , spWarnings       = ["empty patch (0 blocks)" | null blks]
      , spRecordCount    = length blks
      , spRecordUnit     = "blocks"
      , spDirectConvert  = Nothing
      }

  Just FmtVCDIFF -> do
    p <- VCDIFF.parseVCDIFF bs
    let wins = VCDIFF.vcdWindows p
    Right SomePatch
      { spFormat         = "VCDIFF"
      , spInfo           = VCDIFF.vcdiffInfo p
      , spExplain        = Explain.explainVCDIFF p
      , spIsDifferential = True
      , spApply          = InMemory
          { imApply     = \source -> pure (VCDIFF.applyVCDIFF p source)
          , imSourceCRC = Nothing
          , imTargetCRC = Nothing
          }
      , spUndo           = Nothing
      , spVerboseLines   = numbered wins $ \w ->
          "Window " ++ show (VCDIFF.vcdTargetLen w) ++ " bytes target"
      , spWarnings       = ["empty patch (0 windows)" | null wins]
      , spRecordCount    = length wins
      , spRecordUnit     = "windows"
      , spDirectConvert  = Nothing
      }

  Just FmtAPS -> do
    p <- APS.parseAPS bs
    let (cnt, overlay) = case p of
          APS.APSPatch (APS.APSN64 hdr recs) ->
            (length recs, Just (extractAPSN64 hdr recs))
          APS.APSPatch (APS.APSGBA _ recs) ->
            (length recs, Nothing)
    Right SomePatch
      { spFormat         = "APS"
      , spInfo           = APS.apsInfo p
      , spExplain        = Explain.explainAPS p
      , spIsDifferential = False
      , spApply          = InPlace $ \fp -> APS.applyAPS p fp >> pure ()
      , spUndo           = Nothing
      , spVerboseLines   = []
      , spWarnings       = ["empty patch (0 records)" | cnt == 0]
      , spRecordCount    = cnt
      , spRecordUnit     = "records"
      , spDirectConvert  = overlay
      }

  Just FmtRUP -> do
    p <- RUP.parseRUP bs
    Right SomePatch
      { spFormat         = "RUP"
      , spInfo           = RUP.rupInfo p
      , spExplain        = Explain.explainRUP p
      , spIsDifferential = False
      , spApply          = InPlace $ \fp -> RUP.applyRUP p fp >> pure ()
      , spUndo           = Nothing
      , spVerboseLines   = []
      , spWarnings       = ["empty patch (0 records)" | null (RUP.rupRecords p)]
      , spRecordCount    = length (RUP.rupRecords p)
      , spRecordUnit     = "records"
      , spDirectConvert  = Nothing
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
      , spVerboseLines   = numbered recs $ \r ->
          "Write " ++ show (BS.length (NINJA1.n1RecData r)) ++ " bytes at 0x"
          ++ padHex 8 (NINJA1.n1RecOffset r)
      , spWarnings       = warns
      , spRecordCount    = length recs
      , spRecordUnit     = "records"
      , spDirectConvert  = Just (extractNINJA1 p)
      }

  Just FmtBSDiff -> do
    p <- BSDiff.parseBSDiff bs
    Right SomePatch
      { spFormat         = "BSDiff"
      , spInfo           = BSDiff.bsdiffInfo p
      , spExplain        = Explain.explainBSDiff p
      , spIsDifferential = True
      , spApply          = InMemory
          { imApply     = \source -> pure (BSDiff.applyBSDiff p source)
          , imSourceCRC = Nothing
          , imTargetCRC = Nothing
          }
      , spUndo           = Nothing
      , spVerboseLines   = []
      , spWarnings       = ["empty patch (0 control tuples)" | null (BSDiff.bsdControls p)]
      , spRecordCount    = length (BSDiff.bsdControls p)
      , spRecordUnit     = "control tuples"
      , spDirectConvert  = Nothing
      }

  Just FmtGDIFF -> do
    p <- GDIFF.parseGDIFF bs
    Right SomePatch
      { spFormat         = "GDIFF"
      , spInfo           = GDIFF.gdiffInfo p
      , spExplain        = Explain.explainGDIFF p
      , spIsDifferential = True
      , spApply          = InMemory
          { imApply     = \source -> pure (GDIFF.applyGDIFF p source)
          , imSourceCRC = Nothing
          , imTargetCRC = Nothing
          }
      , spUndo           = Nothing
      , spVerboseLines   = []
      , spWarnings       = ["empty patch (0 commands)" | null (GDIFF.gdiffCmds p)]
      , spRecordCount    = length (GDIFF.gdiffCmds p)
      , spRecordUnit     = "commands"
      , spDirectConvert  = Nothing
      }

  Just FmtXDelta1 -> do
    p <- XDelta1.parseXDelta1 bs
    Right SomePatch
      { spFormat         = "xdelta1"
      , spInfo           = XDelta1.xdelta1Info p
      , spExplain        = Explain.explainXDelta1 p
      , spIsDifferential = True
      , spApply          = InMemory
          { imApply     = \source -> pure (XDelta1.applyXDelta1 p source)
          , imSourceCRC = Nothing
          , imTargetCRC = Nothing
          }
      , spUndo           = Nothing
      , spVerboseLines   = []
      , spWarnings       = ["empty patch (0 instructions)" | null (XDelta1.xd1Instructions p)]
      , spRecordCount    = length (XDelta1.xd1Instructions p)
      , spRecordUnit     = "instructions"
      , spDirectConvert  = Nothing
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
      , spVerboseLines   = numbered recs $ \r ->
          "Write " ++ show (BS.length (PMSR.pmsrData r)) ++ " bytes at 0x"
          ++ padHex 8 (PMSR.pmsrOffset r)
      , spWarnings       = ["empty patch (0 records)" | null recs]
      , spRecordCount    = length recs
      , spRecordUnit     = "records"
      , spDirectConvert  = Just (extractPMSR p)
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
