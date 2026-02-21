{-# LANGUAGE OverloadedStrings #-}

module Main (main) where

import Patch.Archive (detectArchive, unwrapArchive)
import Patch.Types (PatchFormat(..))
import Patch.Detect (detectFormat)
import Patch.Binary (crc32)
import Patch.Format (showCRC, padHex)
import qualified Patch.PPF.Types as PPF
import qualified Patch.PPF.Parse as PPF
import qualified Patch.PPF.Apply as PPF
import qualified Patch.PPF.Create as PPF
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
import qualified Data.ByteString.Char8 as BS8
import Data.Int (Int64)
import Control.Monad (when, unless, forM_)
import Data.Char (toLower)
import Data.Maybe (fromMaybe)
import Data.Word (Word32)
import Options.Applicative
import Options.Applicative.Help.Pretty (pretty, vcat)
import System.Directory (copyFile, doesFileExist, removeFile)
import System.Exit (exitFailure, exitSuccess)
import System.FilePath (dropExtension, replaceExtension, takeBaseName, takeExtension)
import System.IO (hClose, hPutStrLn, openBinaryTempFile, stderr)

----------------------------------------------------------------------------
-- Types
----------------------------------------------------------------------------

data CreateFormat
  = CfmtBPS | CfmtIPS | CfmtIPS32 | CfmtEBP | CfmtUPS | CfmtPPF3 | CfmtPMSR
  | CfmtNINJA1 | CfmtDPS | CfmtRUP | CfmtAPSN64 | CfmtAPSGBA | CfmtGDIFF
  deriving (Show, Eq)

-- | Overlay record: offset + replacement bytes.
data OverlayRecord = OverlayRecord Int64 BS.ByteString

-- | Everything an overlay source carries beyond raw records.
data OverlaySource = OverlaySource
  { osName        :: String
  , osRecords     :: [OverlayRecord]
  , osDescription :: Maybe BS.ByteString   -- 50-byte PPF/APS desc, or raw EBP JSON
  , osValidation  :: Maybe BS.ByteString   -- 1024-byte validation block (PPF2/PPF3)
  , osUndoRecs    :: Maybe [(Int64, BS.ByteString, BS.ByteString)]
      -- (off, new, old) triples — PPF3 with undo only
  , osFileSize    :: Maybe Word32          -- PPF2 patchFileSize
  , osDestSize    :: Maybe Word32          -- APS N64 dest_size
  , osSourceCRC   :: Maybe Word32          -- NINJA1 CRC32
  , osSourceMD5   :: Maybe BS.ByteString   -- NINJA1 MD5 (16 bytes)
  , osSourceSHA1  :: Maybe BS.ByteString   -- NINJA1 SHA1 (20 bytes)
  , osTruncate    :: Maybe Int64           -- IPS truncation marker
  , osEBPMeta     :: Maybe BS.ByteString   -- raw EBP JSON (for EBP→EBP)
  }

-- | Strategy for applying a patch to a target.
data ApplyStrategy
  = InPlace (FilePath -> IO ())
    -- ^ Seek-and-write into a mutable file.
  | InMemory
      (BS.ByteString -> IO (Either String BS.ByteString))
      (Maybe Word32)  -- source CRC (checked before apply)
      (Maybe Word32)  -- target CRC (checked after apply)
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

data Command
  = CmdApply
      { cmdForce   :: Bool
      , cmdVerbose :: Bool
      , cmdInPlace :: Bool
      , cmdBackup  :: Bool
      , cmdDryRun  :: Bool
      , cmdRaw     :: Bool
      , cmdPatch   :: FilePath
      , cmdSource  :: FilePath
      , cmdOutput  :: Maybe FilePath
      }
  | CmdUndo
      { cmdVerbose :: Bool
      , cmdRaw     :: Bool
      , cmdPatch   :: FilePath
      , cmdSource  :: FilePath
      , cmdOutput  :: Maybe FilePath
      }
  | CmdCreate
      { cmdCreateFmt  :: CreateFormat
      , cmdRaw        :: Bool
      , cmdOriginal   :: FilePath
      , cmdModified   :: FilePath
      , cmdCreateOut  :: FilePath
      , cmdDesc       :: String
      , cmdUndo       :: Bool
      , cmdValidate   :: Bool
      }
  | CmdConvert
      { cmdConvPatch     :: FilePath
      , cmdConvTo        :: CreateFormat
      , cmdConvOutput    :: Maybe FilePath
      , cmdConvWith      :: Maybe FilePath
      , cmdRaw           :: Bool
      , cmdConvDesc      :: String
      , cmdConvUndo      :: Bool
      , cmdConvValidate  :: Bool
      }
  | CmdInfo    { cmdPatch :: FilePath }
  | CmdExplain { cmdPatch :: FilePath }

----------------------------------------------------------------------------
-- CLI
----------------------------------------------------------------------------

main :: IO ()
main = execParser opts >>= \case
  cmd@CmdApply{}   -> doApply cmd
  cmd@CmdUndo{}    -> doUndo cmd
  cmd@CmdCreate{}  -> doCreate cmd
  cmd@CmdConvert{} -> doConvert cmd
  CmdInfo pf       -> doInfo pf
  CmdExplain pf    -> doExplain pf

opts :: ParserInfo Command
opts = info (commandParser <**> helper)
  (fullDesc <> header "slap - multi-format ROM patching tool"
            <> progDesc "Apply, undo, create, convert, and inspect ROM patches. Format is auto-detected."
            <> footerDoc (Just (vcat
                [ pretty ("Quick start:  slap apply PATCH ROM" :: String)
                , pretty ("              slap apply patch.bps game.rom -o patched.rom" :: String)
                ])))

commandParser :: Parser Command
commandParser = subparser
  ( command "apply"   (info (applyParser   <**> helper) (progDesc "Apply a patch (safe by default; use -i for in-place)"))
 <> command "undo"    (info (undoParser    <**> helper) (progDesc "Undo a patch (PPF3 undo data, or UPS self-inverse)"))
 <> command "create"  (info (createParser  <**> helper) (progDesc "Create a patch from two files"))
 <> command "convert" (info (convertParser <**> helper) (progDesc "Convert a patch to a different format"))
 <> command "info"    (info (patchInfoParser <**> helper) (progDesc "Display patch information"))
 <> command "explain" (info (explainParser <**> helper) (progDesc "Detailed record-by-record patch description"))
  )

explainParser :: Parser Command
explainParser = CmdExplain
  <$> argument str (metavar "PATCH" <> help "Patch file to explain")

applyParser :: Parser Command
applyParser = CmdApply
  <$> forceFlag
  <*> verboseFlag
  <*> inPlaceFlag
  <*> backupFlag
  <*> dryRunFlag
  <*> rawFlag
  <*> argument str (metavar "PATCH"  <> help "Patch file")
  <*> argument str (metavar "SOURCE" <> help "Source file to patch (not modified unless --in-place)")
  <*> outputOpt
  where
    outputOpt = (Just <$> option str (long "output" <> short 'o' <> metavar "FILE"
                  <> help "Write patched output to FILE"))
            <|> optional (argument str (metavar "OUTPUT"))

forceFlag :: Parser Bool
forceFlag = switch (long "force" <> short 'f' <> help "Overwrite existing output / ignore CRC mismatches")
        <|> switch (long "yolo" <> hidden)
        <|> switch (long "send-it" <> hidden)

verboseFlag :: Parser Bool
verboseFlag = switch (long "verbose" <> short 'V' <> help "Print each record as it's applied")

inPlaceFlag :: Parser Bool
inPlaceFlag = switch (long "in-place" <> short 'i'
                <> help "Modify SOURCE directly (destructive; creates .bak by default)")
          <|> switch (long "clobber" <> hidden)

backupFlag :: Parser Bool
backupFlag = flag True False (long "no-backup" <> help "Don't create .bak backup with --in-place")

dryRunFlag :: Parser Bool
dryRunFlag = switch (long "dry-run" <> help "Show what would happen without writing any files")

rawFlag :: Parser Bool
rawFlag = switch (long "raw" <> help "Treat files as raw bytes (skip archive unwrapping)")

undoParser :: Parser Command
undoParser = CmdUndo
  <$> verboseFlag
  <*> rawFlag
  <*> argument str (metavar "PATCH"  <> help "Patch file")
  <*> argument str (metavar "SOURCE" <> help "File to restore")
  <*> optional (option str (long "output" <> short 'o' <> metavar "FILE"
      <> help "Write restored output to FILE instead of modifying SOURCE in place"))

createParser :: Parser Command
createParser = CmdCreate
  <$> option (eitherReader parseCfmt) (long "format" <> metavar "FMT" <> value CfmtBPS
      <> help "Output format: bps (default), ips, ips32, ebp, ups, ppf3, pmsr, ninja1, dps, rup, aps-n64, aps-gba, gdiff")
  <*> rawFlag
  <*> argument str (metavar "ORIGINAL" <> help "Original unmodified file")
  <*> argument str (metavar "MODIFIED" <> help "Modified file")
  <*> argument str (metavar "OUTPUT"   <> help "Output patch file")
  <*> option str (long "description" <> short 'd' <> metavar "TEXT" <> value ""
      <> help "Patch description (PPF3/EBP)")
  <*> switch (long "undo"     <> short 'u' <> help "Include undo data (PPF3 only)")
  <*> switch (long "validate" <> short 'v' <> help "Include validation block (PPF3 only)")

convertParser :: Parser Command
convertParser = CmdConvert
  <$> argument str (metavar "PATCH" <> help "Patch file to convert")
  <*> option (eitherReader parseCfmt) (long "to" <> short 't' <> metavar "FMT"
      <> help "Target format: bps, ips, ips32, ebp, ups, ppf3, pmsr, ninja1, dps, rup, aps-n64, aps-gba, gdiff")
  <*> optional (option str (long "output" <> short 'o' <> metavar "FILE"
      <> help "Output file (default: replace input extension)"))
  <*> optional (option str (long "with" <> metavar "SOURCE"
      <> help "Source ROM (required for differential formats)"))
  <*> rawFlag
  <*> option str (long "description" <> short 'd' <> metavar "TEXT" <> value ""
      <> help "Patch description (PPF3/EBP)")
  <*> flag True False (long "no-undo" <> help "Omit undo data (PPF3 only; included by default)")
  <*> flag True False (long "no-validate" <> help "Omit validation block (PPF3 only; included by default)")

parseCfmt :: String -> Either String CreateFormat
parseCfmt s = case map toLower s of
  "bps"     -> Right CfmtBPS
  "ips"     -> Right CfmtIPS
  "ips32"   -> Right CfmtIPS32
  "ebp"     -> Right CfmtEBP
  "ups"     -> Right CfmtUPS
  "ppf3"    -> Right CfmtPPF3
  "ppf"     -> Right CfmtPPF3
  "pmsr"    -> Right CfmtPMSR
  "ninja1"  -> Right CfmtNINJA1
  "dps"     -> Right CfmtDPS
  "rup"     -> Right CfmtRUP
  "ninja2"  -> Right CfmtRUP
  "aps-n64" -> Right CfmtAPSN64
  "apsn64"  -> Right CfmtAPSN64
  "aps-gba" -> Right CfmtAPSGBA
  "apsgba"  -> Right CfmtAPSGBA
  "gdiff"   -> Right CfmtGDIFF
  _ -> Left ("unknown format: " ++ s ++ "\n  expected: bps, ips, ips32, ebp, ups, ppf3, pmsr, ninja1, dps, rup, aps-n64, aps-gba, gdiff")

patchInfoParser :: Parser Command
patchInfoParser = CmdInfo
  <$> argument str (metavar "PATCH" <> help "Patch file to inspect")

----------------------------------------------------------------------------
-- Archive-aware file reading
----------------------------------------------------------------------------

-- | Read a file, transparently unwrapping single-entry archives.
readUnwrap :: FilePath -> IO BS.ByteString
readUnwrap path = do
  bs <- BS.readFile path
  case detectArchive (BS.take 8 bs) of
    Nothing -> pure bs
    Just fmt -> do
      result <- unwrapArchive fmt path
      case result of
        Left err -> die err
        Right (inner, name) -> do
          hPutStrLn stderr ("slap: unwrapped " ++ path ++ " \8594 " ++ name)
          pure inner

-- | Read a file, skipping unwrap if raw=True.
readMaybeUnwrap :: Bool -> FilePath -> IO BS.ByteString
readMaybeUnwrap True  = BS.readFile
readMaybeUnwrap False = readUnwrap

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
                (\source -> pure (DPS.applyDPS p source))
                Nothing Nothing
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
    Left err -> Left (showPPFError err)
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
      , spDirectConvert  = Just (extractIPS name p)
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
          (\source -> pure (BPS.applyBPS p source))
          (Just (BPS.bpsSourceCRC p))
          (Just (BPS.bpsTargetCRC p))
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
          (\source -> pure (Right (UPS.applyUPS p source)))
          (Just (UPS.upsSourceCRC p))
          (Just (UPS.upsTargetCRC p))
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
          (\source -> pure (VCDIFF.applyVCDIFF p source))
          Nothing Nothing
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
          (\source -> pure (BSDiff.applyBSDiff p source))
          Nothing Nothing
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
          (\source -> pure (GDIFF.applyGDIFF p source))
          Nothing Nothing
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
          (\source -> pure (XDelta1.applyXDelta1 p source))
          Nothing Nothing
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
-- Info & Explain
----------------------------------------------------------------------------

doInfo :: FilePath -> IO ()
doInfo patchFile = do
  patchBs <- readUnwrap patchFile
  case parseSome patchBs of
    Left err -> die err
    Right sp -> do
      putStr (spInfo sp)
      emitWarnings sp

doExplain :: FilePath -> IO ()
doExplain patchFile = do
  patchBs <- readUnwrap patchFile
  case parseSome patchBs of
    Left err -> die err
    Right sp -> do
      putStr (spExplain sp)
      emitWarnings sp

----------------------------------------------------------------------------
-- Apply
----------------------------------------------------------------------------

doApply :: Command -> IO ()
doApply cmd = do
  patchBs <- readUnwrap (cmdPatch cmd)
  case parseSome patchBs of
    Left err -> die err
    Right sp -> do
      emitWarnings sp
      when (cmdVerbose cmd) $
        mapM_ (hPutStrLn stderr) (spVerboseLines sp)

      let outputPath
            | cmdInPlace cmd         = cmdSource cmd
            | Just o <- cmdOutput cmd = o
            | otherwise              = deriveOutput (cmdPatch cmd) (cmdSource cmd)

      -- Dry run: report and exit
      when (cmdDryRun cmd) $ do
        putStrLn $ "would apply " ++ show (spRecordCount sp) ++ " " ++ spRecordUnit sp
                ++ " \8594 " ++ outputPath
        case spApply sp of
          InMemory _ (Just expected) _ -> do
            sourceBs <- readMaybeUnwrap (cmdRaw cmd) (cmdSource cmd)
            let actual = crc32 sourceBs
            putStrLn $ "source CRC: " ++ fmtCRC actual
              ++ if actual == expected then " \10003" else " \10007 (expected " ++ fmtCRC expected ++ ")"
          _ -> pure ()
        exitSuccess

      -- Refuse to overwrite unless --force or --in-place
      unless (cmdInPlace cmd || cmdForce cmd) $ do
        exists <- doesFileExist outputPath
        when exists $
          die (outputPath ++ " already exists (use --force to overwrite)")

      -- Backup for --in-place
      when (cmdInPlace cmd && cmdBackup cmd) $ do
        let bak = cmdSource cmd ++ ".bak"
        copyFile (cmdSource cmd) bak
        hPutStrLn stderr ("slap: backup: " ++ bak)

      case spApply sp of
        InPlace f -> do
          unless (cmdInPlace cmd) $
            copyFile (cmdSource cmd) outputPath
          f (if cmdInPlace cmd then cmdSource cmd else outputPath)
          putStrLn $ "applied " ++ show (spRecordCount sp) ++ " " ++ spRecordUnit sp
                  ++ " \8594 " ++ outputPath
        InMemory apply srcCRC tgtCRC -> do
          sourceBs <- readMaybeUnwrap (cmdRaw cmd) (cmdSource cmd)
          forM_ srcCRC $ \expected ->
            checkCRC (cmdForce cmd) "source" expected (crc32 sourceBs)
          result <- apply sourceBs
          case result of
            Left err -> die err
            Right target -> do
              forM_ tgtCRC $ \expected -> do
                let actual = crc32 target
                when (actual /= expected) $
                  warn ("target CRC mismatch after apply (expected "
                        ++ fmtCRC expected ++ ", got " ++ fmtCRC actual ++ ")")
              BS.writeFile outputPath target
              putStrLn $ "applied " ++ show (spRecordCount sp) ++ " " ++ spRecordUnit sp
                      ++ " \8594 " ++ outputPath

----------------------------------------------------------------------------
-- Undo
----------------------------------------------------------------------------

doUndo :: Command -> IO ()
doUndo cmd = do
  patchBs <- readUnwrap (cmdPatch cmd)
  case parseSome patchBs of
    Left err -> die err
    Right sp -> do
      emitWarnings sp
      case spUndo sp of
        Nothing -> die "undo not supported for this format"
        Just (UndoInPlace f) -> do
          actual <- resolveOutput (cmdSource cmd) (cmdOutput cmd)
          result <- f actual
          case result of
            Left err -> die err
            Right n  -> putStrLn ("reverted " ++ show n ++ " records")
        Just (UndoInMemory f) -> do
          modified <- BS.readFile (cmdSource cmd)
          let result = f modified
          BS.writeFile (fromMaybe (cmdSource cmd) (cmdOutput cmd)) result
          putStrLn "reverted (UPS self-inverse)"

----------------------------------------------------------------------------
-- Create
----------------------------------------------------------------------------

doCreate :: Command -> IO ()
doCreate cmd = case cmdCreateFmt cmd of
  CfmtPPF3 -> do
    let desc = if null (cmdDesc cmd) then "ppf patch" else cmdDesc cmd
    patchBs <- PPF.createPatch (cmdOriginal cmd) (cmdModified cmd) desc (cmdUndo cmd) (cmdValidate cmd)
    BS.writeFile (cmdCreateOut cmd) patchBs
    case PPF.parsePatch patchBs of
      Left _      -> putStrLn ("wrote " ++ cmdCreateOut cmd)
      Right patch -> putStrLn ("wrote " ++ cmdCreateOut cmd ++ " (" ++ show (length (PPF.patchRecords patch)) ++ " records)")
  CfmtIPS -> do
    origBs <- readMaybeUnwrap (cmdRaw cmd) (cmdOriginal cmd)
    modBs  <- readMaybeUnwrap (cmdRaw cmd) (cmdModified cmd)
    case IPS.createIPS origBs modBs of
      Left err -> die err
      Right patchBs -> do
        BS.writeFile (cmdCreateOut cmd) patchBs
        putStrLn ("wrote " ++ cmdCreateOut cmd)
  CfmtEBP -> do
    origBs <- readMaybeUnwrap (cmdRaw cmd) (cmdOriginal cmd)
    modBs  <- readMaybeUnwrap (cmdRaw cmd) (cmdModified cmd)
    case IPS.createEBP origBs modBs (cmdDesc cmd) of
      Left err -> die err
      Right patchBs -> do
        BS.writeFile (cmdCreateOut cmd) patchBs
        putStrLn ("wrote " ++ cmdCreateOut cmd)
  CfmtBPS -> do
    origBs <- readMaybeUnwrap (cmdRaw cmd) (cmdOriginal cmd)
    modBs  <- readMaybeUnwrap (cmdRaw cmd) (cmdModified cmd)
    let patchBs = BPS.createBPS origBs modBs
    BS.writeFile (cmdCreateOut cmd) patchBs
    putStrLn ("wrote " ++ cmdCreateOut cmd)
  CfmtUPS -> do
    origBs <- readMaybeUnwrap (cmdRaw cmd) (cmdOriginal cmd)
    modBs  <- readMaybeUnwrap (cmdRaw cmd) (cmdModified cmd)
    let patchBs = UPS.createUPS origBs modBs
    BS.writeFile (cmdCreateOut cmd) patchBs
    putStrLn ("wrote " ++ cmdCreateOut cmd)
  CfmtIPS32 -> do
    origBs <- readMaybeUnwrap (cmdRaw cmd) (cmdOriginal cmd)
    modBs  <- readMaybeUnwrap (cmdRaw cmd) (cmdModified cmd)
    case IPS.createIPS32 origBs modBs of
      Left err -> die err
      Right patchBs -> do
        BS.writeFile (cmdCreateOut cmd) patchBs
        putStrLn ("wrote " ++ cmdCreateOut cmd)
  CfmtPMSR -> do
    origBs <- readMaybeUnwrap (cmdRaw cmd) (cmdOriginal cmd)
    modBs  <- readMaybeUnwrap (cmdRaw cmd) (cmdModified cmd)
    let patchBs = PMSR.createPMSR origBs modBs
    BS.writeFile (cmdCreateOut cmd) patchBs
    putStrLn ("wrote " ++ cmdCreateOut cmd)
  CfmtNINJA1 -> do
    origBs <- readMaybeUnwrap (cmdRaw cmd) (cmdOriginal cmd)
    modBs  <- readMaybeUnwrap (cmdRaw cmd) (cmdModified cmd)
    let patchBs = NINJA1.createNINJA1 origBs modBs
    BS.writeFile (cmdCreateOut cmd) patchBs
    putStrLn ("wrote " ++ cmdCreateOut cmd)
  CfmtDPS -> do
    origBs <- readMaybeUnwrap (cmdRaw cmd) (cmdOriginal cmd)
    modBs  <- readMaybeUnwrap (cmdRaw cmd) (cmdModified cmd)
    let patchBs = DPS.createDPS origBs modBs
    BS.writeFile (cmdCreateOut cmd) patchBs
    putStrLn ("wrote " ++ cmdCreateOut cmd)
  CfmtRUP -> do
    origBs <- readMaybeUnwrap (cmdRaw cmd) (cmdOriginal cmd)
    modBs  <- readMaybeUnwrap (cmdRaw cmd) (cmdModified cmd)
    let patchBs = RUP.createRUP origBs modBs
    BS.writeFile (cmdCreateOut cmd) patchBs
    putStrLn ("wrote " ++ cmdCreateOut cmd)
  CfmtAPSN64 -> do
    origBs <- readMaybeUnwrap (cmdRaw cmd) (cmdOriginal cmd)
    modBs  <- readMaybeUnwrap (cmdRaw cmd) (cmdModified cmd)
    let patchBs = APS.createAPSN64 origBs modBs
    BS.writeFile (cmdCreateOut cmd) patchBs
    putStrLn ("wrote " ++ cmdCreateOut cmd)
  CfmtAPSGBA -> do
    origBs <- readMaybeUnwrap (cmdRaw cmd) (cmdOriginal cmd)
    modBs  <- readMaybeUnwrap (cmdRaw cmd) (cmdModified cmd)
    let patchBs = APS.createAPSGBA origBs modBs
    BS.writeFile (cmdCreateOut cmd) patchBs
    putStrLn ("wrote " ++ cmdCreateOut cmd)
  CfmtGDIFF -> do
    origBs <- readMaybeUnwrap (cmdRaw cmd) (cmdOriginal cmd)
    modBs  <- readMaybeUnwrap (cmdRaw cmd) (cmdModified cmd)
    let patchBs = GDIFF.createGDIFF origBs modBs
    BS.writeFile (cmdCreateOut cmd) patchBs
    putStrLn ("wrote " ++ cmdCreateOut cmd)

----------------------------------------------------------------------------
-- Convert
----------------------------------------------------------------------------

doConvert :: Command -> IO ()
doConvert cmd = do
  patchBs <- readUnwrap (cmdConvPatch cmd)
  case parseSome patchBs of
    Left err -> die err
    Right sp -> do
      emitWarnings sp
      let outFile = fromMaybe (replaceExtension (cmdConvPatch cmd) (fmtExt (cmdConvTo cmd))) (cmdConvOutput cmd)
      case cmdConvWith cmd of
        Just sourcePath -> do
          -- --with provided: always use apply-and-recreate path
          sourceBs <- readMaybeUnwrap (cmdRaw cmd) sourcePath
          targetBs <- applyForConvert sp sourceBs
          case createFromMemory (cmdConvTo cmd) sourceBs targetBs (cmdConvDesc cmd) (cmdConvUndo cmd) (cmdConvValidate cmd) of
            Left err -> die err
            Right result -> do
              BS.writeFile outFile result
              putStrLn ("converted to " ++ fmtName (cmdConvTo cmd) ++ ": " ++ outFile)
        Nothing -> case spDirectConvert sp of
          Nothing -> die (needWithMsg sp)
          Just os -> case convertOverlay os (cmdConvTo cmd) (cmdConvDesc cmd) (cmdConvUndo cmd) (cmdConvValidate cmd) of
            Left err -> die err
            Right (result, notes) -> do
              forM_ notes $ \n -> hPutStrLn stderr ("slap: " ++ n)
              BS.writeFile outFile result
              putStrLn ("converted to " ++ fmtName (cmdConvTo cmd) ++ ": " ++ outFile)

-- | Apply a parsed patch to source bytes, returning target bytes (for convert).
applyForConvert :: SomePatch -> BS.ByteString -> IO BS.ByteString
applyForConvert sp sourceBs = case spApply sp of
  InMemory apply _ _ -> do
    result <- apply sourceBs
    case result of
      Left err -> die err
      Right r  -> pure r
  InPlace f -> applyViaTemp sourceBs f

-- | Apply a file-handle patch via a temp file and read back the result.
applyViaTemp :: BS.ByteString -> (FilePath -> IO ()) -> IO BS.ByteString
applyViaTemp sourceBs apply = do
  (tmp, h) <- openBinaryTempFile "/tmp" "slap.tmp"
  hClose h
  BS.writeFile tmp sourceBs
  apply tmp
  result <- BS.readFile tmp
  removeFile tmp
  pure result

-- | Create a patch from source and target bytes.
createFromMemory :: CreateFormat -> BS.ByteString -> BS.ByteString -> String -> Bool -> Bool -> Either String BS.ByteString
createFromMemory CfmtBPS  src tgt _ _ _ = Right (BPS.createBPS src tgt)
createFromMemory CfmtUPS  src tgt _ _ _ = Right (UPS.createUPS src tgt)
createFromMemory CfmtPMSR src tgt _ _ _ = Right (PMSR.createPMSR src tgt)
createFromMemory CfmtIPS  src tgt _ _ _ = IPS.createIPS src tgt
createFromMemory CfmtIPS32 src tgt _ _ _ = IPS.createIPS32 src tgt
createFromMemory CfmtEBP  src tgt desc _ _ = IPS.createEBP src tgt desc
createFromMemory CfmtPPF3 src tgt desc undo val =
  Right (PPF.createPatchPure src tgt desc' undo val)
  where desc' = if null desc then "converted patch" else desc
createFromMemory CfmtNINJA1 src tgt _ _ _ = Right (NINJA1.createNINJA1 src tgt)
createFromMemory CfmtDPS    src tgt _ _ _ = Right (DPS.createDPS src tgt)
createFromMemory CfmtRUP    src tgt _ _ _ = Right (RUP.createRUP src tgt)
createFromMemory CfmtAPSN64 src tgt _ _ _ = Right (APS.createAPSN64 src tgt)
createFromMemory CfmtAPSGBA src tgt _ _ _ = Right (APS.createAPSGBA src tgt)
createFromMemory CfmtGDIFF  src tgt _ _ _ = Right (GDIFF.createGDIFF src tgt)

-- | Error message when --with is required but not provided.
needWithMsg :: SomePatch -> String
needWithMsg sp = "converting from " ++ name ++ " requires the original ROM (--with SOURCE)\n"
  ++ name ++ " " ++ reason ++ " \8212 the original ROM is needed\nto reconstruct the target file for re-encoding."
  where
    name = spFormat sp
    reason
      | spIsDifferential sp = "stores differential data, not raw bytes"
      | otherwise           = "applies in-place to the target file"

----------------------------------------------------------------------------
-- Overlay extraction
----------------------------------------------------------------------------

extractIPS :: String -> IPS.IPSPatch -> OverlaySource
extractIPS name p = OverlaySource
  { osName        = name
  , osRecords     = map expandIPS (IPS.ipsRecords p)
  , osDescription = Nothing
  , osValidation  = Nothing
  , osUndoRecs    = Nothing
  , osFileSize    = Nothing
  , osDestSize    = Nothing
  , osSourceCRC   = Nothing
  , osSourceMD5   = Nothing
  , osSourceSHA1  = Nothing
  , osTruncate    = IPS.ipsTruncate p
  , osEBPMeta     = IPS.ipsEBPMeta p
  }
  where
    expandIPS (IPS.IPSRecord off dat)        = OverlayRecord off dat
    expandIPS (IPS.IPSRecordRLE off cnt val) = OverlayRecord off (BS.replicate cnt val)

extractPPF :: PPF.Patch -> OverlaySource
extractPPF p = OverlaySource
  { osName        = "PPF"
  , osRecords     = map (\r -> OverlayRecord (PPF.recOffset r) (PPF.recData r)) (PPF.patchRecords p)
  , osDescription = Just (PPF.patchDescription p)
  , osValidation  = fmap PPF.valBlock (PPF.patchValidation p)
  , osUndoRecs    = if PPF.patchHasUndo p
                    then Just [ (PPF.recOffset r, PPF.recData r, fromMaybe BS.empty (PPF.recUndo r))
                              | r <- PPF.patchRecords p ]
                    else Nothing
  , osFileSize    = PPF.patchFileSize p
  , osDestSize    = Nothing
  , osSourceCRC   = Nothing
  , osSourceMD5   = Nothing
  , osSourceSHA1  = Nothing
  , osTruncate    = Nothing
  , osEBPMeta     = Nothing
  }

extractNINJA1 :: NINJA1.NINJA1Patch -> OverlaySource
extractNINJA1 p = OverlaySource
  { osName        = "NINJA1"
  , osRecords     = map (\r -> OverlayRecord (NINJA1.n1RecOffset r) (NINJA1.n1RecData r)) (NINJA1.n1Records p)
  , osDescription = Nothing
  , osValidation  = Nothing
  , osUndoRecs    = Nothing
  , osFileSize    = Nothing
  , osDestSize    = Nothing
  , osSourceCRC   = NINJA1.n1SourceCRC p
  , osSourceMD5   = NINJA1.n1SourceMD5 p
  , osSourceSHA1  = NINJA1.n1SourceSHA1 p
  , osTruncate    = Nothing
  , osEBPMeta     = Nothing
  }

extractPMSR :: PMSR.PMSRPatch -> OverlaySource
extractPMSR p = OverlaySource
  { osName        = "PMSR"
  , osRecords     = map (\r -> OverlayRecord (PMSR.pmsrOffset r) (PMSR.pmsrData r)) (PMSR.pmsrRecords p)
  , osDescription = Nothing
  , osValidation  = Nothing
  , osUndoRecs    = Nothing
  , osFileSize    = Nothing
  , osDestSize    = Nothing
  , osSourceCRC   = Nothing
  , osSourceMD5   = Nothing
  , osSourceSHA1  = Nothing
  , osTruncate    = Nothing
  , osEBPMeta     = Nothing
  }

extractAPSN64 :: APS.APSN64Header -> [APS.APSN64Record] -> OverlaySource
extractAPSN64 hdr recs = OverlaySource
  { osName        = "APS (N64)"
  , osRecords     = map expandAPS recs
  , osDescription = Just (APS.n64Description hdr)
  , osValidation  = Nothing
  , osUndoRecs    = Nothing
  , osFileSize    = Nothing
  , osDestSize    = Just (APS.n64DestSize hdr)
  , osSourceCRC   = Nothing
  , osSourceMD5   = Nothing
  , osSourceSHA1  = Nothing
  , osTruncate    = Nothing
  , osEBPMeta     = Nothing
  }
  where
    expandAPS (APS.APSN64Normal off dat)  = OverlayRecord off dat
    expandAPS (APS.APSN64RLE off val cnt) = OverlayRecord off (BS.replicate (fromIntegral cnt) val)

----------------------------------------------------------------------------
-- Overlay conversion
----------------------------------------------------------------------------

-- | Convert overlay records to a target format without needing the source ROM.
convertOverlay :: OverlaySource -> CreateFormat -> String -> Bool -> Bool
               -> Either String (BS.ByteString, [String])
convertOverlay os target desc includeUndo includeValidation =
  let notes = overlayWarnings os target
      intRecs = overlayToIntPairs (osRecords os)
  in case target of
    CfmtIPS     -> checkIPSOffsets os >>= \rs -> Right (IPS.encodeIPS (overlayToIntPairs rs) (osTruncate os), notes)
    CfmtIPS32   -> Right (IPS.encodeIPS32 (splitOverlay 0xFFFF intRecs) (osTruncate os), notes)
    CfmtEBP     -> checkIPSOffsets os >>= \rs ->
      let pairs = overlayToIntPairs rs
      in case if null desc then osEBPMeta os else Nothing of
           Just raw -> Right (IPS.encodeEBPRaw pairs raw, notes)
           Nothing  -> Right (IPS.encodeEBP pairs (resolveDesc desc (osEBPMeta os) (osDescription os) ""), notes)
    CfmtPPF3    -> convertToPPF3 os desc includeUndo includeValidation notes
    CfmtNINJA1  -> Right (NINJA1.encodeNINJA1 intRecs (osSourceCRC os) (osSourceMD5 os) (osSourceSHA1 os), notes)
    CfmtPMSR    -> Right (PMSR.encodePMSR intRecs, notes)
    CfmtAPSN64  -> case osDestSize os <|> osFileSize os of
                     Just sz -> Right (APS.encodeAPSN64 intRecs sz (resolveDesc desc Nothing (osDescription os) (replicate 50 ' ')), notes)
                     Nothing -> Left "converting to APS (N64) requires target file size\nuse --with SOURCE to compute it"
    CfmtBPS     -> Left (fmtName CfmtBPS ++ " requires source+target diff data\nuse --with SOURCE")
    CfmtUPS     -> Left (fmtName CfmtUPS ++ " requires source+target diff data\nuse --with SOURCE")
    CfmtDPS     -> Left (fmtName CfmtDPS ++ " requires source+target diff data\nuse --with SOURCE")
    CfmtRUP     -> Left (fmtName CfmtRUP ++ " requires source+target diff data\nuse --with SOURCE")
    CfmtAPSGBA  -> Left (fmtName CfmtAPSGBA ++ " requires source+target diff data\nuse --with SOURCE")
    CfmtGDIFF   -> Left (fmtName CfmtGDIFF ++ " requires source+target diff data\nuse --with SOURCE")

-- | Convert overlay records to (Int, ByteString) pairs for module encoders.
overlayToIntPairs :: [OverlayRecord] -> [(Int, BS.ByteString)]
overlayToIntPairs = map (\(OverlayRecord off dat) -> (fromIntegral off, dat))

-- | Check that all overlay offsets fit in 3-byte IPS range.
checkIPSOffsets :: OverlaySource -> Either String [OverlayRecord]
checkIPSOffsets os
  | any (\(OverlayRecord off _) -> off > 0xFFFFFF) (osRecords os) =
      Left "patch has offsets > 16 MB \8212 cannot convert to IPS\nuse --to ips32, or --with SOURCE to re-diff"
  | otherwise = Right (osRecords os)

-- | PPF3 conversion with undo/validate gating.
convertToPPF3 :: OverlaySource -> String -> Bool -> Bool -> [String]
              -> Either String (BS.ByteString, [String])
convertToPPF3 os desc includeUndo includeValidation notes = do
  undoTriples <- if includeUndo
    then case osUndoRecs os of
      Just u  -> Right (Just u)
      Nothing -> Left "source has no undo data\nuse --no-undo, or --with SOURCE to generate it"
    else Right Nothing
  valBlock <- if includeValidation
    then case osValidation os of
      Just v  -> Right (Just v)
      Nothing -> Left "source has no validation block\nuse --no-validate, or --with SOURCE to generate it"
    else Right Nothing
  let descStr = resolveDesc desc Nothing (osDescription os) "converted patch"
      ppfRecs = splitOverlayI64 255 (map (\(OverlayRecord off dat) -> (off, dat)) (osRecords os))
  Right (PPF.encodePPF3 ppfRecs descStr undoTriples valBlock, notes)

-- | Split (Int64, ByteString) pairs so each data chunk is ≤ maxSize bytes.
splitOverlayI64 :: Int -> [(Int64, BS.ByteString)] -> [(Int64, BS.ByteString)]
splitOverlayI64 maxSize = concatMap split1
  where
    split1 (off, dat)
      | BS.length dat <= maxSize = [(off, dat)]
      | otherwise =
          let (h, t) = BS.splitAt maxSize dat
          in (off, h) : split1 (off + fromIntegral maxSize, t)

-- | Split (Int, ByteString) pairs so each data chunk is ≤ maxSize bytes.
splitOverlay :: Int -> [(Int, BS.ByteString)] -> [(Int, BS.ByteString)]
splitOverlay maxSize = concatMap split1
  where
    split1 (off, dat)
      | BS.length dat <= maxSize = [(off, dat)]
      | otherwise =
          let (h, t) = BS.splitAt maxSize dat
          in (off, h) : split1 (off + maxSize, t)

----------------------------------------------------------------------------
-- Overlay helpers
----------------------------------------------------------------------------

-- | Resolve a description string from CLI flag, source metadata, or default.
resolveDesc :: String -> Maybe BS.ByteString -> Maybe BS.ByteString -> String -> String
resolveDesc cliDesc ebpMeta rawDesc def
  | not (null cliDesc) = cliDesc
  | Just meta <- ebpMeta = extractEBPDesc meta
  | Just d <- rawDesc    = trimNulSpace (BS8.unpack d)
  | otherwise            = def
  where
    -- Extract description from EBP JSON: {"title":"...","author":"...","description":"..."}
    extractEBPDesc bs = case BS8.unpack bs of
      s -> case dropWhile (/= ':') (snd (breakOn "description" s)) of
              (':':'"':rest) -> takeWhile (/= '"') rest
              _              -> def
    breakOn _ [] = ("", "")
    breakOn needle ss@(x:xs)
      | take (length needle) ss == needle = ("", ss)
      | otherwise = let (a, b) = breakOn needle xs in (x:a, b)

-- | Emit info-loss notes for metadata the target format cannot carry.
overlayWarnings :: OverlaySource -> CreateFormat -> [String]
overlayWarnings os target = concat
  [ warnCRC, warnMD5, warnSHA1, warnDesc, warnVal, warnUndo
  , warnFileSize, warnTrunc, warnEBP
  ]
  where
    warnCRC = case osSourceCRC os of
      Just crc | target /= CfmtNINJA1, crc /= 0 ->
        ["note: dropping source CRC32: 0x" ++ showCRC crc]
      _ -> []
    warnMD5 = case osSourceMD5 os of
      Just md5 | target /= CfmtNINJA1, not (BS.all (== 0) md5) ->
        ["note: dropping source MD5: " ++ hexBS md5]
      _ -> []
    warnSHA1 = case osSourceSHA1 os of
      Just sha1 | target /= CfmtNINJA1, not (BS.all (== 0) sha1) ->
        ["note: dropping source SHA1: " ++ hexBS sha1]
      _ -> []
    warnDesc = case osDescription os of
      Just d | target `notElem` [CfmtPPF3, CfmtAPSN64, CfmtEBP]
             , not (BS.all (\b -> b == 0x20 || b == 0) d) ->
        ["note: dropping description: \"" ++ trimNulSpace (BS8.unpack d) ++ "\""]
      _ -> []
    warnVal = case osValidation os of
      Just _ | target /= CfmtPPF3 ->
        ["note: dropping 1024-byte validation block"]
      _ -> []
    warnUndo = case osUndoRecs os of
      Just u | target /= CfmtPPF3 ->
        ["note: dropping undo data (" ++ show (length u) ++ " records)"]
      _ -> []
    warnFileSize = case osFileSize os of
      Just sz | target `notElem` [CfmtPPF3, CfmtAPSN64] ->
        ["note: dropping file size: " ++ show sz ++ " bytes"]
      _ -> []
    warnTrunc = case osTruncate os of
      Just _ | target `notElem` [CfmtIPS, CfmtIPS32] ->
        ["note: dropping truncation marker"]
      _ -> []
    warnEBP = case osEBPMeta os of
      Just _ | target /= CfmtEBP ->
        ["note: dropping EBP metadata"]
      _ -> []

hexBS :: BS.ByteString -> String
hexBS = concatMap (\b -> padHex 2 (fromIntegral b)) . BS.unpack

----------------------------------------------------------------------------
-- Format metadata
----------------------------------------------------------------------------

fmtExt :: CreateFormat -> String
fmtExt CfmtBPS    = ".bps"
fmtExt CfmtIPS    = ".ips"
fmtExt CfmtIPS32  = ".ips"
fmtExt CfmtEBP    = ".ebp"
fmtExt CfmtUPS    = ".ups"
fmtExt CfmtPPF3   = ".ppf"
fmtExt CfmtPMSR   = ".pmsr"
fmtExt CfmtNINJA1 = ".rup"
fmtExt CfmtDPS    = ".dps"
fmtExt CfmtRUP    = ".rup"
fmtExt CfmtAPSN64 = ".aps"
fmtExt CfmtAPSGBA = ".aps"
fmtExt CfmtGDIFF  = ".gdiff"

fmtName :: CreateFormat -> String
fmtName CfmtBPS    = "BPS"
fmtName CfmtIPS    = "IPS"
fmtName CfmtIPS32  = "IPS32"
fmtName CfmtEBP    = "EBP"
fmtName CfmtUPS    = "UPS"
fmtName CfmtPPF3   = "PPF3"
fmtName CfmtPMSR   = "PMSR"
fmtName CfmtNINJA1 = "NINJA1"
fmtName CfmtDPS    = "DPS"
fmtName CfmtRUP    = "RUP"
fmtName CfmtAPSN64 = "APS (N64)"
fmtName CfmtAPSGBA = "APS (GBA)"
fmtName CfmtGDIFF  = "GDIFF"

----------------------------------------------------------------------------
-- Helpers
----------------------------------------------------------------------------

-- | Derive output path from patch and source names.
-- "game.gbc" + "translation.ips" → "game [translation].gbc"
deriveOutput :: FilePath -> FilePath -> FilePath
deriveOutput patchPath sourcePath =
  dropExtension sourcePath ++ " [" ++ takeBaseName patchPath ++ "]" ++ takeExtension sourcePath

resolveOutput :: FilePath -> Maybe FilePath -> IO FilePath
resolveOutput source Nothing    = pure source
resolveOutput source (Just out) = do
  exists <- doesFileExist source
  if exists
    then copyFile source out >> pure out
    else die ("source file not found: " ++ source)

checkCRC :: Bool -> String -> Word32 -> Word32 -> IO ()
checkCRC force label expected actual
  | expected == actual = pure ()
  | force = warn (label ++ " CRC mismatch (expected "
                  ++ fmtCRC expected ++ ", got " ++ fmtCRC actual ++ ")")
  | otherwise = die (label ++ " CRC mismatch (expected "
                     ++ fmtCRC expected ++ ", got " ++ fmtCRC actual
                     ++ ")\n  use --force to apply anyway")

fmtCRC :: Word32 -> String
fmtCRC w = "0x" ++ showCRC w

showPPFError :: PPF.ParseError -> String
showPPFError (PPF.BadMagic bs')       = "not a PPF file (bad magic: " ++ show bs' ++ ")"
showPPFError (PPF.UnknownVersion v)   = "unknown PPF version byte: " ++ show v
showPPFError (PPF.TruncatedFile msg)  = "truncated file: " ++ msg
showPPFError (PPF.UnknownImageType v) = "unknown image type: " ++ show v

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

emitWarnings :: SomePatch -> IO ()
emitWarnings sp = forM_ (spWarnings sp) $ \w ->
  hPutStrLn stderr ("slap: warning: " ++ spFormat sp ++ ": " ++ w)

trimNulSpace :: String -> String
trimNulSpace = reverse . dropWhile (\c -> c == ' ' || c == '\0') . reverse

warn :: String -> IO ()
warn msg = hPutStrLn stderr ("slap: warning: " ++ msg)

die :: String -> IO a
die msg = hPutStrLn stderr ("slap: " ++ msg) >> exitFailure
