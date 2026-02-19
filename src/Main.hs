{-# LANGUAGE OverloadedStrings #-}

module Main (main) where

import Patch.Archive (detectArchive, unwrapArchive)
import Patch.Types (PatchFormat(..))
import Patch.Detect (detectFormat)
import Patch.Binary (crc32, putWord16BE)
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
import qualified Patch.Explain as Explain

import qualified Patch.Yay0 as Yay0

import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BL
import Data.ByteString.Builder
import Data.Bits (shiftR, (.&.))
import Data.Int (Int64)
import Control.Monad (when, unless, forM_)
import Data.Char (toLower)
import Data.Maybe (fromMaybe)
import Data.Word (Word32)
import Options.Applicative
import System.Directory (copyFile, doesFileExist, removeFile)
import System.Exit (exitFailure, exitSuccess)
import System.FilePath (dropExtension, replaceExtension, takeBaseName, takeExtension)
import System.IO (hClose, hPutStrLn, openBinaryTempFile, stderr)

----------------------------------------------------------------------------
-- Types
----------------------------------------------------------------------------

data CreateFormat = CfmtBPS | CfmtIPS | CfmtIPS32 | CfmtUPS | CfmtPPF3 | CfmtPMSR
  deriving (Show, Eq)

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
  , spDirectConvert  :: CreateFormat -> Maybe (Either String BS.ByteString)
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
      { cmdConvPatch  :: FilePath
      , cmdConvTo     :: CreateFormat
      , cmdConvOutput :: Maybe FilePath
      , cmdConvWith   :: Maybe FilePath
      , cmdRaw        :: Bool
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
            <> progDesc "Apply, undo, create, convert, and inspect ROM patches (IPS, BPS, UPS, PPF, VCDIFF, APS, RUP, BSDiff/BDF, GDIFF, xdelta1, PMSR/Yay0). Unwraps ZIP/RAR/7z archives.")

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
      <> help "Output format: bps (default), ips, ips32, ups, ppf3, pmsr")
  <*> rawFlag
  <*> argument str (metavar "ORIGINAL" <> help "Original unmodified file")
  <*> argument str (metavar "MODIFIED" <> help "Modified file")
  <*> argument str (metavar "OUTPUT"   <> help "Output patch file")
  <*> option str (long "description" <> short 'd' <> metavar "TEXT" <> value "ppf patch"
      <> help "Patch description (PPF3 only, max 50 chars)")
  <*> switch (long "undo"     <> short 'u' <> help "Include undo data (PPF3 only)")
  <*> switch (long "validate" <> short 'v' <> help "Include validation block (PPF3 only)")

convertParser :: Parser Command
convertParser = CmdConvert
  <$> argument str (metavar "PATCH" <> help "Patch file to convert")
  <*> option (eitherReader parseCfmt) (long "to" <> short 't' <> metavar "FMT"
      <> help "Target format: bps, ips, ips32, ups, ppf3, pmsr")
  <*> optional (option str (long "output" <> short 'o' <> metavar "FILE"
      <> help "Output file (default: replace input extension)"))
  <*> optional (option str (long "with" <> metavar "SOURCE"
      <> help "Source ROM (required for differential formats)"))
  <*> rawFlag

parseCfmt :: String -> Either String CreateFormat
parseCfmt s = case map toLower s of
  "bps"   -> Right CfmtBPS
  "ips"   -> Right CfmtIPS
  "ips32" -> Right CfmtIPS32
  "ups"   -> Right CfmtUPS
  "ppf3"  -> Right CfmtPPF3
  "ppf"   -> Right CfmtPPF3
  "pmsr"  -> Right CfmtPMSR
  _       -> Left ("unknown format: " ++ s ++ " (expected bps, ips, ips32, ups, ppf3, pmsr)")

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
        , spDirectConvert  = const Nothing
        }

  Just FmtIPS -> do
    p <- IPS.parseIPS bs
    let recs = IPS.ipsRecords p
        (name, direct) = case (IPS.ipsVariant p, IPS.ipsEBPMeta p) of
          (IPS.StandardIPS, Nothing) -> ("IPS", \case
            CfmtIPS32 -> Just (ipsToIPS32 p)
            _         -> Nothing)
          (IPS.StandardIPS, Just _) -> ("EBP", const Nothing)
          (IPS.IPS32, _) -> ("IPS32", \case
            CfmtIPS -> Just (ips32ToIPS p)
            _       -> Nothing)
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
      , spDirectConvert  = direct
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
      , spDirectConvert  = const Nothing
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
      , spDirectConvert  = const Nothing
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
      , spDirectConvert  = const Nothing
      }

  Just FmtAPS -> do
    p <- APS.parseAPS bs
    let cnt = case p of
          APS.APSPatch (APS.APSN64 _ recs) -> length recs
          APS.APSPatch (APS.APSGBA _ recs) -> length recs
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
      , spDirectConvert  = const Nothing
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
      , spDirectConvert  = const Nothing
      }

  Just FmtBSDiff -> do
    p <- BSDiff.parseBSDiff bs
    Right SomePatch
      { spFormat         = "BSDiff"
      , spInfo           = BSDiff.bsdiffInfo p
      , spExplain        = Explain.explainBSDiff p
      , spIsDifferential = True
      , spApply          = InMemory
          (\source -> case BSDiff.applyBSDiff p source of
            Right r  -> pure (Right r)
            Left _   -> bsdiffFallback bs source)
          Nothing Nothing
      , spUndo           = Nothing
      , spVerboseLines   = []
      , spWarnings       = ["empty patch (0 control tuples)" | null (BSDiff.bsdControls p)]
      , spRecordCount    = length (BSDiff.bsdControls p)
      , spRecordUnit     = "control tuples"
      , spDirectConvert  = const Nothing
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
      , spDirectConvert  = const Nothing
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
      , spDirectConvert  = const Nothing
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
      , spDirectConvert  = const Nothing
      }

-- | External bspatch fallback: write patch+source to temp files, call bspatch.
bsdiffFallback :: BS.ByteString -> BS.ByteString -> IO (Either String BS.ByteString)
bsdiffFallback patchBs sourceBs = do
  (tmpPatch, h1) <- openBinaryTempFile "/tmp" "slap-patch.tmp"
  hClose h1
  (tmpSrc, h2) <- openBinaryTempFile "/tmp" "slap-src.tmp"
  hClose h2
  (tmpOut, h3) <- openBinaryTempFile "/tmp" "slap-out.tmp"
  hClose h3
  BS.writeFile tmpPatch patchBs
  BS.writeFile tmpSrc sourceBs
  r <- BSDiff.tryExternalBspatch tmpPatch tmpSrc tmpOut
  removeFile tmpPatch
  removeFile tmpSrc
  case r of
    Right () -> do
      result <- BS.readFile tmpOut
      removeFile tmpOut
      pure (Right result)
    Left err -> do
      removeFile tmpOut
      pure (Left err)

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
    patchBs <- PPF.createPatch (cmdOriginal cmd) (cmdModified cmd) (cmdDesc cmd) (cmdUndo cmd) (cmdValidate cmd)
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
      case spDirectConvert sp (cmdConvTo cmd) of
        Just (Right result) -> do
          BS.writeFile outFile result
          putStrLn ("converted to " ++ fmtName (cmdConvTo cmd) ++ ": " ++ outFile)
        Just (Left err) -> die err
        Nothing -> do
          sourcePath <- case cmdConvWith cmd of
            Just s  -> pure s
            Nothing -> die (needWithMsg sp)
          sourceBs <- readMaybeUnwrap (cmdRaw cmd) sourcePath
          targetBs <- applyForConvert sp sourceBs
          case createFromMemory (cmdConvTo cmd) sourceBs targetBs of
            Left err -> die err
            Right result -> do
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
createFromMemory :: CreateFormat -> BS.ByteString -> BS.ByteString -> Either String BS.ByteString
createFromMemory CfmtBPS  src tgt = Right (BPS.createBPS src tgt)
createFromMemory CfmtUPS  src tgt = Right (UPS.createUPS src tgt)
createFromMemory CfmtPMSR src tgt = Right (PMSR.createPMSR src tgt)
createFromMemory CfmtIPS  src tgt = IPS.createIPS src tgt
createFromMemory CfmtIPS32 src tgt = IPS.createIPS32 src tgt
createFromMemory CfmtPPF3 src tgt = Right (PPF.createPatchPure src tgt "converted patch" False False)

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
-- IPS conversion helpers
----------------------------------------------------------------------------

ipsToIPS32 :: IPS.IPSPatch -> Either String BS.ByteString
ipsToIPS32 patch = Right $ BL.toStrict $ toLazyByteString $
    byteString "IPS32"
    <> foldMap (encodeIPSRecordWith 4) (IPS.ipsRecords patch)
    <> byteString "EEOF"

ips32ToIPS :: IPS.IPSPatch -> Either String BS.ByteString
ips32ToIPS patch
  | any (exceedsIPS . ipsRecOff) (IPS.ipsRecords patch) =
      Left "IPS32 patch has offsets > 0xFFFFFF \8212 cannot convert to standard IPS"
  | otherwise = Right $ BL.toStrict $ toLazyByteString $
      byteString "PATCH"
      <> foldMap (encodeIPSRecordWith 3) (IPS.ipsRecords patch)
      <> byteString "EOF"
  where
    exceedsIPS off = off > 0xFFFFFF

ipsRecOff :: IPS.IPSRecord -> Int64
ipsRecOff (IPS.IPSRecord off _)      = off
ipsRecOff (IPS.IPSRecordRLE off _ _) = off

encodeIPSRecordWith :: Int -> IPS.IPSRecord -> Builder
encodeIPSRecordWith offWidth (IPS.IPSRecord off dat) =
  encodeOff offWidth off
  <> if BS.length dat >= 3 && BS.all (== BS.index dat 0) dat
     then word8 0 <> word8 0 <> putWord16BE (BS.length dat) <> word8 (BS.index dat 0)
     else putWord16BE (BS.length dat) <> byteString dat
encodeIPSRecordWith offWidth (IPS.IPSRecordRLE off count val) =
  encodeOff offWidth off
  <> word8 0 <> word8 0
  <> putWord16BE count
  <> word8 val

encodeOff :: Int -> Int64 -> Builder
encodeOff 3 off =
  word8 (fromIntegral (off `shiftR` 16))
  <> word8 (fromIntegral ((off `shiftR` 8) .&. 0xFF))
  <> word8 (fromIntegral (off .&. 0xFF))
encodeOff _ off =
  word8 (fromIntegral (off `shiftR` 24))
  <> word8 (fromIntegral ((off `shiftR` 16) .&. 0xFF))
  <> word8 (fromIntegral ((off `shiftR` 8) .&. 0xFF))
  <> word8 (fromIntegral (off .&. 0xFF))

----------------------------------------------------------------------------
-- Format metadata
----------------------------------------------------------------------------

fmtExt :: CreateFormat -> String
fmtExt CfmtBPS  = ".bps"
fmtExt CfmtIPS  = ".ips"
fmtExt CfmtIPS32 = ".ips"
fmtExt CfmtUPS  = ".ups"
fmtExt CfmtPPF3 = ".ppf"
fmtExt CfmtPMSR = ".pmsr"

fmtName :: CreateFormat -> String
fmtName CfmtBPS  = "BPS"
fmtName CfmtIPS  = "IPS"
fmtName CfmtIPS32 = "IPS32"
fmtName CfmtUPS  = "UPS"
fmtName CfmtPPF3 = "PPF3"
fmtName CfmtPMSR = "PMSR"

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

-- | Print any warnings from a parsed patch.
emitWarnings :: SomePatch -> IO ()
emitWarnings sp = forM_ (spWarnings sp) $ \w ->
  hPutStrLn stderr ("slap: warning: " ++ spFormat sp ++ ": " ++ w)

warn :: String -> IO ()
warn msg = hPutStrLn stderr ("slap: warning: " ++ msg)

die :: String -> IO a
die msg = hPutStrLn stderr ("slap: " ++ msg) >> exitFailure
