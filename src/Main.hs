module Main (main) where

import Patch.Types
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
import qualified Patch.Explain as Explain

import qualified Data.ByteString as BS
import Control.Monad (when)
import Data.Char (toLower)
import Data.Maybe (fromMaybe)
import Data.Word (Word32)
import Options.Applicative
import System.Directory (copyFile, doesFileExist, renameFile)
import System.Exit (exitFailure)
import System.IO (hPutStrLn, stderr)

data CreateFormat = CfmtBPS | CfmtIPS | CfmtUPS | CfmtPPF3
  deriving (Show, Eq)

data Command
  = CmdApply
      { cmdForce   :: Bool
      , cmdVerbose :: Bool
      , cmdPatch   :: FilePath
      , cmdTarget  :: FilePath
      , cmdOutput  :: Maybe FilePath
      }
  | CmdUndo
      { cmdVerbose :: Bool
      , cmdPatch   :: FilePath
      , cmdTarget  :: FilePath
      , cmdOutput  :: Maybe FilePath
      }
  | CmdCreate
      { cmdCreateFmt  :: CreateFormat
      , cmdOriginal   :: FilePath
      , cmdModified   :: FilePath
      , cmdCreateOut  :: FilePath
      , cmdDesc       :: String
      , cmdUndo       :: Bool
      , cmdValidate   :: Bool
      }
  | CmdInfo    { cmdPatch :: FilePath }
  | CmdExplain { cmdPatch :: FilePath }

main :: IO ()
main = execParser opts >>= \case
  cmd@CmdApply{}   -> doApply cmd
  cmd@CmdUndo{}    -> doUndo cmd
  cmd@CmdCreate{}  -> doCreate cmd
  CmdInfo pf       -> doInfo pf
  CmdExplain pf    -> doExplain pf

opts :: ParserInfo Command
opts = info (commandParser <**> helper)
  (fullDesc <> header "slap - multi-format ROM patching tool"
            <> progDesc "Apply, undo, create, and inspect ROM patches (IPS, BPS, UPS, PPF, VCDIFF, APS, RUP, BSDiff, GDIFF, xdelta1)")

commandParser :: Parser Command
commandParser = subparser
  ( command "apply"  (info (applyParser  <**> helper) (progDesc "Apply a patch to a target file"))
 <> command "undo"   (info (undoParser   <**> helper) (progDesc "Undo a patch (PPF3 undo data, or UPS self-inverse)"))
 <> command "create" (info (createParser <**> helper) (progDesc "Create a patch from two files"))
 <> command "info"   (info (patchInfoParser <**> helper) (progDesc "Display patch information"))
 <> command "explain" (info (explainParser <**> helper) (progDesc "Detailed record-by-record patch description"))
  )

explainParser :: Parser Command
explainParser = CmdExplain
  <$> argument str (metavar "PATCH" <> help "Patch file to explain")

applyParser :: Parser Command
applyParser = CmdApply
  <$> forceFlag
  <*> verboseFlag
  <*> argument str (metavar "PATCH"  <> help "Patch file")
  <*> argument str (metavar "TARGET" <> help "File to patch")
  <*> optional (option str (long "output" <> short 'o' <> metavar "FILE"
      <> help "Write patched output to FILE instead of modifying TARGET in place"))

forceFlag :: Parser Bool
forceFlag = switch (long "force" <> short 'f' <> help "Apply despite checksum mismatches")
        <|> switch (long "yolo" <> help "Alias for --force")

verboseFlag :: Parser Bool
verboseFlag = switch (long "verbose" <> short 'V' <> help "Print each record as it's applied")

undoParser :: Parser Command
undoParser = CmdUndo
  <$> verboseFlag
  <*> argument str (metavar "PATCH"  <> help "Patch file")
  <*> argument str (metavar "TARGET" <> help "File to restore")
  <*> optional (option str (long "output" <> short 'o' <> metavar "FILE"
      <> help "Write restored output to FILE instead of modifying TARGET in place"))

createParser :: Parser Command
createParser = CmdCreate
  <$> option (eitherReader parseCfmt) (long "format" <> metavar "FMT" <> value CfmtBPS
      <> help "Output format: bps (default), ips, ups, ppf3")
  <*> argument str (metavar "ORIGINAL" <> help "Original unmodified file")
  <*> argument str (metavar "MODIFIED" <> help "Modified file")
  <*> argument str (metavar "OUTPUT"   <> help "Output patch file")
  <*> option str (long "description" <> short 'd' <> metavar "TEXT" <> value "ppf patch"
      <> help "Patch description (PPF3 only, max 50 chars)")
  <*> switch (long "undo"     <> short 'u' <> help "Include undo data (PPF3 only)")
  <*> switch (long "validate" <> short 'v' <> help "Include validation block (PPF3 only)")

parseCfmt :: String -> Either String CreateFormat
parseCfmt s = case map toLower s of
  "bps"  -> Right CfmtBPS
  "ips"  -> Right CfmtIPS
  "ups"  -> Right CfmtUPS
  "ppf3" -> Right CfmtPPF3
  "ppf"  -> Right CfmtPPF3
  _      -> Left ("unknown format: " ++ s ++ " (expected bps, ips, ups, ppf3)")

patchInfoParser :: Parser Command
patchInfoParser = CmdInfo
  <$> argument str (metavar "PATCH" <> help "Patch file to inspect")

----------------------------------------------------------------------------
-- Unified parse/info/explain dispatch
----------------------------------------------------------------------------

-- | Parse any supported patch format into SomePatch.
parseSome :: BS.ByteString -> Either String SomePatch
parseSome bs = case detectFormat bs of
  Nothing     -> Left "unknown patch format"
  Just FmtPPF -> case PPF.parsePatch bs of
    Left err -> Left (showPPFError err)
    Right p  -> Right (SomePPF p)
  Just FmtIPS     -> SomeIPS     <$> IPS.parseIPS bs
  Just FmtBPS     -> SomeBPS     <$> BPS.parseBPS bs
  Just FmtUPS     -> SomeUPS     <$> UPS.parseUPS bs
  Just FmtVCDIFF  -> SomeVCDIFF  <$> VCDIFF.parseVCDIFF bs
  Just FmtAPS     -> SomeAPS     <$> APS.parseAPS bs
  Just FmtRUP     -> SomeRUP     <$> RUP.parseRUP bs
  Just FmtBSDiff  -> SomeBSDiff  <$> BSDiff.parseBSDiff bs
  Just FmtGDIFF   -> SomeGDIFF   <$> GDIFF.parseGDIFF bs
  Just FmtXDelta1 -> SomeXDelta1 <$> XDelta1.parseXDelta1 bs

-- | Human-readable summary of any parsed patch.
someInfo :: SomePatch -> String
someInfo (SomePPF p)     = PPF.showInfo p
someInfo (SomeIPS p)     = IPS.ipsInfo p
someInfo (SomeBPS p)     = BPS.bpsInfo p
someInfo (SomeUPS p)     = UPS.upsInfo p
someInfo (SomeVCDIFF p)  = VCDIFF.vcdiffInfo p
someInfo (SomeAPS p)     = APS.apsInfo p
someInfo (SomeRUP p)     = RUP.rupInfo p
someInfo (SomeBSDiff p)  = BSDiff.bsdiffInfo p
someInfo (SomeGDIFF p)   = GDIFF.gdiffInfo p
someInfo (SomeXDelta1 p) = XDelta1.xdelta1Info p

-- | Record-by-record explanation of any parsed patch.
someExplain :: SomePatch -> String
someExplain (SomePPF p)     = Explain.explainPPF p
someExplain (SomeIPS p)     = Explain.explainIPS p
someExplain (SomeBPS p)     = Explain.explainBPS p
someExplain (SomeUPS p)     = Explain.explainUPS p
someExplain (SomeVCDIFF p)  = Explain.explainVCDIFF p
someExplain (SomeAPS p)     = Explain.explainAPS p
someExplain (SomeRUP p)     = Explain.explainRUP p
someExplain (SomeBSDiff p)  = Explain.explainBSDiff p
someExplain (SomeGDIFF p)   = Explain.explainGDIFF p
someExplain (SomeXDelta1 p) = Explain.explainXDelta1 p

----------------------------------------------------------------------------
-- Info & Explain
----------------------------------------------------------------------------

doInfo :: FilePath -> IO ()
doInfo patchFile = do
  patchBs <- BS.readFile patchFile
  case parseSome patchBs of
    Left err -> die err
    Right p  -> putStr (someInfo p)

doExplain :: FilePath -> IO ()
doExplain patchFile = do
  patchBs <- BS.readFile patchFile
  case parseSome patchBs of
    Left err -> die err
    Right p  -> putStr (someExplain p)

----------------------------------------------------------------------------
-- Apply
----------------------------------------------------------------------------

doApply :: Command -> IO ()
doApply cmd = do
  patchBs <- BS.readFile (cmdPatch cmd)
  case parseSome patchBs of
    Left err -> die err
    Right p  -> someApply cmd patchBs p

someApply :: Command -> BS.ByteString -> SomePatch -> IO ()

someApply cmd _patchBs (SomePPF patch) = do
  actual <- resolveOutput (cmdTarget cmd) (cmdOutput cmd)
  let recs = PPF.patchRecords patch
      total = length recs
  when (cmdVerbose cmd) $ mapM_ (\(i, r) ->
    hPutStrLn stderr ("[" ++ show i ++ "/" ++ show total ++ "] Write "
      ++ show (BS.length (PPF.recData r)) ++ " bytes at 0x"
      ++ padHex 8 (PPF.recOffset r)))
    (zip [(1::Int)..] recs)
  (warnings, n) <- PPF.applyPatch patch actual
  mapM_ (hPutStrLn stderr) warnings
  putStrLn ("applied " ++ show n ++ " records")

someApply cmd _patchBs (SomeIPS patch) = do
  actual <- resolveOutput (cmdTarget cmd) (cmdOutput cmd)
  let recs = IPS.ipsRecords patch
      total = length recs
  when (cmdVerbose cmd) $ mapM_ (\(i, r) ->
    hPutStrLn stderr ("[" ++ show i ++ "/" ++ show total ++ "] " ++ describeIPS r))
    (zip [(1::Int)..] recs)
  n <- IPS.applyIPS patch actual
  putStrLn ("applied " ++ show n ++ " records")

someApply cmd _patchBs (SomeBPS patch) = do
  source <- BS.readFile (cmdTarget cmd)
  let srcCRC = crc32 source
  checkCRC (cmdForce cmd) "source" (BPS.bpsSourceCRC patch) srcCRC
  let acts = BPS.bpsActions patch
      total = length acts
  when (cmdVerbose cmd) $ mapM_ (\(i, a) ->
    hPutStrLn stderr ("[" ++ show i ++ "/" ++ show total ++ "] " ++ describeBPS a))
    (zip [(1::Int)..] acts)
  case BPS.applyBPS patch source of
    Left err -> die err
    Right result -> do
      let tgtCRC = crc32 result
      when (tgtCRC /= BPS.bpsTargetCRC patch) $
        warn ("target CRC mismatch after apply (expected "
              ++ fmtCRC (BPS.bpsTargetCRC patch) ++ ", got " ++ fmtCRC tgtCRC ++ ")")
      BS.writeFile (fromMaybe (cmdTarget cmd) (cmdOutput cmd)) result
      putStrLn ("applied " ++ show total ++ " actions")

someApply cmd _patchBs (SomeUPS patch) = do
  source <- BS.readFile (cmdTarget cmd)
  let srcCRC = crc32 source
  checkCRC (cmdForce cmd) "source" (UPS.upsSourceCRC patch) srcCRC
  let blks = UPS.upsBlocks patch
      total = length blks
  when (cmdVerbose cmd) $ mapM_ (\(i, b) ->
    hPutStrLn stderr ("[" ++ show i ++ "/" ++ show total ++ "] XOR "
      ++ show (BS.length (UPS.upsXorData b)) ++ " bytes (skip " ++ show (UPS.upsSkip b) ++ ")"))
    (zip [(1::Int)..] blks)
  let result = UPS.applyUPS patch source
      tgtCRC = crc32 result
  when (tgtCRC /= UPS.upsTargetCRC patch) $
    warn ("target CRC mismatch after apply (expected "
          ++ fmtCRC (UPS.upsTargetCRC patch) ++ ", got " ++ fmtCRC tgtCRC ++ ")")
  BS.writeFile (fromMaybe (cmdTarget cmd) (cmdOutput cmd)) result
  putStrLn ("applied " ++ show total ++ " blocks")

someApply cmd _patchBs (SomeVCDIFF patch) = do
  source <- BS.readFile (cmdTarget cmd)
  let wins = VCDIFF.vcdWindows patch
      total = length wins
  when (cmdVerbose cmd) $ mapM_ (\(i, w) ->
    hPutStrLn stderr ("[" ++ show i ++ "/" ++ show total ++ "] Window "
      ++ show (VCDIFF.vcdTargetLen w) ++ " bytes target"))
    (zip [(1::Int)..] wins)
  case VCDIFF.applyVCDIFF patch source of
    Left err -> die err
    Right result -> do
      BS.writeFile (fromMaybe (cmdTarget cmd) (cmdOutput cmd)) result
      putStrLn ("applied " ++ show total ++ " windows")

someApply cmd _patchBs (SomeAPS patch) = do
  actual <- resolveOutput (cmdTarget cmd) (cmdOutput cmd)
  n <- APS.applyAPS patch actual
  putStrLn ("applied " ++ show n ++ " records")

someApply cmd _patchBs (SomeRUP patch) = do
  actual <- resolveOutput (cmdTarget cmd) (cmdOutput cmd)
  n <- RUP.applyRUP patch actual
  putStrLn ("applied " ++ show n ++ " records")

someApply cmd _patchBs (SomeBSDiff patch) = do
  source <- BS.readFile (cmdTarget cmd)
  case BSDiff.applyBSDiff patch source of
    Right result -> do
      BS.writeFile (fromMaybe (cmdTarget cmd) (cmdOutput cmd)) result
      putStrLn ("applied " ++ show (length (BSDiff.bsdControls patch)) ++ " control tuples")
    Left _ -> do
      let target = cmdTarget cmd
          outFile = fromMaybe target (cmdOutput cmd)
      if outFile == target
        then do
          let tmpFile = target ++ ".slap.tmp"
          r <- BSDiff.tryExternalBspatch (cmdPatch cmd) target tmpFile
          case r of
            Right () -> do
              renameFile tmpFile target
              putStrLn "applied bsdiff (external bspatch)"
            Left err -> die err
        else do
          r <- BSDiff.tryExternalBspatch (cmdPatch cmd) target outFile
          case r of
            Right () -> putStrLn "applied bsdiff (external bspatch)"
            Left err -> die err

someApply cmd _patchBs (SomeGDIFF patch) = do
  source <- BS.readFile (cmdTarget cmd)
  case GDIFF.applyGDIFF patch source of
    Left err -> die err
    Right result -> do
      BS.writeFile (fromMaybe (cmdTarget cmd) (cmdOutput cmd)) result
      putStrLn ("applied " ++ show (length (GDIFF.gdiffCmds patch)) ++ " commands")

someApply cmd _patchBs (SomeXDelta1 patch) = do
  source <- BS.readFile (cmdTarget cmd)
  case XDelta1.applyXDelta1 patch source of
    Left err -> die err
    Right result -> do
      BS.writeFile (fromMaybe (cmdTarget cmd) (cmdOutput cmd)) result
      putStrLn ("applied " ++ show (length (XDelta1.xd1Instructions patch)) ++ " instructions")

----------------------------------------------------------------------------
-- Undo
----------------------------------------------------------------------------

doUndo :: Command -> IO ()
doUndo cmd = do
  patchBs <- BS.readFile (cmdPatch cmd)
  case parseSome patchBs of
    Left err -> die err
    Right (SomePPF patch) -> do
      actual <- resolveOutput (cmdTarget cmd) (cmdOutput cmd)
      result <- PPF.undoPatch patch actual
      case result of
        Left err -> die err
        Right n  -> putStrLn ("reverted " ++ show n ++ " records")
    Right (SomeUPS patch) -> do
      modified <- BS.readFile (cmdTarget cmd)
      let result = UPS.applyUPS patch modified
      BS.writeFile (fromMaybe (cmdTarget cmd) (cmdOutput cmd)) result
      putStrLn "reverted (UPS self-inverse)"
    Right _ -> die "undo not supported for this format"

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
    origBs <- BS.readFile (cmdOriginal cmd)
    modBs  <- BS.readFile (cmdModified cmd)
    case IPS.createIPS origBs modBs of
      Left err -> die err
      Right patchBs -> do
        BS.writeFile (cmdCreateOut cmd) patchBs
        putStrLn ("wrote " ++ cmdCreateOut cmd)
  CfmtBPS -> do
    origBs <- BS.readFile (cmdOriginal cmd)
    modBs  <- BS.readFile (cmdModified cmd)
    let patchBs = BPS.createBPS origBs modBs
    BS.writeFile (cmdCreateOut cmd) patchBs
    putStrLn ("wrote " ++ cmdCreateOut cmd)
  CfmtUPS -> do
    origBs <- BS.readFile (cmdOriginal cmd)
    modBs  <- BS.readFile (cmdModified cmd)
    let patchBs = UPS.createUPS origBs modBs
    BS.writeFile (cmdCreateOut cmd) patchBs
    putStrLn ("wrote " ++ cmdCreateOut cmd)

----------------------------------------------------------------------------
-- Helpers
----------------------------------------------------------------------------

resolveOutput :: FilePath -> Maybe FilePath -> IO FilePath
resolveOutput target Nothing    = pure target
resolveOutput target (Just out) = do
  exists <- doesFileExist target
  if exists
    then copyFile target out >> pure out
    else die ("target file not found: " ++ target)

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
showPPFError (PPF.BadMagic bs)        = "not a PPF file (bad magic: " ++ show bs ++ ")"
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

warn :: String -> IO ()
warn msg = hPutStrLn stderr ("slap: warning: " ++ msg)

die :: String -> IO a
die msg = hPutStrLn stderr ("slap: " ++ msg) >> exitFailure
