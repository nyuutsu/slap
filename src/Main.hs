module Main (main) where

import Patch.Types
import Patch.Detect (detectFormat)
import Patch.Binary (crc32)
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
import Numeric (showHex)
import Options.Applicative
import System.Directory (copyFile, doesFileExist, renameFile)
import System.Exit (exitFailure)
import System.IO (hPutStrLn, stderr)

data CreateFormat = CfmtBPS | CfmtIPS | CfmtUPS | CfmtPPF3
  deriving (Show, Eq)

data Command
  = Apply  Bool Bool FilePath FilePath (Maybe FilePath)  -- force, verbose, patch, target, output
  | Undo   Bool FilePath FilePath (Maybe FilePath)       -- verbose, patch, target, output
  | Create CreateFormat FilePath FilePath FilePath String Bool Bool
  | Info    FilePath
  | Explain FilePath

main :: IO ()
main = execParser opts >>= \case
  Apply force verb pf tgt mOut -> doApply force verb pf tgt mOut
  Undo  verb pf tgt mOut       -> doUndo verb pf tgt mOut
  Create fmt o m out d u v     -> doCreate fmt o m out d u v
  Info  pf                     -> doInfo pf
  Explain pf                   -> doExplain pf

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
explainParser = Explain
  <$> argument str (metavar "PATCH" <> help "Patch file to explain")

applyParser :: Parser Command
applyParser = Apply
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
undoParser = Undo
  <$> verboseFlag
  <*> argument str (metavar "PATCH"  <> help "Patch file")
  <*> argument str (metavar "TARGET" <> help "File to restore")
  <*> optional (option str (long "output" <> short 'o' <> metavar "FILE"
      <> help "Write restored output to FILE instead of modifying TARGET in place"))

createParser :: Parser Command
createParser = Create
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
patchInfoParser = Info
  <$> argument str (metavar "PATCH" <> help "Patch file to inspect")

----------------------------------------------------------------------------
-- Apply
----------------------------------------------------------------------------

doApply :: Bool -> Bool -> FilePath -> FilePath -> Maybe FilePath -> IO ()
doApply force verbose patchFile target mOut = do
  patchBs <- BS.readFile patchFile
  case detectFormat patchBs of
    Nothing  -> die ("unknown patch format: " ++ patchFile)
    Just fmt -> case fmt of
      FmtPPF     -> doApplyPPF force verbose patchBs target mOut
      FmtIPS     -> doApplyIPS verbose patchBs target mOut
      FmtBPS     -> doApplyBPS force verbose patchBs target mOut
      FmtUPS     -> doApplyUPS force verbose patchBs target mOut
      FmtVCDIFF  -> doApplyVCDIFF force verbose patchBs target mOut
      FmtAPS     -> doApplyAPS verbose patchBs target mOut
      FmtRUP     -> doApplyRUP verbose patchBs target mOut
      FmtBSDiff  -> doApplyBSDiff verbose patchFile patchBs target mOut
      FmtGDIFF   -> doApplyGDIFF verbose patchBs target mOut
      FmtXDelta1 -> doApplyXDelta1 verbose patchBs target mOut

doApplyPPF :: Bool -> Bool -> BS.ByteString -> FilePath -> Maybe FilePath -> IO ()
doApplyPPF _force verbose patchBs target mOut = do
  actual <- resolveOutput target mOut
  case PPF.parsePatch patchBs of
    Left err -> die (showPPFError err)
    Right patch -> do
      let recs = PPF.patchRecords patch
          total = length recs
      when verbose $ mapM_ (\(i, r) ->
        hPutStrLn stderr ("[" ++ show i ++ "/" ++ show total ++ "] Write "
          ++ show (BS.length (PPF.recData r)) ++ " bytes at 0x"
          ++ showHex (fromIntegral (PPF.recOffset r) :: Word32) ""))
        (zip [(1::Int)..] recs)
      (warnings, n) <- PPF.applyPatch patch actual
      mapM_ (hPutStrLn stderr) warnings
      putStrLn ("applied " ++ show n ++ " records")

doApplyIPS :: Bool -> BS.ByteString -> FilePath -> Maybe FilePath -> IO ()
doApplyIPS verbose patchBs target mOut = do
  actual <- resolveOutput target mOut
  case IPS.parseIPS patchBs of
    Left err -> die err
    Right patch -> do
      let recs = IPS.ipsRecords patch
          total = length recs
      when verbose $ mapM_ (\(i, r) ->
        hPutStrLn stderr ("[" ++ show i ++ "/" ++ show total ++ "] " ++ describeIPS r))
        (zip [(1::Int)..] recs)
      n <- IPS.applyIPS patch actual
      putStrLn ("applied " ++ show n ++ " records")

doApplyBPS :: Bool -> Bool -> BS.ByteString -> FilePath -> Maybe FilePath -> IO ()
doApplyBPS force verbose patchBs target mOut = do
  case BPS.parseBPS patchBs of
    Left err -> die err
    Right patch -> do
      source <- BS.readFile target
      let srcCRC = crc32 source
      checkCRC force "source" (BPS.bpsSourceCRC patch) srcCRC
      let acts = BPS.bpsActions patch
          total = length acts
      when verbose $ mapM_ (\(i, a) ->
        hPutStrLn stderr ("[" ++ show i ++ "/" ++ show total ++ "] " ++ describeBPS a))
        (zip [(1::Int)..] acts)
      case BPS.applyBPS patch source of
        Left err -> die err
        Right result -> do
          let tgtCRC = crc32 result
          when (tgtCRC /= BPS.bpsTargetCRC patch) $
            warn ("target CRC mismatch after apply (expected "
                  ++ fmtCRC (BPS.bpsTargetCRC patch) ++ ", got " ++ fmtCRC tgtCRC ++ ")")
          BS.writeFile (fromMaybe target mOut) result
          putStrLn ("applied " ++ show total ++ " actions")

doApplyUPS :: Bool -> Bool -> BS.ByteString -> FilePath -> Maybe FilePath -> IO ()
doApplyUPS force verbose patchBs target mOut = do
  case UPS.parseUPS patchBs of
    Left err -> die err
    Right patch -> do
      source <- BS.readFile target
      let srcCRC = crc32 source
      checkCRC force "source" (UPS.upsSourceCRC patch) srcCRC
      let blks = UPS.upsBlocks patch
          total = length blks
      when verbose $ mapM_ (\(i, b) ->
        hPutStrLn stderr ("[" ++ show i ++ "/" ++ show total ++ "] XOR "
          ++ show (BS.length (UPS.upsXorData b)) ++ " bytes (skip " ++ show (UPS.upsSkip b) ++ ")"))
        (zip [(1::Int)..] blks)
      let result = UPS.applyUPS patch source
      let tgtCRC = crc32 result
      when (tgtCRC /= UPS.upsTargetCRC patch) $
        warn ("target CRC mismatch after apply (expected "
              ++ fmtCRC (UPS.upsTargetCRC patch) ++ ", got " ++ fmtCRC tgtCRC ++ ")")
      BS.writeFile (fromMaybe target mOut) result
      putStrLn ("applied " ++ show total ++ " blocks")

doApplyVCDIFF :: Bool -> Bool -> BS.ByteString -> FilePath -> Maybe FilePath -> IO ()
doApplyVCDIFF _force verbose patchBs target mOut = do
  case VCDIFF.parseVCDIFF patchBs of
    Left err -> die err
    Right patch -> do
      source <- BS.readFile target
      let wins = VCDIFF.vcdWindows patch
          total = length wins
      when verbose $ mapM_ (\(i, w) ->
        hPutStrLn stderr ("[" ++ show i ++ "/" ++ show total ++ "] Window "
          ++ show (VCDIFF.vcdTargetLen w) ++ " bytes target"))
        (zip [(1::Int)..] wins)
      case VCDIFF.applyVCDIFF patch source of
        Left err -> die err
        Right result -> do
          BS.writeFile (fromMaybe target mOut) result
          putStrLn ("applied " ++ show total ++ " windows")

doApplyAPS :: Bool -> BS.ByteString -> FilePath -> Maybe FilePath -> IO ()
doApplyAPS _verbose patchBs target mOut = do
  actual <- resolveOutput target mOut
  case APS.parseAPS patchBs of
    Left err -> die err
    Right patch -> do
      n <- APS.applyAPS patch actual
      putStrLn ("applied " ++ show n ++ " records")

doApplyRUP :: Bool -> BS.ByteString -> FilePath -> Maybe FilePath -> IO ()
doApplyRUP _verbose patchBs target mOut = do
  actual <- resolveOutput target mOut
  case RUP.parseRUP patchBs of
    Left err -> die err
    Right patch -> do
      n <- RUP.applyRUP patch actual
      putStrLn ("applied " ++ show n ++ " records")

doApplyGDIFF :: Bool -> BS.ByteString -> FilePath -> Maybe FilePath -> IO ()
doApplyGDIFF _verbose patchBs target mOut = do
  case GDIFF.parseGDIFF patchBs of
    Left err -> die err
    Right patch -> do
      source <- BS.readFile target
      case GDIFF.applyGDIFF patch source of
        Left err -> die err
        Right result -> do
          BS.writeFile (fromMaybe target mOut) result
          putStrLn ("applied " ++ show (length (GDIFF.gdiffCmds patch)) ++ " commands")

doApplyBSDiff :: Bool -> FilePath -> BS.ByteString -> FilePath -> Maybe FilePath -> IO ()
doApplyBSDiff _verbose patchFile patchBs target mOut = do
  case BSDiff.parseBSDiff patchBs of
    Left err -> die err
    Right patch -> do
      source <- BS.readFile target
      case BSDiff.applyBSDiff patch source of
        Right result -> do
          BS.writeFile (fromMaybe target mOut) result
          putStrLn ("applied " ++ show (length (BSDiff.bsdControls patch)) ++ " control tuples")
        Left _ -> do
          -- Native apply not available, try external bspatch
          let outFile = fromMaybe target mOut
          if outFile == target
            then do
              -- In-place: bspatch needs separate input/output
              let tmpFile = target ++ ".slap.tmp"
              r <- BSDiff.tryExternalBspatch patchFile target tmpFile
              case r of
                Right () -> do
                  renameFile tmpFile target
                  putStrLn "applied bsdiff (external bspatch)"
                Left err -> die err
            else do
              r <- BSDiff.tryExternalBspatch patchFile target outFile
              case r of
                Right () -> putStrLn "applied bsdiff (external bspatch)"
                Left err -> die err

doApplyXDelta1 :: Bool -> BS.ByteString -> FilePath -> Maybe FilePath -> IO ()
doApplyXDelta1 _verbose patchBs target mOut = do
  case XDelta1.parseXDelta1 patchBs of
    Left err -> die err
    Right patch -> do
      source <- BS.readFile target
      case XDelta1.applyXDelta1 patch source of
        Left err -> die err
        Right result -> do
          BS.writeFile (fromMaybe target mOut) result
          putStrLn ("applied " ++ show (length (XDelta1.xd1Instructions patch)) ++ " instructions")

----------------------------------------------------------------------------
-- Undo
----------------------------------------------------------------------------

doUndo :: Bool -> FilePath -> FilePath -> Maybe FilePath -> IO ()
doUndo _verbose patchFile target mOut = do
  patchBs <- BS.readFile patchFile
  case detectFormat patchBs of
    Nothing  -> die ("unknown patch format: " ++ patchFile)
    Just fmt -> case fmt of
      FmtPPF -> do
        actual <- resolveOutput target mOut
        case PPF.parsePatch patchBs of
          Left err -> die (showPPFError err)
          Right patch -> do
            result <- PPF.undoPatch patch actual
            case result of
              Left err -> die err
              Right n  -> putStrLn ("reverted " ++ show n ++ " records")
      FmtUPS -> do
        case UPS.parseUPS patchBs of
          Left err -> die err
          Right patch -> do
            -- UPS is self-inverting: apply patch to target to get source back.
            modified <- BS.readFile target
            let result = UPS.applyUPS patch modified
            BS.writeFile (fromMaybe target mOut) result
            putStrLn ("reverted (UPS self-inverse)")
      _ -> die ("undo not supported for " ++ show fmt ++ " format")

----------------------------------------------------------------------------
-- Create
----------------------------------------------------------------------------

doCreate :: CreateFormat -> FilePath -> FilePath -> FilePath -> String -> Bool -> Bool -> IO ()
doCreate fmt orig modified out desc undo val = case fmt of
  CfmtPPF3 -> do
    patchBs <- PPF.createPatch orig modified desc undo val
    BS.writeFile out patchBs
    case PPF.parsePatch patchBs of
      Left _      -> putStrLn ("wrote " ++ out)
      Right patch -> putStrLn ("wrote " ++ out ++ " (" ++ show (length (PPF.patchRecords patch)) ++ " records)")
  CfmtIPS -> do
    origBs <- BS.readFile orig
    modBs  <- BS.readFile modified
    case IPS.createIPS origBs modBs of
      Left err -> die err
      Right patchBs -> do
        BS.writeFile out patchBs
        putStrLn ("wrote " ++ out)
  CfmtBPS -> do
    origBs <- BS.readFile orig
    modBs  <- BS.readFile modified
    let patchBs = BPS.createBPS origBs modBs
    BS.writeFile out patchBs
    putStrLn ("wrote " ++ out)
  CfmtUPS -> do
    origBs <- BS.readFile orig
    modBs  <- BS.readFile modified
    let patchBs = UPS.createUPS origBs modBs
    BS.writeFile out patchBs
    putStrLn ("wrote " ++ out)

----------------------------------------------------------------------------
-- Info
----------------------------------------------------------------------------

doInfo :: FilePath -> IO ()
doInfo patchFile = do
  patchBs <- BS.readFile patchFile
  case detectFormat patchBs of
    Nothing -> die ("unknown patch format: " ++ patchFile)
    Just fmt -> case fmt of
      FmtPPF -> case PPF.parsePatch patchBs of
        Left err -> die (showPPFError err)
        Right p  -> putStr (PPF.showInfo p)
      FmtIPS -> case IPS.parseIPS patchBs of
        Left err -> die err
        Right p  -> putStr (IPS.ipsInfo p)
      FmtBPS -> case BPS.parseBPS patchBs of
        Left err -> die err
        Right p  -> putStr (BPS.bpsInfo p)
      FmtUPS -> case UPS.parseUPS patchBs of
        Left err -> die err
        Right p  -> putStr (UPS.upsInfo p)
      FmtVCDIFF -> case VCDIFF.parseVCDIFF patchBs of
        Left err -> die err
        Right p  -> putStr (VCDIFF.vcdiffInfo p)
      FmtAPS -> case APS.parseAPS patchBs of
        Left err -> die err
        Right p  -> putStr (APS.apsInfo p)
      FmtRUP -> case RUP.parseRUP patchBs of
        Left err -> die err
        Right p  -> putStr (RUP.rupInfo p)
      FmtBSDiff -> case BSDiff.parseBSDiff patchBs of
        Left err -> die err
        Right p  -> putStr (BSDiff.bsdiffInfo p)
      FmtGDIFF -> case GDIFF.parseGDIFF patchBs of
        Left err -> die err
        Right p  -> putStr (GDIFF.gdiffInfo p)
      FmtXDelta1 -> case XDelta1.parseXDelta1 patchBs of
        Left err -> die err
        Right p  -> putStr (XDelta1.xdelta1Info p)

----------------------------------------------------------------------------
-- Explain
----------------------------------------------------------------------------

doExplain :: FilePath -> IO ()
doExplain patchFile = do
  patchBs <- BS.readFile patchFile
  case detectFormat patchBs of
    Nothing -> die ("unknown patch format: " ++ patchFile)
    Just fmt -> case fmt of
      FmtPPF -> case PPF.parsePatch patchBs of
        Left err -> die (showPPFError err)
        Right p  -> putStr (Explain.explainPPF p)
      FmtIPS -> case IPS.parseIPS patchBs of
        Left err -> die err
        Right p  -> putStr (Explain.explainIPS p)
      FmtBPS -> case BPS.parseBPS patchBs of
        Left err -> die err
        Right p  -> putStr (Explain.explainBPS p)
      FmtUPS -> case UPS.parseUPS patchBs of
        Left err -> die err
        Right p  -> putStr (Explain.explainUPS p)
      FmtVCDIFF -> case VCDIFF.parseVCDIFF patchBs of
        Left err -> die err
        Right p  -> putStr (Explain.explainVCDIFF p)
      FmtAPS -> case APS.parseAPS patchBs of
        Left err -> die err
        Right p  -> putStr (Explain.explainAPS p)
      FmtRUP -> case RUP.parseRUP patchBs of
        Left err -> die err
        Right p  -> putStr (Explain.explainRUP p)
      FmtBSDiff -> case BSDiff.parseBSDiff patchBs of
        Left err -> die err
        Right p  -> putStr (Explain.explainBSDiff p)
      FmtGDIFF -> case GDIFF.parseGDIFF patchBs of
        Left err -> die err
        Right p  -> putStr (Explain.explainGDIFF p)
      FmtXDelta1 -> case XDelta1.parseXDelta1 patchBs of
        Left err -> die err
        Right p  -> putStr (Explain.explainXDelta1 p)

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
fmtCRC w = "0x" ++ padHex 8 (showHex w "")

padHex :: Int -> String -> String
padHex n s = replicate (n - length s) '0' ++ s

showPPFError :: PPF.ParseError -> String
showPPFError (PPF.BadMagic bs)        = "not a PPF file (bad magic: " ++ show bs ++ ")"
showPPFError (PPF.UnknownVersion v)   = "unknown PPF version byte: " ++ show v
showPPFError (PPF.TruncatedFile msg)  = "truncated file: " ++ msg
showPPFError (PPF.UnknownImageType v) = "unknown image type: " ++ show v

describeIPS :: IPS.IPSRecord -> String
describeIPS (IPS.IPSRecord off dat) =
  "Write " ++ show (BS.length dat) ++ " bytes at 0x" ++ showHex (fromIntegral off :: Word32) ""
describeIPS (IPS.IPSRecordRLE off count val) =
  "Fill " ++ show count ++ " x 0x" ++ showHex val "" ++ " at 0x" ++ showHex (fromIntegral off :: Word32) ""

describeBPS :: BPS.BPSAction -> String
describeBPS (BPS.SourceRead len) = "SourceRead " ++ show len ++ " bytes"
describeBPS (BPS.TargetRead dat) = "TargetRead " ++ show (BS.length dat) ++ " bytes"
describeBPS (BPS.SourceCopy len _) = "SourceCopy " ++ show len ++ " bytes"
describeBPS (BPS.TargetCopy len _) = "TargetCopy " ++ show len ++ " bytes"

warn :: String -> IO ()
warn msg = hPutStrLn stderr ("slap: warning: " ++ msg)

die :: String -> IO a
die msg = hPutStrLn stderr ("slap: " ++ msg) >> exitFailure
