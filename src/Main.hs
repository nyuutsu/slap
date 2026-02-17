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

import qualified Data.ByteString as BS
import Control.Monad (when)
import Data.Char (toLower)
import Data.Maybe (fromMaybe)
import Data.Word (Word32)
import Numeric (showHex)
import Options.Applicative
import System.Directory (copyFile, doesFileExist)
import System.Exit (exitFailure)
import System.IO (hPutStrLn, stderr)

data CreateFormat = CfmtBPS | CfmtIPS | CfmtPPF3
  deriving (Show, Eq)

data Command
  = Apply  Bool Bool FilePath FilePath (Maybe FilePath)  -- force, verbose, patch, target, output
  | Undo   Bool FilePath FilePath (Maybe FilePath)       -- verbose, patch, target, output
  | Create CreateFormat FilePath FilePath FilePath String Bool Bool
  | Info    FilePath

main :: IO ()
main = execParser opts >>= \case
  Apply force verb pf tgt mOut -> doApply force verb pf tgt mOut
  Undo  verb pf tgt mOut       -> doUndo verb pf tgt mOut
  Create fmt o m out d u v     -> doCreate fmt o m out d u v
  Info  pf                     -> doInfo pf

opts :: ParserInfo Command
opts = info (commandParser <**> helper)
  (fullDesc <> header "slap - multi-format ROM patching tool"
            <> progDesc "Apply, undo, create, and inspect ROM patches (PPF, IPS, BPS)")

commandParser :: Parser Command
commandParser = subparser
  ( command "apply"  (info (applyParser  <**> helper) (progDesc "Apply a patch to a target file"))
 <> command "undo"   (info (undoParser   <**> helper) (progDesc "Undo a patch (PPF3 undo data)"))
 <> command "create" (info (createParser <**> helper) (progDesc "Create a patch from two files"))
 <> command "info"   (info (patchInfoParser <**> helper) (progDesc "Display patch information"))
  )

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
      <> help "Output format: bps (default), ips, ppf3")
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
  "ppf3" -> Right CfmtPPF3
  "ppf"  -> Right CfmtPPF3
  _      -> Left ("unknown format: " ++ s ++ " (expected bps, ips, ppf3)")

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
      FmtPPF -> doApplyPPF force verbose patchBs target mOut
      FmtIPS -> doApplyIPS verbose patchBs target mOut
      FmtBPS -> doApplyBPS force verbose patchBs target mOut

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
