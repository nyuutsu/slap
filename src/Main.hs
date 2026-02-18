{-# LANGUAGE OverloadedStrings #-}

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
import qualified Patch.PMSR as PMSR
import qualified Patch.Explain as Explain

import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BL
import Data.ByteString.Builder
import Data.Int (Int64)
import Control.Monad (when)
import Data.Char (toLower)
import Data.Maybe (fromMaybe)
import Data.Word (Word32)
import Options.Applicative
import System.Directory (copyFile, doesFileExist, removeFile, renameFile)
import System.Exit (exitFailure)
import System.IO (hPutStrLn, stderr)

data CreateFormat = CfmtBPS | CfmtIPS | CfmtIPS32 | CfmtUPS | CfmtPPF3 | CfmtPMSR
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
  | CmdConvert
      { cmdConvPatch  :: FilePath
      , cmdConvTo     :: CreateFormat
      , cmdConvOutput :: Maybe FilePath
      , cmdConvWith   :: Maybe FilePath
      }
  | CmdInfo    { cmdPatch :: FilePath }
  | CmdExplain { cmdPatch :: FilePath }

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
            <> progDesc "Apply, undo, create, convert, and inspect ROM patches (IPS, BPS, UPS, PPF, VCDIFF, APS, RUP, BSDiff/BDF, GDIFF, xdelta1, PMSR)")

commandParser :: Parser Command
commandParser = subparser
  ( command "apply"   (info (applyParser   <**> helper) (progDesc "Apply a patch to a target file"))
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
      <> help "Output format: bps (default), ips, ips32, ups, ppf3, pmsr")
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
  Just FmtPMSR    -> SomePMSR    <$> PMSR.parsePMSR bs

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
someInfo (SomePMSR p)    = PMSR.pmsrInfo p

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
someExplain (SomePMSR p)    = Explain.explainPMSR p

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

someApply cmd _patchBs (SomePMSR patch) = do
  actual <- resolveOutput (cmdTarget cmd) (cmdOutput cmd)
  let recs = PMSR.pmsrRecords patch
      total = length recs
  when (cmdVerbose cmd) $ mapM_ (\(i, r) ->
    hPutStrLn stderr ("[" ++ show i ++ "/" ++ show total ++ "] Write "
      ++ show (BS.length (PMSR.pmsrData r)) ++ " bytes at 0x"
      ++ padHex 8 (PMSR.pmsrOffset r)))
    (zip [(1::Int)..] recs)
  n <- PMSR.applyPMSR patch actual
  putStrLn ("applied " ++ show n ++ " records")

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
  CfmtIPS32 -> do
    origBs <- BS.readFile (cmdOriginal cmd)
    modBs  <- BS.readFile (cmdModified cmd)
    case IPS.createIPS32 origBs modBs of
      Left err -> die err
      Right patchBs -> do
        BS.writeFile (cmdCreateOut cmd) patchBs
        putStrLn ("wrote " ++ cmdCreateOut cmd)
  CfmtPMSR -> do
    origBs <- BS.readFile (cmdOriginal cmd)
    modBs  <- BS.readFile (cmdModified cmd)
    let patchBs = PMSR.createPMSR origBs modBs
    BS.writeFile (cmdCreateOut cmd) patchBs
    putStrLn ("wrote " ++ cmdCreateOut cmd)

----------------------------------------------------------------------------
-- Convert
----------------------------------------------------------------------------

doConvert :: Command -> IO ()
doConvert cmd = do
  patchBs <- BS.readFile (cmdConvPatch cmd)
  case parseSome patchBs of
    Left err -> die err
    Right parsed -> do
      let outFile = fromMaybe (replaceExt (cmdConvPatch cmd) (fmtExt (cmdConvTo cmd))) (cmdConvOutput cmd)
      -- Try direct conversion first
      case tryDirect parsed (cmdConvTo cmd) of
        Just (Right result) -> do
          BS.writeFile outFile result
          putStrLn ("converted to " ++ fmtName (cmdConvTo cmd) ++ ": " ++ outFile)
        Just (Left err) -> die err
        Nothing -> do
          -- Need --with for apply-then-create
          sourcePath <- case cmdConvWith cmd of
            Just s  -> pure s
            Nothing -> die (needWithMsg parsed)
          sourceBs <- BS.readFile sourcePath
          targetBs <- applyToMemory parsed patchBs sourcePath sourceBs
          result <- createFromMemory (cmdConvTo cmd) sourceBs targetBs
          BS.writeFile outFile result
          putStrLn ("converted to " ++ fmtName (cmdConvTo cmd) ++ ": " ++ outFile)

-- | Try direct conversion without needing the source ROM.
-- Returns Nothing if direct conversion is not possible.
tryDirect :: SomePatch -> CreateFormat -> Maybe (Either String BS.ByteString)
-- IPS → IPS32: widen offsets
tryDirect (SomeIPS patch) CfmtIPS32
  | IPS.ipsVariant patch == IPS.StandardIPS =
      Just (ipsToIPS32 patch)
-- IPS32 → IPS: narrow offsets (may fail)
tryDirect (SomeIPS patch) CfmtIPS
  | IPS.ipsVariant patch == IPS.IPS32 =
      Just (ips32ToIPS patch)
tryDirect _ _ = Nothing

-- | Convert IPS → IPS32 by re-encoding with 4-byte offsets.
ipsToIPS32 :: IPS.IPSPatch -> Either String BS.ByteString
ipsToIPS32 patch = Right $ BL.toStrict $ toLazyByteString $
    byteString "IPS32"
    <> foldMap (encodeIPSRecordWith 4) (IPS.ipsRecords patch)
    <> byteString "EEOF"

-- | Convert IPS32 → IPS by re-encoding with 3-byte offsets.
-- Fails if any offset exceeds 0xFFFFFF.
ips32ToIPS :: IPS.IPSPatch -> Either String BS.ByteString
ips32ToIPS patch
  | any (exceedsIPS . ipsRecOff) (IPS.ipsRecords patch) =
      Left "IPS32 patch has offsets > 0xFFFFFF — cannot convert to standard IPS"
  | otherwise = Right $ BL.toStrict $ toLazyByteString $
      byteString "PATCH"
      <> foldMap (encodeIPSRecordWith 3) (IPS.ipsRecords patch)
      <> byteString "EOF"
  where
    exceedsIPS off = off > 0xFFFFFF

-- | Get the offset from an IPS record.
ipsRecOff :: IPS.IPSRecord -> Int64
ipsRecOff (IPS.IPSRecord off _)      = off
ipsRecOff (IPS.IPSRecordRLE off _ _) = off

-- | Encode an IPS record with the given offset width (3 or 4 bytes).
encodeIPSRecordWith :: Int -> IPS.IPSRecord -> Builder
encodeIPSRecordWith offWidth (IPS.IPSRecord off dat) =
  encodeOff offWidth off
  <> if BS.length dat >= 3 && BS.all (== BS.index dat 0) dat
     then word8 0 <> word8 0 <> w16be (BS.length dat) <> word8 (BS.index dat 0)
     else w16be (BS.length dat) <> byteString dat
encodeIPSRecordWith offWidth (IPS.IPSRecordRLE off count val) =
  encodeOff offWidth off
  <> word8 0 <> word8 0
  <> w16be count
  <> word8 val

encodeOff :: Int -> Int64 -> Builder
encodeOff 3 off =
  word8 (fromIntegral (off `div` 0x10000))
  <> word8 (fromIntegral ((off `div` 0x100) `mod` 0x100))
  <> word8 (fromIntegral (off `mod` 0x100))
encodeOff _ off =
  word8 (fromIntegral (off `div` 0x1000000))
  <> word8 (fromIntegral ((off `div` 0x10000) `mod` 0x100))
  <> word8 (fromIntegral ((off `div` 0x100) `mod` 0x100))
  <> word8 (fromIntegral (off `mod` 0x100))

w16be :: Int -> Builder
w16be n = word8 (fromIntegral ((n `div` 0x100) `mod` 0x100))
       <> word8 (fromIntegral (n `mod` 0x100))

-- | Apply a parsed patch to source data, returning the target ByteString.
-- For file-handle formats (IPS, PPF, APS, RUP, PMSR), writes to a temp file.
applyToMemory :: SomePatch -> BS.ByteString -> FilePath -> BS.ByteString -> IO BS.ByteString
applyToMemory (SomeBPS patch) _patchBs _sourcePath sourceBs =
  case BPS.applyBPS patch sourceBs of
    Left err -> die err
    Right r  -> pure r
applyToMemory (SomeUPS patch) _patchBs _sourcePath sourceBs =
  pure (UPS.applyUPS patch sourceBs)
applyToMemory (SomeVCDIFF patch) _patchBs _sourcePath sourceBs =
  case VCDIFF.applyVCDIFF patch sourceBs of
    Left err -> die err
    Right r  -> pure r
applyToMemory (SomeBSDiff patch) patchBs _sourcePath sourceBs =
  case BSDiff.applyBSDiff patch sourceBs of
    Right r  -> pure r
    Left _   -> do
      -- Fallback: external bspatch
      let tmpPatch = "/tmp/slap-conv-patch.tmp"
          tmpSrc   = "/tmp/slap-conv-src.tmp"
          tmpOut   = "/tmp/slap-conv-out.tmp"
      BS.writeFile tmpPatch patchBs
      BS.writeFile tmpSrc sourceBs
      r <- BSDiff.tryExternalBspatch tmpPatch tmpSrc tmpOut
      removeFile tmpPatch
      removeFile tmpSrc
      case r of
        Right () -> do
          result <- BS.readFile tmpOut
          removeFile tmpOut
          pure result
        Left err -> die err
applyToMemory (SomeGDIFF patch) _patchBs _sourcePath sourceBs =
  case GDIFF.applyGDIFF patch sourceBs of
    Left err -> die err
    Right r  -> pure r
applyToMemory (SomeXDelta1 patch) _patchBs _sourcePath sourceBs =
  case XDelta1.applyXDelta1 patch sourceBs of
    Left err -> die err
    Right r  -> pure r
-- File-handle formats: write source to temp, apply in-place, read back
applyToMemory (SomeIPS patch) _patchBs _sourcePath sourceBs = applyViaTemp sourceBs $ \tmp ->
  IPS.applyIPS patch tmp >> pure ()
applyToMemory (SomePPF patch) _patchBs _sourcePath sourceBs = applyViaTemp sourceBs $ \tmp -> do
  (warnings, _) <- PPF.applyPatch patch tmp
  mapM_ (hPutStrLn stderr) warnings
applyToMemory (SomeAPS patch) _patchBs _sourcePath sourceBs = applyViaTemp sourceBs $ \tmp ->
  APS.applyAPS patch tmp >> pure ()
applyToMemory (SomeRUP patch) _patchBs _sourcePath sourceBs = applyViaTemp sourceBs $ \tmp ->
  RUP.applyRUP patch tmp >> pure ()
applyToMemory (SomePMSR patch) _patchBs _sourcePath sourceBs = applyViaTemp sourceBs $ \tmp ->
  PMSR.applyPMSR patch tmp >> pure ()

-- | Apply a file-handle-based patch via a temp file and read back the result.
applyViaTemp :: BS.ByteString -> (FilePath -> IO ()) -> IO BS.ByteString
applyViaTemp sourceBs apply = do
  let tmp = "/tmp/slap-convert.tmp"
  BS.writeFile tmp sourceBs
  apply tmp
  result <- BS.readFile tmp
  removeFile tmp
  pure result

-- | Create a patch from source and target in memory, returning the patch bytes.
createFromMemory :: CreateFormat -> BS.ByteString -> BS.ByteString -> IO BS.ByteString
createFromMemory CfmtBPS  src tgt = pure (BPS.createBPS src tgt)
createFromMemory CfmtUPS  src tgt = pure (UPS.createUPS src tgt)
createFromMemory CfmtPMSR src tgt = pure (PMSR.createPMSR src tgt)
createFromMemory CfmtIPS  src tgt = case IPS.createIPS src tgt of
  Left err -> die err
  Right r  -> pure r
createFromMemory CfmtIPS32 src tgt = case IPS.createIPS32 src tgt of
  Left err -> die err
  Right r  -> pure r
createFromMemory CfmtPPF3 src tgt =
  pure (PPF.createPatchPure src tgt "converted patch" False False)

-- | Error message when --with is required but not provided.
needWithMsg :: SomePatch -> String
needWithMsg p = "converting from " ++ srcFmt ++ " requires the original ROM (--with SOURCE)\n"
  ++ reason
  where
    (srcFmt, reason) = case p of
      SomeBPS _     -> ("BPS",     "BPS stores differential data, not raw bytes — the original ROM is needed\nto reconstruct the target file for re-encoding.")
      SomeUPS _     -> ("UPS",     "UPS stores XOR differences — the original ROM is needed\nto reconstruct the target file for re-encoding.")
      SomeVCDIFF _  -> ("VCDIFF",  "VCDIFF stores delta-encoded data — the original ROM is needed\nto reconstruct the target file for re-encoding.")
      SomeBSDiff _  -> ("BSDiff",  "BSDiff stores differential data — the original ROM is needed\nto reconstruct the target file for re-encoding.")
      SomeGDIFF _   -> ("GDIFF",   "GDIFF stores copy/data commands referencing the source — the original ROM\nis needed to reconstruct the target file for re-encoding.")
      SomeXDelta1 _ -> ("xdelta1", "xdelta1 stores delta-encoded data — the original ROM is needed\nto reconstruct the target file for re-encoding.")
      SomePPF _     -> ("PPF",     "PPF applies in-place to the target file — the original ROM is needed\nto reconstruct the target file for re-encoding.")
      SomeIPS _     -> ("IPS",     "IPS applies in-place to the target file — the original ROM is needed\nto reconstruct the target file for re-encoding.")
      SomeAPS _     -> ("APS",     "APS applies in-place to the target file — the original ROM is needed\nto reconstruct the target file for re-encoding.")
      SomeRUP _     -> ("RUP",     "RUP applies in-place to the target file — the original ROM is needed\nto reconstruct the target file for re-encoding.")
      SomePMSR _    -> ("PMSR",    "PMSR applies in-place to the target file — the original ROM is needed\nto reconstruct the target file for re-encoding.")

-- | Replace the file extension, or append if no extension.
replaceExt :: FilePath -> String -> FilePath
replaceExt path ext =
  let base = dropExtension path
  in base ++ ext

dropExtension :: FilePath -> FilePath
dropExtension path =
  let name = reverse path
      (_, rest) = break (== '.') name
  in if null rest then path else reverse (drop 1 rest)

-- | File extension for a CreateFormat.
fmtExt :: CreateFormat -> String
fmtExt CfmtBPS  = ".bps"
fmtExt CfmtIPS  = ".ips"
fmtExt CfmtIPS32 = ".ips"
fmtExt CfmtUPS  = ".ups"
fmtExt CfmtPPF3 = ".ppf"
fmtExt CfmtPMSR = ".pmsr"

-- | Human-readable name for a CreateFormat.
fmtName :: CreateFormat -> String
fmtName CfmtBPS  = "BPS"
fmtName CfmtIPS  = "IPS"
fmtName CfmtIPS32 = "IPS32"
fmtName CfmtUPS  = "UPS"
fmtName CfmtPPF3 = "PPF3"
fmtName CfmtPMSR = "PMSR"

----------------------------------------------------------------------------
-- Helpers

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
