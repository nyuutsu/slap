{-# LANGUAGE OverloadedStrings #-}

module Main (main) where

import Patch.SomePatch (SomePatch(..), ApplyStrategy(..), UndoStrategy(..), parseSome)
import Patch.Overlay (CreateFormat(..), createFromMemory, convertOverlay, fmtExt, fmtName)
import Patch.Archive (detectArchive, unwrapArchive)
import Patch.Binary (crc32)
import Patch.Format (showCRC)

import qualified Data.ByteString as BS
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
          InMemory { imSourceCRC = Just expected } -> do
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
        InMemory { imApply = apply, imSourceCRC = srcCRC, imTargetCRC = tgtCRC } -> do
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
doCreate cmd = do
  origBs <- readMaybeUnwrap (cmdRaw cmd) (cmdOriginal cmd)
  modBs  <- readMaybeUnwrap (cmdRaw cmd) (cmdModified cmd)
  case createFromMemory (cmdCreateFmt cmd) origBs modBs
         (cmdDesc cmd) (cmdUndo cmd) (cmdValidate cmd) of
    Left err -> die err
    Right patchBs -> do
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
  InMemory { imApply = apply } -> do
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

emitWarnings :: SomePatch -> IO ()
emitWarnings sp = forM_ (spWarnings sp) $ \w ->
  hPutStrLn stderr ("slap: warning: " ++ spFormat sp ++ ": " ++ w)

warn :: String -> IO ()
warn msg = hPutStrLn stderr ("slap: warning: " ++ msg)

die :: String -> IO a
die msg = hPutStrLn stderr ("slap: " ++ msg) >> exitFailure
