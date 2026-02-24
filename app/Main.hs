{-# LANGUAGE OverloadedStrings #-}

module Main (main) where

import Patch.SomePatch (SomePatch(..), ApplyStrategy(..), UndoStrategy(..), Verification(..), parseSome)
import Patch.Convert (CreateFormat(..), CreateMeta(..), createFromMemory, convertDirect, fmtExt, fmtName)
import Patch.PPF.Types (ImageType(..))
import Patch.NINJA1 (NINJA1RomType(..), fromNINJA1RomType)
import Patch.Explain (renderExplain, renderSummary)
import Patch.Archive (detectArchive, unwrapArchive)
import Patch.Binary (crc32, crc16, md5, sha1, adler32)
import Patch.Format (showCRC, padHex)

import qualified Data.ByteString as BS
import Control.Monad (when, unless, forM_)
import Data.Char (toLower)
import Data.Int (Int64)
import Data.Maybe (fromMaybe, isJust)
import Data.Word (Word8, Word16, Word32)
import Options.Applicative
import Options.Applicative.Help.Pretty (pretty, vcat)
import System.Directory (copyFile, doesFileExist, removeFile)
import System.Exit (exitFailure, exitSuccess)
import System.FilePath (dropExtension, replaceExtension, takeBaseName, takeExtension)
import Control.Exception (SomeException, catch, finally)
import System.IO (hClose, hPutStrLn, openBinaryTempFile, stderr)

----------------------------------------------------------------------------
-- Types
----------------------------------------------------------------------------

data Command
  = CmdApply
      { cmdForce    :: Bool
      , cmdNoVerify :: Bool
      , cmdVerbose  :: Bool
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
      , cmdTitle      :: String
      , cmdAuthor     :: String
      , cmdUndo       :: Bool
      , cmdValidate   :: Bool
      , cmdVersion    :: String
      , cmdUnstable   :: Bool
      , cmdRomType    :: Maybe Word8
      , cmdImageType  :: Maybe ImageType
      , cmdMetadata   :: Maybe FilePath
      }
  | CmdConvert
      { cmdConvPatch     :: FilePath
      , cmdConvTo        :: CreateFormat
      , cmdConvOutput    :: Maybe FilePath
      , cmdConvWith      :: Maybe FilePath
      , cmdRaw           :: Bool
      , cmdConvDesc      :: String
      , cmdConvTitle     :: String
      , cmdConvAuthor    :: String
      , cmdConvUndo      :: Bool
      , cmdConvValidate  :: Bool
      , cmdNoVerify      :: Bool
      , cmdConvVersion   :: String
      , cmdConvUnstable  :: Bool
      , cmdConvRomType   :: Maybe Word8
      , cmdConvImageType :: Maybe ImageType
      , cmdConvMetadata  :: Maybe FilePath
      }
  | CmdInfo    { cmdPatch :: FilePath }
  | CmdExplain FilePath Bool (Maybe FilePath) Bool

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
  CmdExplain pf rc mw raw -> doExplain pf rc mw raw

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
 <> command "explain" (info (explainParser <**> helper) (progDesc "Patch structure summary (use --records for full dump)"))
  )

explainParser :: Parser Command
explainParser = CmdExplain
  <$> argument str (metavar "PATCH" <> help "Patch file to explain")
  <*> switch (long "records" <> help "Show full record-by-record dump instead of summary")
  <*> optional (option str (long "with" <> metavar "SOURCE"
      <> help "Source file (resolves delta/copy operations in output)"))
  <*> rawFlag

applyParser :: Parser Command
applyParser = mk
  <$> forceFlag <*> noVerifyFlag <*> yoloFlag
  <*> verboseFlag <*> inPlaceFlag <*> backupFlag <*> dryRunFlag <*> rawFlag
  <*> argument str (metavar "PATCH"  <> help "Patch file")
  <*> argument str (metavar "SOURCE" <> help "Source file to patch (not modified unless --in-place)")
  <*> outputOpt
  where
    mk force' nv yolo' = CmdApply (force' || yolo') (nv || yolo')
    outputOpt = (Just <$> option str (long "output" <> short 'o' <> metavar "FILE"
                  <> help "Write patched output to FILE"))
            <|> optional (argument str (metavar "OUTPUT"))

forceFlag :: Parser Bool
forceFlag = switch (long "force" <> short 'f' <> help "Overwrite existing output files")

noVerifyFlag :: Parser Bool
noVerifyFlag = switch (long "no-verify" <> help "Skip checksum validation (mismatches become warnings)")

yoloFlag :: Parser Bool
yoloFlag = switch (long "yolo" <> hidden)

verboseFlag :: Parser Bool
verboseFlag = switch (long "verbose" <> short 'V' <> help "Print each record as it's applied")

inPlaceFlag :: Parser Bool
inPlaceFlag = switch (long "in-place" <> short 'i'
                <> help "Modify SOURCE directly (destructive; creates .bak by default)")

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
      <> help "Output format: bps (default), ips, ips32, ebp, ups, ppf3, pmsr, ninja1, dps, rup, aps-n64, aps-gba, gdiff, pchtxt")
  <*> rawFlag
  <*> argument str (metavar "ORIGINAL" <> help "Original unmodified file")
  <*> argument str (metavar "MODIFIED" <> help "Modified file")
  <*> argument str (metavar "OUTPUT"   <> help "Output patch file")
  <*> option str (long "description" <> short 'd' <> metavar "TEXT" <> value ""
      <> help "Patch description (DPS/PPF3/EBP/APS-N64/RUP/PCHTXT)")
  <*> option str (long "title" <> metavar "TEXT" <> value ""
      <> help "Patch title (EBP/RUP)")
  <*> option str (long "author" <> metavar "TEXT" <> value ""
      <> help "Patch author (EBP/DPS/RUP)")
  <*> switch (long "undo"     <> short 'u' <> help "Include undo data (PPF3 only)")
  <*> switch (long "validate" <> short 'v' <> help "Include validation block (PPF3 only)")
  <*> option str (long "version" <> metavar "TEXT" <> value ""
      <> help "Patch version (DPS/RUP)")
  <*> switch (long "unstable" <> help "Mark patch unstable (DPS)")
  <*> optional (option (eitherReader parseRomType) (long "rom-type" <> metavar "TYPE"
      <> help "ROM type (NINJA1/RUP): raw, nes, snes, n64, gb, gbc, gba, ..."))
  <*> optional (option (eitherReader parseImageType) (long "image-type" <> metavar "TYPE"
      <> help "Image type (PPF3): bin, gi"))
  <*> optional (option str (long "metadata" <> metavar "FILE"
      <> help "Metadata file to embed (BPS)"))

convertParser :: Parser Command
convertParser = mk
  <$> argument str (metavar "PATCH" <> help "Patch file to convert")
  <*> option (eitherReader parseCfmt) (long "to" <> short 't' <> metavar "FMT"
      <> help "Target format: bps, ips, ips32, ebp, ups, ppf3, pmsr, ninja1, dps, rup, aps-n64, aps-gba, gdiff, pchtxt")
  <*> optional (option str (long "output" <> short 'o' <> metavar "FILE"
      <> help "Output file (default: replace input extension)"))
  <*> optional (option str (long "with" <> metavar "SOURCE"
      <> help "Source ROM (required for differential formats)"))
  <*> rawFlag
  <*> option str (long "description" <> short 'd' <> metavar "TEXT" <> value ""
      <> help "Patch description (DPS/PPF3/EBP/APS-N64/RUP/PCHTXT)")
  <*> option str (long "title" <> metavar "TEXT" <> value ""
      <> help "Patch title (EBP/RUP)")
  <*> option str (long "author" <> metavar "TEXT" <> value ""
      <> help "Patch author (EBP/DPS/RUP)")
  <*> flag True False (long "no-undo" <> help "Omit undo data (PPF3 only; included by default)")
  <*> flag True False (long "no-validate" <> help "Omit validation block (PPF3 only; included by default)")
  <*> noVerifyFlag <*> yoloFlag
  <*> option str (long "version" <> metavar "TEXT" <> value ""
      <> help "Patch version (DPS/RUP)")
  <*> switch (long "unstable" <> help "Mark patch unstable (DPS)")
  <*> optional (option (eitherReader parseRomType) (long "rom-type" <> metavar "TYPE"
      <> help "ROM type (NINJA1/RUP): raw, nes, snes, n64, gb, gbc, gba, ..."))
  <*> optional (option (eitherReader parseImageType) (long "image-type" <> metavar "TYPE"
      <> help "Image type (PPF3): bin, gi"))
  <*> optional (option str (long "metadata" <> metavar "FILE"
      <> help "Metadata file to embed (BPS)"))
  where
    mk p t o w r d ti au u v nv yolo' ver un rt it md =
      CmdConvert p t o w r d ti au u v (nv || yolo') ver un rt it md

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
  "pchtxt"  -> Right CfmtPCHTXT
  _ -> Left ("unknown format: " ++ s ++ "\n  expected: bps, ips, ips32, ebp, ups, ppf3, pmsr, ninja1, dps, rup, aps-n64, aps-gba, gdiff, pchtxt")

parseRomType :: String -> Either String Word8
parseRomType s = case map toLower s of
  "raw"  -> Right (fromNINJA1RomType RomRAW)
  "nes"  -> Right (fromNINJA1RomType RomNES)
  "snes" -> Right (fromNINJA1RomType RomSNES)
  "n64"  -> Right (fromNINJA1RomType RomN64)
  "gb"   -> Right (fromNINJA1RomType RomGB)
  "gbc"  -> Right (fromNINJA1RomType RomGBC)
  "gba"  -> Right (fromNINJA1RomType RomGBA)
  "ngp"  -> Right (fromNINJA1RomType RomNGP)
  "ngpc" -> Right (fromNINJA1RomType RomNGPC)
  "sms"  -> Right (fromNINJA1RomType RomSMS)
  "gg"   -> Right (fromNINJA1RomType RomGameGear)
  "mega" -> Right (fromNINJA1RomType RomGenesis)
  "pce"  -> Right (fromNINJA1RomType RomPCEngine)
  "ws"   -> Right (fromNINJA1RomType RomWonderSwan)
  "wsc"  -> Right (fromNINJA1RomType RomWonderSwanColor)
  "lynx" -> Right (fromNINJA1RomType RomLynx)
  "jag"  -> Right (fromNINJA1RomType RomJaguar)
  "gp32" -> Right (fromNINJA1RomType RomGP32)
  _ -> Left ("unknown ROM type: " ++ s
    ++ "\n  expected: raw, nes, snes, n64, gb, gbc, gba, ngp, ngpc, sms, gg, mega, pce, ws, wsc, lynx, jag, gp32")

parseImageType :: String -> Either String ImageType
parseImageType s = case map toLower s of
  "bin" -> Right BIN
  "gi"  -> Right GI
  _ -> Left ("unknown image type: " ++ s ++ "\n  expected: bin, gi")

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

doExplain :: FilePath -> Bool -> Maybe FilePath -> Bool -> IO ()
doExplain patchFile records mWithPath raw = do
  patchBs <- readUnwrap patchFile
  case parseSome patchBs of
    Left err -> die err
    Right sp -> do
      mSource <- case mWithPath of
        Nothing   -> pure Nothing
        Just path -> Just <$> readMaybeUnwrap raw path
      let render = if records then renderExplain else renderSummary
      putStr (render mSource (spExplain sp))
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
          v = spVerification sp
          nv = cmdNoVerify cmd

      -- Dry run: report and exit
      when (cmdDryRun cmd) $ do
        putStrLn $ "would apply " ++ show (spRecordCount sp) ++ " " ++ spRecordUnit sp
                ++ " \8594 " ++ outputPath
        case vSourceCRC32 v of
          Just expected -> do
            sourceBs <- readMaybeUnwrap (cmdRaw cmd) (cmdSource cmd)
            let actual = crc32 sourceBs
            putStrLn $ "source CRC: " ++ fmtCRC actual
              ++ if actual == expected then " \10003" else " \10007 (expected " ++ fmtCRC expected ++ ")"
          Nothing -> pure ()
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
          -- Read source for pre-apply verification if needed
          when (hasSourceV v) $ do
            sourceBs <- readMaybeUnwrap (cmdRaw cmd) (cmdSource cmd)
            verifySource nv v sourceBs
          unless (cmdInPlace cmd) $
            copyFile (cmdSource cmd) outputPath
          f (if cmdInPlace cmd then cmdSource cmd else outputPath)
          -- Post-apply target verification if needed
          when (hasTargetV v) $ do
            targetBs <- BS.readFile (if cmdInPlace cmd then cmdSource cmd else outputPath)
            verifyTarget nv v targetBs
          putStrLn $ "applied " ++ show (spRecordCount sp) ++ " " ++ spRecordUnit sp
                  ++ " \8594 " ++ outputPath
        InMemory { imApply = apply } -> do
          sourceBs <- readMaybeUnwrap (cmdRaw cmd) (cmdSource cmd)
          verifySource nv v sourceBs
          result <- apply sourceBs
          case result of
            Left err -> die err
            Right target -> do
              verifyTarget nv v target
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
  mMeta <- case cmdMetadata cmd of
    Nothing   -> pure Nothing
    Just path -> Just <$> BS.readFile path
  let meta = CreateMeta
        { cmTitle       = cmdTitle cmd
        , cmAuthor      = cmdAuthor cmd
        , cmDesc        = cmdDesc cmd
        , cmVersion     = cmdVersion cmd
        , cmUndo        = cmdUndo cmd
        , cmValidate    = cmdValidate cmd
        , cmUnstable    = cmdUnstable cmd
        , cmRomType     = cmdRomType cmd
        , cmImageType   = cmdImageType cmd
        , cmBPSMetadata = mMeta
        }
  case createFromMemory (cmdCreateFmt cmd) origBs modBs meta of
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
      mMeta <- case cmdConvMetadata cmd of
        Nothing   -> pure Nothing
        Just path -> Just <$> BS.readFile path
      let meta = CreateMeta
            { cmTitle       = cmdConvTitle cmd
            , cmAuthor      = cmdConvAuthor cmd
            , cmDesc        = cmdConvDesc cmd
            , cmVersion     = cmdConvVersion cmd
            , cmUndo        = cmdConvUndo cmd
            , cmValidate    = cmdConvValidate cmd
            , cmUnstable    = cmdConvUnstable cmd
            , cmRomType     = cmdConvRomType cmd
            , cmImageType   = cmdConvImageType cmd
            , cmBPSMetadata = mMeta
            }
      let emitNotes ns = forM_ ns $ \n -> hPutStrLn stderr ("slap: " ++ n)
      case cmdConvWith cmd of
        Just sourcePath -> do
          -- --with provided: always use apply-and-recreate path
          sourceBs <- readMaybeUnwrap (cmdRaw cmd) sourcePath
          verifySource (cmdNoVerify cmd) (spVerification sp) sourceBs
          targetBs <- applyForConvert sp sourceBs
          case createFromMemory (cmdConvTo cmd) sourceBs targetBs meta of
            Left err -> die err
            Right result -> do
              emitNotes (spSourceNotes sp)
              BS.writeFile outFile result
              putStrLn ("converted to " ++ fmtName (cmdConvTo cmd) ++ ": " ++ outFile)
        Nothing -> case spContents sp of
          Nothing -> die (needWithMsg sp)
          Just pc -> case convertDirect pc (cmdConvTo cmd) meta of
            Left err -> die err
            Right (result, notes) -> do
              emitNotes (spSourceNotes sp ++ notes)
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
  flip finally (removeFile tmp `catch` (\(_ :: SomeException) -> pure ())) $ do
    BS.writeFile tmp sourceBs
    apply tmp
    BS.readFile tmp

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

----------------------------------------------------------------------------
-- Verification helpers
----------------------------------------------------------------------------

verifySource :: Bool -> Verification -> BS.ByteString -> IO ()
verifySource nv v bs = do
  forM_ (vSourceCRC32 v) $ \expected ->
    checkCRC nv "source" expected (crc32 bs)
  forM_ (vSourceMD5 v) $ \expected ->
    checkHash nv "source MD5" expected (md5 bs)
  forM_ (vSourceSHA1 v) $ \expected ->
    checkHash nv "source SHA1" expected (sha1 bs)
  -- Per-block CRC16 and PPF validation are advisory (warning-only)
  unless nv $ do
    forM_ (vSourceBlocks v) $ \(off, expected) ->
      warnBlock "source" off expected (crc16 (safeSlice off 0x10000 bs))
    forM_ (vPPFBlock v) $ \(off, expected) ->
      warnPPFBlock off expected bs
    forM_ (vFileSize v) $ \expected ->
      warnFileSize expected (fromIntegral (BS.length bs))
    forM_ (vSourceBytes v) $ \(off, expected, label) ->
      warnSourceBytes label off expected bs

verifyTarget :: Bool -> Verification -> BS.ByteString -> IO ()
verifyTarget nv v bs = do
  forM_ (vTargetCRC32 v) $ \expected ->
    checkCRC nv "target" expected (crc32 bs)
  forM_ (vTargetMD5 v) $ \expected ->
    checkHash nv "target MD5" expected (md5 bs)
  unless nv $
    forM_ (vTargetBlocks v) $ \(off, expected) ->
      warnBlock "target" off expected (crc16 (safeSlice off 0x10000 bs))
  forM_ (vWindowAdler32 v) $ \(off, len, expected) ->
    checkAdler nv off expected (adler32 (safeSlice off len bs))

hasSourceV :: Verification -> Bool
hasSourceV v = isJust (vSourceCRC32 v) || isJust (vSourceMD5 v) || isJust (vSourceSHA1 v)
            || not (null (vSourceBlocks v)) || isJust (vPPFBlock v) || isJust (vFileSize v)
            || not (null (vSourceBytes v))

hasTargetV :: Verification -> Bool
hasTargetV v = isJust (vTargetCRC32 v) || isJust (vTargetMD5 v)
            || not (null (vTargetBlocks v)) || not (null (vWindowAdler32 v))

checkCRC :: Bool -> String -> Word32 -> Word32 -> IO ()
checkCRC nv label expected actual
  | expected == actual = pure ()
  | nv = warn (label ++ " CRC mismatch (expected "
               ++ fmtCRC expected ++ ", got " ++ fmtCRC actual ++ ")")
  | otherwise = die (label ++ " CRC mismatch (expected "
                     ++ fmtCRC expected ++ ", got " ++ fmtCRC actual
                     ++ ")\n  use --no-verify to apply anyway")

checkHash :: Bool -> String -> BS.ByteString -> BS.ByteString -> IO ()
checkHash nv label expected actual
  | expected == actual = pure ()
  | nv = warn (label ++ " mismatch")
  | otherwise = die (label ++ " mismatch\n  use --no-verify to apply anyway")

checkAdler :: Bool -> Int -> Word32 -> Word32 -> IO ()
checkAdler nv off expected actual
  | expected == actual = pure ()
  | nv = warn msg
  | otherwise = die (msg ++ "\n  use --no-verify to apply anyway")
  where msg = "Adler32 mismatch at window 0x" ++ padHex 8 (fromIntegral off)
            ++ " (expected " ++ fmtCRC expected ++ ", got " ++ fmtCRC actual ++ ")"

warnBlock :: String -> Int -> Word16 -> Word16 -> IO ()
warnBlock label off expected actual
  | expected == actual = pure ()
  | otherwise = warn (label ++ " CRC16 mismatch at 0x" ++ padHex 8 (fromIntegral off))

warnPPFBlock :: Int64 -> BS.ByteString -> BS.ByteString -> IO ()
warnPPFBlock off expected bs =
  let actual = safeSlice (fromIntegral off) (BS.length expected) bs
  in when (actual /= expected) $
       warn ("validation block mismatch at 0x" ++ padHex 8 (fromIntegral off))

warnFileSize :: Word32 -> Word32 -> IO ()
warnFileSize expected actual =
  when (expected /= actual) $
    warn ("file size mismatch (expected " ++ show expected ++ ", got " ++ show actual ++ ")")

warnSourceBytes :: String -> Int -> BS.ByteString -> BS.ByteString -> IO ()
warnSourceBytes label off expected bs =
  let actual = safeSlice off (BS.length expected) bs
  in when (actual /= expected) $
       warn (label ++ " mismatch at 0x" ++ padHex 8 (fromIntegral off))

safeSlice :: Int -> Int -> BS.ByteString -> BS.ByteString
safeSlice off len bs = BS.take len (BS.drop off bs)

fmtCRC :: Word32 -> String
fmtCRC w = "0x" ++ showCRC w

emitWarnings :: SomePatch -> IO ()
emitWarnings sp = forM_ (spWarnings sp) $ \w ->
  hPutStrLn stderr ("slap: warning: " ++ spFormat sp ++ ": " ++ w)

warn :: String -> IO ()
warn msg = hPutStrLn stderr ("slap: warning: " ++ msg)

die :: String -> IO a
die msg = hPutStrLn stderr ("slap: " ++ msg) >> exitFailure
