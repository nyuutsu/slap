{-# LANGUAGE OverloadedStrings #-}

module Main (main) where

import Patch.SomePatch (SomePatch(..), ApplyStrategy(..), UndoStrategy(..), Verification(..), BlockCheck(..), ValidationBlock(..), WindowCheck(..), ByteCheck(..), parseSome)
import Patch.Measure (Offset(..), Length(..), FileSize(..))
import Patch.Convert (CreateFormat(..), CreateMeta(..), createFromMemory, createDefaultNotes, convertDirect, formatExtension, formatName)
import Patch.PPF.Types (ImageType(..))
import Patch.NINJA1 (NINJA1RomType(..), fromNINJA1RomType)
import Patch.Explain (renderExplain, renderSummary)
import Patch.Archive (detectArchive, unwrapArchive)
import Patch.Binary (crc16, md5, sha1, adler32)
import Patch.FFI (rustyCRC32)
import Patch.Format (showCRC, padHex)

import qualified Data.ByteString as ByteString
import Control.Monad (when, unless, forM_)
import Data.Char (toLower)
import Data.Maybe (fromMaybe, isJust, isNothing)
import Data.Word (Word8, Word16, Word32)
import Options.Applicative
import Options.Applicative.Help.Pretty (pretty, vcat)
import System.Directory (copyFile, doesFileExist, removeFile)
import System.Exit (exitFailure, exitSuccess)
import System.FilePath (dropExtension, replaceExtension, takeBaseName, takeExtension)
import Control.Exception (IOException, catch, finally)
import System.IO (hClose, hPutStrLn, openBinaryTempFile, stderr)

----------------------------------------------------------------------------
-- Types
----------------------------------------------------------------------------

data Command
  = CommandApply
      { commandForce    :: Bool
      , commandNoVerify :: Bool
      , commandVerbose  :: Bool
      , commandInPlace :: Bool
      , commandBackup  :: Bool
      , commandDryRun  :: Bool
      , commandRaw     :: Bool
      , commandPatch   :: FilePath
      , commandSource  :: FilePath
      , commandOutput  :: Maybe FilePath
      }
  | CommandUndo
      { commandVerbose :: Bool
      , commandRaw     :: Bool
      , commandPatch   :: FilePath
      , commandSource  :: FilePath
      , commandOutput  :: Maybe FilePath
      }
  | CommandCreate
      { commandCreateFormat  :: CreateFormat
      , commandRaw        :: Bool
      , commandOriginal   :: FilePath
      , commandModified   :: FilePath
      , commandCreateOutput  :: FilePath
      , commandDescription       :: Maybe String
      , commandTitle      :: Maybe String
      , commandAuthor     :: Maybe String
      , commandUndo       :: Bool
      , commandValidate   :: Bool
      , commandVersion    :: Maybe String
      , commandUnstable   :: Bool
      , commandRomType    :: Maybe Word8
      , commandImageType  :: Maybe ImageType
      , commandMetadata   :: Maybe FilePath
      }
  | CommandConvert
      { commandConvertPatch     :: FilePath
      , commandConvertTo        :: CreateFormat
      , commandConvertOutput    :: Maybe FilePath
      , commandConvertSource      :: Maybe FilePath
      , commandRaw           :: Bool
      , commandConvertDescription      :: Maybe String
      , commandConvertTitle     :: Maybe String
      , commandConvertAuthor    :: Maybe String
      , commandConvertUndo      :: Bool
      , commandConvertValidate  :: Bool
      , commandNoVerify      :: Bool
      , commandConvertVersion   :: Maybe String
      , commandConvertUnstable  :: Bool
      , commandConvertRomType   :: Maybe Word8
      , commandConvertImageType :: Maybe ImageType
      , commandConvertMetadata  :: Maybe FilePath
      }
  | CommandInfo    { commandPatch :: FilePath, commandExtractMetadata :: Maybe FilePath }
  | CommandExplain FilePath Bool (Maybe FilePath) Bool

----------------------------------------------------------------------------
-- CLI
----------------------------------------------------------------------------

main :: IO ()
main = execParser options >>= \case
  parsedCommand@CommandApply{}   -> doApply parsedCommand
  parsedCommand@CommandUndo{}    -> doUndo parsedCommand
  parsedCommand@CommandCreate{}  -> doCreate parsedCommand
  parsedCommand@CommandConvert{} -> doConvert parsedCommand
  parsedCommand@CommandInfo{}    -> doInfo parsedCommand
  CommandExplain patchFile records maybeWithPath raw -> doExplain patchFile records maybeWithPath raw

options :: ParserInfo Command
options = info (commandParser <**> helper)
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
explainParser = CommandExplain
  <$> argument str (metavar "PATCH" <> help "Patch file to explain")
  <*> switch (long "records" <> help "Show full record-by-record dump instead of summary")
  <*> optional (option str (long "with" <> metavar "SOURCE"
      <> help "Source file (resolves delta/copy operations in output)"))
  <*> rawFlag

applyParser :: Parser Command
applyParser = constructApplyCommand
  <$> forceFlag <*> noVerifyFlag <*> yoloFlag
  <*> verboseFlag <*> inPlaceFlag <*> backupFlag <*> dryRunFlag <*> rawFlag
  <*> argument str (metavar "PATCH"  <> help "Patch file")
  <*> argument str (metavar "SOURCE" <> help "Source file to patch (not modified unless --in-place)")
  <*> outputOption
  where
    constructApplyCommand force noVerify yolo = CommandApply (force || yolo) (noVerify || yolo)
    outputOption = (Just <$> option str (long "output" <> short 'o' <> metavar "FILE"
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
undoParser = CommandUndo
  <$> verboseFlag
  <*> rawFlag
  <*> argument str (metavar "PATCH"  <> help "Patch file")
  <*> argument str (metavar "SOURCE" <> help "File to restore")
  <*> optional (option str (long "output" <> short 'o' <> metavar "FILE"
      <> help "Write restored output to FILE instead of modifying SOURCE in place"))

createParser :: Parser Command
createParser = CommandCreate
  <$> option (eitherReader parseCreateFormat) (long "format" <> metavar "FMT" <> value CreateBPS
      <> help "Output format: bps (default), ips, ips32, ebp, ups, ppf3, pmsr, ninja1, dps, rup, aps-n64, aps-gba, gdiff, pchtxt")
  <*> rawFlag
  <*> argument str (metavar "ORIGINAL" <> help "Original unmodified file")
  <*> argument str (metavar "MODIFIED" <> help "Modified file")
  <*> argument str (metavar "OUTPUT"   <> help "Output patch file")
  <*> optional (option str (long "description" <> short 'd' <> metavar "TEXT"
      <> help "Patch description (DPS/PPF3/EBP/APS-N64/RUP/PCHTXT)"))
  <*> optional (option str (long "title" <> metavar "TEXT"
      <> help "Patch title (EBP/RUP)"))
  <*> optional (option str (long "author" <> metavar "TEXT"
      <> help "Patch author (EBP/DPS/RUP)"))
  <*> switch (long "undo"     <> short 'u' <> help "Include undo data (PPF3 only)")
  <*> switch (long "validate" <> short 'v' <> help "Include validation block (PPF3 only)")
  <*> optional (option str (long "version" <> metavar "TEXT"
      <> help "Patch version (DPS/RUP)"))
  <*> switch (long "unstable" <> help "Mark patch unstable (DPS)")
  <*> optional (option (eitherReader parseRomType) (long "rom-type" <> metavar "TYPE"
      <> help "ROM type (NINJA1/RUP): raw, nes, snes, n64, gb, gbc, gba, ..."))
  <*> optional (option (eitherReader parseImageType) (long "image-type" <> metavar "TYPE"
      <> help "Image type (PPF3): bin, gi"))
  <*> optional (option str (long "metadata" <> metavar "FILE"
      <> help "Metadata file to embed (BPS)"))

convertParser :: Parser Command
convertParser = constructConvertCommand
  <$> argument str (metavar "PATCH" <> help "Patch file to convert")
  <*> option (eitherReader parseCreateFormat) (long "to" <> short 't' <> metavar "FMT"
      <> help "Target format: bps, ips, ips32, ebp, ups, ppf3, pmsr, ninja1, dps, rup, aps-n64, aps-gba, gdiff, pchtxt")
  <*> optional (option str (long "output" <> short 'o' <> metavar "FILE"
      <> help "Output file (default: replace input extension)"))
  <*> optional (option str (long "with" <> metavar "SOURCE"
      <> help "Source ROM (required for differential formats)"))
  <*> rawFlag
  <*> optional (option str (long "description" <> short 'd' <> metavar "TEXT"
      <> help "Patch description (DPS/PPF3/EBP/APS-N64/RUP/PCHTXT)"))
  <*> optional (option str (long "title" <> metavar "TEXT"
      <> help "Patch title (EBP/RUP)"))
  <*> optional (option str (long "author" <> metavar "TEXT"
      <> help "Patch author (EBP/DPS/RUP)"))
  <*> flag True False (long "no-undo" <> help "Omit undo data (PPF3 only; included by default)")
  <*> flag True False (long "no-validate" <> help "Omit validation block (PPF3 only; included by default)")
  <*> noVerifyFlag <*> yoloFlag
  <*> optional (option str (long "version" <> metavar "TEXT"
      <> help "Patch version (DPS/RUP)"))
  <*> switch (long "unstable" <> help "Mark patch unstable (DPS)")
  <*> optional (option (eitherReader parseRomType) (long "rom-type" <> metavar "TYPE"
      <> help "ROM type (NINJA1/RUP): raw, nes, snes, n64, gb, gbc, gba, ..."))
  <*> optional (option (eitherReader parseImageType) (long "image-type" <> metavar "TYPE"
      <> help "Image type (PPF3): bin, gi"))
  <*> optional (option str (long "metadata" <> metavar "FILE"
      <> help "Metadata file to embed (BPS)"))
  where
    constructConvertCommand patch targetFormat output conversionSource raw description title author undo validate noVerify yolo version unstable romType imageType metadata =
      CommandConvert patch targetFormat output conversionSource raw description title author undo validate
        (noVerify || yolo) version unstable romType imageType metadata

parseCreateFormat :: String -> Either String CreateFormat
parseCreateFormat formatString = case map toLower formatString of
  "bps"     -> Right CreateBPS
  "ips"     -> Right CreateIPS
  "ips32"   -> Right CreateIPS32
  "ebp"     -> Right CreateEBP
  "ups"     -> Right CreateUPS
  "ppf3"    -> Right CreatePPF3
  "ppf"     -> Right CreatePPF3
  "pmsr"    -> Right CreatePMSR
  "ninja1"  -> Right CreateNINJA1
  "dps"     -> Right CreateDPS
  "rup"     -> Right CreateRUP
  "ninja2"  -> Right CreateRUP
  "aps-n64" -> Right CreateAPSN64
  "apsn64"  -> Right CreateAPSN64
  "aps-gba" -> Right CreateAPSGBA
  "apsgba"  -> Right CreateAPSGBA
  "gdiff"   -> Right CreateGDIFF
  "pchtxt"  -> Right CreatePCHTXT
  _ -> Left ("unknown format: " ++ formatString ++ "\n  expected: bps, ips, ips32, ebp, ups, ppf3, pmsr, ninja1, dps, rup, aps-n64, aps-gba, gdiff, pchtxt")

parseRomType :: String -> Either String Word8
parseRomType typeString = case map toLower typeString of
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
  _ -> Left ("unknown ROM type: " ++ typeString
    ++ "\n  expected: raw, nes, snes, n64, gb, gbc, gba, ngp, ngpc, sms, gg, mega, pce, ws, wsc, lynx, jag, gp32")

parseImageType :: String -> Either String ImageType
parseImageType typeString = case map toLower typeString of
  "bin" -> Right BIN
  "gi"  -> Right GI
  _ -> Left ("unknown image type: " ++ typeString ++ "\n  expected: bin, gi")

patchInfoParser :: Parser Command
patchInfoParser = CommandInfo
  <$> argument str (metavar "PATCH" <> help "Patch file to inspect")
  <*> optional (option str (long "extract-metadata" <> metavar "FILE"
      <> help "Write embedded metadata to FILE (BPS)"))

----------------------------------------------------------------------------
-- Archive-aware file reading
----------------------------------------------------------------------------

-- | Read a file, transparently unwrapping single-entry archives.
readUnwrap :: FilePath -> IO ByteString.ByteString
readUnwrap path = do
  fileBytes <- ByteString.readFile path
  case detectArchive (ByteString.take 8 fileBytes) of
    Nothing -> pure fileBytes
    Just format -> do
      result <- unwrapArchive format path
      case result of
        Left errorMessage -> die errorMessage
        Right (unwrappedBytes, entryName) -> do
          hPutStrLn stderr ("slap: unwrapped " ++ path ++ " \8594 " ++ entryName)
          pure unwrappedBytes

-- | Read a file, skipping unwrap if raw=True.
readMaybeUnwrap :: Bool -> FilePath -> IO ByteString.ByteString
readMaybeUnwrap True  = ByteString.readFile
readMaybeUnwrap False = readUnwrap

----------------------------------------------------------------------------
-- Info & Explain
----------------------------------------------------------------------------

doInfo :: Command -> IO ()
doInfo parsedCommand = do
  patchBytes <- readUnwrap (commandPatch parsedCommand)
  case parseSome patchBytes of
    Left errorMessage -> die errorMessage
    Right parsed -> do
      putStr (patchInfo parsed)
      emitWarnings parsed
      case commandExtractMetadata parsedCommand of
        Nothing -> pure ()
        Just outPath -> case patchMetadata parsed of
          Nothing   -> hPutStrLn stderr "slap: no metadata in this patch"
          Just metadataBytes -> do
            ByteString.writeFile outPath metadataBytes
            putStrLn ("wrote metadata to " ++ outPath)

doExplain :: FilePath -> Bool -> Maybe FilePath -> Bool -> IO ()
doExplain patchFile records maybeWithPath raw = do
  patchBytes <- readUnwrap patchFile
  case parseSome patchBytes of
    Left errorMessage -> die errorMessage
    Right parsed -> do
      maybeSource <- case maybeWithPath of
        Nothing   -> pure Nothing
        Just path -> Just <$> readMaybeUnwrap raw path
      let renderFunction = if records then renderExplain else renderSummary
      putStr (renderFunction maybeSource (patchExplain parsed))
      emitWarnings parsed

----------------------------------------------------------------------------
-- Apply
----------------------------------------------------------------------------

doApply :: Command -> IO ()
doApply parsedCommand = do
  patchBytes <- readUnwrap (commandPatch parsedCommand)
  case parseSome patchBytes of
    Left errorMessage -> die errorMessage
    Right parsed -> do
      emitWarnings parsed
      when (commandVerbose parsedCommand) $
        mapM_ (hPutStrLn stderr) (patchVerboseLines parsed)

      let outputPath
            | commandInPlace parsedCommand         = commandSource parsedCommand
            | Just destination <- commandOutput parsedCommand = destination
            | otherwise              = deriveOutput (commandPatch parsedCommand) (commandSource parsedCommand)
          verification = patchVerification parsed
          noVerify = commandNoVerify parsedCommand

      -- Dry run: report and exit
      when (commandDryRun parsedCommand) $ do
        putStrLn $ "would apply " ++ show (patchRecordCount parsed) ++ " " ++ patchRecordUnit parsed
                ++ " \8594 " ++ outputPath
        case verifySourceCRC32 verification of
          Just expected -> do
            sourceBytes <- readMaybeUnwrap (commandRaw parsedCommand) (commandSource parsedCommand)
            let actual = rustyCRC32 sourceBytes
            putStrLn $ "source CRC: " ++ formatCRC actual
              ++ if actual == expected then " \10003" else " \10007 (expected " ++ formatCRC expected ++ ")"
          Nothing -> pure ()
        exitSuccess

      -- Refuse to overwrite unless --force or --in-place
      unless (commandInPlace parsedCommand || commandForce parsedCommand) $ do
        exists <- doesFileExist outputPath
        when exists $
          die (outputPath ++ " already exists (use --force to overwrite)")

      -- Backup for --in-place
      when (commandInPlace parsedCommand && commandBackup parsedCommand) $ do
        let backup = commandSource parsedCommand ++ ".bak"
        copyFile (commandSource parsedCommand) backup
        hPutStrLn stderr ("slap: backup: " ++ backup)

      case patchApply parsed of
        InPlace applyInPlace -> do
          -- Read source for pre-apply verification if needed
          when (hasSourceVerification verification) $ do
            sourceBytes <- readMaybeUnwrap (commandRaw parsedCommand) (commandSource parsedCommand)
            verifySource noVerify verification sourceBytes
          unless (commandInPlace parsedCommand) $
            copyFile (commandSource parsedCommand) outputPath
          applyInPlace (if commandInPlace parsedCommand then commandSource parsedCommand else outputPath)
          -- Post-apply target verification if needed
          when (hasTargetVerification verification) $ do
            targetBytes <- ByteString.readFile (if commandInPlace parsedCommand then commandSource parsedCommand else outputPath)
            verifyTarget noVerify verification targetBytes
          putStrLn $ "applied " ++ show (patchRecordCount parsed) ++ " " ++ patchRecordUnit parsed
                  ++ " \8594 " ++ outputPath
        InMemory { inMemoryApply = apply } -> do
          sourceBytes <- readMaybeUnwrap (commandRaw parsedCommand) (commandSource parsedCommand)
          verifySource noVerify verification sourceBytes
          result <- apply sourceBytes
          case result of
            Left errorMessage -> die errorMessage
            Right target -> do
              verifyTarget noVerify verification target
              ByteString.writeFile outputPath target
              putStrLn $ "applied " ++ show (patchRecordCount parsed) ++ " " ++ patchRecordUnit parsed
                      ++ " \8594 " ++ outputPath

----------------------------------------------------------------------------
-- Undo
----------------------------------------------------------------------------

doUndo :: Command -> IO ()
doUndo parsedCommand = do
  patchBytes <- readUnwrap (commandPatch parsedCommand)
  case parseSome patchBytes of
    Left errorMessage -> die errorMessage
    Right parsed -> do
      emitWarnings parsed
      case patchUndo parsed of
        Nothing -> die "undo not supported for this format"
        Just (UndoInPlace undoInPlace) -> do
          undoPath <- resolveOutput (commandSource parsedCommand) (commandOutput parsedCommand)
          result <- undoInPlace undoPath
          case result of
            Left errorMessage -> die errorMessage
            Right count -> putStrLn ("reverted " ++ show count ++ " records")
        Just (UndoInMemory revert) -> do
          modified <- ByteString.readFile (commandSource parsedCommand)
          let result = revert modified
          ByteString.writeFile (fromMaybe (commandSource parsedCommand) (commandOutput parsedCommand)) result
          putStrLn "reverted (UPS self-inverse)"

----------------------------------------------------------------------------
-- Create
----------------------------------------------------------------------------

doCreate :: Command -> IO ()
doCreate parsedCommand = do
  originalBytes <- readMaybeUnwrap (commandRaw parsedCommand) (commandOriginal parsedCommand)
  modifiedBytes <- readMaybeUnwrap (commandRaw parsedCommand) (commandModified parsedCommand)
  maybeMeta <- case commandMetadata parsedCommand of
    Nothing   -> pure Nothing
    Just path -> Just <$> ByteString.readFile path
  let createMeta = CreateMeta
        { metaTitle       = commandTitle parsedCommand
        , metaAuthor      = commandAuthor parsedCommand
        , metaDescription        = commandDescription parsedCommand
        , metaVersion     = commandVersion parsedCommand
        , metaUndo        = commandUndo parsedCommand
        , metaValidate    = commandValidate parsedCommand
        , metaUnstable    = commandUnstable parsedCommand
        , metaRomType     = commandRomType parsedCommand
        , metaImageType   = commandImageType parsedCommand
        , metaBPSMetadata = maybeMeta
        }
  let defaultNotes = createDefaultNotes (commandCreateFormat parsedCommand) createMeta
  forM_ defaultNotes $ \note -> hPutStrLn stderr ("slap: " ++ note)
  case createFromMemory (commandCreateFormat parsedCommand) originalBytes modifiedBytes createMeta of
    Left errorMessage -> die errorMessage
    Right patchBytes -> do
      ByteString.writeFile (commandCreateOutput parsedCommand) patchBytes
      putStrLn ("wrote " ++ commandCreateOutput parsedCommand)

----------------------------------------------------------------------------
-- Convert
----------------------------------------------------------------------------

doConvert :: Command -> IO ()
doConvert parsedCommand = do
  patchBytes <- readUnwrap (commandConvertPatch parsedCommand)
  case parseSome patchBytes of
    Left errorMessage -> die errorMessage
    Right parsed -> do
      emitWarnings parsed
      let outputFile = fromMaybe (replaceExtension (commandConvertPatch parsedCommand) (formatExtension (commandConvertTo parsedCommand))) (commandConvertOutput parsedCommand)
      maybeMetadata <- case commandConvertMetadata parsedCommand of
        Nothing   -> pure Nothing
        Just path -> Just <$> ByteString.readFile path
      let createMeta = CreateMeta
            { metaTitle       = commandConvertTitle parsedCommand
            , metaAuthor      = commandConvertAuthor parsedCommand
            , metaDescription        = commandConvertDescription parsedCommand
            , metaVersion     = commandConvertVersion parsedCommand
            , metaUndo        = commandConvertUndo parsedCommand
            , metaValidate    = commandConvertValidate parsedCommand
            , metaUnstable    = commandConvertUnstable parsedCommand
            , metaRomType     = commandConvertRomType parsedCommand
            , metaImageType   = commandConvertImageType parsedCommand
            , metaBPSMetadata = maybeMetadata
            }
      let printNotes notes = forM_ notes $ \note -> hPutStrLn stderr ("slap: " ++ note)
          metaNotes = case patchMetadata parsed of
            Nothing -> []
            Just metaBytes ->
              let metaSize = ByteString.length metaBytes
              in if commandConvertTo parsedCommand == CreateBPS
                 then ["note: source has " ++ show metaSize ++ " bytes of BPS metadata; use --metadata FILE to carry it forward"
                      | isNothing (metaBPSMetadata createMeta)]
                 else ["note: dropping BPS metadata (" ++ show metaSize ++ " bytes)"]
      case commandConvertSource parsedCommand of
        Just sourcePath -> do
          -- --with provided: always use apply-and-recreate path
          sourceBytes <- readMaybeUnwrap (commandRaw parsedCommand) sourcePath
          verifySource (commandNoVerify parsedCommand) (patchVerification parsed) sourceBytes
          targetBytes <- applyForConvert parsed sourceBytes
          case createFromMemory (commandConvertTo parsedCommand) sourceBytes targetBytes createMeta of
            Left errorMessage -> die errorMessage
            Right result -> do
              printNotes (patchSourceNotes parsed ++ metaNotes ++ createDefaultNotes (commandConvertTo parsedCommand) createMeta)
              ByteString.writeFile outputFile result
              putStrLn ("converted to " ++ formatName (commandConvertTo parsedCommand) ++ ": " ++ outputFile)
        Nothing -> case patchContents parsed of
          Nothing -> die (needSourceMessage parsed)
          Just contents -> case convertDirect contents (commandConvertTo parsedCommand) createMeta of
            Left errorMessage -> die errorMessage
            Right (result, notes) -> do
              printNotes (patchSourceNotes parsed ++ notes)
              ByteString.writeFile outputFile result
              putStrLn ("converted to " ++ formatName (commandConvertTo parsedCommand) ++ ": " ++ outputFile)

-- | Apply a parsed patch to source bytes, returning target bytes (for convert).
applyForConvert :: SomePatch -> ByteString.ByteString -> IO ByteString.ByteString
applyForConvert somePatch sourceBytes = case patchApply somePatch of
  InMemory { inMemoryApply = apply } -> do
    result <- apply sourceBytes
    case result of
      Left errorMessage -> die errorMessage
      Right target      -> pure target
  InPlace applyInPlace -> applyViaTemporary sourceBytes applyInPlace

-- | Apply a file-handle patch via a temporary file and read back the result.
applyViaTemporary :: ByteString.ByteString -> (FilePath -> IO ()) -> IO ByteString.ByteString
applyViaTemporary sourceBytes apply = do
  (temporaryPath, handle) <- openBinaryTempFile "/tmp" "slap.tmp"
  hClose handle
  flip finally (removeFile temporaryPath `catch` (\(_ :: IOException) -> pure ())) $ do
    ByteString.writeFile temporaryPath sourceBytes
    apply temporaryPath
    ByteString.readFile temporaryPath

-- | Error message when --with is required but not provided.
needSourceMessage :: SomePatch -> String
needSourceMessage somePatch = "converting from " ++ name ++ " requires the original ROM (--with SOURCE)\n"
  ++ name ++ " " ++ reason ++ " \8212 the original ROM is needed\nto reconstruct the target file for re-encoding."
  where
    name = patchFormat somePatch
    reason
      | patchIsDifferential somePatch = "stores differential data, not raw bytes"
      | otherwise                  = "applies in-place to the target file"

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

verifySource :: Bool -> Verification -> ByteString.ByteString -> IO ()
verifySource noVerify verification sourceBytes = do
  let preprocessed = verifySourcePreHash verification sourceBytes
  forM_ (verifySourceCRC32 verification) $ \expected ->
    checkCRC noVerify "source" expected (rustyCRC32 preprocessed)
  forM_ (verifySourceMD5 verification) $ \expected ->
    checkHash noVerify "source MD5" expected (md5 preprocessed)
  forM_ (verifySourceSHA1 verification) $ \expected ->
    checkHash noVerify "source SHA1" expected (sha1 preprocessed)
  -- Per-block CRC16 and PPF validation are advisory (warning-only)
  unless noVerify $ do
    forM_ (verifySourceBlocks verification) $ \(BlockCheck blockOffset expectedCRC) ->
      warnBlock "source" blockOffset expectedCRC (crc16 (safeSlice (fromIntegral (unOffset blockOffset)) 0x10000 sourceBytes))
    forM_ (verifyPPFBlock verification) $ \(ValidationBlock blockOffset expectedData) ->
      warnPPFBlock blockOffset expectedData sourceBytes
    forM_ (verifyFileSize verification) $ \expectedSize ->
      warnFileSize expectedSize (FileSize (fromIntegral (ByteString.length sourceBytes)))
    forM_ (verifySourceBytes verification) $ \(ByteCheck checkOffset expectedData checkLabel) ->
      warnSourceBytes checkLabel checkOffset expectedData sourceBytes

verifyTarget :: Bool -> Verification -> ByteString.ByteString -> IO ()
verifyTarget noVerify verification targetBytes = do
  forM_ (verifyTargetCRC32 verification) $ \expected ->
    checkCRC noVerify "target" expected (rustyCRC32 targetBytes)
  forM_ (verifyTargetMD5 verification) $ \expected ->
    checkHash noVerify "target MD5" expected (md5 targetBytes)
  unless noVerify $
    forM_ (verifyTargetBlocks verification) $ \(BlockCheck blockOffset expectedCRC) ->
      warnBlock "target" blockOffset expectedCRC (crc16 (safeSlice (fromIntegral (unOffset blockOffset)) 0x10000 targetBytes))
  forM_ (verifyWindowAdler32 verification) $ \(WindowCheck windowOffset windowLength expectedChecksum) ->
    checkAdler noVerify windowOffset expectedChecksum (adler32 (safeSlice (fromIntegral (unOffset windowOffset)) (unLength windowLength) targetBytes))

hasSourceVerification :: Verification -> Bool
hasSourceVerification verification = or
  [ isJust (verifySourceCRC32 verification), isJust (verifySourceMD5 verification), isJust (verifySourceSHA1 verification)
  , not (null (verifySourceBlocks verification)), isJust (verifyPPFBlock verification), isJust (verifyFileSize verification)
  , not (null (verifySourceBytes verification))
  ]

hasTargetVerification :: Verification -> Bool
hasTargetVerification verification = or
  [ isJust (verifyTargetCRC32 verification), isJust (verifyTargetMD5 verification)
  , not (null (verifyTargetBlocks verification)), not (null (verifyWindowAdler32 verification))
  ]

checkCRC :: Bool -> String -> Word32 -> Word32 -> IO ()
checkCRC noVerify label expected actual
  | expected == actual = pure ()
  | noVerify = warn (label ++ " CRC mismatch (expected "
               ++ formatCRC expected ++ ", got " ++ formatCRC actual ++ ")")
  | otherwise = die (label ++ " CRC mismatch (expected "
                     ++ formatCRC expected ++ ", got " ++ formatCRC actual
                     ++ ")\n  use --no-verify to apply anyway")

checkHash :: Bool -> String -> ByteString.ByteString -> ByteString.ByteString -> IO ()
checkHash noVerify label expected actual
  | expected == actual = pure ()
  | noVerify = warn (label ++ " mismatch")
  | otherwise = die (label ++ " mismatch\n  use --no-verify to apply anyway")

checkAdler :: Bool -> Offset -> Word32 -> Word32 -> IO ()
checkAdler noVerify windowOffset expected actual
  | expected == actual = pure ()
  | noVerify = warn message
  | otherwise = die (message ++ "\n  use --no-verify to apply anyway")
  where message = "Adler32 mismatch at window 0x" ++ padHex 8 (fromIntegral (unOffset windowOffset))
            ++ " (expected " ++ formatCRC expected ++ ", got " ++ formatCRC actual ++ ")"

warnBlock :: String -> Offset -> Word16 -> Word16 -> IO ()
warnBlock label blockOffset expected actual
  | expected == actual = pure ()
  | otherwise = warn (label ++ " CRC16 mismatch at 0x" ++ padHex 8 (fromIntegral (unOffset blockOffset)))

warnPPFBlock :: Offset -> ByteString.ByteString -> ByteString.ByteString -> IO ()
warnPPFBlock blockOffset expectedData sourceBytes =
  let actual = safeSlice (fromIntegral (unOffset blockOffset)) (ByteString.length expectedData) sourceBytes
  in when (actual /= expectedData) $
       warn ("validation block mismatch at 0x" ++ padHex 8 (fromIntegral (unOffset blockOffset)))

warnFileSize :: FileSize -> FileSize -> IO ()
warnFileSize (FileSize expectedSize) (FileSize actualSize) =
  when (expectedSize /= actualSize) $
    warn ("file size mismatch (expected " ++ show expectedSize ++ ", got " ++ show actualSize ++ ")")

warnSourceBytes :: String -> Offset -> ByteString.ByteString -> ByteString.ByteString -> IO ()
warnSourceBytes label checkOffset expectedData sourceBytes =
  let actual = safeSlice (fromIntegral (unOffset checkOffset)) (ByteString.length expectedData) sourceBytes
  in when (actual /= expectedData) $
       warn (label ++ " mismatch at 0x" ++ padHex 8 (fromIntegral (unOffset checkOffset)))

safeSlice :: Int -> Int -> ByteString.ByteString -> ByteString.ByteString
safeSlice offset sliceLength input = ByteString.take sliceLength (ByteString.drop offset input)

formatCRC :: Word32 -> String
formatCRC crcValue = "0x" ++ showCRC crcValue

emitWarnings :: SomePatch -> IO ()
emitWarnings somePatch = forM_ (patchWarnings somePatch) $ \warning ->
  hPutStrLn stderr ("slap: warning: " ++ patchFormat somePatch ++ ": " ++ warning)

warn :: String -> IO ()
warn message = hPutStrLn stderr ("slap: warning: " ++ message)

die :: String -> IO a
die message = hPutStrLn stderr ("slap: " ++ message) >> exitFailure
