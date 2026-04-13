{-# LANGUAGE ApplicativeDo #-}
{-# LANGUAGE OverloadedStrings #-}

module Main (main) where

import Slap.SomePatch (SomePatch(..), RecordSummary(..), ApplyStrategy(..), UndoStrategy(..), Verification(..), BlockCheck(..), ValidationBlock(..), WindowCheck(..), ByteCheck(..), parseSome)
import Slap.FileContents (SourceFileContents(..), TargetFileContents(..), PatchFileContents(..))
import Slap.Measure (Offset(..), Length(..), FileSize(..))
import Slap.Convert (DirectCreate(..), DiffCreate(..), CreateFormat(..), CreateMeta(..), PatchEncoding(..), createFromMemory, createDefaultNotes, convertDirect, mergeMeta, formatExtension, formatName)
import Slap.PPF.Types (PPFImageType(..))
import Slap.Platform (PlatformType(..))
import Slap.Archive (detectArchive, unwrapArchive)
import Slap.Binary (crc16, md5, sha1, adler32)
import Slap.Checksum (CRC32(..), CRC16(..), Adler32(..), MD5Hash(..), SHA1Hash(..), showCRC32, showAdler32)
import Slap.FFI (rustyCRC32)
import Slap.Error (SlapError, SlapWarning(..), CreateResult(..), renderSlapError, renderSlapWarning)
import Slap.Format (MetaField(..), padHex, renderField)
import Slap.FormatLabel (formatLabelName)
import Slap.Explain (ExplainData(..), renderExplain, renderSummary)

import qualified Data.ByteString as ByteString
import Control.Monad (when, unless, forM_)
import Data.Char (toLower)
import Data.Maybe (fromMaybe, isNothing)
import Options.Applicative
import Options.Applicative.Help.Pretty (pretty, vcat)
import System.Directory (copyFile, doesFileExist)
import System.Exit (exitFailure, exitSuccess)
import System.FilePath (dropExtension, replaceExtension, takeBaseName, takeExtension)
import System.IO (hPutStr, hPutStrLn, stderr)

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
      , commandUndo       :: Maybe Bool
      , commandValidate   :: Maybe Bool
      , commandVersion    :: Maybe String
      , commandUnstable   :: Maybe Bool
      , commandRomType    :: Maybe PlatformType
      , commandImageType  :: Maybe PPFImageType
      , commandGenre      :: Maybe String
      , commandLanguage   :: Maybe String
      , commandDate       :: Maybe String
      , commandWebsite    :: Maybe String
      , commandPatchEncoding :: PatchEncoding
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
      , commandConvertUndo      :: Maybe Bool
      , commandConvertValidate  :: Maybe Bool
      , commandNoVerify      :: Bool
      , commandConvertVersion   :: Maybe String
      , commandConvertUnstable  :: Maybe Bool
      , commandConvertRomType   :: Maybe PlatformType
      , commandConvertImageType :: Maybe PPFImageType
      , commandConvertGenre     :: Maybe String
      , commandConvertLanguage  :: Maybe String
      , commandConvertDate      :: Maybe String
      , commandConvertWebsite   :: Maybe String
      , commandConvertPatchEncoding :: PatchEncoding
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
applyParser = do
    force <- forceFlag
    noVerify <- noVerifyFlag
    verbose <- verboseFlag
    inPlace <- inPlaceFlag
    backup <- backupFlag
    dryRun <- dryRunFlag
    raw <- rawFlag
    patch <- argument str (metavar "PATCH" <> help "Patch file")
    source <- argument str (metavar "SOURCE" <> help "Source file to patch (not modified unless --in-place)")
    output <- outputOption
    pure CommandApply
      { commandForce = force
      , commandNoVerify = noVerify
      , commandVerbose = verbose
      , commandInPlace = inPlace
      , commandBackup = backup
      , commandDryRun = dryRun
      , commandRaw = raw
      , commandPatch = patch
      , commandSource = source
      , commandOutput = output
      }
  where
    outputOption = (Just <$> option str (long "output" <> short 'o' <> metavar "FILE"
                  <> help "Write patched output to FILE"))
            <|> optional (argument str (metavar "OUTPUT"))

forceFlag :: Parser Bool
forceFlag = switch (long "force" <> short 'f' <> help "Overwrite existing output files")

noVerifyFlag :: Parser Bool
noVerifyFlag = switch (long "no-verify" <> help "Skip checksum validation (mismatches become warnings)")

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
undoParser = do
    verbose <- verboseFlag
    raw <- rawFlag
    patch <- argument str (metavar "PATCH" <> help "Patch file")
    source <- argument str (metavar "SOURCE" <> help "File to restore")
    output <- optional (option str (long "output" <> short 'o' <> metavar "FILE"
        <> help "Write restored output to FILE instead of modifying SOURCE in place"))
    pure CommandUndo
      { commandVerbose = verbose
      , commandRaw = raw
      , commandPatch = patch
      , commandSource = source
      , commandOutput = output
      }

createParser :: Parser Command
createParser = do
    createFormat <- option (eitherReader parseCreateFormat) (long "format" <> metavar "FMT" <> value (CreateDiff CreateBPS)
        <> help "Output format: bps (default), ips, ips32, ebp, ups, ppf3, pmsr, ninja1, ninja2, dps, aps-n64, aps-gba, gdiff, pchtxt")
    raw <- rawFlag
    original <- argument str (metavar "ORIGINAL" <> help "Original unmodified file")
    modified <- argument str (metavar "MODIFIED" <> help "Modified file")
    outputFile <- argument str (metavar "OUTPUT" <> help "Output patch file")
    description <- optional (option str (long "description" <> short 'd' <> metavar "TEXT"
        <> help "Patch description (DPS/PPF3/EBP/APS-N64/NINJA2/PCHTXT)"))
    title <- optional (option str (long "title" <> metavar "TEXT"
        <> help "Patch title (EBP/NINJA2)"))
    author <- optional (option str (long "author" <> metavar "TEXT"
        <> help "Patch author (EBP/DPS/NINJA2)"))
    includeUndo <- optional (flag' True (long "undo" <> short 'u' <> help "Include undo data (PPF3 only)"))
    includeValidation <- optional (flag' True (long "validate" <> short 'v' <> help "Include validation block (PPF3 only)"))
    version <- optional (option str (long "version" <> metavar "TEXT"
        <> help "Patch version (DPS/NINJA2)"))
    unstable <- optional (flag' True (long "unstable" <> help "Mark patch unstable (DPS)"))
    romType <- optional (option (eitherReader parseRomType) (long "rom-type" <> metavar "TYPE"
        <> help "ROM type (NINJA1/NINJA2): raw, nes, fds, snes, n64, gb, gbc, gba, ..."))
    imageType <- optional (option (eitherReader parseImageType) (long "image-type" <> metavar "TYPE"
        <> help "Image type (PPF3): bin, gi"))
    genre <- optional (option str (long "genre" <> metavar "TEXT"
        <> help "Genre (NINJA2)"))
    language <- optional (option str (long "language" <> metavar "TEXT"
        <> help "Language (NINJA2)"))
    date <- optional (option str (long "date" <> metavar "YYYYMMDD"
        <> help "Date (NINJA2)"))
    website <- optional (option str (long "website" <> metavar "URL"
        <> help "Website (NINJA2)"))
    patchEncoding <- option (eitherReader parsePatchEncoding) (long "patch-encoding" <> metavar "ENC"
        <> value PatchEncodingUTF8
        <> help "Text encoding for NINJA2 metadata: utf8 (default), system")
    metadataFile <- optional (option str (long "metadata" <> metavar "FILE"
        <> help "Metadata file to embed (BPS)"))
    pure CommandCreate
      { commandCreateFormat = createFormat
      , commandRaw = raw
      , commandOriginal = original
      , commandModified = modified
      , commandCreateOutput = outputFile
      , commandDescription = description
      , commandTitle = title
      , commandAuthor = author
      , commandUndo = includeUndo
      , commandValidate = includeValidation
      , commandVersion = version
      , commandUnstable = unstable
      , commandRomType = romType
      , commandImageType = imageType
      , commandGenre = genre
      , commandLanguage = language
      , commandDate = date
      , commandWebsite = website
      , commandPatchEncoding = patchEncoding
      , commandMetadata = metadataFile
      }

convertParser :: Parser Command
convertParser = do
    patchFile <- argument str (metavar "PATCH" <> help "Patch file to convert")
    targetFormat <- option (eitherReader parseCreateFormat) (long "to" <> short 't' <> metavar "FMT"
        <> help "Target format: bps, ips, ips32, ebp, ups, ppf3, pmsr, ninja1, ninja2, dps, aps-n64, aps-gba, gdiff, pchtxt")
    outputFile <- optional (option str (long "output" <> short 'o' <> metavar "FILE"
        <> help "Output file (default: replace input extension)"))
    conversionSource <- optional (option str (long "with" <> metavar "SOURCE"
        <> help "Source ROM (required for differential formats)"))
    raw <- rawFlag
    description <- optional (option str (long "description" <> short 'd' <> metavar "TEXT"
        <> help "Patch description (DPS/PPF3/EBP/APS-N64/NINJA2/PCHTXT)"))
    title <- optional (option str (long "title" <> metavar "TEXT"
        <> help "Patch title (EBP/NINJA2)"))
    author <- optional (option str (long "author" <> metavar "TEXT"
        <> help "Patch author (EBP/DPS/NINJA2)"))
    includeUndo <- optional (flag' True (long "undo" <> help "Include undo data (PPF3)")
                         <|> flag' False (long "no-undo" <> help "Omit undo data (PPF3)"))
    includeValidation <- optional (flag' True (long "validate" <> help "Include validation block (PPF3)")
                               <|> flag' False (long "no-validate" <> help "Omit validation block (PPF3)"))
    noVerify <- noVerifyFlag
    version <- optional (option str (long "version" <> metavar "TEXT"
        <> help "Patch version (DPS/NINJA2)"))
    unstable <- optional (flag' True (long "unstable" <> help "Mark patch unstable (DPS)"))
    romType <- optional (option (eitherReader parseRomType) (long "rom-type" <> metavar "TYPE"
        <> help "ROM type (NINJA1/NINJA2): raw, nes, fds, snes, n64, gb, gbc, gba, ..."))
    imageType <- optional (option (eitherReader parseImageType) (long "image-type" <> metavar "TYPE"
        <> help "Image type (PPF3): bin, gi"))
    genre <- optional (option str (long "genre" <> metavar "TEXT"
        <> help "Genre (NINJA2)"))
    language <- optional (option str (long "language" <> metavar "TEXT"
        <> help "Language (NINJA2)"))
    date <- optional (option str (long "date" <> metavar "YYYYMMDD"
        <> help "Date (NINJA2)"))
    website <- optional (option str (long "website" <> metavar "URL"
        <> help "Website (NINJA2)"))
    patchEncoding <- option (eitherReader parsePatchEncoding) (long "patch-encoding" <> metavar "ENC"
        <> value PatchEncodingUTF8
        <> help "Text encoding for NINJA2 metadata: utf8 (default), system")
    metadataFile <- optional (option str (long "metadata" <> metavar "FILE"
        <> help "Metadata file to embed (BPS)"))
    pure CommandConvert
      { commandConvertPatch = patchFile
      , commandConvertTo = targetFormat
      , commandConvertOutput = outputFile
      , commandConvertSource = conversionSource
      , commandRaw = raw
      , commandConvertDescription = description
      , commandConvertTitle = title
      , commandConvertAuthor = author
      , commandConvertUndo = includeUndo
      , commandConvertValidate = includeValidation
      , commandNoVerify = noVerify
      , commandConvertVersion = version
      , commandConvertUnstable = unstable
      , commandConvertRomType = romType
      , commandConvertImageType = imageType
      , commandConvertGenre = genre
      , commandConvertLanguage = language
      , commandConvertDate = date
      , commandConvertWebsite = website
      , commandConvertPatchEncoding = patchEncoding
      , commandConvertMetadata = metadataFile
      }

parseCreateFormat :: String -> Either String CreateFormat
parseCreateFormat formatString = case map toLower formatString of
  "bps"     -> Right (CreateDiff CreateBPS)
  "ips"     -> Right (CreateDirect CreateIPS)
  "ips32"   -> Right (CreateDirect CreateIPS32)
  "ebp"     -> Right (CreateDirect CreateEBP)
  "ups"     -> Right (CreateDiff CreateUPS)
  "ppf3"    -> Right (CreateDirect CreatePPF3)
  "ppf"     -> Right (CreateDirect CreatePPF3)
  "pmsr"    -> Right (CreateDirect CreatePMSR)
  "ninja1"  -> Right (CreateDirect CreateNINJA1)
  "dps"     -> Right (CreateDiff CreateDPS)
  "ninja2"  -> Right (CreateDiff CreateNINJA2)
  "aps-n64" -> Right (CreateDirect CreateAPSN64)
  "apsn64"  -> Right (CreateDirect CreateAPSN64)
  "aps-gba" -> Right (CreateDiff CreateAPSGBA)
  "apsgba"  -> Right (CreateDiff CreateAPSGBA)
  "gdiff"   -> Right (CreateDiff CreateGDIFF)
  "pchtxt"  -> Right (CreateDirect CreatePCHTXT)
  _ -> Left ("unknown format: " ++ formatString ++ "\n  expected: bps, ips, ips32, ebp, ups, ppf3, pmsr, ninja1, ninja2, dps, aps-n64, aps-gba, gdiff, pchtxt")

parsePatchEncoding :: String -> Either String PatchEncoding
parsePatchEncoding encodingString = case map toLower encodingString of
  "utf8"   -> Right PatchEncodingUTF8
  "utf-8"  -> Right PatchEncodingUTF8
  "system" -> Right PatchEncodingSystem
  _ -> Left ("unknown patch encoding: " ++ encodingString ++ "\n  expected: utf8, system")

parseRomType :: String -> Either String PlatformType
parseRomType typeString = case map toLower typeString of
  "raw"  -> Right PlatformRaw
  "nes"  -> Right PlatformNES
  "fds"  -> Right PlatformFDS
  "snes" -> Right PlatformSNES
  "n64"  -> Right PlatformN64
  "gb"   -> Right PlatformGB
  "gbc"  -> Right PlatformGBC
  "gba"  -> Right PlatformGBA
  "ngp"  -> Right PlatformNGP
  "ngpc" -> Right PlatformNGPC
  "sms"  -> Right PlatformSMS
  "gg"   -> Right PlatformGameGear
  "mega" -> Right PlatformGenesis
  "pce"  -> Right PlatformPCEngine
  "ws"   -> Right PlatformWonderSwan
  "wsc"  -> Right PlatformWonderSwanColor
  "lynx" -> Right PlatformLynx
  "jag"  -> Right PlatformJaguar
  "gp32" -> Right PlatformGP32
  _ -> Left ("unknown ROM type: " ++ typeString
    ++ "\n  expected: raw, nes, fds, snes, n64, gb, gbc, gba, ngp, ngpc, sms, gg, mega, pce, ws, wsc, lynx, jag, gp32")

parseImageType :: String -> Either String PPFImageType
parseImageType typeString = case map toLower typeString of
  "bin" -> Right BIN
  "gi"  -> Right GI
  _ -> Left ("unknown image type: " ++ typeString ++ "\n  expected: bin, gi")

patchInfoParser :: Parser Command
patchInfoParser = do
    patchFile <- argument str (metavar "PATCH" <> help "Patch file to inspect")
    extractMetadataPath <- optional (option str (long "extract-metadata" <> metavar "FILE"
        <> help "Write embedded metadata to FILE (BPS)"))
    pure CommandInfo
      { commandPatch = patchFile
      , commandExtractMetadata = extractMetadataPath
      }

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
  case parseSome (PatchFileContents patchBytes) of
    Left slapError -> dieError slapError
    Right parsed -> do
      let explain = patchExplain parsed
          summary = patchRecordSummary parsed
      putStrLn $ "format:      " ++ explainFormat explain
      mapM_ (putStrLn . renderField) (explainHeader explain)
      putStrLn $ renderField (MetaField (recordUnit summary) (show (recordCount summary)))
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
  case parseSome (PatchFileContents patchBytes) of
    Left slapError -> dieError slapError
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
  case parseSome (PatchFileContents patchBytes) of
    Left slapError -> dieError slapError
    Right parsed -> do
      emitWarnings parsed
      when (commandVerbose parsedCommand) $
        hPutStr stderr (renderExplain Nothing (patchExplain parsed))

      let outputPath
            | commandInPlace parsedCommand         = commandSource parsedCommand
            | Just destination <- commandOutput parsedCommand = destination
            | otherwise              = deriveOutput (commandPatch parsedCommand) (commandSource parsedCommand)
          verification = patchVerification parsed
          noVerify = commandNoVerify parsedCommand

      -- Dry run: report and exit
      when (commandDryRun parsedCommand) $ do
        let summary = patchRecordSummary parsed
        putStrLn $ "would apply " ++ show (recordCount summary) ++ " " ++ recordUnit summary
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

      let apply = inMemoryApply (patchApply parsed)
      sourceBytes <- readMaybeUnwrap (commandRaw parsedCommand) (commandSource parsedCommand)
      let source = SourceFileContents sourceBytes
      verifySource noVerify verification source
      result <- apply source
      case result of
        Left slapError -> dieError slapError
        Right target -> do
          verifyTarget noVerify verification target
          ByteString.writeFile outputPath (unTargetFileContents target)
          let appliedSummary = patchRecordSummary parsed
          putStrLn $ "applied " ++ show (recordCount appliedSummary) ++ " " ++ recordUnit appliedSummary
                  ++ " \8594 " ++ outputPath

----------------------------------------------------------------------------
-- Undo
----------------------------------------------------------------------------

doUndo :: Command -> IO ()
doUndo parsedCommand = do
  patchBytes <- readUnwrap (commandPatch parsedCommand)
  case parseSome (PatchFileContents patchBytes) of
    Left slapError -> dieError slapError
    Right parsed -> do
      emitWarnings parsed
      case patchUndo parsed of
        Nothing -> die "undo not supported for this format"
        Just (UndoInMemory revert) -> do
          modified <- ByteString.readFile (commandSource parsedCommand)
          case revert (TargetFileContents modified) of
            Left slapError -> dieError slapError
            Right (SourceFileContents result) -> do
              ByteString.writeFile
                (fromMaybe (commandSource parsedCommand) (commandOutput parsedCommand))
                result
              putStrLn "reverted"

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
        , metaGenre       = commandGenre parsedCommand
        , metaLanguage    = commandLanguage parsedCommand
        , metaDate        = commandDate parsedCommand
        , metaWebsite     = commandWebsite parsedCommand
        , metaPatchEncoding = commandPatchEncoding parsedCommand
        , metaBPSMetadata = maybeMeta
        }
  let defaultWarnings = createDefaultNotes (commandCreateFormat parsedCommand) createMeta
  forM_ defaultWarnings $ \warning -> hPutStrLn stderr ("slap: " ++ renderSlapWarning warning)
  case createFromMemory (commandCreateFormat parsedCommand) (SourceFileContents originalBytes) (TargetFileContents modifiedBytes) createMeta Nothing of
    Left slapError -> dieError slapError
    Right result -> do
      forM_ (resultWarnings result) $ \warning -> hPutStrLn stderr ("slap: " ++ renderSlapWarning warning)
      ByteString.writeFile (commandCreateOutput parsedCommand) (unPatchFileContents (resultBytes result))
      putStrLn ("wrote " ++ commandCreateOutput parsedCommand)

----------------------------------------------------------------------------
-- Convert
----------------------------------------------------------------------------

doConvert :: Command -> IO ()
doConvert parsedCommand = do
  patchBytes <- readUnwrap (commandConvertPatch parsedCommand)
  case parseSome (PatchFileContents patchBytes) of
    Left slapError -> dieError slapError
    Right parsed -> do
      emitWarnings parsed
      let outputFile = fromMaybe (replaceExtension (commandConvertPatch parsedCommand) (formatExtension (commandConvertTo parsedCommand))) (commandConvertOutput parsedCommand)
      maybeMetadata <- case commandConvertMetadata parsedCommand of
        Nothing   -> pure Nothing
        Just path -> Just <$> ByteString.readFile path
      let cliMeta = CreateMeta
            { metaTitle       = commandConvertTitle parsedCommand
            , metaAuthor      = commandConvertAuthor parsedCommand
            , metaDescription        = commandConvertDescription parsedCommand
            , metaVersion     = commandConvertVersion parsedCommand
            , metaUndo        = commandConvertUndo parsedCommand
            , metaValidate    = commandConvertValidate parsedCommand
            , metaUnstable    = commandConvertUnstable parsedCommand
            , metaRomType     = commandConvertRomType parsedCommand
            , metaImageType   = commandConvertImageType parsedCommand
            , metaGenre       = commandConvertGenre parsedCommand
            , metaLanguage    = commandConvertLanguage parsedCommand
            , metaDate        = commandConvertDate parsedCommand
            , metaWebsite     = commandConvertWebsite parsedCommand
            , metaPatchEncoding = commandConvertPatchEncoding parsedCommand
            , metaBPSMetadata = maybeMetadata
            }
          mergedMeta = mergeMeta cliMeta (patchExtractedMeta parsed)
      let printWarnings warnings = forM_ warnings $ \warning ->
              hPutStrLn stderr ("slap: " ++ renderSlapWarning warning)
          metaWarnings = case patchMetadata parsed of
            Nothing -> []
            Just metaBytes ->
              let metaSize = ByteString.length metaBytes
              in if commandConvertTo parsedCommand == CreateDiff CreateBPS
                 then []
                 else [MetadataDropped metaSize]
          metaCarryNote = case patchMetadata parsed of
            Just metaBytes | commandConvertTo parsedCommand == CreateDiff CreateBPS
                           , isNothing (metaBPSMetadata mergedMeta) ->
              Just ("note: source has " ++ show (ByteString.length metaBytes)
                    ++ " bytes of BPS metadata; use --metadata FILE to carry it forward")
            _ -> Nothing
      case commandConvertSource parsedCommand of
        Just sourcePath -> do
          -- --with provided: always use apply-and-recreate path
          sourceBytes <- readMaybeUnwrap (commandRaw parsedCommand) sourcePath
          let source = SourceFileContents sourceBytes
          verifySource (commandNoVerify parsedCommand) (patchVerification parsed) source
          target <- applyForConvert parsed source
          -- For --with conversion, default undo/validate to True (preservation)
          let withMeta = mergedMeta
                { metaUndo     = metaUndo mergedMeta     <|> Just True
                , metaValidate = metaValidate mergedMeta <|> Just True
                }
          case createFromMemory (commandConvertTo parsedCommand) (SourceFileContents sourceBytes) target withMeta (patchContents parsed) of
            Left slapError -> dieError slapError
            Right createResult -> do
              printWarnings (patchSourceNotes parsed ++ metaWarnings
                            ++ createDefaultNotes (commandConvertTo parsedCommand) mergedMeta
                            ++ resultWarnings createResult)
              forM_ metaCarryNote $ \note -> hPutStrLn stderr ("slap: " ++ note)
              ByteString.writeFile outputFile (unPatchFileContents (resultBytes createResult))
              putStrLn ("converted to " ++ formatName (commandConvertTo parsedCommand) ++ ": " ++ outputFile)
        Nothing -> case patchContents parsed of
          Nothing -> die (needSourceMessage parsed)
          Just contents -> case convertDirect contents (commandConvertTo parsedCommand) mergedMeta of
            Left slapError -> dieError slapError
            Right convertResult -> do
              printWarnings (patchSourceNotes parsed ++ resultWarnings convertResult)
              ByteString.writeFile outputFile (unPatchFileContents (resultBytes convertResult))
              putStrLn ("converted to " ++ formatName (commandConvertTo parsedCommand) ++ ": " ++ outputFile)

-- | Apply a parsed patch to source bytes, returning target bytes (for convert).
applyForConvert :: SomePatch -> SourceFileContents -> IO TargetFileContents
applyForConvert somePatch source = do
  result <- inMemoryApply (patchApply somePatch) source
  case result of
    Left slapError -> dieError slapError
    Right target      -> pure target

-- | Error message when --with is required but not provided.
needSourceMessage :: SomePatch -> String
needSourceMessage somePatch = "converting from " ++ name ++ " requires the original ROM (--with SOURCE)\n"
  ++ name ++ " " ++ reason ++ " \8212 the original ROM is needed\nto reconstruct the target file for re-encoding."
  where
    name = formatLabelName (patchFormat somePatch)
    reason
      | patchIsDifferential somePatch = "stores differential data, not raw bytes"
      | otherwise                  = "does not carry extractable records"

----------------------------------------------------------------------------
-- Helpers
----------------------------------------------------------------------------

-- | Derive output path from patch and source names.
-- "game.gbc" + "translation.ips" → "game [translation].gbc"
deriveOutput :: FilePath -> FilePath -> FilePath
deriveOutput patchPath sourcePath =
  dropExtension sourcePath ++ " [" ++ takeBaseName patchPath ++ "]" ++ takeExtension sourcePath

----------------------------------------------------------------------------
-- Verification helpers
----------------------------------------------------------------------------

verifySource :: Bool -> Verification -> SourceFileContents -> IO ()
verifySource noVerify verification (SourceFileContents sourceBytes) = do
  let preprocessed = verifySourcePreHash verification sourceBytes
  forM_ (verifySourceCRC32 verification) $ \expected ->
    checkCRC noVerify "source" expected (rustyCRC32 preprocessed)
  forM_ (verifySourceMD5 verification) $ \expected ->
    checkHash noVerify "source MD5" (unMD5Hash expected) (unMD5Hash (md5 preprocessed))
  forM_ (verifySourceSHA1 verification) $ \expected ->
    checkHash noVerify "source SHA1" (unSHA1Hash expected) (unSHA1Hash (sha1 preprocessed))
  -- Per-block CRC16 and PPF validation are advisory (warning-only)
  unless noVerify $ do
    forM_ (verifySourceBlocks verification) $ \(BlockCheck blockOffset expectedCRC) ->
      warnBlock "source" blockOffset expectedCRC (CRC16 (crc16 (safeSlice (fromIntegral (unOffset blockOffset)) 0x10000 sourceBytes)))
    forM_ (verifyPPFBlock verification) $ \(ValidationBlock blockOffset expectedData) ->
      warnPPFBlock blockOffset expectedData sourceBytes
    forM_ (verifyFileSize verification) $ \expectedSize ->
      warnFileSize expectedSize (FileSize (fromIntegral (ByteString.length sourceBytes)))
    forM_ (verifySourceBytes verification) $ \(ByteCheck checkOffset expectedData checkLabel) ->
      warnSourceBytes checkLabel checkOffset expectedData sourceBytes

verifyTarget :: Bool -> Verification -> TargetFileContents -> IO ()
verifyTarget noVerify verification (TargetFileContents targetBytes) = do
  forM_ (verifyTargetCRC32 verification) $ \expected ->
    checkCRC noVerify "target" expected (rustyCRC32 targetBytes)
  forM_ (verifyTargetMD5 verification) $ \expected ->
    checkHash noVerify "target MD5" (unMD5Hash expected) (unMD5Hash (md5 targetBytes))
  unless noVerify $
    forM_ (verifyTargetBlocks verification) $ \(BlockCheck blockOffset expectedCRC) ->
      warnBlock "target" blockOffset expectedCRC (CRC16 (crc16 (safeSlice (fromIntegral (unOffset blockOffset)) 0x10000 targetBytes)))
  forM_ (verifyWindowAdler32 verification) $ \(WindowCheck windowOffset windowLength expectedChecksum) ->
    checkAdler noVerify windowOffset expectedChecksum (adler32 (safeSlice (fromIntegral (unOffset windowOffset)) (unLength windowLength) targetBytes))

checkCRC :: Bool -> String -> CRC32 -> CRC32 -> IO ()
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

checkAdler :: Bool -> Offset -> Adler32 -> Adler32 -> IO ()
checkAdler noVerify windowOffset expected actual
  | expected == actual = pure ()
  | noVerify = warn message
  | otherwise = die (message ++ "\n  use --no-verify to apply anyway")
  where message = "Adler32 mismatch at window 0x" ++ padHex 8 (unOffset windowOffset)
            ++ " (expected 0x" ++ showAdler32 expected
            ++ ", got 0x" ++ showAdler32 actual ++ ")"

warnBlock :: String -> Offset -> CRC16 -> CRC16 -> IO ()
warnBlock label blockOffset expected actual
  | expected == actual = pure ()
  | otherwise = warn (label ++ " CRC16 mismatch at 0x" ++ padHex 8 (unOffset blockOffset))

warnPPFBlock :: Offset -> ByteString.ByteString -> ByteString.ByteString -> IO ()
warnPPFBlock blockOffset expectedData sourceBytes =
  let actual = safeSlice (fromIntegral (unOffset blockOffset)) (ByteString.length expectedData) sourceBytes
  in when (actual /= expectedData) $
       warn ("validation block mismatch at 0x" ++ padHex 8 (unOffset blockOffset))

warnFileSize :: FileSize -> FileSize -> IO ()
warnFileSize (FileSize expectedSize) (FileSize actualSize) =
  when (expectedSize /= actualSize) $
    warn ("file size mismatch (expected " ++ show expectedSize ++ ", got " ++ show actualSize ++ ")")

warnSourceBytes :: String -> Offset -> ByteString.ByteString -> ByteString.ByteString -> IO ()
warnSourceBytes label checkOffset expectedData sourceBytes =
  let actual = safeSlice (unOffset checkOffset) (ByteString.length expectedData) sourceBytes
  in when (actual /= expectedData) $
       warn (label ++ " mismatch at 0x" ++ padHex 8 (unOffset checkOffset))

safeSlice :: Int -> Int -> ByteString.ByteString -> ByteString.ByteString
safeSlice offset sliceLength input = ByteString.take sliceLength (ByteString.drop offset input)

formatCRC :: CRC32 -> String
formatCRC crcValue = "0x" ++ showCRC32 crcValue

emitWarnings :: SomePatch -> IO ()
emitWarnings somePatch = forM_ (patchWarnings somePatch) $ \warning ->
  hPutStrLn stderr ("slap: warning: " ++ renderSlapWarning warning)

warn :: String -> IO ()
warn message = hPutStrLn stderr ("slap: warning: " ++ message)

die :: String -> IO a
die message = hPutStrLn stderr ("slap: " ++ message) >> exitFailure

dieError :: SlapError -> IO a
dieError = die . renderSlapError
