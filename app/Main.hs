{-# LANGUAGE ApplicativeDo #-}
{-# LANGUAGE OverloadedStrings #-}

module Main (main) where

import Slap.SomePatch (SomePatch(..), RecordSummary(..), ApplyStrategy(..), UndoStrategy(..), Verification(..), BlockCheck(..), ValidationBlock(..), WindowCheck(..), ByteCheck(..), parseSome)
import Slap.FileContents (SourceFileContents(..), TargetFileContents(..), PatchFileContents(..))
import Slap.Measure (Offset(..), Length(..), FileSize(..))
import Slap.Convert (DirectCreate(..), DiffCreate(..), CreateFormat(..),
                     PatchContents,
                     RequestedPatchMetadata(..), RequestedPatchMetadataInputs(..),
                     UndoInclusion(..), ValidationInclusion(..), PatchStability(..),
                     PatchEncoding(..), createDefaultNotes, convertDirect,
                     mergeRequestedMetadata, formatExtension, formatName)
import Slap.Create (createFromMemory)
import Slap.PPF.Types (PPFImageType(..), ValidationBlockBytes(..))
import Slap.PlatformType (PlatformType(..))
import Slap.Archive (detectArchive, unwrapArchive)
import Slap.Binary (crc16, md5, sha1, adler32)
import Slap.Checksum (CRC32(..), CRC16, Adler32(..), MD5Hash(..), SHA1Hash(..), showCRC32, showAdler32)
import Slap.FFI (rustyCRC32)
import Slap.Error (SlapError, SlapWarning(..), CreateResult(..), renderSlapError, renderSlapWarning)
import Slap.Format (MetaField(..), padHex, renderField)
import Slap.FormatLabel (formatLabelName)
import Slap.Explain (ExplainData(..), renderExplain, renderSummary)

import qualified Data.ByteString as ByteString
import Control.Monad (when, forM_)
import Data.Foldable (traverse_)
import Data.Char (toLower)
import Data.Maybe (isNothing)
import Options.Applicative
import Options.Applicative.Help.Pretty (pretty, vcat)
import System.Directory (copyFile, doesFileExist)
import System.Exit (exitFailure, exitSuccess)
import System.FilePath (dropExtension, replaceExtension, takeBaseName, takeExtension)
import System.IO (hPutStr, hPutStrLn, stderr)

----------------------------------------------------------------------------
-- Types
----------------------------------------------------------------------------

-- | How slap should interpret input files whose first bytes look like an
-- archive signature.
--
-- Slap can open single-entry zip and 7z archives transparently, so a user
-- with @rom.zip@ containing one @rom.gbc@ can pass either the archive or
-- the unwrapped ROM.  The @--raw@ flag exists to disable that: some files
-- share a magic-byte prefix with an archive format without actually being
-- one, and unwrapping them would fail or silently return the wrong bytes.
data ArchiveHandling
  = AutoUnwrapSingleEntryArchives
  | ReadBytesVerbatim
  deriving (Show, Eq)

-- | Per-operation options for how slap reads its input files.  One field
-- today; more can land here as new file-reading concerns appear (e.g. a
-- future @--allow-missing@ for tolerating absent optional inputs).
--
-- The @--raw@ switch that populates 'fileReadingArchiveHandling' is
-- defined in 'fileReadingOptionsParser' below.
data FileReadingOptions = FileReadingOptions
  { fileReadingArchiveHandling :: ArchiveHandling
  }
  deriving (Show, Eq)

-- | How much detail 'slap explain' should emit.
--
-- @Summary@ is the default: top-level structure, field-by-field metadata,
-- aggregate record counts.  @FullRecords@ adds every parsed record to the
-- output, which is what you want when investigating a specific byte range
-- or comparing patches record-for-record.  Selected via @--records@.
data ExplainVerbosity
  = Summary
  | FullRecords
  deriving (Show, Eq)

-- | What to do with an applied patch's output bytes.
--
-- The four variants correspond to four mutually exclusive CLI lanes; the
-- parser rejects any command line that mixes distinguishing flags from
-- more than one lane (see 'applyOutputParser').
--
-- 'ApplyInPlace' overwrites the source file (the most invasive option;
-- carries a 'BackupBehavior' to opt into a @.bak@ copy before writing).
-- Mutually exclusive with @-o@\/positional @OUTPUT@ and with @--dry-run@.
-- 'ApplyToExplicitFile' writes to an operator-chosen path.  @-o FILE@ and
-- the positional @OUTPUT@ are two spellings of this same lane, so using
-- both in one command is a parse error.  Carries an 'OverwritePolicy' to
-- opt into clobbering an existing destination via @--force@; the flag is
-- a sub-flag of this lane (and 'ApplyToDerivedFile') because it is
-- meaningless against an in-place write or a dry run.
-- 'ApplyToDerivedFile' writes to a path derived from the source file name
-- (the default when no lane-distinguishing flag is given).  Also carries
-- an 'OverwritePolicy' for the same reason as 'ApplyToExplicitFile'.
-- 'ApplyDryRun' writes nothing; it only reports what would happen.  The
-- report names the derived-default destination since dry runs do not
-- accept lane-modifying flags (no @--in-place@, no @-o@, no @--force@).
-- Users who want to preview a specific destination should run without
-- @--dry-run@ against a scratch file.
data ApplyOutput
  = ApplyInPlace BackupBehavior
  | ApplyToExplicitFile FilePath OverwritePolicy
  | ApplyToDerivedFile OverwritePolicy
  | ApplyDryRun
  deriving (Show, Eq)

-- | Whether in-place apply should make a @.bak@ copy before writing.
data BackupBehavior
  = WriteBackup
  | NoBackup
  deriving (Show, Eq)

-- | Where undo writes its restored source bytes.
--
-- 'UndoInPlace' overwrites the (modified) source file.
-- 'UndoToExplicitFile' writes to an operator-chosen path via @-o@.
data UndoOutput
  = UndoInPlace
  | UndoToExplicitFile FilePath
  deriving (Show, Eq)

-- | Where convert writes the produced patch bytes.
--
-- 'ConvertToExplicitFile' uses an operator-chosen path via @-o@.
-- 'ConvertToDerivedFile' uses the source patch path with the target
-- format's extension substituted in.
data ConvertOutput
  = ConvertToExplicitFile FilePath
  | ConvertToDerivedFile
  deriving (Show, Eq)

-- | Optional side-channel for @slap convert@ when the target format needs
-- the original ROM or the user opts into apply-and-recreate.  Couples the
-- source path with its verification policy because @--no-verify@ is only
-- meaningful when there's a source to verify against; the convert parser
-- rejects @--no-verify@ alone.
data ConvertWithSource = ConvertWithSource
  { convertWithSourcePath   :: FilePath
  , convertWithVerification :: VerificationPolicy
  }
  deriving (Show, Eq)

-- | Whether to refuse writing over an existing output file.
--
-- @RefuseOverwrite@ (default) checks 'doesFileExist' before writing and
-- aborts if the target is present; the user gets a clear error and can
-- decide whether to delete the existing file.  @ForceOverwrite@ (set by
-- @--force@) skips the check; the output path is overwritten
-- unconditionally.  Does not apply to the @--in-place@ lane, which
-- writes to the source by definition.
data OverwritePolicy
  = RefuseOverwrite
  | ForceOverwrite
  deriving (Show, Eq)

-- | Whether apply and convert should verify the source file's hash
-- against the patch's declared source checksum before applying.
--
-- @EnforceVerification@ (default) fails with a readable error on hash
-- mismatch; @SkipVerification@ (set by @--no-verify@) downgrades
-- mismatches to warnings and proceeds.  Formats without source
-- checksums are unaffected either way.
data VerificationPolicy
  = EnforceVerification
  | SkipVerification
  deriving (Show, Eq)

-- | How much progress output apply and undo emit to stderr during
-- operation.  Distinct from 'ExplainVerbosity', which controls the
-- detail of @slap explain@'s structural dump.
--
-- @Quiet@ (default) prints only the final \"applied N records \8594 PATH\"
-- summary.  @Verbose@ (set by @-V@\/@--verbose@) also prints each
-- record as it's applied, via 'renderExplain'.
data Verbosity
  = Quiet
  | Verbose
  deriving (Show, Eq)

data Command
  = CommandApply
      { commandVerificationPolicy :: VerificationPolicy
      , commandVerbosity          :: Verbosity
      , commandApplyOutput :: ApplyOutput
      , commandFileReading :: FileReadingOptions
      , commandPatch   :: FilePath
      , commandSource  :: FilePath
      }
  | CommandUndo
      { commandVerbosity   :: Verbosity
      , commandFileReading :: FileReadingOptions
      , commandPatch   :: FilePath
      , commandSource  :: FilePath
      , commandUndoOutput :: UndoOutput
      }
  | CommandCreate
      { commandCreateFormat   :: CreateFormat
      , commandFileReading    :: FileReadingOptions
      , commandOriginal       :: FilePath
      , commandModified       :: FilePath
      , commandCreateOutput   :: FilePath
      , commandCreateMetadata :: RequestedPatchMetadataInputs
      }
  | CommandConvert
      { commandConvertPatch       :: FilePath
      , commandConvertTo          :: CreateFormat
      , commandConvertOutput      :: ConvertOutput
      , commandConvertWithSource  :: Maybe ConvertWithSource
      , commandFileReading        :: FileReadingOptions
      , commandConvertMetadata    :: RequestedPatchMetadataInputs
      }
  | CommandInfo    { commandPatch :: FilePath, commandExtractMetadata :: Maybe FilePath }
  | CommandExplain
      { commandPatch            :: FilePath
      , commandExplainVerbosity :: ExplainVerbosity
      , commandExplainSource    :: Maybe FilePath
      , commandFileReading      :: FileReadingOptions
      }

----------------------------------------------------------------------------
-- CLI
----------------------------------------------------------------------------

main :: IO ()
main = customExecParser (prefs showHelpOnEmpty) options >>= \case
  parsedCommand@CommandApply{}   -> doApply parsedCommand
  parsedCommand@CommandUndo{}    -> doUndo parsedCommand
  parsedCommand@CommandCreate{}  -> doCreate parsedCommand
  parsedCommand@CommandConvert{} -> doConvert parsedCommand
  parsedCommand@CommandInfo{}    -> doInfo parsedCommand
  parsedCommand@CommandExplain{} -> doExplain parsedCommand

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
explainParser = do
    patchFile          <- argument str (metavar "PATCH" <> help "Patch file to explain")
    verbosity          <- flag Summary FullRecords
                            (long "records" <> help "Show full record-by-record dump instead of summary")
    maybeWithPath      <- optional (option str (long "with" <> metavar "SOURCE"
                            <> help "Source file (resolves delta/copy operations in output)"))
    fileReadingOptions <- fileReadingOptionsParser
    pure CommandExplain
      { commandPatch            = patchFile
      , commandExplainVerbosity = verbosity
      , commandExplainSource    = maybeWithPath
      , commandFileReading      = fileReadingOptions
      }

applyParser :: Parser Command
applyParser = do
    verificationPolicy <- verificationPolicyParser
    verbosity          <- verbosityParser
    fileReadingOptions <- fileReadingOptionsParser
    patch  <- argument str (metavar "PATCH" <> help "Patch file")
    source <- argument str (metavar "SOURCE" <> help "Source file to patch (not modified unless --in-place)")
    applyOutput <- applyOutputParser
    pure CommandApply
      { commandVerificationPolicy = verificationPolicy
      , commandVerbosity          = verbosity
      , commandApplyOutput = applyOutput
      , commandFileReading = fileReadingOptions
      , commandPatch = patch
      , commandSource = source
      }

verificationPolicyParser :: Parser VerificationPolicy
verificationPolicyParser = flag EnforceVerification SkipVerification
  (long "no-verify" <> help "Skip checksum validation (mismatches become warnings)")

verbosityParser :: Parser Verbosity
verbosityParser = flag Quiet Verbose
  (long "verbose" <> short 'V' <> help "Print each record as it's applied")

-- | Parser for the four mutually exclusive output lanes.  'asum' tries
-- each lane in turn; combinations that span multiple lanes are rejected
-- at parse time, with no silent precedence resolution.  The two writing
-- lanes ('ApplyToExplicitFile' and 'ApplyToDerivedFile') share a single
-- 'writingLane' parser so that @--force@ has exactly one home in the
-- parser tree — otherwise a bare @--force@ would partially match the
-- explicit-file lane (consuming the flag but missing the path) and
-- optparse-applicative would prefer that partial match's error over the
-- derived-file lane's success.  Within 'writingLane', whether the user
-- supplied an explicit path decides which constructor 'mkWritingLane'
-- returns, and @--force@ is consumed at that one site.  @--in-place@
-- and @--dry-run@ commit to their own lanes, so combining them with
-- @--force@ leaves @--force@ unconsumed and produces a parse error.
applyOutputParser :: Parser ApplyOutput
applyOutputParser = asum
  [ dryRunLane
  , inPlaceLane
  , writingLane
  ]
  where
    dryRunLane :: Parser ApplyOutput
    dryRunLane = ApplyDryRun <$
      flag' () (long "dry-run" <> help "Show what would happen without writing any files")

    inPlaceLane :: Parser ApplyOutput
    inPlaceLane = ApplyInPlace
      <$> (flag' () (long "in-place" <> short 'i'
              <> help "Modify SOURCE directly (destructive; creates .bak by default)")
          *> backupBehaviorFlag)
      where
        backupBehaviorFlag = flag WriteBackup NoBackup
          (long "no-backup" <> help "Don't create .bak backup with --in-place")

    writingLane :: Parser ApplyOutput
    writingLane = mkWritingLane
      <$> optional outputPathOption
      <*> overwritePolicyFlag
      where
        outputPathOption :: Parser FilePath
        outputPathOption =
              option str (long "output" <> short 'o' <> metavar "FILE"
                <> help "Write patched output to FILE (alternative: positional OUTPUT)")
          <|> argument str (metavar "OUTPUT"
                <> help "Write patched output to this path (alternative: -o FILE)")

        overwritePolicyFlag :: Parser OverwritePolicy
        overwritePolicyFlag = flag RefuseOverwrite ForceOverwrite
          (long "force" <> short 'f'
            <> help "Overwrite existing output files")

        mkWritingLane :: Maybe FilePath -> OverwritePolicy -> ApplyOutput
        mkWritingLane Nothing     policy = ApplyToDerivedFile policy
        mkWritingLane (Just path) policy = ApplyToExplicitFile path policy

fileReadingOptionsParser :: Parser FileReadingOptions
fileReadingOptionsParser = FileReadingOptions <$> archiveHandlingFromSwitch
  where
    archiveHandlingFromSwitch = flag AutoUnwrapSingleEntryArchives ReadBytesVerbatim
      (long "raw" <> help "Read input files as raw bytes; do not attempt to unwrap zip/7z archives")

undoParser :: Parser Command
undoParser = do
    verbosity          <- verbosityParser
    fileReadingOptions <- fileReadingOptionsParser
    patch  <- argument str (metavar "PATCH" <> help "Patch file")
    source <- argument str (metavar "SOURCE" <> help "File to restore")
    undoOutput <- undoOutputParser
    pure CommandUndo
      { commandVerbosity   = verbosity
      , commandFileReading = fileReadingOptions
      , commandPatch = patch
      , commandSource = source
      , commandUndoOutput = undoOutput
      }

undoOutputParser :: Parser UndoOutput
undoOutputParser = maybe UndoInPlace UndoToExplicitFile
  <$> optional (option str (long "output" <> short 'o' <> metavar "FILE"
      <> help "Write restored source to FILE (default: overwrite SOURCE)"))

convertOutputParser :: Parser ConvertOutput
convertOutputParser = maybe ConvertToDerivedFile ConvertToExplicitFile
  <$> optional (option str (long "output" <> short 'o' <> metavar "FILE"
      <> help "Output file (default: replace input extension with target format's)"))

createParser :: Parser Command
createParser = do
    createFormat       <- createFormatParser
    fileReadingOptions <- fileReadingOptionsParser
    original           <- argument str (metavar "ORIGINAL" <> help "Original unmodified file")
    modified           <- argument str (metavar "MODIFIED" <> help "Modified file")
    outputFile         <- argument str (metavar "OUTPUT"   <> help "Output patch file")
    metadataInputs     <- requestedPatchMetadataInputsParser
    pure CommandCreate
      { commandCreateFormat   = createFormat
      , commandFileReading    = fileReadingOptions
      , commandOriginal       = original
      , commandModified       = modified
      , commandCreateOutput   = outputFile
      , commandCreateMetadata = metadataInputs
      }

convertParser :: Parser Command
convertParser = do
    patchFile          <- argument str (metavar "PATCH" <> help "Patch file to convert")
    targetFormat       <- convertToParser
    convertOutput      <- convertOutputParser
    withSource         <- optional convertWithSourceParser
    fileReadingOptions <- fileReadingOptionsParser
    metadataInputs     <- requestedPatchMetadataInputsParser
    pure CommandConvert
      { commandConvertPatch       = patchFile
      , commandConvertTo          = targetFormat
      , commandConvertOutput      = convertOutput
      , commandConvertWithSource  = withSource
      , commandFileReading        = fileReadingOptions
      , commandConvertMetadata    = metadataInputs
      }

-- | Parser for @--with SOURCE@ plus its sub-flag @--no-verify@.  The
-- @--with@ option is the distinguishing flag: if absent, the whole parser
-- fails and the enclosing 'optional' falls back to 'Nothing', which leaves
-- any stray @--no-verify@ for the top-level parser to reject.  That's how
-- the coupling is enforced at parse time — @--no-verify@ is only accepted
-- alongside @--with@.
convertWithSourceParser :: Parser ConvertWithSource
convertWithSourceParser = ConvertWithSource
  <$> option str (long "with" <> metavar "SOURCE"
        <> help "Source file: enables apply-and-recreate conversion and source hash verification")
  <*> flag EnforceVerification SkipVerification
        (long "no-verify"
          <> help "Skip source hash verification (requires --with SOURCE; mismatches become warnings)")

-- | The output-format flag accepted by @slap create@.  Defaults to BPS
-- so the bare @slap create base mod out@ command works without needing
-- the user to spell out a format.
createFormatParser :: Parser CreateFormat
createFormatParser = option (eitherReader parseCreateFormat)
  (long "format" <> metavar "FMT" <> value (CreateDiff CreateBPS)
    <> help "Output format: bps (default), ips, ips32, ebp, ups, ppf3, pmsr, ninja1, ninja2, dps, aps-n64, aps-gba, gdiff, pchtxt")

-- | The target-format flag accepted by @slap convert@.  No default:
-- conversion has to know what it is converting to.
convertToParser :: Parser CreateFormat
convertToParser = option (eitherReader parseCreateFormat)
  (long "to" <> short 't' <> metavar "FMT"
    <> help "Target format: bps, ips, ips32, ebp, ups, ppf3, pmsr, ninja1, ninja2, dps, aps-n64, aps-gba, gdiff, pchtxt")

-- | Parser for the user-declared metadata that both @create@ and
-- @convert@ accept.  The returned value is pre-IO: the blob path
-- still points to a file that hasn't been read.  Call
-- 'resolveRequestedPatchMetadata' to perform the IO and produce a
-- 'RequestedPatchMetadata'.
requestedPatchMetadataInputsParser :: Parser RequestedPatchMetadataInputs
requestedPatchMetadataInputsParser = do
    title             <- optional (option str (long "title" <> metavar "TEXT"
                            <> help "Patch title (EBP/NINJA2)"))
    author            <- optional (option str (long "author" <> metavar "TEXT"
                            <> help "Patch author (EBP/DPS/NINJA2)"))
    description       <- optional (option str (long "description" <> short 'd' <> metavar "TEXT"
                            <> help "Patch description (DPS/PPF3/EBP/APS-N64/NINJA2/PCHTXT)"))
    version           <- optional (option str (long "version" <> metavar "TEXT"
                            <> help "Patch version (DPS/NINJA2)"))
    includeUndo       <- optional (flag' OmitUndoData       (long "no-undo"
                            <> help "Omit undo data (default: included when the format supports it)"))
    includeValidation <- optional (flag' OmitValidationBlock (long "no-validate"
                            <> help "Omit validation block (default: included when the format supports it)"))
    unstable          <- optional (flag' UnstablePatch (long "unstable"
                            <> help "Mark patch unstable (DPS)"))
    romType           <- optional (option (eitherReader parseRomType) (long "rom-type" <> metavar "TYPE"
                            <> help "ROM type (NINJA1/NINJA2): raw, nes, fds, snes, n64, gb, gbc, gba, ..."))
    imageType         <- optional (option (eitherReader parseImageType) (long "image-type" <> metavar "TYPE"
                            <> help "Image type (PPF3): bin, gi"))
    genre             <- optional (option str (long "genre" <> metavar "TEXT"
                            <> help "Genre (NINJA2)"))
    language          <- optional (option str (long "language" <> metavar "TEXT"
                            <> help "Language (NINJA2)"))
    date              <- optional (option str (long "date" <> metavar "YYYYMMDD"
                            <> help "Date (NINJA2)"))
    website           <- optional (option str (long "website" <> metavar "URL"
                            <> help "Website (NINJA2)"))
    patchEncoding     <- option (eitherReader parsePatchEncoding) (long "patch-encoding" <> metavar "ENC"
                            <> value PatchEncodingUTF8
                            <> help "Text encoding for NINJA2 metadata: utf8 (default), system")
    metadataFile      <- optional (option str (long "metadata" <> metavar "FILE"
                            <> help "Metadata file to embed (BPS)"))
    pure RequestedPatchMetadataInputs
      { inputTitle               = title
      , inputAuthor              = author
      , inputDescription         = description
      , inputVersion             = version
      , inputUndoInclusion       = includeUndo
      , inputValidationInclusion = includeValidation
      , inputStability           = unstable
      , inputRomType             = romType
      , inputImageType           = imageType
      , inputGenre               = genre
      , inputLanguage            = language
      , inputDate                = date
      , inputWebsite             = website
      , inputPatchEncoding       = patchEncoding
      , inputEmbeddedBlobPath    = metadataFile
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

-- | Read a file, honoring the 'FileReadingOptions' view of archive handling.
-- CommandInfo currently uses 'readUnwrap' unconditionally; if it ever grows a
-- '--raw' flag of its own, route it through here instead.
readMaybeUnwrap :: FileReadingOptions -> FilePath -> IO ByteString.ByteString
readMaybeUnwrap fileReadingOptions = case fileReadingArchiveHandling fileReadingOptions of
  AutoUnwrapSingleEntryArchives -> readUnwrap
  ReadBytesVerbatim             -> ByteString.readFile

-- | Resolve the CLI's pre-IO 'RequestedPatchMetadataInputs' into the
-- library's 'RequestedPatchMetadata'.  The only transition with IO is
-- reading the @--metadata FILE@ contents; the other 14 fields carry
-- through unchanged.
resolveRequestedPatchMetadata :: RequestedPatchMetadataInputs -> IO RequestedPatchMetadata
resolveRequestedPatchMetadata inputs = do
  embeddedBlob <- traverse ByteString.readFile (inputEmbeddedBlobPath inputs)
  pure RequestedPatchMetadata
    { requestedTitle               = inputTitle               inputs
    , requestedAuthor              = inputAuthor              inputs
    , requestedDescription         = inputDescription         inputs
    , requestedVersion             = inputVersion             inputs
    , requestedUndoInclusion       = inputUndoInclusion       inputs
    , requestedValidationInclusion = inputValidationInclusion inputs
    , requestedStability           = inputStability           inputs
    , requestedRomType             = inputRomType             inputs
    , requestedImageType           = inputImageType           inputs
    , requestedGenre               = inputGenre               inputs
    , requestedLanguage            = inputLanguage            inputs
    , requestedDate                = inputDate                inputs
    , requestedWebsite             = inputWebsite             inputs
    , requestedPatchEncoding       = inputPatchEncoding       inputs
    , requestedEmbeddedBlob        = embeddedBlob
    }

----------------------------------------------------------------------------
-- Info & Explain
----------------------------------------------------------------------------

doInfo :: Command -> IO ()
doInfo parsedCommand = do
  parsed <- readAndParsePatch (commandPatch parsedCommand)
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

doExplain :: Command -> IO ()
doExplain parsedCommand = do
  parsed <- readAndParsePatch (commandPatch parsedCommand)
  maybeSource <- case commandExplainSource parsedCommand of
    Nothing   -> pure Nothing
    Just path -> Just <$> readMaybeUnwrap (commandFileReading parsedCommand) path
  let renderFunction = case commandExplainVerbosity parsedCommand of
        Summary     -> renderSummary
        FullRecords -> renderExplain
  putStr (renderFunction maybeSource (patchExplain parsed))
  emitWarnings parsed

----------------------------------------------------------------------------
-- Apply
----------------------------------------------------------------------------

doApply :: Command -> IO ()
doApply parsedCommand = do
  parsed <- readAndParsePatch (commandPatch parsedCommand)
  emitWarnings parsed
  case commandVerbosity parsedCommand of
    Verbose -> hPutStr stderr (renderExplain Nothing (patchExplain parsed))
    Quiet   -> pure ()

  let verification = patchVerification parsed
      verificationPolicy = commandVerificationPolicy parsedCommand

      applyAndWriteTo outputPath = do
        sourceBytes <- readMaybeUnwrap (commandFileReading parsedCommand) (commandSource parsedCommand)
        let source = SourceFileContents sourceBytes
        verifySource verificationPolicy verification source
        target <- orDie =<< inMemoryApply (patchApply parsed) source
        verifyTarget verificationPolicy verification target
        ByteString.writeFile outputPath (unTargetFileContents target)
        let appliedSummary = patchRecordSummary parsed
        putStrLn $ "applied " ++ show (recordCount appliedSummary) ++ " " ++ recordUnit appliedSummary
                ++ " \8594 " ++ outputPath

  case commandApplyOutput parsedCommand of
    ApplyDryRun -> do
      let reportedPath = deriveOutput (commandPatch parsedCommand) (commandSource parsedCommand)
          summary = patchRecordSummary parsed
      putStrLn $ "would apply " ++ show (recordCount summary) ++ " " ++ recordUnit summary
              ++ " \8594 " ++ reportedPath
      case verifySourceCRC32 verification of
        Just expected -> do
          sourceBytes <- readMaybeUnwrap (commandFileReading parsedCommand) (commandSource parsedCommand)
          let actual = rustyCRC32 sourceBytes
          putStrLn $ "source CRC: " ++ formatCRC actual
            ++ if actual == expected then " \10003" else " \10007 (expected " ++ formatCRC expected ++ ")"
        Nothing -> pure ()
      exitSuccess
    ApplyInPlace backupBehavior -> do
      case backupBehavior of
        WriteBackup -> do
          let backupPath = commandSource parsedCommand ++ ".bak"
          copyFile (commandSource parsedCommand) backupPath
          hPutStrLn stderr ("slap: backup: " ++ backupPath)
        NoBackup -> pure ()
      applyAndWriteTo (commandSource parsedCommand)
    ApplyToExplicitFile outputPath overwritePolicy -> do
      refuseOverwrite overwritePolicy outputPath
      applyAndWriteTo outputPath
    ApplyToDerivedFile overwritePolicy -> do
      let outputPath = deriveOutput (commandPatch parsedCommand) (commandSource parsedCommand)
      refuseOverwrite overwritePolicy outputPath
      applyAndWriteTo outputPath

----------------------------------------------------------------------------
-- Undo
----------------------------------------------------------------------------

doUndo :: Command -> IO ()
doUndo parsedCommand = do
  parsed <- readAndParsePatch (commandPatch parsedCommand)
  emitWarnings parsed
  case commandVerbosity parsedCommand of
    Verbose -> hPutStr stderr (renderExplain Nothing (patchExplain parsed))
    Quiet   -> pure ()
  case patchUndo parsed of
    Nothing -> die "undo not supported for this format"
    Just (UndoInMemory revert) -> do
      modified <- ByteString.readFile (commandSource parsedCommand)
      SourceFileContents result <- orDie (revert (TargetFileContents modified))
      let outputPath = case commandUndoOutput parsedCommand of
            UndoInPlace                 -> commandSource parsedCommand
            UndoToExplicitFile explicit -> explicit
      ByteString.writeFile outputPath result
      putStrLn "reverted"

----------------------------------------------------------------------------
-- Create
----------------------------------------------------------------------------

doCreate :: Command -> IO ()
doCreate parsedCommand = do
  originalBytes <- readMaybeUnwrap (commandFileReading parsedCommand) (commandOriginal parsedCommand)
  modifiedBytes <- readMaybeUnwrap (commandFileReading parsedCommand) (commandModified parsedCommand)
  createMeta    <- resolveRequestedPatchMetadata (commandCreateMetadata parsedCommand)
  emitSlapWarnings (createDefaultNotes (commandCreateFormat parsedCommand) createMeta)
  result <- orDie (createFromMemory (commandCreateFormat parsedCommand) (SourceFileContents originalBytes) (TargetFileContents modifiedBytes) createMeta Nothing)
  emitSlapWarnings (resultWarnings result)
  ByteString.writeFile (commandCreateOutput parsedCommand) (unPatchFileContents (resultBytes result))
  putStrLn ("wrote " ++ commandCreateOutput parsedCommand)

----------------------------------------------------------------------------
-- Convert
----------------------------------------------------------------------------

doConvert :: Command -> IO ()
doConvert parsedCommand = do
  parsed <- readAndParsePatch (commandConvertPatch parsedCommand)
  emitWarnings parsed
  cliMeta <- resolveRequestedPatchMetadata (commandConvertMetadata parsedCommand)
  let outputFile = case commandConvertOutput parsedCommand of
        ConvertToExplicitFile explicit -> explicit
        ConvertToDerivedFile           -> replaceExtension (commandConvertPatch parsedCommand)
                                                           (formatExtension (commandConvertTo parsedCommand))
      mergedMeta = mergeRequestedMetadata cliMeta (patchExtractedMeta parsed)
      notes = computeBPSConversionNotes parsed (commandConvertTo parsedCommand) mergedMeta
  case chooseConvertDispatch parsedCommand parsed of
    ApplyAndRecreate withSource -> do
      sourceBytes <- readMaybeUnwrap (commandFileReading parsedCommand) (convertWithSourcePath withSource)
      let source = SourceFileContents sourceBytes
      verifySource (convertWithVerification withSource) (patchVerification parsed) source
      target <- applyForConvert parsed source
      createResult <- orDie (createFromMemory (commandConvertTo parsedCommand) (SourceFileContents sourceBytes) target mergedMeta (patchContents parsed))
      emitSlapWarnings (patchSourceNotes parsed ++ bpsConversionWarnings notes
                        ++ createDefaultNotes (commandConvertTo parsedCommand) mergedMeta
                        ++ resultWarnings createResult)
      forM_ (bpsConversionCarryNote notes) $ \note -> hPutStrLn stderr ("slap: " ++ note)
      ByteString.writeFile outputFile (unPatchFileContents (resultBytes createResult))
      putStrLn ("converted to " ++ formatName (commandConvertTo parsedCommand) ++ ": " ++ outputFile)
    SourceLessConvert contents -> do
      convertResult <- orDie (convertDirect contents (commandConvertTo parsedCommand) mergedMeta)
      emitSlapWarnings (patchSourceNotes parsed ++ resultWarnings convertResult)
      ByteString.writeFile outputFile (unPatchFileContents (resultBytes convertResult))
      putStrLn ("converted to " ++ formatName (commandConvertTo parsedCommand) ++ ": " ++ outputFile)
    ConvertRequiresSource somePatch ->
      die (needSourceMessage somePatch)

-- | Apply a parsed patch to source bytes, returning target bytes (for convert).
applyForConvert :: SomePatch -> SourceFileContents -> IO TargetFileContents
applyForConvert somePatch source =
  orDie =<< inMemoryApply (patchApply somePatch) source

-- | Error message when --with is required but not provided.
needSourceMessage :: SomePatch -> String
needSourceMessage somePatch = "converting from " ++ name ++ " requires the original ROM (--with SOURCE)\n"
  ++ name ++ " " ++ reason ++ " \8212 the original ROM is needed\nto reconstruct the target file for re-encoding."
  where
    name = formatLabelName (patchFormat somePatch)
    reason
      | patchIsDifferential somePatch = "stores differential data, not raw bytes"
      | otherwise                  = "does not carry extractable records"

-- | The three real convert cases, each with the inputs the branch needs.
-- Built once from the parsed patch and the CLI command by
-- 'chooseConvertDispatch'; pattern-matched once in 'doConvert'.
data ConvertDispatch
  = ApplyAndRecreate ConvertWithSource
    -- ^ User supplied @--with SOURCE@; load the source, apply the patch,
    -- re-encode the target bytes as the target format.
  | SourceLessConvert PatchContents
    -- ^ User didn't supply source, but the parsed patch carries enough
    -- structure ('PatchContents') to re-encode without source bytes.
  | ConvertRequiresSource SomePatch
    -- ^ User didn't supply source, and the parsed patch doesn't carry
    -- 'PatchContents' (diff formats without self-contained records).
    -- Terminates via 'needSourceMessage'.

-- | Flatten the two Maybe values that decide which convert path runs into
-- the single sum they really express.  The user's @--with SOURCE@ flag
-- commits to apply-and-recreate outright; without it, the parsed patch
-- either carries 'PatchContents' (source-less conversion works) or it
-- doesn't (the user has to supply source or give up).
chooseConvertDispatch :: Command -> SomePatch -> ConvertDispatch
chooseConvertDispatch parsedCommand parsed =
  case commandConvertWithSource parsedCommand of
    Just withSource -> ApplyAndRecreate withSource
    Nothing -> case patchContents parsed of
      Just contents -> SourceLessConvert contents
      Nothing       -> ConvertRequiresSource parsed

-- | BPS-specific conversion notes: a warning when a patch's metadata bytes
-- are being dropped because the target format has no metadata channel, and
-- an informational note when the target is BPS but the user didn't supply
-- @--metadata FILE@ to carry the source's metadata forward.
data BPSConversionNotes = BPSConversionNotes
  { bpsConversionWarnings  :: [SlapWarning]
  , bpsConversionCarryNote :: Maybe String
  }

computeBPSConversionNotes
  :: SomePatch
  -> CreateFormat
  -> RequestedPatchMetadata
  -> BPSConversionNotes
computeBPSConversionNotes parsed targetFormat mergedMeta = BPSConversionNotes
  { bpsConversionWarnings  = dropWarnings
  , bpsConversionCarryNote = carryNote
  }
  where
    targetIsBPS = targetFormat == CreateDiff CreateBPS
    dropWarnings = case patchMetadata parsed of
      Just metaBytes | not targetIsBPS -> [MetadataDropped (ByteString.length metaBytes)]
      _                                -> []
    carryNote = case patchMetadata parsed of
      Just metaBytes
        | targetIsBPS
        , isNothing (requestedEmbeddedBlob mergedMeta) ->
            Just ("note: source has " ++ show (ByteString.length metaBytes)
                  ++ " bytes of BPS metadata; use --metadata FILE to carry it forward")
      _ -> Nothing

----------------------------------------------------------------------------
-- Helpers
----------------------------------------------------------------------------

-- | Derive output path from patch and source names.
-- "game.gbc" + "translation.ips" → "game [translation].gbc"
deriveOutput :: FilePath -> FilePath -> FilePath
deriveOutput patchPath sourcePath =
  dropExtension sourcePath ++ " [" ++ takeBaseName patchPath ++ "]" ++ takeExtension sourcePath

-- | Abort if the destination already exists and the user did not pass
-- @--force@.  Used by the two apply lanes that write to a path other
-- than the source ('ApplyToExplicitFile' and 'ApplyToDerivedFile').
refuseOverwrite :: OverwritePolicy -> FilePath -> IO ()
refuseOverwrite ForceOverwrite  _          = pure ()
refuseOverwrite RefuseOverwrite outputPath = do
  exists <- doesFileExist outputPath
  when exists $
    die (outputPath ++ " already exists (use --force to overwrite)")

----------------------------------------------------------------------------
-- Verification helpers
----------------------------------------------------------------------------

verifySource :: VerificationPolicy -> Verification -> SourceFileContents -> IO ()
verifySource verificationPolicy verification (SourceFileContents sourceBytes) = do
  let preprocessed = verifySourcePreHash verification sourceBytes
  forM_ (verifySourceCRC32 verification) $ \expected ->
    checkCRC verificationPolicy SourceSide expected (rustyCRC32 preprocessed)
  forM_ (verifySourceMD5 verification) $ \expected ->
    checkHash verificationPolicy SourceSide MD5 (unMD5Hash expected) (unMD5Hash (md5 preprocessed))
  forM_ (verifySourceSHA1 verification) $ \expected ->
    checkHash verificationPolicy SourceSide SHA1 (unSHA1Hash expected) (unSHA1Hash (sha1 preprocessed))
  -- Per-block CRC16 and PPF validation are advisory (warning-only)
  case verificationPolicy of
    SkipVerification    -> pure ()
    EnforceVerification -> do
      forM_ (verifySourceBlocks verification) $ \(BlockCheck blockOffset expectedCRC) ->
        warnBlock "source" blockOffset expectedCRC (crc16 (safeSlice (fromIntegral (unOffset blockOffset)) 0x10000 sourceBytes))
      forM_ (verifyPPFBlock verification) $ \(ValidationBlock blockOffset expectedData) ->
        warnPPFBlock blockOffset expectedData sourceBytes
      forM_ (verifyFileSizeAdvisory verification) $ \expectedSize ->
        warnFileSize expectedSize (FileSize (fromIntegral (ByteString.length sourceBytes)))
      forM_ (verifySourceBytes verification) $ \(ByteCheck checkOffset expectedData checkLabel) ->
        warnSourceBytes checkLabel checkOffset expectedData sourceBytes
  forM_ (verifyFileSizeRequired verification) $ \expectedSize ->
    checkFileSize verificationPolicy SourceSide expectedSize (FileSize (fromIntegral (ByteString.length sourceBytes)))

verifyTarget :: VerificationPolicy -> Verification -> TargetFileContents -> IO ()
verifyTarget verificationPolicy verification (TargetFileContents targetBytes) = do
  forM_ (verifyTargetCRC32 verification) $ \expected ->
    checkCRC verificationPolicy TargetSide expected (rustyCRC32 targetBytes)
  forM_ (verifyTargetMD5 verification) $ \expected ->
    checkHash verificationPolicy TargetSide MD5 (unMD5Hash expected) (unMD5Hash (md5 targetBytes))
  case verificationPolicy of
    SkipVerification    -> pure ()
    EnforceVerification ->
      forM_ (verifyTargetBlocks verification) $ \(BlockCheck blockOffset expectedCRC) ->
        warnBlock "target" blockOffset expectedCRC (crc16 (safeSlice (fromIntegral (unOffset blockOffset)) 0x10000 targetBytes))
  forM_ (verifyWindowAdler32 verification) $ \(WindowCheck windowOffset windowLength expectedChecksum) ->
    checkAdler verificationPolicy windowOffset expectedChecksum (adler32 (safeSlice (fromIntegral (unOffset windowOffset)) (unLength windowLength) targetBytes))

data VerificationSide = SourceSide | TargetSide
  deriving (Show, Eq)

verificationSideLabel :: VerificationSide -> String
verificationSideLabel SourceSide = "source"
verificationSideLabel TargetSide = "target"

data HashAlgorithm = MD5 | SHA1
  deriving (Show, Eq)

hashAlgorithmLabel :: HashAlgorithm -> String
hashAlgorithmLabel MD5  = "MD5"
hashAlgorithmLabel SHA1 = "SHA1"

checkCRC :: VerificationPolicy -> VerificationSide -> CRC32 -> CRC32 -> IO ()
checkCRC verificationPolicy side expected actual
  | expected == actual = pure ()
  | otherwise = case verificationPolicy of
      SkipVerification    -> warn (mismatchMessage)
      EnforceVerification -> die (mismatchMessage ++ "\n  use --no-verify to apply anyway")
  where
    label = verificationSideLabel side
    mismatchMessage = label ++ " CRC mismatch (expected "
                   ++ formatCRC expected ++ ", got " ++ formatCRC actual ++ ")"

checkHash :: VerificationPolicy -> VerificationSide -> HashAlgorithm -> ByteString.ByteString -> ByteString.ByteString -> IO ()
checkHash verificationPolicy side algorithm expected actual
  | expected == actual = pure ()
  | otherwise = case verificationPolicy of
      SkipVerification    -> warn (label ++ " mismatch")
      EnforceVerification -> die (label ++ " mismatch\n  use --no-verify to apply anyway")
  where label = verificationSideLabel side ++ " " ++ hashAlgorithmLabel algorithm

checkAdler :: VerificationPolicy -> Offset -> Adler32 -> Adler32 -> IO ()
checkAdler verificationPolicy windowOffset expected actual
  | expected == actual = pure ()
  | otherwise = case verificationPolicy of
      SkipVerification    -> warn message
      EnforceVerification -> die (message ++ "\n  use --no-verify to apply anyway")
  where message = "Adler32 mismatch at window 0x" ++ padHex 8 (unOffset windowOffset)
            ++ " (expected 0x" ++ showAdler32 expected
            ++ ", got 0x" ++ showAdler32 actual ++ ")"

warnBlock :: String -> Offset -> CRC16 -> CRC16 -> IO ()
warnBlock label blockOffset expected actual
  | expected == actual = pure ()
  | otherwise = warn (label ++ " CRC16 mismatch at 0x" ++ padHex 8 (unOffset blockOffset))

warnPPFBlock :: Offset -> ValidationBlockBytes -> ByteString.ByteString -> IO ()
warnPPFBlock blockOffset (ValidationBlockBytes expectedData) sourceBytes =
  let actual = safeSlice (fromIntegral (unOffset blockOffset)) (ByteString.length expectedData) sourceBytes
  in when (actual /= expectedData) $
       warn ("validation block mismatch at 0x" ++ padHex 8 (unOffset blockOffset))

warnFileSize :: FileSize -> FileSize -> IO ()
warnFileSize (FileSize expectedSize) (FileSize actualSize) =
  when (expectedSize /= actualSize) $
    warn ("file size mismatch (expected " ++ show expectedSize ++ ", got " ++ show actualSize ++ ")")

checkFileSize :: VerificationPolicy -> VerificationSide -> FileSize -> FileSize -> IO ()
checkFileSize verificationPolicy side (FileSize expectedSize) (FileSize actualSize)
  | expectedSize == actualSize = pure ()
  | otherwise = case verificationPolicy of
      SkipVerification    -> warn mismatchMessage
      EnforceVerification -> die (mismatchMessage ++ "\n  use --no-verify to apply anyway")
  where
    label = verificationSideLabel side
    mismatchMessage = label ++ " file size mismatch (expected "
                   ++ show expectedSize ++ " bytes, got " ++ show actualSize ++ " bytes)"

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

-- | Emit a list of 'SlapWarning's to stderr, each prefixed with "slap: ".
-- Replaces the inline 'forM_ warnings $ \\w -> hPutStrLn stderr ...' pattern
-- that CLI callers reach for when surfacing library-level warnings.
emitSlapWarnings :: [SlapWarning] -> IO ()
emitSlapWarnings = traverse_ $ \warning ->
  hPutStrLn stderr ("slap: " ++ renderSlapWarning warning)

warn :: String -> IO ()
warn message = hPutStrLn stderr ("slap: warning: " ++ message)

die :: String -> IO a
die message = hPutStrLn stderr ("slap: " ++ message) >> exitFailure

dieError :: SlapError -> IO a
dieError = die . renderSlapError

-- | Unwrap an 'Either SlapError' or terminate with a rendered error.
-- Replaces the 'case ... of Left err -> dieError err; Right v -> ...' pattern
-- that appears in every do-function that calls into the library.
orDie :: Either SlapError a -> IO a
orDie = either dieError pure

-- | Read a patch file, parse it, return the parsed 'SomePatch'.  Terminates
-- with a rendered error if the file can't be read or the bytes don't parse.
-- Caller is responsible for calling 'emitWarnings' on the result if parse-time
-- warnings should be surfaced — 'doApply' and 'doUndo' interleave a verbosity
-- check between parse and warning emission, so the helper stays parse-only.
readAndParsePatch :: FilePath -> IO SomePatch
readAndParsePatch path = do
  patchBytes <- readUnwrap path
  orDie (parseSome (PatchFileContents patchBytes))
