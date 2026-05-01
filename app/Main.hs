{-# LANGUAGE ApplicativeDo #-}
{-# LANGUAGE OverloadedStrings #-}

module Main (main) where

import Slap.SomePatch
  ( SomePatch(..)
  , RecordSummary(..)
  , ApplyStrategy(..)
  , UndoStrategy(..)
  , Verification(..)
  , BlockCheck(..)
  , ValidationBlock(..)
  , WindowCheck(..)
  , ByteCheck(..)
  , AdvisoryExpectedBytes(..)
  , parseSome
  )
import Slap.FileContents (SourceFileContents(..), TargetFileContents(..), PatchFileContents(..))
import Slap.Measure (Offset(..), Length(..), FileSize(..))
import Slap.Convert (DirectCreate(..), DiffCreate(..), CreateFormat(..),
                     PatchContents,
                     RequestedPatchMetadata(..),
                     RequestedConstraints(..),
                     rejectIncompatibleConstraints,
                     UndoInclusion(..), ValidationInclusion(..), PatchStability(..),
                     PatchEncoding(..), createDefaultNotes, convertDirect,
                     mergeRequestedMetadata, rejectIncompatibleMetadata,
                     formatExtension, formatName)
import Slap.Constraint (Constraint(..), constraintFlagName)
import Slap.IPS.Types (SMCShapeRequirement(..))
import Slap.Create (createFromMemory)
import Slap.PPF.Types (PPFImageType(..), ValidationBlockBytes(..))
import Slap.PlatformType (PlatformType(..))
import Slap.Archive (detectArchive, unwrapArchive)
import Slap.Binary (crc16, md5, sha1, adler32)
import Slap.Checksum (CRC32(..), CRC16, Adler32(..), MD5Hash(..), SHA1Hash(..), showCRC32, showAdler32)
import Slap.FFI (rustyCRC32)
import Slap.Error (SlapError, SlapWarning(..), CreateResult(..), Outcome(..),
                   renderSlapError, renderSlapWarning)
import Slap.Format (MetaField(..), padHex, renderField,
                    rightwardsArrow, checkMark, ballotX, emDash,
                    spacePaddedRightwardsArrow)
import Slap.FormatLabel (formatLabelName)
import Slap.Explain (ExplainData(..), renderExplain, renderSummary)

import qualified Data.ByteString as ByteString
import Control.Monad (when, forM_)
import Data.Foldable (traverse_)
import Data.Char (toLower)
import Data.List (intercalate)
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

-- | What the user wants done with the BPS embedded-metadata blob during
-- a convert.  'CarryIfPresent' is the default and matches the behavior
-- of every other metadata field: inherit from the source patch unless
-- the user overrides.  'EmbedFromFile' overrides with user-supplied
-- bytes.  'DropEmbeddedBlob' discards the source's blob without
-- substituting anything — the only way to produce a metadata-less BPS
-- from a source BPS that carried metadata.  The three intents are
-- mutually exclusive at the CLI: 'embeddedBlobIntentParser' commits to
-- exactly one based on which (if any) of @--metadata FILE@ and
-- @--drop-metadata@ the user typed.
data EmbeddedBlobIntent
  = CarryIfPresent
  | EmbedFromFile FilePath
  | DropEmbeddedBlob
  deriving (Show, Eq)

-- | The fourteen metadata fields the user can declare on either
-- @create@ or @convert@.  Distinct from 'RequestedPatchMetadata'
-- (the library-facing record) because the embedded-blob concern
-- diverges between the two commands: 'create' asks for an optional
-- file path; 'convert' asks for an 'EmbeddedBlobIntent'.  Those two
-- live in 'CreateMetadataInputs' and 'ConvertMetadataInputs', each
-- of which embeds a 'RequestedMetadataCore' alongside its own
-- blob-shaped field.
data RequestedMetadataCore = RequestedMetadataCore
  { coreTitle                :: Maybe String
  , coreAuthor               :: Maybe String
  , coreDescription          :: Maybe String
  , coreVersion              :: Maybe String
  , coreUndoInclusion        :: Maybe UndoInclusion
  , coreValidationInclusion  :: Maybe ValidationInclusion
  , coreStability            :: Maybe PatchStability
  , coreRomType              :: Maybe PlatformType
  , coreImageType            :: Maybe PPFImageType
  , coreGenre                :: Maybe String
  , coreLanguage             :: Maybe String
  , coreDate                 :: Maybe String
  , coreWebsite              :: Maybe String
  , corePatchEncoding        :: PatchEncoding
  }
  deriving (Show, Eq)

-- | What @slap create@ accepts on the metadata side: the shared core
-- plus an optional path whose bytes get embedded as the patch's
-- metadata blob.  Only BPS consumes the blob today; on other targets
-- the path triggers the same metadata-rejection check as any other
-- format-incompatible field.
data CreateMetadataInputs = CreateMetadataInputs
  { createMetadataCore     :: RequestedMetadataCore
  , createEmbeddedBlobPath :: Maybe FilePath
  }
  deriving (Show, Eq)

-- | What @slap convert@ accepts on the metadata side: the shared core
-- plus an 'EmbeddedBlobIntent' instead of a raw path.  The intent
-- distinguishes \"override with these bytes\", \"drop the source's
-- blob\", and the unspecified case (\"inherit if present\") — the
-- last of which is the convert-default and what every other field
-- on the inputs record does implicitly.
data ConvertMetadataInputs = ConvertMetadataInputs
  { convertMetadataCore       :: RequestedMetadataCore
  , convertEmbeddedBlobIntent :: EmbeddedBlobIntent
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
-- @Quiet@ (default) prints only the final \"applied N records → PATH\"
-- summary.  @Verbose@ (set by @-V@\/@--verbose@) also prints each
-- record as it's applied, via 'renderExplain'.
data Verbosity
  = Quiet
  | Verbose
  deriving (Show, Eq)

-- | The two stderr-prefix categories slap uses; see 'severityPrefix'.
data WarningSeverity = WarningProper | InformationalNote
  deriving (Eq, Show)

-- | The top-level CLI command.  Each constructor wraps a dedicated record
-- type whose fields are total within that subcommand's scope; field
-- selectors are therefore total too, and the @-Wpartial-fields@ warning
-- (enabled in @slap.cabal@) fires on no field of any record below.  The
-- per-record verb prefix (@apply*@, @undo*@, ...) isn't dodging cross-
-- constructor field collisions — there are none — but it makes per-record
-- field accesses self-describing at use sites.
data Command
  = Apply   ApplyCommand
  | Undo    UndoCommand
  | Create  CreateCommand
  | Convert ConvertCommand
  | Info    InfoCommand
  | Explain ExplainCommand

data ApplyCommand = ApplyCommand
  { applyVerificationPolicy :: VerificationPolicy
  , applyVerbosity          :: Verbosity
  , applyOutput             :: ApplyOutput
  , applyFileReading        :: FileReadingOptions
  , applyPatch              :: FilePath
  , applySource             :: FilePath
  }
  deriving (Show)

data UndoCommand = UndoCommand
  { undoVerbosity   :: Verbosity
  , undoFileReading :: FileReadingOptions
  , undoPatch       :: FilePath
  , undoSource      :: FilePath
  , undoOutput      :: UndoOutput
  }
  deriving (Show)

data CreateCommand = CreateCommand
  { createFormat      :: CreateFormat
  , createFileReading :: FileReadingOptions
  , createOriginal    :: FilePath
  , createModified    :: FilePath
  , createOutput      :: FilePath
  , createMetadata    :: CreateMetadataInputs
  , createConstraints :: RequestedConstraints
  }
  deriving (Show)

-- | The 'convertWithSource' field reuses the type name 'ConvertWithSource'
-- defined above; that's namespace coincidence, not collision — Haskell's
-- term/type namespaces are separate.
data ConvertCommand = ConvertCommand
  { convertPatch       :: FilePath
  , convertTo          :: CreateFormat
  , convertOutput      :: ConvertOutput
  , convertWithSource  :: Maybe ConvertWithSource
  , convertFileReading :: FileReadingOptions
  , convertMetadata    :: ConvertMetadataInputs
  , convertConstraints :: RequestedConstraints
  }
  deriving (Show)

data InfoCommand = InfoCommand
  { infoPatch           :: FilePath
  , infoExtractMetadata :: Maybe FilePath
  }
  deriving (Show)

data ExplainCommand = ExplainCommand
  { explainPatch       :: FilePath
  , explainVerbosity   :: ExplainVerbosity
  , explainSource      :: Maybe FilePath
  , explainFileReading :: FileReadingOptions
  }
  deriving (Show)

----------------------------------------------------------------------------
-- CLI
----------------------------------------------------------------------------

main :: IO ()
main = customExecParser (prefs showHelpOnEmpty) options >>= \case
  Apply   parsedCommand -> doApply   parsedCommand
  Undo    parsedCommand -> doUndo    parsedCommand
  Create  parsedCommand -> doCreate  parsedCommand
  Convert parsedCommand -> doConvert parsedCommand
  Info    parsedCommand -> doInfo    parsedCommand
  Explain parsedCommand -> doExplain parsedCommand

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
  ( command "apply"   (info (Apply   <$> applyParser     <**> helper) (progDesc "Apply a patch (safe by default; use -i for in-place)"))
 <> command "undo"    (info (Undo    <$> undoParser      <**> helper) (progDesc "Undo a patch (PPF3 undo data, or UPS self-inverse)"))
 <> command "create"  (info (Create  <$> createParser    <**> helper) (progDesc "Create a patch from two files"))
 <> command "convert" (info (Convert <$> convertParser   <**> helper) (progDesc "Convert a patch to a different format"))
 <> command "info"    (info (Info    <$> patchInfoParser <**> helper) (progDesc "Display patch information"))
 <> command "explain" (info (Explain <$> explainParser   <**> helper) (progDesc "Patch structure summary (use --records for full dump)"))
  )

explainParser :: Parser ExplainCommand
explainParser = do
    patchFile          <- argument str (metavar "PATCH" <> help "Patch file to explain")
    verbosity          <- flag Summary FullRecords
                            (long "records" <> help "Show full record-by-record dump instead of summary")
    maybeWithPath      <- optional (option str (long "with" <> metavar "SOURCE"
                            <> help "Source file (resolves delta/copy operations in output)"))
    fileReadingOptions <- fileReadingOptionsParser
    pure ExplainCommand
      { explainPatch       = patchFile
      , explainVerbosity   = verbosity
      , explainSource      = maybeWithPath
      , explainFileReading = fileReadingOptions
      }

applyParser :: Parser ApplyCommand
applyParser = do
    verificationPolicy <- verificationPolicyParser
    verbosity          <- verbosityParser
    fileReadingOptions <- fileReadingOptionsParser
    patch              <- argument str (metavar "PATCH" <> help "Patch file")
    source             <- argument str (metavar "SOURCE" <> help "Source file to patch (not modified unless --in-place)")
    output             <- applyOutputParser
    pure ApplyCommand
      { applyVerificationPolicy = verificationPolicy
      , applyVerbosity          = verbosity
      , applyOutput             = output
      , applyFileReading        = fileReadingOptions
      , applyPatch              = patch
      , applySource             = source
      }

verificationPolicyParser :: Parser VerificationPolicy
verificationPolicyParser = flag EnforceVerification SkipVerification
  (long "no-verify" <> help "Skip checksum validation (mismatches become warnings)")

verbosityParser :: Parser Verbosity
verbosityParser = flag Quiet Verbose
  (long "verbose" <> short 'v' <> help "Print each record as it's applied")

-- | Parser for the four mutually exclusive output lanes.  'asum' tries
-- each lane in turn; combinations that span multiple lanes are rejected
-- at parse time, with no silent precedence resolution.  The two writing
-- lanes ('ApplyToExplicitFile' and 'ApplyToDerivedFile') share a single
-- 'writingLane' parser so that @--force@ has exactly one home in the
-- parser tree — otherwise a bare @--force@ would partially match the
-- explicit-file lane (consuming the flag but missing the path) and
-- optparse-applicative would prefer that partial match's error over the
-- derived-file lane's success.  Within 'writingLane', whether the user
-- supplied an explicit path decides which constructor 'chooseWritingLane'
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
    writingLane = chooseWritingLane
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

        chooseWritingLane :: Maybe FilePath -> OverwritePolicy -> ApplyOutput
        chooseWritingLane Nothing     policy = ApplyToDerivedFile policy
        chooseWritingLane (Just path) policy = ApplyToExplicitFile path policy

fileReadingOptionsParser :: Parser FileReadingOptions
fileReadingOptionsParser = FileReadingOptions <$> archiveHandlingFromSwitch
  where
    archiveHandlingFromSwitch = flag AutoUnwrapSingleEntryArchives ReadBytesVerbatim
      (long "raw" <> help "Read input files as raw bytes; do not attempt to unwrap zip/7z archives")

undoParser :: Parser UndoCommand
undoParser = do
    verbosity          <- verbosityParser
    fileReadingOptions <- fileReadingOptionsParser
    patch              <- argument str (metavar "PATCH" <> help "Patch file")
    source             <- argument str (metavar "SOURCE" <> help "File to restore")
    output             <- undoOutputParser
    pure UndoCommand
      { undoVerbosity   = verbosity
      , undoFileReading = fileReadingOptions
      , undoPatch       = patch
      , undoSource      = source
      , undoOutput      = output
      }

undoOutputParser :: Parser UndoOutput
undoOutputParser = maybe UndoInPlace UndoToExplicitFile
  <$> optional (option str (long "output" <> short 'o' <> metavar "FILE"
      <> help "Write restored source to FILE (default: overwrite SOURCE)"))

convertOutputParser :: Parser ConvertOutput
convertOutputParser = maybe ConvertToDerivedFile ConvertToExplicitFile
  <$> optional (option str (long "output" <> short 'o' <> metavar "FILE"
      <> help "Output file (default: replace input extension with target format's)"))

createParser :: Parser CreateCommand
createParser = do
    format             <- createFormatParser
    fileReadingOptions <- fileReadingOptionsParser
    original           <- argument str (metavar "ORIGINAL" <> help "Original unmodified file")
    modified           <- argument str (metavar "MODIFIED" <> help "Modified file")
    outputFile         <- argument str (metavar "OUTPUT"   <> help "Output patch file")
    metadataInputs     <- createMetadataInputsParser
    constraints        <- constraintsParser
    pure CreateCommand
      { createFormat      = format
      , createFileReading = fileReadingOptions
      , createOriginal    = original
      , createModified    = modified
      , createOutput      = outputFile
      , createMetadata    = metadataInputs
      , createConstraints = constraints
      }

convertParser :: Parser ConvertCommand
convertParser = do
    patchFile          <- argument str (metavar "PATCH" <> help "Patch file to convert")
    targetFormat       <- convertToParser
    output             <- convertOutputParser
    withSource         <- optional convertWithSourceParser
    fileReadingOptions <- fileReadingOptionsParser
    metadataInputs     <- convertMetadataInputsParser
    constraints        <- constraintsParser
    pure ConvertCommand
      { convertPatch       = patchFile
      , convertTo          = targetFormat
      , convertOutput      = output
      , convertWithSource  = withSource
      , convertFileReading = fileReadingOptions
      , convertMetadata    = metadataInputs
      , convertConstraints = constraints
      }

-- | Parser for the 'RequestedConstraints' bag, shared between
-- @slap create@ and @slap convert@. Each constraint contributes one
-- flag; 'constraintFlagName' is the single source of truth for the
-- spelling.
constraintsParser :: Parser RequestedConstraints
constraintsParser = do
  smcShape <- flag AllowAnyTruncationShape RequireSMCShapedTruncation
    ( long (constraintFlagName SMCShapeConstraint)
   <> help ("Refuse to emit an IPS truncation marker whose declared size"
         ++ " doesn't satisfy SNESTool's (size & 0xFFF) == 0x200 shape filter")
    )
  pure RequestedConstraints
    { requestedSMCShape = smcShape
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
    <> help ("Output format: " ++ intercalate ", " advertisedCreateFormats
              ++ " (default: bps)"))

-- | The target-format flag accepted by @slap convert@.  No default:
-- conversion has to know what it is converting to.
convertToParser :: Parser CreateFormat
convertToParser = option (eitherReader parseCreateFormat)
  (long "to" <> short 't' <> metavar "FMT"
    <> help ("Target format: " ++ intercalate ", " advertisedCreateFormats))

-- | Parser for the fourteen metadata fields shared between @create@
-- and @convert@.  The embedded-blob concern lives elsewhere because
-- it diverges between the two commands; see 'createMetadataInputsParser'
-- and 'convertMetadataInputsParser'.
requestedMetadataCoreParser :: Parser RequestedMetadataCore
requestedMetadataCoreParser = do
    title             <- optional (option str (long "title" <> metavar "TEXT"
                            <> help "Patch title (EBP/NINJA2)"))
    author            <- optional (option str (long "author" <> metavar "TEXT"
                            <> help "Patch author (EBP/DPS/NINJA2)"))
    description       <- optional (option str (long "description" <> metavar "TEXT"
                            <> help "Patch description (DPS/PPF3/EBP/APS-N64/NINJA2/PCHTXT)"))
    version           <- optional (option str (long "patch-version" <> metavar "TEXT"
                            <> help "Patch version (DPS/NINJA2)"))
    includeUndo       <- optional (flag' OmitUndoData       (long "no-undo"
                            <> help "Omit undo data (default: included when the format supports it)"))
    includeValidation <- optional (flag' OmitValidationBlock (long "no-validate"
                            <> help "Omit validation block (default: included when the format supports it)"))
    unstable          <- optional (flag' UnstablePatch (long "unstable"
                            <> help "Mark patch unstable (DPS)"))
    romType           <- optional (option (eitherReader parseRomType) (long "rom-type" <> metavar "TYPE"
                            <> help ("ROM type (NINJA1/NINJA2): " ++ intercalate ", " advertisedRomTypes)))
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
                            <> help "Text encoding for NINJA2 metadata: utf8, system (default: utf8)")
    pure RequestedMetadataCore
      { coreTitle               = title
      , coreAuthor              = author
      , coreDescription         = description
      , coreVersion             = version
      , coreUndoInclusion       = includeUndo
      , coreValidationInclusion = includeValidation
      , coreStability           = unstable
      , coreRomType             = romType
      , coreImageType           = imageType
      , coreGenre               = genre
      , coreLanguage            = language
      , coreDate                = date
      , coreWebsite             = website
      , corePatchEncoding       = patchEncoding
      }

-- | Create-side metadata: shared core plus an optional file path
-- whose bytes get embedded as the patch's metadata blob (BPS only;
-- the rejection check refuses the flag against any other target).
createMetadataInputsParser :: Parser CreateMetadataInputs
createMetadataInputsParser = CreateMetadataInputs
  <$> requestedMetadataCoreParser
  <*> optional (option str (long "metadata" <> metavar "FILE"
        <> help "Embed bytes from FILE as the output patch's metadata (BPS only)"))

-- | Convert-side metadata: shared core plus an 'EmbeddedBlobIntent'.
-- The intent parser admits one of @--metadata FILE@, @--drop-metadata@,
-- or neither — combining the two is rejected at parse time because
-- @--drop-metadata@'s alternative consumes only itself.
convertMetadataInputsParser :: Parser ConvertMetadataInputs
convertMetadataInputsParser = ConvertMetadataInputs
  <$> requestedMetadataCoreParser
  <*> embeddedBlobIntentParser

-- | Parse the BPS embedded-blob intent for @slap convert@.  The three
-- alternatives are mutually exclusive: @--metadata FILE@ commits to
-- 'EmbedFromFile' and consumes the path; @--drop-metadata@ commits
-- to 'DropEmbeddedBlob' and consumes nothing else; absent both, the
-- 'pure' fallback selects 'CarryIfPresent'.  Passing both flags
-- leaves one unconsumed and the top-level parser rejects the
-- command — the same lane discipline used elsewhere in this file.
embeddedBlobIntentParser :: Parser EmbeddedBlobIntent
embeddedBlobIntentParser = asum
  [ EmbedFromFile <$> option str (long "metadata" <> metavar "FILE"
      <> help "Override embedded metadata with bytes from FILE (BPS target only)")
  , DropEmbeddedBlob <$ flag' () (long "drop-metadata"
      <> help ("Discard the source patch's embedded metadata (BPS"
               ++ [rightwardsArrow] ++ "BPS; default is to inherit)"))
  , pure CarryIfPresent
  ]

-- | Whether a CLI token is part of the canonical advertised set or
-- a quietly-accepted alias.  The parser case bodies in
-- 'parseCreateFormat' and 'parseRomType' historically inlined the
-- canonical list in their error messages and had no compiler-checked
-- relationship to the case arms.  Tagging each token in a single
-- table lets the advertised list be derived, eliminating any drift
-- between "what the parser accepts" and "what we tell users to type."
data TokenVisibility = Canonical | Alias

-- | The full set of CLI tokens 'parseCreateFormat' accepts, paired
-- with the 'CreateFormat' each token resolves to and a tag for
-- whether the token is advertised in error messages and help strings
-- ('Canonical') or quietly accepted as a convenience alias ('Alias').
-- Source of truth — both 'parseCreateFormat' and
-- 'advertisedCreateFormats' derive from this table.
createFormatTokens :: [(String, CreateFormat, TokenVisibility)]
createFormatTokens =
  [ ("bps",     CreateDiff   CreateBPS,    Canonical)
  , ("ips",     CreateDirect CreateIPS,    Canonical)
  , ("ips32",   CreateDirect CreateIPS32,  Canonical)
  , ("ebp",     CreateDirect CreateEBP,    Canonical)
  , ("ups",     CreateDiff   CreateUPS,    Canonical)
  , ("ppf3",    CreateDirect CreatePPF3,   Canonical)
  , ("ppf",     CreateDirect CreatePPF3,   Alias)
  , ("pmsr",    CreateDirect CreatePMSR,   Canonical)
  , ("ninja1",  CreateDirect CreateNINJA1, Canonical)
  , ("dps",     CreateDiff   CreateDPS,    Canonical)
  , ("ninja2",  CreateDiff   CreateNINJA2, Canonical)
  , ("aps-n64", CreateDirect CreateAPSN64, Canonical)
  , ("apsn64",  CreateDirect CreateAPSN64, Alias)
  , ("aps-gba", CreateDiff   CreateAPSGBA, Canonical)
  , ("apsgba",  CreateDiff   CreateAPSGBA, Alias)
  , ("gdiff",   CreateDiff   CreateGDIFF,  Canonical)
  , ("pchtxt",  CreateDirect CreatePCHTXT, Canonical)
  ]

-- | The canonical create-format tokens 'parseCreateFormat'
-- advertises in its error message and the @--format@ / @--to@ help
-- strings.  Derived from 'createFormatTokens' by filtering out
-- aliases.
advertisedCreateFormats :: [String]
advertisedCreateFormats =
  [token | (token, _format, Canonical) <- createFormatTokens]

parseCreateFormat :: String -> Either String CreateFormat
parseCreateFormat input =
  case lookup (map toLower input)
              [(token, format) | (token, format, _visibility) <- createFormatTokens] of
    Just format -> Right format
    Nothing     -> Left ("unknown format: " ++ input
                      ++ "\n  expected: " ++ intercalate ", " advertisedCreateFormats)

parsePatchEncoding :: String -> Either String PatchEncoding
parsePatchEncoding input = case map toLower input of
  "utf8"   -> Right PatchEncodingUTF8
  "system" -> Right PatchEncodingSystem
  _        -> Left ("unknown patch encoding: " ++ input ++ "\n  expected: utf8, system")

-- | The full set of CLI tokens 'parseRomType' accepts, paired with
-- the 'PlatformType' each token resolves to and a 'TokenVisibility'
-- tag.  Source of truth — both 'parseRomType' and 'advertisedRomTypes'
-- derive from this table.  No aliases today; every token is
-- 'Canonical'.
romTypeTokens :: [(String, PlatformType, TokenVisibility)]
romTypeTokens =
  [ ("raw",  PlatformRaw,             Canonical)
  , ("nes",  PlatformNES,             Canonical)
  , ("fds",  PlatformFDS,             Canonical)
  , ("snes", PlatformSNES,            Canonical)
  , ("n64",  PlatformN64,             Canonical)
  , ("gb",   PlatformGB,              Canonical)
  , ("gbc",  PlatformGBC,             Canonical)
  , ("gba",  PlatformGBA,             Canonical)
  , ("ngp",  PlatformNGP,             Canonical)
  , ("ngpc", PlatformNGPC,            Canonical)
  , ("sms",  PlatformSMS,             Canonical)
  , ("gg",   PlatformGameGear,        Canonical)
  , ("mega", PlatformGenesis,         Canonical)
  , ("pce",  PlatformPCEngine,        Canonical)
  , ("ws",   PlatformWonderSwan,      Canonical)
  , ("wsc",  PlatformWonderSwanColor, Canonical)
  , ("lynx", PlatformLynx,            Canonical)
  , ("jag",  PlatformJaguar,          Canonical)
  , ("gp32", PlatformGP32,            Canonical)
  ]

-- | The canonical ROM-type tokens 'parseRomType' advertises in its
-- error message and the @--rom-type@ help string.  Derived from
-- 'romTypeTokens' by filtering out aliases.  (Today every entry is
-- canonical; the filter is structural, not narrowing.)
advertisedRomTypes :: [String]
advertisedRomTypes =
  [token | (token, _platformType, Canonical) <- romTypeTokens]

parseRomType :: String -> Either String PlatformType
parseRomType input =
  case lookup (map toLower input)
              [(token, platformType) | (token, platformType, _visibility) <- romTypeTokens] of
    Just platformType -> Right platformType
    Nothing           -> Left ("unknown ROM type: " ++ input
                            ++ "\n  expected: " ++ intercalate ", " advertisedRomTypes)

parseImageType :: String -> Either String PPFImageType
parseImageType typeString = case map toLower typeString of
  "bin" -> Right BIN
  "gi"  -> Right GI
  _ -> Left ("unknown image type: " ++ typeString ++ "\n  expected: bin, gi")

patchInfoParser :: Parser InfoCommand
patchInfoParser = do
    patchFile <- argument str (metavar "PATCH" <> help "Patch file to inspect")
    extractMetadataPath <- optional (option str (long "extract-metadata" <> metavar "FILE"
        <> help "Write embedded metadata to FILE (BPS)"))
    pure InfoCommand
      { infoPatch           = patchFile
      , infoExtractMetadata = extractMetadataPath
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
          hPutStrLn stderr ("slap: unwrapped " ++ path ++ spacePaddedRightwardsArrow ++ entryName)
          pure unwrappedBytes

-- | Read a file, honoring the 'FileReadingOptions' view of archive handling.
-- 'InfoCommand' currently uses 'readUnwrap' unconditionally; if it ever grows
-- a @--raw@ flag of its own, route it through here instead.
readMaybeUnwrap :: FileReadingOptions -> FilePath -> IO ByteString.ByteString
readMaybeUnwrap fileReadingOptions = case fileReadingArchiveHandling fileReadingOptions of
  AutoUnwrapSingleEntryArchives -> readUnwrap
  ReadBytesVerbatim             -> ByteString.readFile

-- | Lift a 'RequestedMetadataCore' into the library's
-- 'RequestedPatchMetadata' record.  Every core field maps to its
-- 'requested*' counterpart unchanged; 'requestedEmbeddedBlob' is left
-- 'Nothing' so each command's resolver can populate it from its own
-- blob-shaped input.
coreToRequestedPatchMetadata :: RequestedMetadataCore -> RequestedPatchMetadata
coreToRequestedPatchMetadata core = RequestedPatchMetadata
  { requestedTitle               = coreTitle               core
  , requestedAuthor              = coreAuthor              core
  , requestedDescription         = coreDescription         core
  , requestedVersion             = coreVersion             core
  , requestedUndoInclusion       = coreUndoInclusion       core
  , requestedValidationInclusion = coreValidationInclusion core
  , requestedStability           = coreStability           core
  , requestedRomType             = coreRomType             core
  , requestedImageType           = coreImageType           core
  , requestedGenre               = coreGenre               core
  , requestedLanguage            = coreLanguage            core
  , requestedDate                = coreDate                core
  , requestedWebsite             = coreWebsite             core
  , requestedPatchEncoding       = corePatchEncoding       core
  , requestedEmbeddedBlob        = Nothing
  }

-- | Resolve @slap create@'s metadata inputs.  @--metadata FILE@'s
-- contents (when supplied) become the embedded blob; otherwise the
-- blob field stays 'Nothing'.
resolveCreateMetadata :: CreateMetadataInputs -> IO RequestedPatchMetadata
resolveCreateMetadata inputs = do
  embeddedBlob <- traverse ByteString.readFile (createEmbeddedBlobPath inputs)
  pure (coreToRequestedPatchMetadata (createMetadataCore inputs))
        { requestedEmbeddedBlob = embeddedBlob }

-- | Resolve @slap convert@'s metadata inputs.  Only 'EmbedFromFile'
-- triggers IO and produces a 'Just'; 'CarryIfPresent' and
-- 'DropEmbeddedBlob' both leave the field 'Nothing'.  Distinguishing
-- the latter two happens in 'doConvert' after the source-patch
-- merge: the merge would re-introduce the source's blob for both,
-- but a 'DropEmbeddedBlob' intent overrides it back to 'Nothing'.
resolveConvertMetadata :: ConvertMetadataInputs -> IO RequestedPatchMetadata
resolveConvertMetadata inputs = do
  embeddedBlob <- case convertEmbeddedBlobIntent inputs of
    EmbedFromFile path -> Just <$> ByteString.readFile path
    DropEmbeddedBlob   -> pure Nothing
    CarryIfPresent     -> pure Nothing
  pure (coreToRequestedPatchMetadata (convertMetadataCore inputs))
        { requestedEmbeddedBlob = embeddedBlob }

----------------------------------------------------------------------------
-- Info & Explain
----------------------------------------------------------------------------

doInfo :: InfoCommand -> IO ()
doInfo parsedCommand = do
  parsed <- readAndParsePatch (infoPatch parsedCommand)
  let explain = patchExplain parsed
      summary = patchRecordSummary parsed
  putStrLn $ "format:      " ++ explainFormat explain
  mapM_ (putStrLn . renderField) (explainHeader explain)
  putStrLn $ renderField (MetaField (recordUnit summary) (show (recordCount summary)))
  emitWarnings WarningProper (patchWarnings parsed)
  case infoExtractMetadata parsedCommand of
    Nothing -> pure ()
    Just outPath -> case patchMetadata parsed of
      Nothing   -> hPutStrLn stderr "slap: no metadata in this patch"
      Just metadataBytes -> do
        ByteString.writeFile outPath metadataBytes
        putStrLn ("wrote metadata to " ++ outPath)

doExplain :: ExplainCommand -> IO ()
doExplain parsedCommand = do
  parsed <- readAndParsePatch (explainPatch parsedCommand)
  maybeSource <- case explainSource parsedCommand of
    Nothing   -> pure Nothing
    Just path -> Just <$> readMaybeUnwrap (explainFileReading parsedCommand) path
  let renderFunction = case explainVerbosity parsedCommand of
        Summary     -> renderSummary
        FullRecords -> renderExplain
  putStr (renderFunction maybeSource (patchExplain parsed))
  emitWarnings WarningProper (patchWarnings parsed)

----------------------------------------------------------------------------
-- Apply
----------------------------------------------------------------------------

doApply :: ApplyCommand -> IO ()
doApply parsedCommand = do
  parsed <- readAndParsePatch (applyPatch parsedCommand)
  emitWarnings WarningProper (patchWarnings parsed)
  case applyVerbosity parsedCommand of
    Verbose -> hPutStr stderr (renderExplain Nothing (patchExplain parsed))
    Quiet   -> pure ()

  let verification = patchVerification parsed
      verificationPolicy = applyVerificationPolicy parsedCommand

      applyAndWriteTo outputPath = do
        sourceBytes <- readMaybeUnwrap (applyFileReading parsedCommand) (applySource parsedCommand)
        let source = SourceFileContents sourceBytes
        verifySource verificationPolicy verification source
        outcome <- orDie =<< runApply (patchApply parsed) source
        emitWarnings WarningProper (outcomeWarnings outcome)
        let target = outcomeValue outcome
        verifyTarget verificationPolicy verification target
        ByteString.writeFile outputPath (unTargetFileContents target)
        let appliedSummary = patchRecordSummary parsed
        putStrLn $ "applied " ++ show (recordCount appliedSummary) ++ " " ++ recordUnit appliedSummary
                ++ spacePaddedRightwardsArrow ++ outputPath

  case applyOutput parsedCommand of
    ApplyDryRun -> do
      let reportedPath = deriveOutput (applyPatch parsedCommand) (applySource parsedCommand)
          summary = patchRecordSummary parsed
      putStrLn $ "would apply " ++ show (recordCount summary) ++ " " ++ recordUnit summary
              ++ spacePaddedRightwardsArrow ++ reportedPath
      case verifySourceCRC32 verification of
        Just expected -> do
          sourceBytes <- readMaybeUnwrap (applyFileReading parsedCommand) (applySource parsedCommand)
          let actual = rustyCRC32 sourceBytes
          putStrLn $ "source CRC: " ++ formatCRC actual
            ++ if actual == expected
                 then [' ', checkMark]
                 else [' ', ballotX] ++ " (expected " ++ formatCRC expected ++ ")"
        Nothing -> pure ()
      exitSuccess
    ApplyInPlace backupBehavior -> do
      case backupBehavior of
        WriteBackup -> do
          let backupPath = applySource parsedCommand ++ ".bak"
          copyFile (applySource parsedCommand) backupPath
          hPutStrLn stderr ("slap: backup: " ++ backupPath)
        NoBackup -> pure ()
      applyAndWriteTo (applySource parsedCommand)
    ApplyToExplicitFile outputPath overwritePolicy -> do
      refuseOverwrite overwritePolicy outputPath
      applyAndWriteTo outputPath
    ApplyToDerivedFile overwritePolicy -> do
      let outputPath = deriveOutput (applyPatch parsedCommand) (applySource parsedCommand)
      refuseOverwrite overwritePolicy outputPath
      applyAndWriteTo outputPath

----------------------------------------------------------------------------
-- Undo
----------------------------------------------------------------------------

doUndo :: UndoCommand -> IO ()
doUndo parsedCommand = do
  parsed <- readAndParsePatch (undoPatch parsedCommand)
  emitWarnings WarningProper (patchWarnings parsed)
  case undoVerbosity parsedCommand of
    Verbose -> hPutStr stderr (renderExplain Nothing (patchExplain parsed))
    Quiet   -> pure ()
  case patchUndo parsed of
    Nothing -> die "undo not supported for this format"
    Just undo -> do
      modified <- ByteString.readFile (undoSource parsedCommand)
      outcome <- orDie (runUndo undo (TargetFileContents modified))
      emitWarnings WarningProper (outcomeWarnings outcome)
      let SourceFileContents result = outcomeValue outcome
          outputPath = case undoOutput parsedCommand of
            UndoInPlace                 -> undoSource parsedCommand
            UndoToExplicitFile explicit -> explicit
      ByteString.writeFile outputPath result
      putStrLn "reverted"

----------------------------------------------------------------------------
-- Create
----------------------------------------------------------------------------

doCreate :: CreateCommand -> IO ()
doCreate parsedCommand = do
  createMeta    <- resolveCreateMetadata (createMetadata parsedCommand)
  orDie (rejectIncompatibleMetadata    (createFormat parsedCommand) createMeta)
  orDie (rejectIncompatibleConstraints (createFormat parsedCommand) (createConstraints parsedCommand))
  originalBytes <- readMaybeUnwrap (createFileReading parsedCommand) (createOriginal parsedCommand)
  modifiedBytes <- readMaybeUnwrap (createFileReading parsedCommand) (createModified parsedCommand)
  emitWarnings InformationalNote (createDefaultNotes (createFormat parsedCommand) createMeta)
  result <- orDie (createFromMemory
                     (createFormat parsedCommand)
                     (SourceFileContents originalBytes)
                     (TargetFileContents modifiedBytes)
                     createMeta
                     Nothing
                     (createConstraints parsedCommand))
  emitWarnings InformationalNote (resultWarnings result)
  ByteString.writeFile (createOutput parsedCommand) (unPatchFileContents (resultBytes result))
  putStrLn ("wrote " ++ createOutput parsedCommand)

----------------------------------------------------------------------------
-- Convert
----------------------------------------------------------------------------

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
chooseConvertDispatch :: ConvertCommand -> SomePatch -> ConvertDispatch
chooseConvertDispatch parsedCommand parsed =
  case convertWithSource parsedCommand of
    Just withSource -> ApplyAndRecreate withSource
    Nothing -> case patchContents parsed of
      Just contents -> SourceLessConvert contents
      Nothing       -> ConvertRequiresSource parsed

doConvert :: ConvertCommand -> IO ()
doConvert parsedCommand = do
  cliMeta <- resolveConvertMetadata (convertMetadata parsedCommand)
  orDie (rejectIncompatibleMetadata    (convertTo parsedCommand) cliMeta)
  orDie (rejectIncompatibleConstraints (convertTo parsedCommand) (convertConstraints parsedCommand))
  parsed <- readAndParsePatch (convertPatch parsedCommand)
  emitWarnings WarningProper (patchWarnings parsed)
  let outputFile = case convertOutput parsedCommand of
        ConvertToExplicitFile explicit -> explicit
        ConvertToDerivedFile           -> replaceExtension (convertPatch parsedCommand)
                                                           (formatExtension (convertTo parsedCommand))
      blobIntent = convertEmbeddedBlobIntent (convertMetadata parsedCommand)
      -- The merge inherits the source patch's embedded blob whenever
      -- the CLI didn't supply one — desirable for 'CarryIfPresent',
      -- but for 'DropEmbeddedBlob' it would re-introduce the very
      -- bytes the user asked to discard.  Override the field back to
      -- 'Nothing' for that one intent.
      mergedMeta = case blobIntent of
        DropEmbeddedBlob ->
          (mergeRequestedMetadata cliMeta (patchExtractedMeta parsed))
            { requestedEmbeddedBlob = Nothing }
        _ -> mergeRequestedMetadata cliMeta (patchExtractedMeta parsed)
      bpsDropWarnings = computeBPSDropWarnings parsed (convertTo parsedCommand)
  case chooseConvertDispatch parsedCommand parsed of
    ApplyAndRecreate withSource -> do
      sourceBytes <- readMaybeUnwrap (convertFileReading parsedCommand) (convertWithSourcePath withSource)
      let source = SourceFileContents sourceBytes
      verifySource (convertWithVerification withSource) (patchVerification parsed) source
      target <- applyForConvert parsed source
      createResult <- orDie (createFromMemory (convertTo parsedCommand) (SourceFileContents sourceBytes) target mergedMeta (patchContents parsed) (convertConstraints parsedCommand))
      emitWarnings InformationalNote (patchSourceNotes parsed ++ bpsDropWarnings
                        ++ createDefaultNotes (convertTo parsedCommand) mergedMeta
                        ++ resultWarnings createResult)
      ByteString.writeFile outputFile (unPatchFileContents (resultBytes createResult))
      putStrLn ("converted to " ++ formatName (convertTo parsedCommand) ++ ": " ++ outputFile)
    SourceLessConvert contents -> do
      convertResult <- orDie (convertDirect contents (convertTo parsedCommand) mergedMeta (convertConstraints parsedCommand))
      emitWarnings InformationalNote (patchSourceNotes parsed ++ resultWarnings convertResult)
      ByteString.writeFile outputFile (unPatchFileContents (resultBytes convertResult))
      putStrLn ("converted to " ++ formatName (convertTo parsedCommand) ++ ": " ++ outputFile)
    ConvertRequiresSource somePatch ->
      die (needSourceMessage somePatch)

-- | Apply a parsed patch to source bytes, returning target bytes (for convert).
applyForConvert :: SomePatch -> SourceFileContents -> IO TargetFileContents
applyForConvert somePatch source = do
  outcome <- orDie =<< runApply (patchApply somePatch) source
  emitWarnings WarningProper (outcomeWarnings outcome)
  pure (outcomeValue outcome)

-- | Error message when --with is required but not provided.
needSourceMessage :: SomePatch -> String
needSourceMessage somePatch = "converting from " ++ name ++ " requires the original ROM (--with SOURCE)\n"
  ++ name ++ " " ++ reason ++ " " ++ [emDash] ++ " the original ROM is needed\nto reconstruct the target file for re-encoding."
  where
    name = formatLabelName (patchFormat somePatch)
    reason
      | patchIsDifferential somePatch = "stores differential data, not raw bytes"
      | otherwise                  = "does not carry extractable records"

-- | Warn when the source patch carries embedded BPS metadata bytes and
-- the target format has no metadata channel to put them in — i.e.,
-- when conversion silently drops the bytes.  Returns @[]@ for
-- BPS→BPS (the merge carries the bytes through) and for any source
-- patch that didn't have metadata to begin with.
computeBPSDropWarnings :: SomePatch -> CreateFormat -> [SlapWarning]
computeBPSDropWarnings parsed targetFormat = case patchMetadata parsed of
  Just metaBytes | targetFormat /= CreateDiff CreateBPS ->
    [MetadataDropped (ByteString.length metaBytes)]
  _ -> []

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
  forM_ (verifyFileSizeRequired verification) $ \expectedSize ->
    checkFileSize verificationPolicy SourceSide expectedSize (FileSize (fromIntegral (ByteString.length sourceBytes)))
  forM_ (verifySourceBlocks verification) $ \(BlockCheck blockOffset expectedCRC) ->
    warnBlock verificationPolicy "source" blockOffset expectedCRC (crc16 (safeSlice (fromIntegral (unOffset blockOffset)) 0x10000 sourceBytes))
  forM_ (verifyPPFBlock verification) $ \(ValidationBlock blockOffset expectedData) ->
    warnPPFBlock verificationPolicy blockOffset expectedData sourceBytes
  forM_ (verifyFileSizeAdvisory verification) $ \expectedSize ->
    warnFileSize verificationPolicy expectedSize (FileSize (fromIntegral (ByteString.length sourceBytes)))
  forM_ (verifySourceBytes verification) $ \(ByteCheck checkOffset (AdvisoryExpectedBytes expectedData) checkLabel) ->
    warnSourceBytes verificationPolicy checkLabel checkOffset expectedData sourceBytes

verifyTarget :: VerificationPolicy -> Verification -> TargetFileContents -> IO ()
verifyTarget verificationPolicy verification (TargetFileContents targetBytes) = do
  forM_ (verifyTargetCRC32 verification) $ \expected ->
    checkCRC verificationPolicy TargetSide expected (rustyCRC32 targetBytes)
  forM_ (verifyTargetMD5 verification) $ \expected ->
    checkHash verificationPolicy TargetSide MD5 (unMD5Hash expected) (unMD5Hash (md5 targetBytes))
  forM_ (verifyTargetBlocks verification) $ \(BlockCheck blockOffset expectedCRC) ->
    warnBlock verificationPolicy "target" blockOffset expectedCRC (crc16 (safeSlice (fromIntegral (unOffset blockOffset)) 0x10000 targetBytes))
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

warnBlock :: VerificationPolicy -> String -> Offset -> CRC16 -> CRC16 -> IO ()
warnBlock verificationPolicy label blockOffset expected actual = case verificationPolicy of
  SkipVerification    -> pure ()
  EnforceVerification
    | expected == actual -> pure ()
    | otherwise          -> warn (label ++ " CRC16 mismatch at 0x" ++ padHex 8 (unOffset blockOffset))

warnPPFBlock :: VerificationPolicy -> Offset -> ValidationBlockBytes -> ByteString.ByteString -> IO ()
warnPPFBlock verificationPolicy blockOffset (ValidationBlockBytes expectedData) sourceBytes = case verificationPolicy of
  SkipVerification    -> pure ()
  EnforceVerification ->
    let actual = safeSlice (fromIntegral (unOffset blockOffset)) (ByteString.length expectedData) sourceBytes
    in when (actual /= expectedData) $
         warn ("validation block mismatch at 0x" ++ padHex 8 (unOffset blockOffset))

warnFileSize :: VerificationPolicy -> FileSize -> FileSize -> IO ()
warnFileSize verificationPolicy (FileSize expectedSize) (FileSize actualSize) = case verificationPolicy of
  SkipVerification    -> pure ()
  EnforceVerification ->
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

warnSourceBytes :: VerificationPolicy -> String -> Offset -> ByteString.ByteString -> ByteString.ByteString -> IO ()
warnSourceBytes verificationPolicy label checkOffset expectedData sourceBytes = case verificationPolicy of
  SkipVerification    -> pure ()
  EnforceVerification ->
    let actual = safeSlice (unOffset checkOffset) (ByteString.length expectedData) sourceBytes
    in when (actual /= expectedData) $
         warn (label ++ " mismatch at 0x" ++ padHex 8 (unOffset checkOffset))

safeSlice :: Int -> Int -> ByteString.ByteString -> ByteString.ByteString
safeSlice offset sliceLength input = ByteString.take sliceLength (ByteString.drop offset input)

formatCRC :: CRC32 -> String
formatCRC crcValue = "0x" ++ showCRC32 crcValue

severityPrefix :: WarningSeverity -> String
severityPrefix WarningProper     = "slap: warning: "
severityPrefix InformationalNote = "slap: "

emitWarnings :: WarningSeverity -> [SlapWarning] -> IO ()
emitWarnings severity = traverse_ $ \warning ->
  hPutStrLn stderr (severityPrefix severity ++ renderSlapWarning warning)

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
