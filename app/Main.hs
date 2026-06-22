{-# LANGUAGE ApplicativeDo #-}
{-# LANGUAGE OverloadedStrings #-}

module Main (main) where

import Slap.SomePatch
  ( SomePatch(..)
  , PatchKind(..)
  , ApplyStrategy(..)
  , UndoStrategy(..)
  , Verification(..)
  , BlockCheck(..)
  , ValidationBlock(..)
  , WindowCheck(..)
  , ByteCheck(..)
  , AdvisoryExpectedBytes(..)
  , FileSizeCheck(..)
  , applySourcePreHash
  , parseSome
  )
import Slap.Display.Common (renderInfoLine, pathText)
import Slap.Display.Info (renderPatchInfo, renderActionLine)
import Slap.Display.Analysis (renderAnalysisFull, renderAnalysisSummary)
import Slap.FileContents (InputFileContents(..), OutputFileContents(..), PatchFileContents(..))
import Slap.Measure (Offset(..), Length(..), FileSize(..),
                     ExpectedSize(..), ActualSize(..), byteLength)
import Slap.Convert (DirectCreate(..), DifferentialCreate(..), CreateFormat(..),
                     PatchContents,
                     RequestedPatchMetadata(..),
                     RequestedConstraints(..),
                     rejectIncompatibleConstraints,
                     RequestedDialects(..),
                     noDialectsRequested,
                     acceptedDialects,
                     rejectIncompatibleDialects,
                     UndoInclusion(..), VerificationInclusion(..), PatchStability(..),
                     TextMode(..), createDefaultAdvisories, convertDirect,
                     mergeRequestedMetadata, rejectIncompatibleMetadata,
                     formatExtension, formatName)
import Slap.XDelta1.Types (ResolvedXDelta1FileNames,
                            resolveXDelta1FileNames,
                            requireXDelta1FileNames,
                            XDelta1FromName(..), XDelta1ToName(..),
                            XDelta1PatchCompression(..))
import Slap.Constraint (Constraint(..), constraintFlagName)
import Slap.Dialect (Dialect(..), dialectFlagName)
import Slap.PPF1.Types (PPF1Origin(..))
import Slap.IPS.Types (SMCShapeRequirement(..))
import Slap.Create (createPatch)
import Slap.Text (EncodedText(..), EncodingName(..), resolveEncodingName,
                  advertisedEncodingNames, renderAdvertisedEncodings)
import Data.Text (Text)
import qualified Data.Text as Text
import qualified Data.Text.IO as TextIO
-- The CLI parsers below wrap incoming 'String' as 'EncodedText' tagged 'EncodingUtf8' at the boundary:
-- text slap writes is always UTF-8, with no write-side encoding choice.
import Slap.PPF3.Types (PPF3ImageType(..))
import Slap.PlatformType (PlatformType(..))
import Slap.Archive (detectArchive, unwrapArchive)
import Slap.Binary (crc16, md5, sha1, viewBytesInRange)
import Slap.Checksum (CRC32(..), CRC16, Adler32(..),
                      ExpectedCRC32(..), ActualCRC32(..), showCRC32)
import Slap.FFI (crc32, adler32)
import Slap.Status (SlapError(..), SlapAdvisory(..), CreateResult(..), Outcome(..),
                   VerificationSide(..), HashAlgorithm(..),
                   ExpectedAdler32(..), ActualAdler32(..), ByteCheckLabel(..),
                   emitAdvisories, bail, bailError, orBail)
import Slap.Display.Glyph (rightwardsArrow, checkMark, ballotX, emDash, spacePaddedRightwardsArrow)
import Slap.FormatLabel (formatLabelName)

import qualified Data.ByteString as ByteString
import Control.Exception (try)
import Control.Monad (when, forM_)
import Data.Char (toLower)
import Data.List (intercalate)
import Options.Applicative
import Options.Applicative.Help.Pretty (pretty, vcat)
import System.Directory (copyFile, doesFileExist)
import System.Exit (exitSuccess)
import System.FilePath (dropExtension, replaceExtension, takeBaseName, takeExtension)
import System.IO (hSetEncoding, stderr, stdout)
import System.IO.Error (isDoesNotExistError, ioeGetErrorString)
import GHC.IO.Encoding (setFileSystemEncoding, utf8)
import GHC.IO.Encoding.UTF8 (mkUTF8)
import GHC.IO.Encoding.Failure (CodingFailureMode(TransliterateCodingFailure))

----------------------------------------------------------------------------
-- Types
----------------------------------------------------------------------------

-- | How slap should interpret input files whose first bytes look like an archive signature.
--
-- Slap can open single-entry zip and 7z archives transparently,
-- so a user with @rom.zip@ containing one @rom.gbc@ can pass either the archive or the unwrapped ROM.
-- The @--raw@ flag exists to disable that:
-- some files share a magic-byte prefix with an archive format without actually being one,
-- and unwrapping them would fail or silently return the wrong bytes.
data ArchiveHandling
  = AutoUnwrapSingleEntryArchives
  | ReadBytesVerbatim
  deriving (Show, Eq)

-- | Per-operation options for how slap reads its input files.
data FileReadingOptions = FileReadingOptions
  { fileReadingArchiveHandling :: ArchiveHandling
  }
  deriving (Show, Eq)

-- | How much detail 'slap explain' should emit.
--
-- @Summary@ is the default: top-level structure, field-by-field metadata, aggregate record counts.
-- @FullRecords@ adds every parsed record to the output.
-- Selected via @--records@.
data ExplainVerbosity
  = Summary
  | FullRecords
  deriving (Show, Eq)

-- | What to do with an applied patch's output bytes.
-- The four variants are mutually exclusive CLI lanes;
-- the parser rejects a command line that mixes distinguishing flags from more than one (see 'applyOutputParser').
--
-- 'ApplyInPlace' overwrites the source file, carrying a 'BackupBehavior' for an optional @.bak@ copy.
-- 'ApplyToExplicitFile' writes to an operator-chosen path.
-- The path is @-o FILE@ or, equivalently, a bare third positional @OUTPUT@; both at once is a parse error.
-- 'ApplyToDerivedFile' writes to a path derived from the source name — the default lane.
-- The 'OverwritePolicy' those two carry guards @--force@;
-- it is a sub-flag of the two file-writing lanes because clobbering is meaningless in place or on a dry run.
-- 'ApplyDryRun' writes nothing and reports against the derived-default destination, since it accepts no lane-modifying flags.
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

-- | What to do with an undo's reverted source bytes.
-- Mirrors 'ApplyOutput' lane-for-lane (see there for the @-o@\/positional and @--force@ rules);
-- the only difference is that undo operates on the modified file where apply operates on the source file —
-- so 'UndoInPlace' overwrites it and 'UndoToDerivedFile' derives its path from it.
-- The parser rejects mixing distinguishing flags from more than one lane (see 'undoOutputParser').
data UndoOutput
  = UndoInPlace BackupBehavior
  | UndoToExplicitFile FilePath OverwritePolicy
  | UndoToDerivedFile OverwritePolicy
  | UndoDryRun
  deriving (Show, Eq)

-- | Where convert writes the produced patch bytes.
-- 'ConvertToDerivedFile' uses the source patch path with the target format's extension substituted in.
data ConvertOutput
  = ConvertToExplicitFile FilePath
  | ConvertToDerivedFile
  deriving (Show, Eq)

-- | Optional side-channel for @slap convert@ when the target format needs the original ROM,
-- or the user opts into apply-and-recreate.
-- Couples the source path with its verification policy because @--no-verify@ is only meaningful when there's a source to verify against;
-- the convert parser rejects @--no-verify@ alone.
data ConvertWithSource = ConvertWithSource
  { convertWithSourcePath   :: FilePath
  , convertWithVerification :: VerificationPolicy
  }
  deriving (Show, Eq)

-- | What the user wants done with the BPS embedded-metadata blob during a convert.
-- 'CarryIfPresent' (the default) inherits from the source patch unless the user overrides, like every other metadata field.
-- 'EmbedFromFile' overrides with user-supplied bytes.
-- 'DropEmbeddedBlob' discards the source's blob without substituting anything —
-- the only way to produce a metadata-less BPS from a source BPS that carried metadata.
data EmbeddedBlobIntent
  = CarryIfPresent
  | EmbedFromFile FilePath
  | DropEmbeddedBlob
  deriving (Show, Eq)

-- | What @slap create@ accepts on the metadata side: the parsed metadata fields,
-- with 'requestedEmbeddedBlob' filled by the resolver from the optional @--metadata FILE@ path below.
-- A target that doesn't consume the blob triggers the same metadata-rejection check as any other format-incompatible field.
data CreateMetadataInputs = CreateMetadataInputs
  { createParsedMetadata   :: RequestedPatchMetadata
  , createEmbeddedBlobPath :: Maybe FilePath
  }

-- | What @slap convert@ accepts on the metadata side: the parsed metadata fields,
-- with 'requestedEmbeddedBlob' filled by the resolver from the 'EmbeddedBlobIntent' below.
data ConvertMetadataInputs = ConvertMetadataInputs
  { convertParsedMetadata     :: RequestedPatchMetadata
  , convertEmbeddedBlobIntent :: EmbeddedBlobIntent
  }

-- | Whether to refuse writing over an existing output file.
-- Does not apply to the @--in-place@ lane, which writes to the source by definition.
data OverwritePolicy
  = RefuseOverwrite
  | ForceOverwrite
  deriving (Show, Eq)

-- | The user's runtime posture toward verification mismatches.
-- @EnforceVerification@ (default) fails with a readable error on a hash mismatch;
-- @SkipVerification@ (set by @--no-verify@) downgrades the mismatch to a warning and applies anyway.
-- Formats without source checksums are unaffected either way.
--
-- The enforcement axis of slap's @--no-verify@ family, set on apply, undo, and convert (the @--with INPUT@ check).
-- The embed-side counterpart and the full family map live on 'VerificationInclusion'.
data VerificationPolicy
  = EnforceVerification
  | SkipVerification
  deriving (Show, Eq)

-- | How much progress output apply and undo emit to stderr during operation.
-- Distinct from 'ExplainVerbosity', which controls the detail of @slap explain@'s structural dump.
data Verbosity
  = Quiet
  | Verbose
  deriving (Show, Eq)

-- | The top-level CLI command.
-- The per-record verb prefix (@apply*@, @undo*@, ...) isn't dodging cross-constructor field collisions — there are none —
-- but it makes per-record field accesses self-describing at use sites.
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
  , applyDialects           :: RequestedDialects
  }

data UndoCommand = UndoCommand
  { undoVerificationPolicy :: VerificationPolicy
  , undoVerbosity          :: Verbosity
  , undoFileReading        :: FileReadingOptions
  , undoPatch              :: FilePath
  , undoSource             :: FilePath
  , undoOutput             :: UndoOutput
  , undoDialects           :: RequestedDialects
  }

data CreateCommand = CreateCommand
  { createFormat      :: CreateFormat
  , createFileReading :: FileReadingOptions
  , createOriginal    :: FilePath
  , createModified    :: FilePath
  , createOutput      :: FilePath
  , createMetadata    :: CreateMetadataInputs
  , createConstraints :: RequestedConstraints
  }

data ConvertCommand = ConvertCommand
  { convertPatch       :: FilePath
  , convertTo          :: CreateFormat
  , convertOutput      :: ConvertOutput
  , convertWithSource  :: Maybe ConvertWithSource
  , convertFileReading :: FileReadingOptions
  , convertMetadata    :: ConvertMetadataInputs
  , convertConstraints :: RequestedConstraints
  , convertDialects    :: RequestedDialects
  , convertMetadataEncoding :: EncodingName
  }

data InfoCommand = InfoCommand
  { infoPatch           :: FilePath
  , infoExtractMetadata :: Maybe FilePath
  , infoDialects        :: RequestedDialects
  , infoMetadataEncoding :: EncodingName
  }

data ExplainCommand = ExplainCommand
  { explainPatch       :: FilePath
  , explainVerbosity   :: ExplainVerbosity
  , explainSource      :: Maybe FilePath
  , explainFileReading :: FileReadingOptions
  , explainDialects    :: RequestedDialects
  , explainMetadataEncoding :: EncodingName
  }

----------------------------------------------------------------------------
-- CLI
----------------------------------------------------------------------------

main :: IO ()
main = do
  -- Slap is a UTF-8 program on both sides:
  -- setFileSystemEncoding utf8 pins argument decoding to UTF-8 and setStdoutAndStderrToLenientUtf8 pins output,
  -- so LANG/LC_CTYPE cannot change how slap reads its arguments or what it prints.
  -- The filesystem pin must run first, before customExecParser decodes argv.
  setFileSystemEncoding utf8
  setStdoutAndStderrToLenientUtf8
  parsedCommand <- customExecParser (prefs showHelpOnEmpty) options
  case parsedCommand of
    Apply   subcommand -> doApply   subcommand
    Undo    subcommand -> doUndo    subcommand
    Create  subcommand -> doCreate  subcommand
    Convert subcommand -> doConvert subcommand
    Info    subcommand -> doInfo    subcommand
    Explain subcommand -> doExplain subcommand

-- | The top-level @--encodings@ flag: print the text encodings slap can decode and exit, like @--help@.
encodingsInfo :: Parser (a -> a)
encodingsInfo = infoOption renderAdvertisedEncodings
  ( long "encodings"
 <> help "List the text encodings slap can decode (for --metadata-encoding) and exit" )

options :: ParserInfo Command
options = info (commandParser <**> encodingsInfo <**> helper)
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

-- | Carries @action "file"@ so generated shell-completion scripts complete paths at this argument position.
pathArgument :: Mod ArgumentFields FilePath -> Parser FilePath
pathArgument modifiers = argument str (modifiers <> action "file")

-- | Carries @action "file"@ for the same reason as 'pathArgument'.
pathOption :: Mod OptionFields FilePath -> Parser FilePath
pathOption modifiers = option str (modifiers <> action "file")

-- | The @--metadata-encoding ENC@ option.
-- The name resolves at parse time via 'resolveEncodingName',
-- so an unresolvable name fails the CLI parse rather than surprising the user mid-run.
metadataEncodingParser :: Parser EncodingName
metadataEncodingParser = option (eitherReader resolveMetadataEncoding)
  ( long "metadata-encoding"
 <> metavar "ENC"
 <> value EncodingUtf8
 <> completeWith advertisedEncodingNames
 <> help ("Interpret text fields whose encoding the patch format leaves"
       ++ " undeclared (PPF descriptions, xdelta1 names, DPS metadata,"
       ++ " NINJA2 mode-0 fields) as ENC (e.g. shift-jis, cp1252; see"
       ++ " --encodings). Default: utf8.") )

-- | Resolve a @--metadata-encoding@ value to an 'EncodingName', or name the value that didn't resolve.
-- Write is always UTF-8, so this only ever feeds the read side.
resolveMetadataEncoding :: String -> Either String EncodingName
resolveMetadataEncoding raw = case resolveEncodingName (Text.pack raw) of
  Right named -> Right (EncodingNamed named)
  Left _      -> Left ("unrecognized encoding " ++ show raw
                        ++ "; run 'slap --encodings' to see the names slap accepts")

explainParser :: Parser ExplainCommand
explainParser = do
    patchFile          <- pathArgument (metavar "PATCH" <> help "Patch file to explain")
    verbosity          <- flag Summary FullRecords
                            (long "records" <> help "Show full record-by-record dump instead of summary")
    maybeWithPath      <- optional (pathOption (long "with" <> metavar "SOURCE"
                            <> help "Source file (resolves delta/copy operations in output)"))
    fileReadingOptions <- fileReadingOptionsParser
    dialects           <- dialectsParser
    metadataEncoding   <- metadataEncodingParser
    pure ExplainCommand
      { explainPatch       = patchFile
      , explainVerbosity   = verbosity
      , explainSource      = maybeWithPath
      , explainFileReading = fileReadingOptions
      , explainDialects    = dialects
      , explainMetadataEncoding = metadataEncoding
      }

applyParser :: Parser ApplyCommand
applyParser = do
    verificationPolicy <- verificationPolicyParser
    verbosity          <- verbosityParser
    fileReadingOptions <- fileReadingOptionsParser
    patch              <- pathArgument (metavar "PATCH" <> help "Patch file")
    source             <- pathArgument (metavar "SOURCE" <> help "Source file to patch (not modified unless --in-place)")
    output             <- applyOutputParser
    dialects           <- dialectsParser
    pure ApplyCommand
      { applyVerificationPolicy = verificationPolicy
      , applyVerbosity          = verbosity
      , applyOutput             = output
      , applyFileReading        = fileReadingOptions
      , applyPatch              = patch
      , applySource             = source
      , applyDialects           = dialects
      }

verificationPolicyParser :: Parser VerificationPolicy
verificationPolicyParser = flag EnforceVerification SkipVerification
  (long "no-verify" <> help "Skip checksum validation (mismatches become warnings)")

verbosityParser :: Parser Verbosity
verbosityParser = flag Quiet Verbose
  (long "verbose" <> short 'v' <> help "Print each record as it's applied")

-- | Parser for the four mutually exclusive output lanes.
-- 'asum' tries each in turn; a combination spanning lanes is rejected at parse time rather than resolved by precedence.
-- The two writing lanes share one 'writingLane' parser so @--force@ has a single home in the parser tree.
-- Split across lanes, a bare @--force@ would partially match the explicit-file lane (flag consumed, path missing),
-- and optparse-applicative would then prefer that partial match's error over the derived-file lane's success.
-- @--in-place@ and @--dry-run@ commit to their own lanes, so a @--force@ paired with either is left unconsumed and errors.
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
              pathOption (long "output" <> short 'o' <> metavar "FILE"
                <> help "Write patched output to FILE. Or pass it as the third argument.")
          <|> pathArgument (metavar "OUTPUT"
                <> help "Write patched output to this path. Or pass it via -o FILE.")

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
    verificationPolicy <- verificationPolicyParser
    verbosity          <- verbosityParser
    fileReadingOptions <- fileReadingOptionsParser
    patch              <- pathArgument (metavar "PATCH" <> help "Patch file")
    source             <- pathArgument (metavar "SOURCE" <> help "File to restore")
    output             <- undoOutputParser
    dialects           <- dialectsParser
    pure UndoCommand
      { undoVerificationPolicy = verificationPolicy
      , undoVerbosity          = verbosity
      , undoFileReading        = fileReadingOptions
      , undoPatch              = patch
      , undoSource             = source
      , undoOutput             = output
      , undoDialects           = dialects
      }

-- | Parser for the four mutually exclusive undo output lanes.
-- Mirror of 'applyOutputParser'; the same 'asum' \/ 'writingLane' shape, so its @--force@ discipline carries over.
undoOutputParser :: Parser UndoOutput
undoOutputParser = asum
  [ dryRunLane
  , inPlaceLane
  , writingLane
  ]
  where
    dryRunLane :: Parser UndoOutput
    dryRunLane = UndoDryRun <$
      flag' () (long "dry-run" <> help "Show what would happen without writing any files")

    inPlaceLane :: Parser UndoOutput
    inPlaceLane = UndoInPlace
      <$> (flag' () (long "in-place" <> short 'i'
              <> help "Overwrite SOURCE with the reverted bytes (destructive; creates .bak by default)")
          *> backupBehaviorFlag)
      where
        backupBehaviorFlag = flag WriteBackup NoBackup
          (long "no-backup" <> help "Don't create .bak backup with --in-place")

    writingLane :: Parser UndoOutput
    writingLane = chooseWritingLane
      <$> optional outputPathOption
      <*> overwritePolicyFlag
      where
        outputPathOption :: Parser FilePath
        outputPathOption =
              pathOption (long "output" <> short 'o' <> metavar "FILE"
                <> help "Write reverted output to FILE. Or pass it as the third argument.")
          <|> pathArgument (metavar "OUTPUT"
                <> help "Write reverted output to this path. Or pass it via -o FILE.")

        overwritePolicyFlag :: Parser OverwritePolicy
        overwritePolicyFlag = flag RefuseOverwrite ForceOverwrite
          (long "force" <> short 'f'
            <> help "Overwrite existing output files")

        chooseWritingLane :: Maybe FilePath -> OverwritePolicy -> UndoOutput
        chooseWritingLane Nothing     policy = UndoToDerivedFile policy
        chooseWritingLane (Just path) policy = UndoToExplicitFile path policy

convertOutputParser :: Parser ConvertOutput
convertOutputParser = maybe ConvertToDerivedFile ConvertToExplicitFile
  <$> optional (pathOption (long "output" <> short 'o' <> metavar "FILE"
      <> help "Output file (default: replace input extension with target format's)"))

createParser :: Parser CreateCommand
createParser = do
    format             <- createFormatParser
    fileReadingOptions <- fileReadingOptionsParser
    original           <- pathArgument (metavar "ORIGINAL" <> help "Original unmodified file")
    modified           <- pathArgument (metavar "MODIFIED" <> help "Modified file")
    outputFile         <- pathArgument (metavar "OUTPUT"   <> help "Output patch file")
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
    patchFile          <- pathArgument (metavar "PATCH" <> help "Patch file to convert")
    targetFormat       <- convertToParser
    output             <- convertOutputParser
    withSource         <- optional convertWithSourceParser
    fileReadingOptions <- fileReadingOptionsParser
    metadataInputs     <- convertMetadataInputsParser
    constraints        <- constraintsParser
    dialects           <- dialectsParser
    metadataEncoding   <- metadataEncodingParser
    pure ConvertCommand
      { convertPatch       = patchFile
      , convertTo          = targetFormat
      , convertOutput      = output
      , convertWithSource  = withSource
      , convertFileReading = fileReadingOptions
      , convertMetadata    = metadataInputs
      , convertConstraints = constraints
      , convertDialects    = dialects
      , convertMetadataEncoding = metadataEncoding
      }

-- | Parser for the 'RequestedConstraints' bag, shared between @slap create@ and @slap convert@.
-- 'constraintFlagName' is the single source of truth for the flag spelling.
constraintsParser :: Parser RequestedConstraints
constraintsParser = do
  smcShape <- flag AllowAnyTruncationShape RequireSMCShapedTruncation
    ( long (Text.unpack (constraintFlagName SMCShapeConstraint))
   <> help ("Refuse to emit an IPS truncation marker whose declared size"
         ++ " doesn't satisfy SNESTool's (size & 0xFFF) == 0x200 shape filter")
    )
  pure RequestedConstraints
    { requestedSMCShape = smcShape
    }

-- | Parser for the 'RequestedDialects' bag, shared between every subcommand that reads or writes a patch.
-- 'dialectFlagName' is the single source of truth for the flag spelling.
dialectsParser :: Parser RequestedDialects
dialectsParser = do
  ppf1Origin <- flag PPF1OriginPC PPF1OriginAmiga
    ( long (Text.unpack (dialectFlagName PPF1OriginAxis))
   <> help ("Decode (apply/undo/info/explain/convert)"
         ++ " PPF1 offsets as big-endian rather than little-endian. PPF1 has no"
         ++ " on-disk endianness marker; the reference applier reads offsets in"
         ++ " host-native byte order, making PC and Amiga PPF1 patches mutually"
         ++ " incompatible. The default (LE) is correct for every PC-origin patch.")
    )
  pure RequestedDialects
    { requestedPPF1Origin = ppf1Origin
    }

-- | Parser for @--with INPUT@ plus its sub-flag @--no-verify@.
-- The @--with@ option is required: if it is absent, the whole parser fails and the enclosing 'optional' falls back to 'Nothing'.
-- That leaves any stray @--no-verify@ for the top-level parser to reject — so @--no-verify@ is accepted only alongside @--with@.
convertWithSourceParser :: Parser ConvertWithSource
convertWithSourceParser = ConvertWithSource
  <$> pathOption (long "with" <> metavar "INPUT"
        <> help "Input file: enables apply-and-recreate conversion and input hash verification")
  <*> flag EnforceVerification SkipVerification
        (long "no-verify"
          <> help "Skip input hash verification (requires --with INPUT; mismatches become warnings)")

-- | The output-format flag for @slap create@.
-- Defaults to BPS, so the bare @slap create base mod out@ works without spelling out a format.
createFormatParser :: Parser CreateFormat
createFormatParser = option (eitherReader parseCreateFormat)
  (long "format" <> metavar "FMT" <> value (CreateDifferential CreateBPS)
    <> help ("Output format: " ++ intercalate ", " advertisedCreateFormats
              ++ " (default: bps)"))

-- | The target-format flag for @slap convert@.
-- No default: conversion has to know what it is converting to.
convertToParser :: Parser CreateFormat
convertToParser = option (eitherReader parseCreateFormat)
  (long "to" <> short 't' <> metavar "FMT"
    <> help ("Target format: " ++ intercalate ", " advertisedCreateFormats))

-- | Parse the metadata flags shared between @slap create@ and @slap convert@.
-- Produces a 'RequestedPatchMetadata' with 'requestedEmbeddedBlob' set to 'Nothing';
-- the resolvers 'resolveCreateMetadata' and 'resolveConvertMetadata' fill that field from each command's blob source:
-- the @--metadata FILE@ path for create, the 'EmbeddedBlobIntent' for convert.
requestedMetadataParser :: Parser RequestedPatchMetadata
requestedMetadataParser = do
    title             <- optional (option str (long "title" <> metavar "TEXT"
                            <> help "Patch title (EBP/DPS/NINJA2)"))
    author            <- optional (option str (long "author" <> metavar "TEXT"
                            <> help "Patch author (EBP/DPS/NINJA2)"))
    description       <- optional (option str (long "description" <> metavar "TEXT"
                            <> help "Patch description (EBP/PPF1/PPF2/PPF3/APS-N64/NINJA2)"))
    version           <- optional (option str (long "patch-version" <> metavar "TEXT"
                            <> help "Patch version (DPS/NINJA2)"))
    includeUndo         <- optional (flag' OmitUndoData     (long "no-undo"
                            <> help "Omit undo data (default: included when the format supports it)"))
    includeVerification <- optional (flag' OmitVerification (long "omit-verification"
                            <> help "Omit source-integrity-checking data from the created patch (default: included when the format supports it)"))
    patchCompression  <- optional (flag' UncompressedPatch (long "no-compress"
                            <> help "Do not gzip-compress the output patch (xdelta1 only; default emits compressed)"))
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
    textMode          <- optional (option (eitherReader parseTextMode) (long "ninja2-text-mode" <> metavar "MODE"
                            <> help ("Wire text mode for NINJA2 metadata: utf8, undeclared."
                                  ++ " Overrides any encoding declared by the source patch when supplied."
                                  ++ " When omitted: inherit from the source patch's metadata encoding"
                                  ++ " if one is available, otherwise utf8.")))
    xdelta1FromName   <- optional (option str (long "from-name" <> metavar "TEXT"
                            <> help ("Embedded source-file display label (xdelta1 only;"
                                  ++ " default: basename of input/source ROM on create,"
                                  ++ " inherited from source patch on xdelta1" ++ [rightwardsArrow] ++ "xdelta1 convert)")))
    xdelta1ToName     <- optional (option str (long "to-name" <> metavar "TEXT"
                            <> help "Embedded target-file display label (xdelta1 only; same defaulting as --from-name)"))
    pure RequestedPatchMetadata
      { requestedTitle               = fmap wrapUtf8 title
      , requestedAuthor              = fmap wrapUtf8 author
      , requestedDescription         = fmap wrapUtf8 description
      , requestedVersion             = fmap wrapUtf8 version
      , requestedUndoInclusion        = includeUndo
      , requestedVerificationInclusion = includeVerification
      , requestedPatchCompression    = patchCompression
      , requestedStability           = unstable
      , requestedRomType             = romType
      , requestedImageType           = imageType
      , requestedGenre               = fmap wrapUtf8 genre
      , requestedLanguage            = fmap wrapUtf8 language
      , requestedDate                = fmap wrapUtf8 date
      , requestedWebsite             = fmap wrapUtf8 website
      , requestedTextMode            = textMode
      , requestedEmbeddedBlob        = Nothing
      , requestedXDelta1FromName     = fmap (XDelta1FromName . wrapUtf8) xdelta1FromName
      , requestedXDelta1ToName       = fmap (XDelta1ToName   . wrapUtf8) xdelta1ToName
      }
  where
    wrapUtf8 :: String -> EncodedText
    wrapUtf8 = EncodedText EncodingUtf8 . Text.pack

-- | Create-side metadata: the parsed metadata fields plus an optional @--metadata FILE@ path
-- whose bytes the resolver embeds as the patch's metadata blob (BPS only; the rejection check refuses the flag against any other target).
createMetadataInputsParser :: Parser CreateMetadataInputs
createMetadataInputsParser = CreateMetadataInputs
  <$> requestedMetadataParser
  <*> optional (pathOption (long "metadata" <> metavar "FILE"
        <> help "Embed bytes from FILE as the output patch's metadata (BPS only)"))

convertMetadataInputsParser :: Parser ConvertMetadataInputs
convertMetadataInputsParser = ConvertMetadataInputs
  <$> requestedMetadataParser
  <*> embeddedBlobIntentParser

-- | Parse the BPS embedded-blob intent for @slap convert@.
-- @--metadata FILE@ selects 'EmbedFromFile', @--drop-metadata@ selects 'DropEmbeddedBlob', neither selects 'CarryIfPresent'.
-- The three are mutually exclusive: passing both flags leaves one unconsumed and the top-level parser rejects the command.
embeddedBlobIntentParser :: Parser EmbeddedBlobIntent
embeddedBlobIntentParser = asum
  [ EmbedFromFile <$> pathOption (long "metadata" <> metavar "FILE"
      <> help "Override embedded metadata with bytes from FILE (BPS target only)")
  , DropEmbeddedBlob <$ flag' () (long "drop-metadata"
      <> help ("Discard the source patch's embedded metadata (BPS"
               ++ [rightwardsArrow] ++ "BPS; default is to inherit)"))
  , pure CarryIfPresent
  ]

-- | Tagging each token in a single table lets the advertised list be derived from the same source the parser uses,
-- so "what the parser accepts" and "what we tell users to type" cannot drift apart.
data TokenVisibility = Canonical | Alias

-- | Source of truth for slap's create-format tokens:
-- both 'parseCreateFormat' and 'advertisedCreateFormats' derive from this table.
createFormatTokens :: [(String, CreateFormat, TokenVisibility)]
createFormatTokens =
  [ ("bps",     CreateDifferential CreateBPS,    Canonical)
  , ("ips",     CreateDirect       CreateIPS,    Canonical)
  , ("ips32",   CreateDirect       CreateIPS32,  Canonical)
  , ("ebp",     CreateDirect       CreateEBP,    Canonical)
  , ("ups",     CreateDifferential CreateUPS,    Canonical)
  , ("ppf1",    CreateDirect       CreatePPF1,   Canonical)
  , ("ppf2",    CreateDirect       CreatePPF2,   Canonical)
  , ("ppf3",    CreateDirect       CreatePPF3,   Canonical)
  , ("ppf4",    CreateDirect       CreatePPF4,   Canonical)
  , ("ppf",     CreateDirect       CreatePPF3,   Alias)
  , ("pmsr",    CreateDirect       CreatePMSR,   Canonical)
  , ("ninja1",  CreateDirect       CreateNINJA1, Canonical)
  , ("dps",     CreateDifferential CreateDPS,    Canonical)
  , ("ninja2",  CreateDifferential CreateNINJA2, Canonical)
  , ("aps-n64", CreateDirect       CreateAPSN64, Canonical)
  , ("apsn64",  CreateDirect       CreateAPSN64, Alias)
  , ("aps-gba", CreateDifferential CreateAPSGBA, Canonical)
  , ("apsgba",  CreateDifferential CreateAPSGBA, Alias)
  , ("gdiff",   CreateDifferential CreateGDIFF,  Canonical)
  , ("xdelta1", CreateDifferential CreateXDelta1, Canonical)
  , ("xdelta",  CreateDifferential CreateXDelta1, Alias)
  , ("rfc-vcdiff", CreateDifferential CreateRFCVCDIFF, Canonical)
  ]

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

parseTextMode :: String -> Either String TextMode
parseTextMode input = case map toLower input of
  "utf8"       -> Right TextModeUTF8
  "undeclared" -> Right TextModeUndeclared
  _            -> Left ("unknown NINJA2 text mode: " ++ input ++ "\n  expected: utf8, undeclared")

-- | Source of truth for slap's ROM-type tokens:
-- both 'parseRomType' and 'advertisedRomTypes' derive from this table.
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

parseImageType :: String -> Either String PPF3ImageType
parseImageType typeString = case map toLower typeString of
  "bin" -> Right BIN
  "gi"  -> Right GI
  _ -> Left ("unknown image type: " ++ typeString ++ "\n  expected: bin, gi")

patchInfoParser :: Parser InfoCommand
patchInfoParser = do
    patchFile <- pathArgument (metavar "PATCH" <> help "Patch file to inspect")
    extractMetadataPath <- optional (pathOption (long "extract-metadata" <> metavar "FILE"
        <> help "Write embedded metadata to FILE (BPS)"))
    dialects <- dialectsParser
    metadataEncoding <- metadataEncodingParser
    pure InfoCommand
      { infoPatch           = patchFile
      , infoExtractMetadata = extractMetadataPath
      , infoDialects        = dialects
      , infoMetadataEncoding = metadataEncoding
      }

----------------------------------------------------------------------------
-- Archive-aware file reading
----------------------------------------------------------------------------

-- | Read a user-supplied input file, turning its two interesting IO failure modes into typed 'SlapError' values on slap's normal error channel:
-- the path is absent ('MissingInputFile'), or present but unopenable ('UnreadableInputFile').
readInputFile :: FilePath -> IO ByteString.ByteString
readInputFile path = do
  result <- try (ByteString.readFile path)
  case result of
    Right fileBytes -> pure fileBytes
    Left ioErr
      | isDoesNotExistError ioErr -> bailError (MissingInputFile path)
      | otherwise                 -> bailError (UnreadableInputFile path (ioeGetErrorString ioErr))

-- | Read a file, transparently unwrapping single-entry archives.
readUnwrap :: FilePath -> IO ByteString.ByteString
readUnwrap path = do
  fileBytes <- readInputFile path
  case detectArchive (ByteString.take 8 fileBytes) of
    Nothing -> pure fileBytes
    Just format -> do
      result <- unwrapArchive format path
      case result of
        Left unwrapError -> bailError (ArchiveUnwrapFailed path format unwrapError)
        Right (unwrappedBytes, entryName) -> do
          TextIO.hPutStrLn stderr ("slap: unwrapped " <> pathText path <> spacePaddedRightwardsArrow <> Text.pack entryName)
          pure unwrappedBytes

readMaybeUnwrap :: FileReadingOptions -> FilePath -> IO ByteString.ByteString
readMaybeUnwrap fileReadingOptions = case fileReadingArchiveHandling fileReadingOptions of
  AutoUnwrapSingleEntryArchives -> readUnwrap
  ReadBytesVerbatim             -> readInputFile

-- | Resolve @slap create@'s metadata inputs: @--metadata FILE@ is read into the embedded blob.
resolveCreateMetadata :: CreateMetadataInputs -> IO RequestedPatchMetadata
resolveCreateMetadata inputs = do
  embeddedBlob <- traverse readInputFile (createEmbeddedBlobPath inputs)
  pure (createParsedMetadata inputs) { requestedEmbeddedBlob = embeddedBlob }

-- | Resolve @slap convert@'s metadata inputs.
-- Only 'EmbedFromFile' triggers IO and produces a 'Just'; 'CarryIfPresent' and 'DropEmbeddedBlob' both leave the field 'Nothing' here.
-- The two 'Nothing' cases diverge only later, in 'doConvert' after the source-patch merge.
resolveConvertMetadata :: ConvertMetadataInputs -> IO RequestedPatchMetadata
resolveConvertMetadata inputs = do
  embeddedBlob <- case convertEmbeddedBlobIntent inputs of
    EmbedFromFile path -> Just <$> readInputFile path
    DropEmbeddedBlob   -> pure Nothing
    CarryIfPresent     -> pure Nothing
  pure (convertParsedMetadata inputs) { requestedEmbeddedBlob = embeddedBlob }

----------------------------------------------------------------------------
-- Info & Explain
----------------------------------------------------------------------------

doInfo :: InfoCommand -> IO ()
doInfo parsedCommand = do
  parsed <- readAndParsePatch (infoDialects parsedCommand) (infoMetadataEncoding parsedCommand) (infoPatch parsedCommand)
  orBail (rejectIncompatibleDialects
            (acceptedDialects (patchFormat parsed))
            (patchFormat parsed)
            (infoDialects parsedCommand))
  mapM_ (TextIO.putStrLn . renderInfoLine) (renderPatchInfo (patchInfo parsed))
  emitAdvisories (patchAdvisories parsed)
  case infoExtractMetadata parsedCommand of
    Nothing -> pure ()
    Just outPath -> case patchMetadata parsed of
      Nothing   -> TextIO.hPutStrLn stderr "slap: no metadata in this patch"
      Just metadataBytes -> do
        ByteString.writeFile outPath metadataBytes
        TextIO.putStrLn ("wrote metadata to " <> pathText outPath)

doExplain :: ExplainCommand -> IO ()
doExplain parsedCommand = do
  parsed <- readAndParsePatch (explainDialects parsedCommand) (explainMetadataEncoding parsedCommand) (explainPatch parsedCommand)
  orBail (rejectIncompatibleDialects
            (acceptedDialects (patchFormat parsed))
            (patchFormat parsed)
            (explainDialects parsedCommand))
  maybeSource <- case explainSource parsedCommand of
    Nothing   -> pure Nothing
    Just path -> Just <$> readMaybeUnwrap (explainFileReading parsedCommand) path
  let renderFunction = case explainVerbosity parsedCommand of
        Summary     -> renderAnalysisSummary
        FullRecords -> renderAnalysisFull
  TextIO.putStr (renderFunction (patchInfo parsed) (patchAnalysis parsed) maybeSource)
  emitAdvisories (patchAdvisories parsed)

----------------------------------------------------------------------------
-- Apply
----------------------------------------------------------------------------

doApply :: ApplyCommand -> IO ()
doApply parsedCommand = do
  parsed <- readAndParsePatch (applyDialects parsedCommand) EncodingUtf8 (applyPatch parsedCommand)
  orBail (rejectIncompatibleDialects
            (acceptedDialects (patchFormat parsed))
            (patchFormat parsed)
            (applyDialects parsedCommand))
  emitAdvisories (patchAdvisories parsed)
  emitVerboseAnalysis (applyVerbosity parsedCommand) parsed

  let verification = patchVerification parsed
      verificationPolicy = applyVerificationPolicy parsedCommand

      applyAndWriteTo outputPath = do
        sourceBytes <- readMaybeUnwrap (applyFileReading parsedCommand) (applySource parsedCommand)
        let source = InputFileContents sourceBytes
        verifySource verificationPolicy verification source
        outcome <- orBail =<< runApply (patchApply parsed) source
        emitAdvisories (outcomeAdvisories outcome)
        let target = outcomeValue outcome
        verifyTarget verificationPolicy verification target
        ByteString.writeFile outputPath (unOutputFileContents target)
        TextIO.putStrLn (renderActionLine "applied" (patchInfo parsed) outputPath)

  case applyOutput parsedCommand of
    ApplyDryRun -> do
      let reportedPath = deriveOutput (applyPatch parsedCommand) (applySource parsedCommand)
      TextIO.putStrLn (renderActionLine "would apply" (patchInfo parsed) reportedPath)
      case verifySourceCRC32 verification of
        Just expected -> do
          sourceBytes <- readMaybeUnwrap (applyFileReading parsedCommand) (applySource parsedCommand)
          TextIO.putStrLn (renderCrcCheck "input CRC" expected (crc32 sourceBytes))
        Nothing -> pure ()
      exitSuccess
    ApplyInPlace backupBehavior -> do
      case backupBehavior of
        WriteBackup -> do
          let backupPath = applySource parsedCommand ++ ".bak"
          copyFile (applySource parsedCommand) backupPath
          TextIO.hPutStrLn stderr ("slap: backup: " <> pathText backupPath)
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
  parsed <- readAndParsePatch (undoDialects parsedCommand) EncodingUtf8 (undoPatch parsedCommand)
  orBail (rejectIncompatibleDialects
            (acceptedDialects (patchFormat parsed))
            (patchFormat parsed)
            (undoDialects parsedCommand))
  emitAdvisories (patchAdvisories parsed)
  emitVerboseAnalysis (undoVerbosity parsedCommand) parsed
  case patchUndo parsed of
    Nothing -> bail "undo not supported for this format"
    Just undo -> do
      let verification       = patchVerification parsed
          verificationPolicy = undoVerificationPolicy parsedCommand

          undoAndWriteTo outputPath = do
            modified <- readMaybeUnwrap (undoFileReading parsedCommand) (undoSource parsedCommand)
            verifyTarget verificationPolicy verification (OutputFileContents modified)
            outcome <- orBail (runUndo undo (OutputFileContents modified))
            emitAdvisories (outcomeAdvisories outcome)
            let revertedSource = outcomeValue outcome
            verifySource verificationPolicy verification revertedSource
            let InputFileContents result = revertedSource
            ByteString.writeFile outputPath result
            TextIO.putStrLn (renderActionLine "reverted" (patchInfo parsed) outputPath)

      case undoOutput parsedCommand of
        UndoDryRun -> do
          let reportedPath = deriveUndoOutput (undoSource parsedCommand)
          TextIO.putStrLn (renderActionLine "would revert" (patchInfo parsed) reportedPath)
          case verifyTargetCRC32 verification of
            Just expected -> do
              modifiedBytes <- readMaybeUnwrap (undoFileReading parsedCommand) (undoSource parsedCommand)
              TextIO.putStrLn (renderCrcCheck "output CRC" expected (crc32 modifiedBytes))
            Nothing -> pure ()
          exitSuccess
        UndoInPlace backupBehavior -> do
          case backupBehavior of
            WriteBackup -> do
              let backupPath = undoSource parsedCommand ++ ".bak"
              copyFile (undoSource parsedCommand) backupPath
              TextIO.hPutStrLn stderr ("slap: backup: " <> pathText backupPath)
            NoBackup -> pure ()
          undoAndWriteTo (undoSource parsedCommand)
        UndoToExplicitFile outputPath overwritePolicy -> do
          refuseOverwrite overwritePolicy outputPath
          undoAndWriteTo outputPath
        UndoToDerivedFile overwritePolicy -> do
          let outputPath = deriveUndoOutput (undoSource parsedCommand)
          refuseOverwrite overwritePolicy outputPath
          undoAndWriteTo outputPath

----------------------------------------------------------------------------
-- Create
----------------------------------------------------------------------------

doCreate :: CreateCommand -> IO ()
doCreate parsedCommand = do
  createMeta    <- resolveCreateMetadata (createMetadata parsedCommand)
  orBail (rejectIncompatibleMetadata    (createFormat parsedCommand) createMeta)
  orBail (rejectIncompatibleConstraints (createFormat parsedCommand) (createConstraints parsedCommand))
  resolvedXDelta1Names <- orBail (resolveCreateXDelta1Names parsedCommand createMeta)
  originalBytes <- readMaybeUnwrap (createFileReading parsedCommand) (createOriginal parsedCommand)
  modifiedBytes <- readMaybeUnwrap (createFileReading parsedCommand) (createModified parsedCommand)
  emitAdvisories (createDefaultAdvisories (createFormat parsedCommand) createMeta)
  result <- orBail (createPatch
                     (createFormat parsedCommand)
                     resolvedXDelta1Names
                     (InputFileContents originalBytes)
                     (OutputFileContents modifiedBytes)
                     createMeta
                     Nothing
                     (createConstraints parsedCommand)
                     noDialectsRequested)
  emitAdvisories (resultAdvisories result)
  ByteString.writeFile (createOutput parsedCommand) (unPatchFileContents (resultBytes result))
  TextIO.putStrLn ("wrote " <> pathText (createOutput parsedCommand))

-- | Resolve the xdelta1 file-name pair for @slap create@,
-- falling back to the basename of the source\/target file paths when the CLI flags are absent.
-- 'Just' iff the target format is xdelta1; 'Nothing' for every other target.
resolveCreateXDelta1Names
  :: CreateCommand
  -> RequestedPatchMetadata
  -> Either SlapError (Maybe ResolvedXDelta1FileNames)
resolveCreateXDelta1Names parsedCommand createMeta = case createFormat parsedCommand of
  CreateDifferential CreateXDelta1 -> fmap Just $
    resolveXDelta1FileNames
      (fmap unXDelta1FromName (requestedXDelta1FromName createMeta))
      (fmap unXDelta1ToName   (requestedXDelta1ToName   createMeta))
      (createOriginal parsedCommand)
      (createModified parsedCommand)
  _ -> Right Nothing

----------------------------------------------------------------------------
-- Convert
----------------------------------------------------------------------------

-- | The convert cases, built once by 'chooseConvertDispatch' and pattern-matched once in 'doConvert'.
data ConvertDispatch
  = ApplyAndRecreate ConvertWithSource
    -- ^ User supplied @--with INPUT@.
  | SourceLessConvert PatchContents
    -- ^ No source supplied; the parsed patch carries 'PatchContents'.
  | ConvertRequiresSource SomePatch
    -- ^ No source supplied, and the parsed patch carries no 'PatchContents'.

-- | Decide which convert path runs from the parsed patch and the CLI command.
-- The @--with INPUT@ flag commits to apply-and-recreate outright; without it the parsed 'PatchKind' decides.
-- 'needSourceMessage' renders the user-visible reason for the source-required cases.
chooseConvertDispatch :: ConvertCommand -> SomePatch -> ConvertDispatch
chooseConvertDispatch parsedCommand parsed =
  case convertWithSource parsedCommand of
    Just withSource -> ApplyAndRecreate withSource
    Nothing -> case patchKind parsed of
      Direct (Just contents) -> SourceLessConvert contents
      Direct Nothing         -> ConvertRequiresSource parsed
      Differential           -> ConvertRequiresSource parsed

-- | Project the optional 'PatchContents' bag out of a 'SomePatch'.
patchContentsOf :: SomePatch -> Maybe PatchContents
patchContentsOf parsed = case patchKind parsed of
  Direct optionalContents -> optionalContents
  Differential            -> Nothing

doConvert :: ConvertCommand -> IO ()
doConvert parsedCommand = do
  cliMeta <- resolveConvertMetadata (convertMetadata parsedCommand)
  orBail (rejectIncompatibleMetadata    (convertTo parsedCommand) cliMeta)
  orBail (rejectIncompatibleConstraints (convertTo parsedCommand) (convertConstraints parsedCommand))
  parsed <- readAndParsePatch (convertDialects parsedCommand) (convertMetadataEncoding parsedCommand) (convertPatch parsedCommand)
  orBail (rejectIncompatibleDialects
            (acceptedDialects (patchFormat parsed))
            (patchFormat parsed)
            (convertDialects parsedCommand))
  emitAdvisories (patchAdvisories parsed)
  let outputFile = case convertOutput parsedCommand of
        ConvertToExplicitFile explicit -> explicit
        ConvertToDerivedFile           -> replaceExtension (convertPatch parsedCommand)
                                                           (formatExtension (convertTo parsedCommand))
      blobIntent = convertEmbeddedBlobIntent (convertMetadata parsedCommand)
      -- The merge inherits the source patch's embedded blob when the CLI supplied none;
      -- for 'DropEmbeddedBlob' that would re-introduce the very bytes the user asked to discard.
      mergedMeta = case blobIntent of
        DropEmbeddedBlob ->
          (mergeRequestedMetadata cliMeta (patchExtractedMeta parsed))
            { requestedEmbeddedBlob = Nothing }
        _ -> mergeRequestedMetadata cliMeta (patchExtractedMeta parsed)
      bpsDropAdvisories = computeBPSDropAdvisories parsed (convertTo parsedCommand)
  resolvedXDelta1Names <- orBail (resolveConvertXDelta1Names parsedCommand parsed mergedMeta)
  case chooseConvertDispatch parsedCommand parsed of
    ApplyAndRecreate withSource -> do
      sourceBytes <- readMaybeUnwrap (convertFileReading parsedCommand) (convertWithSourcePath withSource)
      let source = InputFileContents sourceBytes
      verifySource (convertWithVerification withSource) (patchVerification parsed) source
      target <- applyForConvert parsed source
      createResult <- orBail (createPatch (convertTo parsedCommand) resolvedXDelta1Names (InputFileContents sourceBytes) target mergedMeta (patchContentsOf parsed) (convertConstraints parsedCommand) noDialectsRequested)
      emitAdvisories (patchSourceAdvisories parsed ++ bpsDropAdvisories
                        ++ createDefaultAdvisories (convertTo parsedCommand) mergedMeta
                        ++ resultAdvisories createResult)
      ByteString.writeFile outputFile (unPatchFileContents (resultBytes createResult))
      TextIO.putStrLn ("converted to " <> formatName (convertTo parsedCommand) <> ": " <> pathText outputFile)
    SourceLessConvert contents -> do
      convertResult <- orBail (convertDirect contents (convertTo parsedCommand) mergedMeta (convertConstraints parsedCommand) noDialectsRequested)
      emitAdvisories (patchSourceAdvisories parsed ++ resultAdvisories convertResult)
      ByteString.writeFile outputFile (unPatchFileContents (resultBytes convertResult))
      TextIO.putStrLn ("converted to " <> formatName (convertTo parsedCommand) <> ": " <> pathText outputFile)
    ConvertRequiresSource somePatch ->
      bail (needSourceMessage somePatch)

-- | Resolve the xdelta1 file-name pair for @slap convert@.
-- Unlike 'resolveCreateXDelta1Names', this refuses rather than falling back to basenames;
-- 'requireXDelta1FileNames' owns the refusal.
-- 'Just' iff the target format is xdelta1; 'Nothing' for every other target.
resolveConvertXDelta1Names
  :: ConvertCommand
  -> SomePatch
  -> RequestedPatchMetadata
  -> Either SlapError (Maybe ResolvedXDelta1FileNames)
resolveConvertXDelta1Names parsedCommand parsed mergedMeta = case convertTo parsedCommand of
  CreateDifferential CreateXDelta1 -> fmap Just $
    requireXDelta1FileNames
      (fmap unXDelta1FromName (requestedXDelta1FromName mergedMeta))
      (fmap unXDelta1ToName   (requestedXDelta1ToName   mergedMeta))
      (patchFormat parsed)
  _ -> Right Nothing

applyForConvert :: SomePatch -> InputFileContents -> IO OutputFileContents
applyForConvert somePatch source = do
  outcome <- orBail =<< runApply (patchApply somePatch) source
  emitAdvisories (outcomeAdvisories outcome)
  pure (outcomeValue outcome)

-- | Local helper for 'needSourceMessage'.
data SourceRequiredReason = SourceRequiredReason
  { sourceRequiredCause       :: Text
  , sourceRequiredConsequence :: Text
  }

-- | Error message when @--with@ is required but not provided.
needSourceMessage :: SomePatch -> Text
needSourceMessage somePatch =
  "converting from " <> name <> " requires the original ROM (--with INPUT)\n"
  <> name <> " " <> sourceRequiredCause reason <> ". "
  <> sourceRequiredConsequence reason
  where
    name   = formatLabelName (patchFormat somePatch)
    convertConsequence = "To convert it, we'd apply the patch to the input first and convert the result " <> Text.pack [emDash] <> " which is why we need the input."
    reason = case patchKind somePatch of
      Differential -> SourceRequiredReason
        { sourceRequiredCause       = "tells us what to change in the input ROM, not what the result should be"
        , sourceRequiredConsequence = convertConsequence
        }
      Direct _ -> SourceRequiredReason
        { sourceRequiredCause       = "can't be converted directly into another patch format"
        , sourceRequiredConsequence = convertConsequence
        }

-- | Warn when the source patch carries embedded BPS metadata bytes
-- and the target format has no metadata channel to put them in — conversion silently drops the bytes.
-- Returns @[]@ for BPS→BPS (the merge carries the bytes through), and for any source patch that had no metadata to begin with.
computeBPSDropAdvisories :: SomePatch -> CreateFormat -> [SlapAdvisory]
computeBPSDropAdvisories parsed targetFormat = case patchMetadata parsed of
  Just metaBytes | targetFormat /= CreateDifferential CreateBPS ->
    [MetadataDropped (byteLength metaBytes)]
  _ -> []

----------------------------------------------------------------------------
-- Helpers
----------------------------------------------------------------------------

-- | "game.gbc" + "translation.ips" → "game [translation].gbc"
deriveOutput :: FilePath -> FilePath -> FilePath
deriveOutput patchPath sourcePath =
  dropExtension sourcePath ++ " [" ++ takeBaseName patchPath ++ "]" ++ takeExtension sourcePath

-- | Append a @[reverted]@ marker before the extension, if there is one.
--
-- > deriveUndoOutput "patched.gba"  == "patched [reverted].gba"
-- > deriveUndoOutput "patched"      == "patched [reverted]"
-- > deriveUndoOutput "Pokemon Red [translation].gbc"
-- >   == "Pokemon Red [translation] [reverted].gbc"
--
-- Pre-existing bracketed markers are not detected or stripped;
-- the marker is appended unconditionally.
deriveUndoOutput :: FilePath -> FilePath
deriveUndoOutput modifiedPath =
  dropExtension modifiedPath ++ " [reverted]" ++ takeExtension modifiedPath

-- | Abort if the destination already exists and the user did not pass @--force@.
refuseOverwrite :: OverwritePolicy -> FilePath -> IO ()
refuseOverwrite ForceOverwrite  _          = pure ()
refuseOverwrite RefuseOverwrite outputPath = do
  exists <- doesFileExist outputPath
  when exists $
    bail (pathText outputPath <> " already exists (use --force to overwrite)")

----------------------------------------------------------------------------
-- Verification helpers
----------------------------------------------------------------------------

verifySource :: VerificationPolicy -> Verification -> InputFileContents -> IO ()
verifySource verificationPolicy verification (InputFileContents sourceBytes) = do
  let preprocessed = applySourcePreHash (verifySourcePreHash verification) sourceBytes
  -- Advisory-class checks first: per-spec non-fatal diagnostics that the format chose to populate.
  -- These fire regardless of policy because they're structurally non-fatal;
  -- --no-verify operates only on the fatal-class checks below.
  forM_ (verifySourceBlocks verification) $ \(BlockCheck blockOffset expectedCRC) ->
    noteBlockCRC SourceSide blockOffset expectedCRC (crc16 (viewBytesInRange blockOffset (Length 0x10000) sourceBytes))
  forM_ (verifyPPFBlock verification) $ \(ValidationBlock blockOffset expectedData) ->
    notePPFBlock blockOffset expectedData sourceBytes
  forM_ (verifySourceBytes verification) $ \(ByteCheck checkOffset (AdvisoryExpectedBytes expectedData) checkLabel) ->
    noteSourceBytes (ByteCheckLabel checkLabel) checkOffset expectedData sourceBytes
  -- File size straddles the advisory/fatal boundary: 'AdvisorySize' warns, 'RequiredSize' enforces ('FileSizeCheck' carries which).
  -- It runs before the hash checks, so a size warning prints ahead of any fatal mismatch.
  forM_ (verifyFileSize verification) $ \fileSizeCheck ->
    let actualSize = FileSize (fromIntegral (ByteString.length sourceBytes))
    in case fileSizeCheck of
         AdvisorySize expectedSize -> noteFileSize expectedSize actualSize
         RequiredSize expectedSize -> enforceFileSize verificationPolicy SourceSide expectedSize actualSize
  -- Fatal-class checks.
  -- The format's choice to populate these slots expresses the spec's "this mismatch invalidates the patch" judgment.
  forM_ (verifySourceCRC32 verification) $ \expected ->
    enforceCRC verificationPolicy SourceSide expected (crc32 preprocessed)
  forM_ (verifySourceMD5 verification) $ \expected ->
    enforceHash verificationPolicy SourceSide MD5 expected (md5 preprocessed)
  forM_ (verifySourceSHA1 verification) $ \expected ->
    enforceHash verificationPolicy SourceSide SHA1 expected (sha1 preprocessed)

verifyTarget :: VerificationPolicy -> Verification -> OutputFileContents -> IO ()
verifyTarget verificationPolicy verification (OutputFileContents targetBytes) = do
  -- Advisory-class checks first; see verifySource for the discipline.
  forM_ (verifyTargetBlocks verification) $ \(BlockCheck blockOffset expectedCRC) ->
    noteBlockCRC TargetSide blockOffset expectedCRC (crc16 (viewBytesInRange blockOffset (Length 0x10000) targetBytes))
  -- Fatal-class checks.
  forM_ (verifyTargetCRC32 verification) $ \expected ->
    enforceCRC verificationPolicy TargetSide expected (crc32 targetBytes)
  forM_ (verifyTargetMD5 verification) $ \expected ->
    enforceHash verificationPolicy TargetSide MD5 expected (md5 targetBytes)
  forM_ (verifyWindowAdler32 verification) $ \(WindowCheck windowOffset windowLength expectedChecksum) ->
    enforceAdler verificationPolicy windowOffset expectedChecksum (adler32 (viewBytesInRange windowOffset windowLength targetBytes))

-- | Emit a verification-mismatch warning: the single point all mismatch warnings funnel through.
noteMismatch :: SlapAdvisory -> IO ()
noteMismatch warning = emitAdvisories [warning]

-- | The policy gate every @enforce*@ helper routes mismatches through.
-- 'EnforceVerification' makes the mismatch fatal; 'SkipVerification' (@--no-verify@) falls through to 'noteMismatch'.
enforceMismatch :: VerificationPolicy -> SlapAdvisory -> IO ()
enforceMismatch SkipVerification    = noteMismatch
enforceMismatch EnforceVerification = bailError . VerificationFatal

enforceCRC :: VerificationPolicy -> VerificationSide -> CRC32 -> CRC32 -> IO ()
enforceCRC verificationPolicy side expected actual
  | expected == actual = pure ()
  | otherwise          = enforceMismatch verificationPolicy
                           (VerificationCRCMismatch side (ExpectedCRC32 expected) (ActualCRC32 actual))

enforceHash :: Eq a => VerificationPolicy -> VerificationSide -> HashAlgorithm -> a -> a -> IO ()
enforceHash verificationPolicy side algorithm expected actual
  | expected == actual = pure ()
  | otherwise          = enforceMismatch verificationPolicy
                           (VerificationHashMismatch side algorithm)

enforceAdler :: VerificationPolicy -> Offset -> Adler32 -> Adler32 -> IO ()
enforceAdler verificationPolicy windowOffset expected actual
  | expected == actual = pure ()
  | otherwise          = enforceMismatch verificationPolicy
                           (VerificationAdler32Mismatch windowOffset (ExpectedAdler32 expected) (ActualAdler32 actual))

enforceFileSize :: VerificationPolicy -> VerificationSide -> FileSize -> FileSize -> IO ()
enforceFileSize verificationPolicy side expected actual
  | expected == actual = pure ()
  | otherwise          = enforceMismatch verificationPolicy
                           (VerificationFileSizeMismatch side (ExpectedSize expected) (ActualSize actual))

noteBlockCRC :: VerificationSide -> Offset -> CRC16 -> CRC16 -> IO ()
noteBlockCRC side blockOffset expected actual
  | expected == actual = pure ()
  | otherwise          = noteMismatch (VerificationBlockCRC16Mismatch side blockOffset)

notePPFBlock :: Offset -> ByteString.ByteString -> ByteString.ByteString -> IO ()
notePPFBlock blockOffset expectedData sourceBytes =
  let actual = viewBytesInRange blockOffset (Length (ByteString.length expectedData)) sourceBytes
  in when (actual /= expectedData) $
       noteMismatch (VerificationPPFBlockMismatch blockOffset)

noteFileSize :: FileSize -> FileSize -> IO ()
noteFileSize expected actual =
  when (expected /= actual) $
    noteMismatch (VerificationFileSizeAdvisory (ExpectedSize expected) (ActualSize actual))

noteSourceBytes :: ByteCheckLabel -> Offset -> ByteString.ByteString -> ByteString.ByteString -> IO ()
noteSourceBytes label checkOffset expectedData sourceBytes =
  let actual = viewBytesInRange checkOffset (Length (ByteString.length expectedData)) sourceBytes
  in when (actual /= expectedData) $
       noteMismatch (VerificationSourceBytesMismatch label checkOffset)

formatCRC :: CRC32 -> Text
formatCRC crcValue = "0x" <> showCRC32 crcValue

renderCrcCheck :: Text -> CRC32 -> CRC32 -> Text
renderCrcCheck label expected actual =
  label <> ": " <> formatCRC actual
    <> if actual == expected
         then Text.pack [' ', checkMark]
         else Text.pack [' ', ballotX] <> " (expected " <> formatCRC expected <> ")"

-- | Render the full per-record analysis to stderr, gated on 'Verbose'.
emitVerboseAnalysis :: Verbosity -> SomePatch -> IO ()
emitVerboseAnalysis Verbose parsed =
  TextIO.hPutStr stderr (renderAnalysisFull (patchInfo parsed) (patchAnalysis parsed) Nothing)
emitVerboseAnalysis Quiet _ = pure ()

-- | Read a patch file, parse it, return the parsed 'SomePatch'.
-- Emits no advisories itself; the caller invokes 'emitAdvisories'.
-- 'doInfo' and 'doExplain' defer warnings until after their stdout renders,
-- while 'doApply', 'doUndo', and 'doConvert' emit immediately —
-- staying parse-only leaves that ordering to each caller.
readAndParsePatch :: RequestedDialects -> EncodingName -> FilePath -> IO SomePatch
readAndParsePatch dialects metadataEncoding path = do
  patchBytes <- readUnwrap path
  orBail (parseSome dialects metadataEncoding (PatchFileContents patchBytes))

----------------------------------------------------------------------------
-- Stdout and stderr encoding setup
----------------------------------------------------------------------------

-- | Bind 'stdout' and 'stderr' to UTF-8 with transliteration on failure.
-- A codepoint the encoder can't represent then substitutes a placeholder rather than crashing with an @hPutChar@ invalid-argument error.
-- UTF-8 encodes every scalar value, so the only thing it can fail on is a lone surrogate.
-- None is expected to reach output, for two reasons:
-- 'main' pins the filesystem encoding to UTF-8, so GHC's argv and filepath decoders reject malformed bytes instead of surrogate-escaping them;
-- and slap's lenient decode substitutes U+FFFD, a scalar.
-- Transliteration is cheap defensive cover for a stray one.
-- Called once at startup, before any I\/O.
--
-- We deliberately do not consult the locale here — slap does not consult it anywhere.
-- Interpreting patch text fields whose encoding the format leaves undeclared is the @--metadata-encoding@ flag's job
-- (an explicit input-side choice, not a statement about the terminal),
-- and every realistic terminal slap runs in is UTF-8.
-- Encoding our own console output to whatever the locale claims would only invite mojibake:
-- @LANG=ja_JP.SJIS slap info patch.bps@ would re-encode slap's own chatter as shift-jis and render it as garbage on a UTF-8 terminal.
-- Stdout and stderr are UTF-8, full stop.
setStdoutAndStderrToLenientUtf8 :: IO ()
setStdoutAndStderrToLenientUtf8 = do
  hSetEncoding stdout lenientUtf8
  hSetEncoding stderr lenientUtf8
  where
    lenientUtf8 = mkUTF8 TransliterateCodingFailure
