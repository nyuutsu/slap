{-# LANGUAGE ApplicativeDo #-}
{-# LANGUAGE OverloadedStrings #-}

-- | slap's command surface: the parsed shape of every subcommand, and the
-- optparse-applicative parsing that turns argv into a 'Command'.
--
-- This is the native frontend's vocabulary — the command, option, and policy
-- types that say what the user asked for, and the parsers that build them from
-- argv. It depends on @Slap.*@ for the engine-level types its commands carry
-- (formats, metadata, constraints, dialects); the engine does not depend on it.
module CLI
  ( -- The top-level command and its six per-verb payloads
    Command(..)
  , ApplyCommand(..)
  , UndoCommand(..)
  , CreateCommand(..)
  , ConvertCommand(..)
  , InfoCommand(..)
  , ExplainCommand(..)
    -- The option and policy micro-types those payloads carry
  , ArchiveHandling(..)
  , FileReadingOptions(..)
  , ExplainVerbosity(..)
  , ApplyOutput(..)
  , BackupBehavior(..)
  , UndoOutput(..)
  , ConvertOutput(..)
  , ConvertWithSource(..)
  , EmbeddedBlobIntent(..)
  , CreateMetadataInputs(..)
  , ConvertMetadataInputs(..)
  , OverwritePolicy(..)
  , VerificationPolicy(..)
  , Verbosity(..)
    -- Turning argv into the above
  , parseCommandLine
  ) where

import Slap.Convert (DirectCreate(..), DifferentialCreate(..), CreateFormat(..),
                     RequestedPatchMetadata(..),
                     RequestedConstraints(..),
                     RequestedDialects(..),
                     UndoInclusion(..), VerificationInclusion(..), PatchStability(..),
                     TextMode(..))
import Slap.XDelta1.Types (XDelta1FromName(..), XDelta1ToName(..),
                           XDelta1PatchCompression(..))
import Slap.Constraint (Constraint(..), constraintFlagName)
import Slap.Dialect (Dialect(..), dialectFlagName)
import Slap.PPF1.Types (PPF1Origin(..))
import Slap.IPS.Types (SMCShapeRequirement(..))
import Slap.PPF3.Types (PPF3ImageType(..))
import Slap.PlatformType (PlatformType(..))
-- The parsers below wrap incoming 'String' as 'EncodedText' tagged 'EncodingUtf8' at the boundary:
-- text slap writes is always UTF-8, with no write-side encoding choice.
import Slap.Text (EncodedText(..), EncodingName(..), resolveEncodingName,
                  advertisedEncodingNames, renderAdvertisedEncodings)
import Slap.Display.Glyph (rightwardsArrow)

import qualified Data.Text as Text
import Data.Char (toLower)
import Data.List (intercalate)
import Options.Applicative
import Options.Applicative.Help.Pretty (pretty, vcat)

----------------------------------------------------------------------------
-- The parsed command surface
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
-- Parsers
----------------------------------------------------------------------------

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
-- the resolvers @resolveCreateMetadata@ and @resolveConvertMetadata@ (in @Main@) fill that field from each command's blob source:
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
-- Entry point
----------------------------------------------------------------------------

-- | Run the optparse-applicative parser over argv to produce a 'Command',
-- or exit down its help and usage path (@--help@, @--encodings@, a parse error).
parseCommandLine :: IO Command
parseCommandLine = customExecParser (prefs showHelpOnEmpty) options
