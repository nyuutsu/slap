{-# LANGUAGE ApplicativeDo #-}
{-# LANGUAGE OverloadedStrings #-}

-- | slap's command surface: the command, option, and policy types that say what the user asked for,
-- and the optparse-applicative parsers that turn argv into a 'Command'.
--
-- It depends on @Slap.*@ for the engine-level types its commands carry (formats, metadata, constraints, dialects); the engine does not depend on it.
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
  , UndoOutput(..)
  , ConvertOutput(..)
  , ConvertWithSource(..)
  , EmbeddedBlobIntent(..)
  , DizIntent(..)
  , EmbeddedBlobSource(..)
  , FileIdDizSource(..)
  , CreateMetadataInputs(..)
  , ConvertMetadataInputs(..)
  , createMetadataRequests
  , convertMetadataRequests
  , OverwritePolicy(..)
  , Verbosity(..)
    -- Turning argv into the above
  , parseCommandLine
  ) where

import Slap.Convert (CreateFormat(..), DifferentialCreate(CreateBPS),
                     advertisedCreateFormats, lookupCreateFormatToken,
                     metadataRequests,
                     RequestedPatchMetadata(..),
                     FileIdDizRequest(..),
                     RequestedConstraints(..),
                     RequestedDialects(..),
                     UndoInclusion(..), VerificationInclusion(..), CompressionInclusion(..),
                     PatchStability(..), EmbeddedBlobRequest(..),
                     TextMode)
import Slap.MetadataField (MetadataField(..), metadataFieldFlagName,
                           DroppableField(..), dropFlagName,
                           TypedTextField(..), typedTextFlagName,
                           MetadataRequest(..), requestField)
import Slap.Surface (imageTypeTokens, romTypeTokens, textModeTokens)
import Slap.XDelta1.Types (XDelta1FromName(..), XDelta1ToName(..))
import Slap.VCDIFF.SecondaryCompression (XDelta3SecondaryCompressor, secondaryCompressorTokens)
import Slap.VCDIFF.Types (EmissionWindowSize, emissionWindowSizeOfBytes)
import Slap.Constraint (Constraint(..), constraintFlagName)
import Slap.Dialect (Dialect(..), dialectFlagName)
import Slap.PPF1.Types (PPF1Origin(..))
import Slap.IPS.Types (SMCShapeRequirement(..))
import Slap.PPF3.Types (PPF3ImageType)
import Slap.PlatformType (PlatformType)
import Slap.Header (ConsoleHeader, InputHeaderDirective(..), consoleHeaderToken)
import Slap.Verify (VerificationPolicy(..))
-- The parsers below wrap incoming 'String' as 'EncodedText' tagged 'EncodingUtf8' at the boundary:
-- text slap writes is always UTF-8, with no write-side encoding choice.
import Slap.Text (EncodedText(..), EncodingName(..), resolveEncodingName,
                  advertisedEncodingNames, renderAdvertisedEncodings)
import Slap.Display.Glyph (rightwardsArrow)

import Data.Text (Text)
import qualified Data.Text as Text
import Data.Char (isDigit, toLower)
import Data.List (intercalate, sortOn)
import Options.Applicative
import Options.Applicative.Help.Pretty (pretty, vcat)
import Data.Version (showVersion)
import qualified Paths_slap

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
-- 'ApplyToExplicitFile' writes to an operator-chosen path:
-- @-o FILE@ or, equivalently, a bare third positional @OUTPUT@; both at once is a parse error.
-- 'ApplyToDerivedFile' writes to a path derived from the source name — the default lane.
-- The 'OverwritePolicy' both carry guards @--force@.
data ApplyOutput
  = ApplyToExplicitFile FilePath OverwritePolicy
  | ApplyToDerivedFile OverwritePolicy
  deriving (Show, Eq)

-- | What to do with an undo's reverted source bytes.
-- Mirrors 'ApplyOutput' lane-for-lane (see there for the @-o@\/positional and @--force@ rules);
-- the only difference is that undo operates on the modified file where apply operates on the source file,
-- so 'UndoToDerivedFile' derives its path from that.
data UndoOutput
  = UndoToExplicitFile FilePath OverwritePolicy
  | UndoToDerivedFile OverwritePolicy
  deriving (Show, Eq)

-- | Where convert writes the produced patch bytes.
-- 'ConvertToDerivedFile' uses the source patch path with the target format's extension substituted in.
data ConvertOutput
  = ConvertToExplicitFile FilePath OverwritePolicy
  | ConvertToDerivedFile OverwritePolicy
  deriving (Show, Eq)

-- | Optional side-channel for @slap convert@ when the target format needs the original ROM,
-- or the user opts into apply-and-recreate.
-- Couples the source path with its verification policy because @--no-verify@ is only meaningful when there's a source to verify against;
-- the convert parser rejects @--no-verify@ alone.
data ConvertWithSource = ConvertWithSource
  { convertWithSourcePath   :: FilePath
  , convertWithVerification :: VerificationPolicy
  , convertWithDirective    :: InputHeaderDirective
  }
  deriving (Show, Eq)

-- | What the user wants done with the embedded metadata blob during a convert.
-- 'CarryBlob' (the default) inherits from the source patch unless the user overrides, like every other metadata field.
-- 'DropBlob' discards the source's blob without substituting anything —
-- the only way to produce a metadata-less BPS from a source BPS that carried metadata.
data EmbeddedBlobIntent
  = CarryBlob
  | SetBlobFromFile FilePath
  | SetBlobFromTypedText Text
  | DropBlob
  deriving (Show, Eq)

-- | The FILE_ID.DIZ counterpart to 'EmbeddedBlobIntent'.
data DizIntent
  = CarryDiz
  | SetDizFromFile FilePath
  | SetDizFromTypedText Text
  | DropDiz
  deriving (Show, Eq)

-- | What @slap create@ accepts on the metadata side: the parsed metadata fields,
-- with 'requestedEmbeddedBlob' / 'requestedFileIdDiz' filled by the resolver from the 'EmbeddedBlobSource' / 'FileIdDizSource' below.
-- A target that doesn't consume one triggers the same metadata-rejection check as any other format-incompatible field.
data CreateMetadataInputs = CreateMetadataInputs
  { createParsedMetadata     :: RequestedPatchMetadata
  , createEmbeddedBlobSource :: EmbeddedBlobSource
  , createDizSource          :: FileIdDizSource
  }

-- | Where @slap create@'s embedded metadata comes from: a file's bytes verbatim,
-- text typed at the flag itself, or nowhere.
data EmbeddedBlobSource
  = NoEmbeddedBlob
  | EmbeddedBlobFromFile FilePath
  | EmbeddedBlobFromTypedText Text
  deriving (Show, Eq)

-- | Where @slap create@'s FILE_ID.DIZ comes from — the same three shapes as 'EmbeddedBlobSource', for the DIZ.
data FileIdDizSource
  = NoFileIdDiz
  | FileIdDizFromFile FilePath EncodingName
  | FileIdDizFromText Text
  deriving (Show, Eq)

-- | What @slap convert@ accepts on the metadata side: the parsed metadata fields,
-- with 'requestedEmbeddedBlob' / 'requestedFileIdDiz' filled by the resolver from the 'EmbeddedBlobIntent' / 'DizIntent' below.
data ConvertMetadataInputs = ConvertMetadataInputs
  { convertParsedMetadata     :: RequestedPatchMetadata
  , convertEmbeddedBlobIntent :: EmbeddedBlobIntent
  , convertDizIntent          :: DizIntent
  }

-- | The metadata requests a create command makes, read off argv alone.
createMetadataRequests :: CreateMetadataInputs -> [MetadataRequest]
createMetadataRequests inputs = sortOn requestField $
  metadataRequests (createParsedMetadata inputs)
  ++ blobRequest
  ++ dizRequest
  where
    blobRequest = case createEmbeddedBlobSource inputs of
      NoEmbeddedBlob              -> []
      EmbeddedBlobFromFile _      -> [SetField MetadataEmbeddedBlob]
      EmbeddedBlobFromTypedText _ -> [SetFieldFromText TypedTextEmbeddedBlob]
    dizRequest = case createDizSource inputs of
      NoFileIdDiz         -> []
      FileIdDizFromFile _ _ -> [SetField MetadataFileIdDiz]
      FileIdDizFromText _ -> [SetFieldFromText TypedTextFileIdDiz]

-- | The convert-side counterpart of 'createMetadataRequests'.
convertMetadataRequests :: ConvertMetadataInputs -> [MetadataRequest]
convertMetadataRequests inputs = sortOn requestField $
  metadataRequests (convertParsedMetadata inputs) ++ blobRequest ++ dizRequest
  where
    blobRequest = case convertEmbeddedBlobIntent inputs of
      SetBlobFromFile _      -> [SetField MetadataEmbeddedBlob]
      SetBlobFromTypedText _ -> [SetFieldFromText TypedTextEmbeddedBlob]
      DropBlob               -> [DropField DroppableEmbeddedBlob]
      CarryBlob              -> []
    dizRequest = case convertDizIntent inputs of
      SetDizFromFile _      -> [SetField MetadataFileIdDiz]
      SetDizFromTypedText _ -> [SetFieldFromText TypedTextFileIdDiz]
      DropDiz               -> [DropField DroppableFileIdDiz]
      CarryDiz              -> []

-- | Whether to refuse writing over an existing output file.
data OverwritePolicy
  = RefuseOverwrite
  | ForceOverwrite
  deriving (Show, Eq)

-- | How much progress output apply and undo emit to stderr during operation.
-- Distinct from 'ExplainVerbosity', which controls the detail of @slap explain@'s structural dump.
data Verbosity
  = Quiet
  | Verbose
  deriving (Show, Eq)

-- | The top-level CLI command.
-- The per-record verb prefix (@apply*@, @undo*@, ...) makes per-record field accesses self-describing at use sites.
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
  , applyHeaderDirective    :: InputHeaderDirective
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
  , createOverwritePolicy :: OverwritePolicy
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
  { infoPatch            :: FilePath
  , infoExtractMetadata  :: Maybe FilePath
  , infoExtractDiz       :: Maybe FilePath
  , infoFileReading      :: FileReadingOptions
  , infoDialects         :: RequestedDialects
  , infoMetadataEncoding :: EncodingName
  , infoOverwritePolicy  :: OverwritePolicy
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

-- | The top-level @--version@ flag: print slap's version and exit. The string comes from the cabal file via 'Paths_slap', so it never drifts.
versionInfo :: Parser (a -> a)
versionInfo = infoOption ("slap " ++ showVersion Paths_slap.version)
  ( long "version"
 <> help "Show the version and exit" )

options :: ParserInfo Command
options = info (commandParser <**> encodingsInfo <**> versionInfo <**> helper)
  (fullDesc <> header "slap - multi-format ROM patching tool"
            <> progDesc "Apply, undo, create, convert, and inspect ROM patches. Format is auto-detected"
            <> footerDoc (Just (vcat
                [ pretty ("Quick start:  slap apply PATCH ROM" :: String)
                , pretty ("              slap apply patch.bps game.rom -o patched.rom" :: String)
                , pretty ("" :: String)
                , pretty ("Run 'slap COMMAND --help' for a command's options" :: String)
                ])))

commandParser :: Parser Command
commandParser = subparser
  ( command "apply"   (info (Apply   <$> applyParser     <**> helper) (progDesc "Apply a patch"))
 <> command "undo"    (info (Undo    <$> undoParser      <**> helper) (progDesc "Undo a patch (PPF3 undo data, or UPS/NINJA2 self-inverse)"))
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
       ++ " --encodings). Default: utf8") )

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
                            <> help "Source file, so explain can resolve copies and deltas against it, not just describe the structure"))
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
    headerDirective    <- headerDirectiveParser
    patch              <- pathArgument (metavar "PATCH" <> help "Patch file")
    source             <- pathArgument (metavar "SOURCE" <> help "Source file to patch (not modified)")
    output             <- applyOutputParser
    dialects           <- dialectsParser
    pure ApplyCommand
      { applyVerificationPolicy = verificationPolicy
      , applyVerbosity          = verbosity
      , applyOutput             = output
      , applyFileReading        = fileReadingOptions
      , applyHeaderDirective    = headerDirective
      , applyPatch              = patch
      , applySource             = source
      , applyDialects           = dialects
      }

verificationPolicyParser :: Parser VerificationPolicy
verificationPolicyParser = flag EnforceVerification SkipVerification
  (long "no-verify" <> help "Skip checksum validation (mismatches become warnings)")

-- | Parser for the three mutually exclusive header lanes; mixing the two flags errors at parse time.
headerDirectiveParser :: Parser InputHeaderDirective
headerDirectiveParser = asum
  [ AddHeader    <$> consoleHeaderOption "add-header"    "Add a blank CONSOLE header to the front of the input before applying"
  , RemoveHeader <$> consoleHeaderOption "remove-header" "Remove the input's leading CONSOLE header before applying"
  , pure TakeInputAsIs
  ]
  where
    consoleHeaderOption flagName helpText =
      option (eitherReader parseConsoleHeader)
        (long flagName <> metavar "CONSOLE" <> completeWith consoleHeaderTokens <> help helpText)

consoleHeaderTokens :: [String]
consoleHeaderTokens = map consoleHeaderToken [minBound .. maxBound]

parseConsoleHeader :: String -> Either String ConsoleHeader
parseConsoleHeader input =
  case lookup (map toLower input) [(consoleHeaderToken console, console) | console <- [minBound .. maxBound]] of
    Just console -> Right console
    Nothing      -> Left ("unknown console: " ++ input
                       ++ "\n  expected: " ++ intercalate ", " consoleHeaderTokens)

verbosityParser :: Parser Verbosity
verbosityParser = flag Quiet Verbose
  (long "verbose" <> short 'v' <> help "Print each record as it's applied")

-- | One parser spans the explicit-file and derived-file lanes so @--force@ has a single home in the parser tree.
-- Split into 'asum' alternatives, a bare @--force@ would partially match the explicit-file lane (flag consumed, path missing),
-- and optparse-applicative would then prefer that partial match's error over the derived-file lane's success.
applyOutputParser :: Parser ApplyOutput
applyOutputParser = chooseWritingLane
  <$> optional outputPathOption
  <*> overwritePolicyFlag
  where
    outputPathOption :: Parser FilePath
    outputPathOption =
          pathOption (long "output" <> short 'o' <> metavar "FILE"
            <> help "Write patched output to FILE. Or pass it as the third argument")
      <|> pathArgument (metavar "OUTPUT"
            <> help "Write patched output to this path. Or pass it via -o FILE")

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

-- | Mirror of 'applyOutputParser', so its @--force@ discipline carries over.
undoOutputParser :: Parser UndoOutput
undoOutputParser = chooseWritingLane
  <$> optional outputPathOption
  <*> overwritePolicyFlag
  where
    outputPathOption :: Parser FilePath
    outputPathOption =
          pathOption (long "output" <> short 'o' <> metavar "FILE"
            <> help "Write reverted output to FILE. Or pass it as the third argument")
      <|> pathArgument (metavar "OUTPUT"
            <> help "Write reverted output to this path. Or pass it via -o FILE")

    overwritePolicyFlag :: Parser OverwritePolicy
    overwritePolicyFlag = flag RefuseOverwrite ForceOverwrite
      (long "force" <> short 'f'
        <> help "Overwrite existing output files")

    chooseWritingLane :: Maybe FilePath -> OverwritePolicy -> UndoOutput
    chooseWritingLane Nothing     policy = UndoToDerivedFile policy
    chooseWritingLane (Just path) policy = UndoToExplicitFile path policy

convertOutputParser :: Parser ConvertOutput
convertOutputParser = chooseConvertLane
  <$> optional (pathOption (long "output" <> short 'o' <> metavar "FILE"
      <> help "Output file (default: replace input extension with target format's)"))
  <*> overwritePolicyFlag
  where
    overwritePolicyFlag :: Parser OverwritePolicy
    overwritePolicyFlag = flag RefuseOverwrite ForceOverwrite
      (long "force" <> short 'f'
        <> help "Overwrite existing output files")

    chooseConvertLane :: Maybe FilePath -> OverwritePolicy -> ConvertOutput
    chooseConvertLane (Just path) policy = ConvertToExplicitFile path policy
    chooseConvertLane Nothing     policy = ConvertToDerivedFile policy

createParser :: Parser CreateCommand
createParser = do
    format             <- createFormatParser
    fileReadingOptions <- fileReadingOptionsParser
    original           <- pathArgument (metavar "ORIGINAL" <> help "Original unmodified file")
    modified           <- pathArgument (metavar "MODIFIED" <> help "Modified file")
    outputFile         <- pathArgument (metavar "OUTPUT"   <> help "Output patch file")
    metadataInputs     <- createMetadataInputsParser
    constraints        <- constraintsParser
    overwritePolicy    <- overwritePolicyFlag
    pure CreateCommand
      { createFormat      = format
      , createFileReading = fileReadingOptions
      , createOriginal    = original
      , createModified    = modified
      , createOutput      = outputFile
      , createMetadata    = metadataInputs
      , createConstraints = constraints
      , createOverwritePolicy = overwritePolicy
      }
  where
    overwritePolicyFlag :: Parser OverwritePolicy
    overwritePolicyFlag = flag RefuseOverwrite ForceOverwrite
      (long "force" <> short 'f' <> help "Overwrite existing output files")

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
   <> help ("Refuse to emit an IPS truncation marker unless the output size is one SNESTool accepts:"
         ++ " a multiple of 4096 plus 512, the shape a copier-headered SNES ROM has (size & 0xFFF == 0x200)")
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
   <> help ("Read PPF1 offsets as big-endian rather than little-endian. PPF1 carries no"
         ++ " endianness marker, and the reference applier reads offsets in host byte order,"
         ++ " so PC and Amiga PPF1 patches don't interoperate."
         ++ " The default (little-endian) is right for every PC-origin patch")
    )
  pure RequestedDialects
    { requestedPPF1Origin = ppf1Origin
    }

-- | Parser for @--with INPUT@ plus its sub-flags @--no-verify@, @--add-header@, and @--remove-header@.
-- The @--with@ option is required: if it is absent, the whole parser fails and the enclosing 'optional' falls back to 'Nothing'.
-- That leaves any stray sub-flag for the top-level parser to reject — so each is accepted only alongside @--with@.
convertWithSourceParser :: Parser ConvertWithSource
convertWithSourceParser = ConvertWithSource
  <$> pathOption (long "with" <> metavar "INPUT"
        <> help "Input file: lets convert apply the patch and rebuild it in the target format (needed for targets direct conversion can't reach), and verify the input's stored hashes")
  <*> flag EnforceVerification SkipVerification
        (long "no-verify"
          <> help "Skip input hash verification (requires --with INPUT; mismatches become warnings)")
  <*> headerDirectiveParser

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

-- | The one compression request a command line can make: decline compression, or name the xdelta3 secondary compressor.
-- One optional alternative group in 'requestedMetadataParser',
-- so @--no-compress@ and @--compress-with@ exclude each other the way the blob intents do:
-- passing both leaves one unconsumed and the top-level parser rejects the command.
-- Each arm projects onto its own metadata field — declining sets 'requestedPatchCompression',
-- a selection sets 'requestedSecondaryCompressor', compression-on being the default a selection rides —
-- so a rejection names back exactly the flag the user typed.
data CompressionIntent
  = DeclineCompression
  | CompressWith XDelta3SecondaryCompressor

-- | fgk resolves — slap knows the name; whether it can encode with it is judged later,
-- with a fuller answer ('Slap.Convert.rejectUnencodableSecondaryCompressor').
parseSecondaryCompressor :: String -> Either String XDelta3SecondaryCompressor
parseSecondaryCompressor = tokenReader "compressor" secondaryCompressorTokens

-- | Parse a @--window-size@ value: a byte count with an optional k or m suffix (KiB / MiB).
-- Sized in 'Integer' first, so an absurd count is refused rather than wrapped;
-- zero is refused by 'emissionWindowSizeOfBytes', the type's one door.
parseWindowSize :: String -> Either String EmissionWindowSize
parseWindowSize input = case span isDigit input of
  ("", _) -> Left ("not a window size: " ++ input ++ windowSizeShapeHint)
  (digits, suffix) -> do
    multiplier <- case map toLower suffix of
      ""  -> Right 1
      "k" -> Right 1024
      "m" -> Right (1024 * 1024)
      _   -> Left ("unknown window-size suffix: " ++ suffix ++ windowSizeShapeHint)
    let byteCount = read digits * multiplier :: Integer
    if byteCount > toInteger (maxBound :: Int)
      then Left ("window size past what this host can hold: " ++ input)
      else case emissionWindowSizeOfBytes (fromInteger byteCount) of
             Just windowSize -> Right windowSize
             Nothing         -> Left "window size must be at least 1 byte"

windowSizeShapeHint :: String
windowSizeShapeHint = "\n  expected: a byte count with an optional k or m suffix, e.g. 65536, 512k, 8m"

metadataFlag :: HasName f => MetadataField -> Mod f a
metadataFlag field = long (Text.unpack (metadataFieldFlagName field))

dropFlag :: HasName f => DroppableField -> Mod f a
dropFlag droppable = long (Text.unpack (dropFlagName droppable))

typedTextFlag :: HasName f => TypedTextField -> Mod f a
typedTextFlag field = long (Text.unpack (typedTextFlagName field))

-- | Parse the metadata flags shared between @slap create@ and @slap convert@.
-- Produces a 'RequestedPatchMetadata' with 'requestedEmbeddedBlob' left 'InheritEmbeddedBlob';
-- the resolvers @resolveCreateMetadata@ and @resolveConvertMetadata@ (in @Main@) fill that field from each command's blob source:
-- the 'EmbeddedBlobSource' for create, the 'EmbeddedBlobIntent' for convert.
requestedMetadataParser :: Parser RequestedPatchMetadata
requestedMetadataParser = do
    title             <- optional (option str (metadataFlag MetadataTitle <> metavar "TEXT"
                            <> help "Patch title (EBP/DPS/NINJA2)"))
    author            <- optional (option str (metadataFlag MetadataAuthor <> metavar "TEXT"
                            <> help "Patch author (EBP/DPS/NINJA2)"))
    description       <- optional (option str (metadataFlag MetadataDescription <> metavar "TEXT"
                            <> help "Patch description (EBP/PPF1/PPF2/PPF3/APS-N64/NINJA2)"))
    version           <- optional (option str (metadataFlag MetadataVersion <> metavar "TEXT"
                            <> help "Patch version (DPS/NINJA2)"))
    includeUndo         <- optional (flag' OmitUndoData     (metadataFlag MetadataUndoInclusion
                            <> help "Omit undo data (default: included when the format supports it)"))
    includeVerification <- optional (flag' OmitVerification (metadataFlag MetadataVerificationInclusion
                            <> help "Omit source-integrity-checking data from the created patch (default: included when the format supports it)"))
    compressionIntent <- optional
                           (   DeclineCompression <$ flag' () (metadataFlag MetadataPatchCompression
                                 <> help "Do not compress the output patch (xdelta1's gzip envelope, xdelta3's secondary compression; default emits compressed)")
                           <|> CompressWith <$> option (eitherReader parseSecondaryCompressor)
                                 (metadataFlag MetadataSecondaryCompressor <> metavar "ALGORITHM"
                                  <> completeWith (map fst secondaryCompressorTokens)
                                  <> help ("Secondary compressor for xdelta3 (default lzma): "
                                        ++ intercalate ", " (map fst secondaryCompressorTokens))))
    windowSize        <- optional (option (eitherReader parseWindowSize) (metadataFlag MetadataWindowSize <> metavar "SIZE"
                            <> help ("VCDIFF window size: bytes with an optional k or m suffix. xdelta3 defaults to 8m;"
                                  ++ " rfc-vcdiff defaults to one window spanning the whole output."
                                  ++ " The widespread xdelta3 3.0.11 build declines to decode windows past 16m; slap reads them fine")))
    unstable          <- optional (flag' UnstablePatch (metadataFlag MetadataStability
                            <> help "Mark patch unstable (DPS)"))
    romType           <- optional (option (eitherReader parseRomType) (metadataFlag MetadataRomType <> metavar "TYPE"
                            <> completeWith (map fst romTypeTokens)
                            <> help ("ROM type (NINJA1/NINJA2): " ++ intercalate ", " (map fst romTypeTokens))))
    imageType         <- optional (option (eitherReader parseImageType) (metadataFlag MetadataImageType <> metavar "TYPE"
                            <> completeWith (map fst imageTypeTokens)
                            <> help ("Image type (PPF3): " ++ intercalate ", " (map fst imageTypeTokens))))
    genre             <- optional (option str (metadataFlag MetadataGenre <> metavar "TEXT"
                            <> help "Genre (NINJA2)"))
    language          <- optional (option str (metadataFlag MetadataLanguage <> metavar "TEXT"
                            <> help "Language (NINJA2)"))
    date              <- optional (option str (metadataFlag MetadataDate <> metavar "YYYYMMDD"
                            <> help "Date (NINJA2)"))
    website           <- optional (option str (metadataFlag MetadataWebsite <> metavar "URL"
                            <> help "Website (NINJA2)"))
    textMode          <- optional (option (eitherReader parseTextMode) (metadataFlag MetadataTextMode <> metavar "MODE"
                            <> completeWith (map fst textModeTokens)
                            <> help ("Wire text mode for NINJA2 metadata: " ++ intercalate ", " (map fst textModeTokens) ++ "."
                                  ++ " Overrides any encoding declared by the source patch when supplied."
                                  ++ " When omitted: inherit from the source patch's metadata encoding"
                                  ++ " if one is available, otherwise utf8")))
    xdelta1FromName   <- optional (option str (metadataFlag MetadataXDelta1FromName <> metavar "TEXT"
                            <> help ("Embedded source-file display label (xdelta1 only;"
                                  ++ " default: basename of input/source ROM on create,"
                                  ++ " inherited from source patch on xdelta1" ++ [rightwardsArrow] ++ "xdelta1 convert)")))
    xdelta1ToName     <- optional (option str (metadataFlag MetadataXDelta1ToName <> metavar "TEXT"
                            <> help "Embedded target-file display label (xdelta1 only; same defaulting as --from-name)"))
    pure RequestedPatchMetadata
      { requestedTitle               = fmap wrapUtf8 title
      , requestedAuthor              = fmap wrapUtf8 author
      , requestedDescription         = fmap wrapUtf8 description
      , requestedVersion             = fmap wrapUtf8 version
      , requestedUndoInclusion        = includeUndo
      , requestedVerificationInclusion = includeVerification
      , requestedPatchCompression    = compressionInclusionOf =<< compressionIntent
      , requestedSecondaryCompressor = selectedCompressorOf   =<< compressionIntent
      , requestedStability           = unstable
      , requestedRomType             = romType
      , requestedImageType           = imageType
      , requestedFileIdDiz           = InheritFileIdDiz
      , requestedGenre               = fmap wrapUtf8 genre
      , requestedLanguage            = fmap wrapUtf8 language
      , requestedDate                = fmap wrapUtf8 date
      , requestedWebsite             = fmap wrapUtf8 website
      , requestedTextMode            = textMode
      , requestedEmbeddedBlob        = InheritEmbeddedBlob
      , requestedXDelta1FromName     = fmap (XDelta1FromName . wrapUtf8) xdelta1FromName
      , requestedXDelta1ToName       = fmap (XDelta1ToName   . wrapUtf8) xdelta1ToName
      , requestedWindowSize          = windowSize
      }
  where
    wrapUtf8 :: String -> EncodedText
    wrapUtf8 = EncodedText EncodingUtf8 . Text.pack

    compressionInclusionOf :: CompressionIntent -> Maybe CompressionInclusion
    compressionInclusionOf DeclineCompression = Just OmitCompression
    compressionInclusionOf (CompressWith _)   = Nothing

    selectedCompressorOf :: CompressionIntent -> Maybe XDelta3SecondaryCompressor
    selectedCompressorOf (CompressWith compressor) = Just compressor
    selectedCompressorOf DeclineCompression        = Nothing

createMetadataInputsParser :: Parser CreateMetadataInputs
createMetadataInputsParser = CreateMetadataInputs
  <$> requestedMetadataParser
  <*> embeddedBlobSourceParser
  <*> dizSourceParser

-- | The two set lanes are mutually exclusive the same way 'embeddedBlobIntentParser''s are.
embeddedBlobSourceParser :: Parser EmbeddedBlobSource
embeddedBlobSourceParser = asum
  [ EmbeddedBlobFromFile <$> pathOption (metadataFlag MetadataEmbeddedBlob <> metavar "FILE"
      <> help "Embed bytes from FILE as the output patch's embedded metadata")
  , EmbeddedBlobFromTypedText <$> option str (typedTextFlag TypedTextEmbeddedBlob <> metavar "TEXT"
      <> help "Embed TEXT as the output patch's embedded metadata")
  , pure NoEmbeddedBlob
  ]

-- | The FILE_ID.DIZ counterpart to 'embeddedBlobSourceParser': @--diz FILE@ and @--diz-text TEXT@, mutually exclusive.
-- Only the file lane carries an encoding: a DIZ file arrives as bytes that have to be read as some encoding,
-- while text typed at the flag was decoded from argv before slap saw it.
dizSourceParser :: Parser FileIdDizSource
dizSourceParser = asum
  [ FileIdDizFromFile <$> pathOption (metadataFlag MetadataFileIdDiz <> metavar "FILE"
      <> help "Embed FILE as the output patch's FILE_ID.DIZ (PPF2/PPF3)")
                      <*> dizEncodingParser
  , FileIdDizFromText <$> option str (typedTextFlag TypedTextFileIdDiz <> metavar "TEXT"
      <> help "Embed TEXT as the output patch's FILE_ID.DIZ (PPF2/PPF3)")
  , pure NoFileIdDiz
  ]

-- | The @--diz-encoding ENC@ option, distinct from @--metadata-encoding@:
-- that one reads text out of a patch slap was handed, this one reads the bytes of a file the user hands in.
dizEncodingParser :: Parser EncodingName
dizEncodingParser = option (eitherReader resolveMetadataEncoding)
  ( long "diz-encoding"
 <> metavar "ENC"
 <> value EncodingUtf8
 <> completeWith advertisedEncodingNames
 <> help ("Read the --diz file as ENC (e.g. cp437 for DOS scene art; see"
       ++ " --encodings). Default: utf8") )

convertMetadataInputsParser :: Parser ConvertMetadataInputs
convertMetadataInputsParser = ConvertMetadataInputs
  <$> requestedMetadataParser
  <*> embeddedBlobIntentParser
  <*> dizIntentParser

-- | The set and drop flags are mutually exclusive: a pair of them leaves one unconsumed and the top-level parser rejects the command.
embeddedBlobIntentParser :: Parser EmbeddedBlobIntent
embeddedBlobIntentParser = asum
  [ SetBlobFromFile <$> pathOption (metadataFlag MetadataEmbeddedBlob <> metavar "FILE"
      <> help "Override the embedded metadata with bytes from FILE")
  , SetBlobFromTypedText <$> option str (typedTextFlag TypedTextEmbeddedBlob <> metavar "TEXT"
      <> help "Override the embedded metadata with TEXT")
  , DropBlob <$ flag' () (dropFlag DroppableEmbeddedBlob
      <> help "Discard the source patch's embedded metadata (default is to inherit)")
  , pure CarryBlob
  ]

-- | The FILE_ID.DIZ counterpart to 'embeddedBlobIntentParser'.
dizIntentParser :: Parser DizIntent
dizIntentParser = asum
  [ SetDizFromFile <$> pathOption (metadataFlag MetadataFileIdDiz <> metavar "FILE"
      <> help "Set the FILE_ID.DIZ from FILE (PPF2/PPF3 target)")
  , SetDizFromTypedText <$> option str (typedTextFlag TypedTextFileIdDiz <> metavar "TEXT"
      <> help "Set the FILE_ID.DIZ to TEXT (PPF2/PPF3 target)")
  , DropDiz <$ flag' () (dropFlag DroppableFileIdDiz
      <> help "Discard the source patch's FILE_ID.DIZ (default is to inherit)")
  , pure CarryDiz
  ]

-- | The option-reader adapter over 'lookupCreateFormatToken': the token table lives in "Slap.Convert"
-- (shared with the test harness's spec files); what belongs here is the CLI's error message.
parseCreateFormat :: String -> Either String CreateFormat
parseCreateFormat input = case lookupCreateFormatToken input of
  Just format -> Right format
  Nothing     -> Left ("unknown format: " ++ input
                    ++ "\n  expected: " ++ intercalate ", " advertisedCreateFormats)

-- | Read a token against a closed table, answering an unknown word with the real ones.
tokenReader :: String -> [(String, value)] -> String -> Either String value
tokenReader vocabularyNoun tokenTable input =
  case lookup (map toLower input) tokenTable of
    Just resolved -> Right resolved
    Nothing       -> Left ("unknown " ++ vocabularyNoun ++ ": " ++ input
                        ++ "\n  expected: " ++ intercalate ", " (map fst tokenTable))

parseTextMode :: String -> Either String TextMode
parseTextMode = tokenReader "NINJA2 text mode" textModeTokens

parseRomType :: String -> Either String PlatformType
parseRomType = tokenReader "ROM type" romTypeTokens

parseImageType :: String -> Either String PPF3ImageType
parseImageType = tokenReader "image type" imageTypeTokens

patchInfoParser :: Parser InfoCommand
patchInfoParser = do
    patchFile <- pathArgument (metavar "PATCH" <> help "Patch file to inspect")
    extractMetadataPath <- optional (pathOption (long "extract-metadata" <> metavar "FILE"
        <> help "Write embedded metadata to FILE"))
    extractDizPath <- optional (pathOption (long "extract-diz" <> metavar "FILE"
        <> help "Write the FILE_ID.DIZ to FILE (PPF2/PPF3)"))
    fileReadingOptions <- fileReadingOptionsParser
    dialects <- dialectsParser
    metadataEncoding <- metadataEncodingParser
    overwritePolicy <- overwritePolicyFlag
    pure InfoCommand
      { infoPatch            = patchFile
      , infoExtractMetadata  = extractMetadataPath
      , infoExtractDiz       = extractDizPath
      , infoFileReading      = fileReadingOptions
      , infoDialects         = dialects
      , infoMetadataEncoding = metadataEncoding
      , infoOverwritePolicy  = overwritePolicy
      }
  where
    overwritePolicyFlag :: Parser OverwritePolicy
    overwritePolicyFlag = flag RefuseOverwrite ForceOverwrite
      (long "force" <> short 'f' <> help "Overwrite existing extraction targets")

----------------------------------------------------------------------------
-- Entry point
----------------------------------------------------------------------------

-- | Run the optparse-applicative parser over argv to produce a 'Command',
-- or exit down its help and usage path (@--help@, @--encodings@, a parse error).
parseCommandLine :: IO Command
parseCommandLine = customExecParser (prefs showHelpOnEmpty) options
