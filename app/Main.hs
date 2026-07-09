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
  , ExpectedN64ByteOrder(..)
  , applySourcePreHash
  , parseSome
  )
import Slap.Display.Common (pathText)
import Slap.Display.Info (renderPatchInfo, renderActionLine)
import Slap.Display.Analysis (renderAnalysisFull, renderAnalysisSummary)
import Slap.Display.EmbeddedContent (EmbeddedDepth(SizeOnly))
import Slap.FileContents (InputFileContents(..), OutputFileContents(..), PatchFileContents(..))
import Slap.Measure (Offset(..), Length(..), FileSize(..),
                     ExpectedSize(..), ActualSize(..), byteFileSize)
import Slap.Convert (CreateFormat(..), DifferentialCreate(..),
                     PatchContents, contentsFileIdDiz,
                     RequestedPatchMetadata(..),
                     FileIdDizRequest(..),
                     RequestedDialects,
                     rejectIncompatibleConstraints,
                     rejectUnencodableSecondaryCompressor,
                     noDialectsRequested,
                     acceptedDialects,
                     rejectIncompatibleDialects,
                     createDefaultAdvisories, convertDirect,
                     mergeRequestedMetadata, rejectIncompatibleMetadata,
                     formatExtension, formatName)
import Slap.XDelta1.Types (ResolvedXDelta1FileNames,
                           resolveXDelta1FileNames,
                           requireXDelta1FileNames,
                           XDelta1FromName(..), XDelta1ToName(..))
import Slap.Create (createPatch)
import Slap.Text (EncodingName(EncodingUtf8),
                  decodeTextLenient, encodeTextLenient,
                  encodedTextEncoding, encodedTextContent)
import Data.Text (Text)
import qualified Data.Text as Text
import qualified Data.Text.IO as TextIO
import Slap.Archive.Types (detectArchive, EntryName(unEntryName))
import Slap.Binary (crc16, md5, sha1, viewBytesInRange)
import Slap.Checksum (CRC32(..), CRC16, Adler32(..),
                      ExpectedCRC32(..), ActualCRC32(..))
import Slap.FFI (crc32, adler32)
import Slap.Status (SlapError(..), SlapAdvisory(..), CreateResult(..), Outcome(..),
                   VerificationSide(..), HashAlgorithm(..),
                   ExpectedAdler32(..), ActualAdler32(..), ByteCheckLabel(..),
                   emitAdvisories, bail, bailError, orBail)
import Slap.Display.Glyph (emDash, spacePaddedRightwardsArrow)
import Slap.FormatLabel (formatLabelName)
import Slap.Header (addHeader, removeHeader)

import CLI
  ( Command(..)
  , ApplyCommand(..)
  , UndoCommand(..)
  , CreateCommand(..)
  , ConvertCommand(..)
  , InfoCommand(..)
  , ExplainCommand(..)
  , ApplyOutput(..)
  , UndoOutput(..)
  , ConvertOutput(..)
  , ConvertWithSource(..)
  , EmbeddedBlobIntent(..)
  , DizIntent(..)
  , CreateMetadataInputs(..)
  , ConvertMetadataInputs(..)
  , FileReadingOptions(..)
  , ArchiveHandling(..)
  , InputHeaderDirective(..)
  , ExplainVerbosity(..)
  , VerificationPolicy(..)
  , Verbosity(..)
  , OverwritePolicy(..)
  , BackupBehavior(..)
  , parseCommandLine
  )
import Archive (unwrapArchive)

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Control.Exception (try)
import Control.Monad (when, forM_)
import System.Directory (copyFile, doesFileExist)
import System.FilePath (dropExtension, replaceExtension, takeBaseName, takeExtension)
import System.IO (IOMode(ReadMode), hFileSize, hSetEncoding, stderr, stdout, withFile)
import System.IO.MMap (mmapFileByteString)
import System.IO.Error (isDoesNotExistError, ioeGetErrorString)
import GHC.IO.Encoding (setFileSystemEncoding, setLocaleEncoding, utf8)
import GHC.IO.Encoding.UTF8 (mkUTF8)
import GHC.IO.Encoding.Failure (CodingFailureMode(TransliterateCodingFailure))

----------------------------------------------------------------------------
-- Entry point and dispatch
----------------------------------------------------------------------------

main :: IO ()
main = do
  -- Slap is a UTF-8 program on both sides:
  -- setFileSystemEncoding utf8 pins argument decoding to UTF-8 and setStdoutAndStderrToLenientUtf8 pins output,
  -- so LANG/LC_CTYPE cannot change how slap reads its arguments or what it prints.
  -- setLocaleEncoding utf8 pins the entry listings slap reads back from shelled-out archive tools.
  -- The filesystem pin must run first, before parseCommandLine decodes argv.
  setFileSystemEncoding utf8
  setLocaleEncoding utf8
  setStdoutAndStderrToLenientUtf8
  parsedCommand <- parseCommandLine
  case parsedCommand of
    Apply   subcommand -> doApply   subcommand
    Undo    subcommand -> doUndo    subcommand
    Create  subcommand -> doCreate  subcommand
    Convert subcommand -> doConvert subcommand
    Info    subcommand -> doInfo    subcommand
    Explain subcommand -> doExplain subcommand

----------------------------------------------------------------------------
-- Archive-aware file reading
----------------------------------------------------------------------------

-- | Read a user-supplied input file, turning its two interesting IO failure modes into typed 'SlapError' values on slap's normal error channel:
-- the path is absent ('MissingInputFile'), or present but unopenable ('UnreadableInputFile').
-- A mapped input is live pages rather than a snapshot, so an outside process truncating the file mid-run
-- is outside slap's contract; slap's own in-place apply and undo stay clear of the hazard
-- because each writes only a fully materialized output and reads nothing from the input afterwards —
-- 'applyAndWriteTo' and 'undoAndWriteTo' own that ordering.
readInputFile :: FilePath -> IO ByteString
readInputFile path = do
  result <- try (readWholeFile path)
  case result of
    Right fileBytes -> pure fileBytes
    Left ioErr
      | isDoesNotExistError ioErr -> bailError (MissingInputFile path)
      | otherwise                 -> bailError (UnreadableInputFile path (ioeGetErrorString ioErr))

-- | Read a whole input into memory, mapped when the file's shape allows it.
-- A regular file with a real size arrives memory-mapped: address space and evictable page cache rather than a heap copy,
-- paged in as slap touches it.
-- Everything else streams through 'ByteString.readFile', which answers every shape a mapping cannot:
-- pipes and devices (the size probe refuses them), proc-style files whose reported size is zero despite content,
-- and the truly empty file. A probe failure decides nothing by itself —
-- the streaming read then produces the authoritative bytes or the authoritative error for 'readInputFile' to type.
readWholeFile :: FilePath -> IO ByteString
readWholeFile path = do
  probedSize <- try (withFile path ReadMode hFileSize) :: IO (Either IOError Integer)
  case probedSize of
    Right byteCount | byteCount > 0 -> mmapFileByteString path Nothing
    _                               -> ByteString.readFile path

-- | Read a file, transparently unwrapping single-entry archives.
readUnwrap :: FilePath -> IO ByteString
readUnwrap path = do
  fileBytes <- readInputFile path
  case detectArchive (ByteString.take 8 fileBytes) of
    Nothing -> pure fileBytes
    Just format -> do
      result <- unwrapArchive format path
      case result of
        Left unwrapError -> bailError (ArchiveUnwrapFailed path format unwrapError)
        Right (unwrappedBytes, entryName) -> do
          TextIO.hPutStrLn stderr ("slap: unwrapped " <> pathText path <> spacePaddedRightwardsArrow <> unEntryName entryName)
          pure unwrappedBytes

readMaybeUnwrap :: FileReadingOptions -> FilePath -> IO ByteString
readMaybeUnwrap fileReadingOptions = case fileReadingArchiveHandling fileReadingOptions of
  AutoUnwrapSingleEntryArchives -> readUnwrap
  ReadBytesVerbatim             -> readInputFile

-- | Carry out the user's @--add-header@\/@--remove-header@ instruction on the handed input,
-- narrating the action with a note so the reframe never happens silently.
reframeInput :: InputHeaderDirective -> ByteString -> IO ByteString
reframeInput TakeInputAsIs handedBytes = pure handedBytes
reframeInput (AddHeader console) handedBytes = do
  emitAdvisories [InputHeaderAdded console]
  pure (addHeader console handedBytes)
reframeInput (RemoveHeader console) handedBytes = case removeHeader console handedBytes of
  Nothing -> bailError (HeaderRemovalExceedsInput console (ActualSize (byteFileSize handedBytes)))
  Just bytesBeneath -> do
    emitAdvisories [InputHeaderRemoved console]
    pure bytesBeneath

-- | Resolve @slap create@'s metadata inputs: @--metadata FILE@ becomes the embedded blob, @--diz FILE@ the FILE_ID.DIZ.
resolveCreateMetadata :: CreateMetadataInputs -> IO RequestedPatchMetadata
resolveCreateMetadata inputs = do
  embeddedBlob <- traverse readInputFile (createEmbeddedBlobPath inputs)
  fileIdDiz    <- resolveCreateFileIdDiz (createDizPath inputs)
  pure (createParsedMetadata inputs)
    { requestedEmbeddedBlob = embeddedBlob
    , requestedFileIdDiz    = fileIdDiz
    }

-- | The @--diz@ file is read as UTF-8 — create writes every text field as UTF-8
-- and has no @--metadata-encoding@ knob to say otherwise.
resolveCreateFileIdDiz :: Maybe FilePath -> IO FileIdDizRequest
resolveCreateFileIdDiz Nothing     = pure InheritFileIdDiz
resolveCreateFileIdDiz (Just path) =
  SetFileIdDiz . fst . decodeTextLenient EncodingUtf8 <$> readInputFile path

-- | 'CarryIfPresent' and 'DropEmbeddedBlob' both leave the blob 'Nothing' here;
-- the two only diverge later, in 'doConvert', after the source-patch merge.
resolveConvertMetadata :: EncodingName -> ConvertMetadataInputs -> IO RequestedPatchMetadata
resolveConvertMetadata metadataEncoding inputs = do
  embeddedBlob <- case convertEmbeddedBlobIntent inputs of
    EmbedFromFile path -> Just <$> readInputFile path
    DropEmbeddedBlob   -> pure Nothing
    CarryIfPresent     -> pure Nothing
  fileIdDiz <- case convertDizIntent inputs of
    SetDizFromFile path -> SetFileIdDiz . fst . decodeTextLenient metadataEncoding <$> readInputFile path
    DropDiz             -> pure DropFileIdDiz
    CarryDiz            -> pure InheritFileIdDiz
  pure (convertParsedMetadata inputs)
    { requestedEmbeddedBlob = embeddedBlob
    , requestedFileIdDiz    = fileIdDiz
    }

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
  mapM_ TextIO.putStrLn (renderPatchInfo SizeOnly (patchInfo parsed))
  emitAdvisories (patchAdvisories parsed)
  case infoExtractMetadata parsedCommand of
    Nothing -> pure ()
    Just outPath -> case patchMetadata parsed of
      Nothing   -> TextIO.hPutStrLn stderr "slap: no metadata in this patch"
      Just metadataBytes -> do
        ByteString.writeFile outPath metadataBytes
        TextIO.putStrLn ("wrote metadata to " <> pathText outPath)
  case infoExtractDiz parsedCommand of
    Nothing -> pure ()
    Just outPath -> case patchContentsOf parsed >>= contentsFileIdDiz of
      Nothing        -> TextIO.hPutStrLn stderr "slap: no FILE_ID.DIZ in this patch"
      Just fileIdDiz -> do
        ByteString.writeFile outPath (fst (encodeTextLenient (encodedTextEncoding fileIdDiz) (encodedTextContent fileIdDiz)))
        TextIO.putStrLn ("wrote FILE_ID.DIZ to " <> pathText outPath)

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
        handedBytes <- readMaybeUnwrap (applyFileReading parsedCommand) (applySource parsedCommand)
        sourceBytes <- reframeInput (applyHeaderDirective parsedCommand) handedBytes
        let source = InputFileContents sourceBytes
        verifySource verificationPolicy verification source
        outcome <- orBail =<< runApply (patchApply parsed) source
        emitAdvisories (outcomeAdvisories outcome)
        let target = outcomeValue outcome
        verifyTarget verificationPolicy verification target
        ByteString.writeFile outputPath (unOutputFileContents target)
        TextIO.putStrLn (renderActionLine "applied" (patchInfo parsed) outputPath)

  case applyOutput parsedCommand of
    ApplyInPlace backupBehavior -> do
      when (applyHeaderDirective parsedCommand /= TakeInputAsIs) $
        bailError HeaderDirectiveRequiresSeparateOutput
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
  orBail (rejectUnencodableSecondaryCompressor (createFormat parsedCommand) createMeta)
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
  cliMeta <- resolveConvertMetadata (convertMetadataEncoding parsedCommand) (convertMetadata parsedCommand)
  orBail (rejectIncompatibleMetadata    (convertTo parsedCommand) cliMeta)
  orBail (rejectUnencodableSecondaryCompressor (convertTo parsedCommand) cliMeta)
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
  resolvedXDelta1Names <- orBail (resolveConvertXDelta1Names parsedCommand parsed mergedMeta)
  case chooseConvertDispatch parsedCommand parsed of
    ApplyAndRecreate withSource -> do
      sourceBytes <- readMaybeUnwrap (convertFileReading parsedCommand) (convertWithSourcePath withSource)
      let source = InputFileContents sourceBytes
      verifySource (convertWithVerification withSource) (patchVerification parsed) source
      target <- applyForConvert parsed source
      createResult <- orBail (createPatch (convertTo parsedCommand) resolvedXDelta1Names (InputFileContents sourceBytes) target mergedMeta (patchContentsOf parsed) (convertConstraints parsedCommand) noDialectsRequested)
      emitAdvisories (patchSourceAdvisories parsed
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
  -- --no-verify doesn't gate these; it operates only on the fatal-class checks below.
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
  -- Only when no source checksum can vouch the input; a present checksum is the stronger gate and handles that case itself.
  forM_ (verifyRomTypeUnrecognized verification) $ \label ->
    case (verifySourceCRC32 verification, verifySourceMD5 verification, verifySourceSHA1 verification) of
      (Nothing, Nothing, Nothing) ->
        enforceMismatch verificationPolicy (UnrecognizedRomTypeWithoutChecksum label)
      _ -> pure ()
  forM_ (verifyN64ByteOrder verification) $ \expected ->
    let v64LeadingMagic = ByteString.pack [0x37, 0x80, 0x40, 0x12]  -- V64 (byteswapped) leads with this; Z64/native do not
        sourceIsV64     = ByteString.take 4 sourceBytes == v64LeadingMagic
        mismatched      = case expected of
          SourceMustBeV64    -> not sourceIsV64
          SourceMustNotBeV64 -> sourceIsV64
    in when mismatched (enforceMismatch verificationPolicy APSN64ImageFormatMismatch)

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

notePPFBlock :: Offset -> ByteString -> ByteString -> IO ()
notePPFBlock blockOffset expectedData sourceBytes =
  let actual = viewBytesInRange blockOffset (Length (ByteString.length expectedData)) sourceBytes
  in when (actual /= expectedData) $
       noteMismatch (VerificationPPFBlockMismatch blockOffset)

noteFileSize :: FileSize -> FileSize -> IO ()
noteFileSize expected actual =
  when (expected /= actual) $
    noteMismatch (VerificationFileSizeAdvisory (ExpectedSize expected) (ActualSize actual))

noteSourceBytes :: ByteCheckLabel -> Offset -> ByteString -> ByteString -> IO ()
noteSourceBytes label checkOffset expectedData sourceBytes =
  let actual = viewBytesInRange checkOffset (Length (ByteString.length expectedData)) sourceBytes
  in when (actual /= expectedData) $
       noteMismatch (VerificationSourceBytesMismatch label checkOffset)

-- | Render the full per-record analysis to stderr, gated on 'Verbose'.
emitVerboseAnalysis :: Verbosity -> SomePatch -> IO ()
emitVerboseAnalysis Verbose parsed =
  TextIO.hPutStr stderr (renderAnalysisFull (patchInfo parsed) (patchAnalysis parsed) Nothing)
emitVerboseAnalysis Quiet _ = pure ()

-- | Emits no advisories itself, leaving warning-ordering to each caller:
-- 'doInfo' and 'doExplain' defer until after their stdout renders, while 'doApply', 'doUndo', and 'doConvert' emit immediately (each via 'emitAdvisories').
readAndParsePatch :: RequestedDialects -> EncodingName -> FilePath -> IO SomePatch
readAndParsePatch dialects metadataEncoding path = do
  patchBytes <- readUnwrap path
  orBail (parseSome dialects metadataEncoding (PatchFileContents patchBytes))

----------------------------------------------------------------------------
-- Stdout and stderr encoding setup
----------------------------------------------------------------------------

-- | Bind 'stdout' and 'stderr' to UTF-8, transliterating on failure so a codepoint the encoder can't represent substitutes a placeholder rather than crashing with an @hPutChar@ invalid-argument error.
-- UTF-8 can only fail on a lone surrogate, and one is unlikely to reach output:
-- 'main' pins the filesystem encoding to UTF-8, so GHC's argv and filepath decoders reject malformed bytes rather than surrogate-escaping them, and slap's lenient decode substitutes U+FFFD.
-- Transliteration is cheap cover for a stray one.
-- Called once at startup, before any I/O.
setStdoutAndStderrToLenientUtf8 :: IO ()
setStdoutAndStderrToLenientUtf8 = do
  hSetEncoding stdout lenientUtf8
  hSetEncoding stderr lenientUtf8
  where
    lenientUtf8 = mkUTF8 TransliterateCodingFailure
