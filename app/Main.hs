{-# LANGUAGE CPP #-}
{-# LANGUAGE OverloadedStrings #-}

module Main (main) where

import Slap.SomePatch
  ( SomePatch(..)
  , PatchKind(..)
  , patchContentsOf
  , clearToRun
  , UndoStrategy(..)
  , UndoAvailability(..)
  , parseSome
  )
import Slap.Apply (PatchedRom(..), VerdictStanding(..), runPreparedApply)
import Slap.Verify (weighSource, flipSpokenSides, judgeWeighing, verdictOnWeighing)
import Slap.Display.Common (pathText)
import Slap.Display.Info (renderPatchInfo, renderActionLine,
                          InputSideVerdict(..), OutputSideVerdict(..), renderVerificationReport)
import Slap.Display.Analysis (renderAnalysisFull, renderAnalysisSummary)
import Slap.Display.EmbeddedContent (EmbeddedDepth(SizeOnly))
import Slap.FileContents (InputFileContents(..), OutputFileContents(..), PatchFileContents(..))
import Slap.Convert (CreateFormat(..), DifferentialCreate(..),
                     PatchContents,
                     RequestedPatchMetadata(..),
                     FileIdDizRequest(..),
                     RequestedDialects,
                     rejectIncompatibleConstraints,
                     rejectUnencodableSecondaryCompressor,
                     noDialectsRequested,
                     acceptedDialects,
                     rejectIncompatibleDialects,
                     rejectCrossPlatformRomTypeRetag,
                     createDefaultAdvisories, convertDirect, createFormatLabel,
                     mergeRequestedMetadata, rejectIncompatibleMetadataRequests,
                     EmbeddedBlobContents(..), EmbeddedBlobRequest(..),
                     formatExtension, formatName)
import Slap.XDelta1.Types (ResolvedXDelta1FileNames,
                           resolveXDelta1FileNames,
                           requireXDelta1FileNames,
                           XDelta1FromName(..), XDelta1ToName(..))
import Slap.Create (createPatch)
import Slap.Text (EncodingName(EncodingUtf8), EncodedText(..), decodeTextLenient, decodeLossAdvisories)
import qualified Data.Text.IO as TextIO
import Slap.Archive.Types (detectArchive, EntryName(unEntryName))
import Slap.Status (SlapError(..), SourceRequiredCause(..), ExtractionSubject(..),
                   CreateResult(..), Outcome(..),
                   emitAdvisories, bailError, orBail)
import Slap.FieldName (FieldName(FieldFileIdDiz))
import Slap.FormatLabel (FormatLabel)
import Slap.Normalize (NormalizedSource(..), normalizeApplySource)
import Slap.Display.Glyph (spacePaddedRightwardsArrow)
import Slap.Display.Primitives (renderEscapingNonPrintable)
import Slap.Preflight (PreparedApplySource(..), prepareApplySource, weighUndoInput)

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
  , EmbeddedBlobSource(..)
  , FileIdDizSource(..)
  , CreateMetadataInputs(..)
  , ConvertMetadataInputs(..)
  , createMetadataRequests
  , convertMetadataRequests
  , FileReadingOptions(..)
  , ArchiveHandling(..)
  , ExplainVerbosity(..)
  , Verbosity(..)
  , OverwritePolicy(..)
  , parseCommandLine
  )
import Archive (unwrapArchive)

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Control.Exception (try, bracketOnError)
#if defined(mingw32_HOST_OS)
import Control.Exception (bracket)
import Data.Word (Word32)
import Foreign.C.Types (CInt(CInt))
#endif
import Control.Monad (when)
import System.Directory (doesFileExist, renameFile, removeFile, copyPermissions)
import System.FilePath (dropExtension, replaceExtension, takeBaseName, takeExtension, takeDirectory, takeFileName)
import System.IO (IOMode(ReadMode), hFileSize, hSetEncoding, stderr, stdout, openBinaryFile, openBinaryTempFile, hClose, hIsSeekable)
import System.IO.MMap (mmapFileByteString)
import System.IO.Error (isDoesNotExistError, ioeGetErrorString)
import GHC.IO.Encoding (setFileSystemEncoding, setLocaleEncoding, utf8)
import GHC.IO.Encoding.UTF8 (mkUTF8)
import GHC.IO.Encoding.Failure (CodingFailureMode(TransliterateCodingFailure, RoundtripFailure))
import Control.Exception.Backtrace (setBacktraceMechanismState, BacktraceMechanism(IPEBacktrace))

----------------------------------------------------------------------------
-- Entry point and dispatch
----------------------------------------------------------------------------

main :: IO ()
main = withConsoleListeningInUtf8 $ do
  -- Source-located backtraces on an uncaught exception; the info-table map they resolve against is turned on in cabal.project.
  setBacktraceMechanismState IPEBacktrace True
  -- Slap is a UTF-8 program on both sides:
  -- the filesystem pin decodes arguments and path bytes as UTF-8 (RoundtripFailure, so an odd non-UTF-8 name still round-trips),
  -- setStdoutAndStderrToLenientUtf8 pins output, so LANG/LC_CTYPE cannot change how slap reads its arguments or what it prints.
  -- setLocaleEncoding utf8 pins the entry listings slap reads back from shelled-out archive tools.
  -- The filesystem pin must run first, before parseCommandLine decodes argv.
  setFileSystemEncoding (mkUTF8 RoundtripFailure)
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

-- The Windows console renders program output through its own code page, a CP437-era default that garbles UTF-8,
-- so slap asks it to listen in UTF-8 for the run and puts its choice back on the way out.
-- Elsewhere there is no console code page to ask.
#if defined(mingw32_HOST_OS)
foreign import ccall unsafe "windows.h GetConsoleOutputCP" getConsoleOutputCodePage :: IO Word32
foreign import ccall unsafe "windows.h SetConsoleOutputCP" setConsoleOutputCodePage :: Word32 -> IO CInt

withConsoleListeningInUtf8 :: IO a -> IO a
withConsoleListeningInUtf8 body =
  bracket rememberAndRetune restore (const body)
  where
    utf8CodePage = 65001
    rememberAndRetune = do
      originalCodePage <- getConsoleOutputCodePage
      _ <- setConsoleOutputCodePage utf8CodePage
      pure originalCodePage
    restore originalCodePage = () <$ setConsoleOutputCodePage originalCodePage
#else
withConsoleListeningInUtf8 :: IO a -> IO a
withConsoleListeningInUtf8 = id
#endif

----------------------------------------------------------------------------
-- Archive-aware file reading
----------------------------------------------------------------------------

-- | Read a user-supplied input file, memory-mapped when its shape allows ('readWholeFile').
-- The mapped bytes are live pages, not a snapshot, so nothing may read the input after slap has written over it:
-- every verb stays clear by writing a finished output and never reading the input again.
-- An absent or unopenable path surfaces as a typed 'SlapError' rather than an exception.
readInputFile :: FilePath -> IO ByteString
readInputFile path = do
  result <- try (readWholeFile path)
  case result of
    Right fileBytes -> pure fileBytes
    Left ioErr
      | isDoesNotExistError ioErr -> bailError (MissingInputFile path)
      | otherwise                 -> bailError (UnreadableInputFile path (ioeGetErrorString ioErr))

-- | Read a whole input into memory, memory-mapped where the file's shape allows:
-- a regular, seekable file with a real size arrives as address space and evictable page cache rather than a heap copy.
-- Every other shape — a pipe or FIFO, a device, a proc-style file reporting size zero, the empty file — reads from the one open handle.
-- Opening it a second time would be wrong: opening a FIFO consumes whatever a writer has queued,
-- so a size probe that opened and closed one first would leave the real read empty.
readWholeFile :: FilePath -> IO ByteString
readWholeFile path =
  bracketOnError (openBinaryFile path ReadMode) hClose $ \handle -> do
    seekable <- hIsSeekable handle
    size     <- if seekable then hFileSize handle else pure 0
    if seekable && size > 0
      then hClose handle >> mmapFileByteString path Nothing
      else ByteString.hGetContents handle <* hClose handle

-- | Write an output file: the write-side mirror of 'readInputFile'.
writeOutputFile :: FilePath -> ByteString -> IO ()
writeOutputFile path outputBytes = do
  result <- try (ByteString.writeFile path outputBytes)
  case result of
    Right ()   -> pure ()
    Left ioErr -> bailError (UnwritableOutputFile path (ioeGetErrorString ioErr))

-- | Write @path@. An existing file is replaced atomically — a sibling temporary, then a 'renameFile' over it —
-- so an interrupted write leaves the original whole, which is what makes a @--force@ overwrite survivable on a file the user cannot re-fetch;
-- the temporary inherits the target's mode, not its own private default.
-- A path that doesn't exist yet has nothing to protect from a half-write,
-- so it is written directly, at the umask's mode like any created file rather than the temporary's @0600@.
writeFileAtomicallyOver :: FilePath -> ByteString -> IO ()
writeFileAtomicallyOver path outputBytes = do
  targetExists <- doesFileExist path
  if not targetExists
    then writeOutputFile path outputBytes
    else do
      result <- try $ bracketOnError
        (openBinaryTempFile (takeDirectory path) (takeFileName path <> ".tmp"))
        (\(tempPath, tempHandle) -> hClose tempHandle >> removeFileIfExists tempPath)
        (\(tempPath, tempHandle) -> do
           ByteString.hPut tempHandle outputBytes
           hClose tempHandle
           copyPermissions path tempPath
           renameFile tempPath path)
      case result of
        Right ()   -> pure ()
        Left ioErr -> bailError (UnwritableOutputFile path (ioeGetErrorString ioErr))

removeFileIfExists :: FilePath -> IO ()
removeFileIfExists path = do
  exists <- doesFileExist path
  when exists (removeFile path)

-- | Read a file, transparently unwrapping single-entry archives.
readUnwrap :: FilePath -> IO ByteString
readUnwrap path = do
  fileBytes <- readInputFile path
  case detectArchive (ByteString.take 8 fileBytes) of
    Nothing -> pure fileBytes
    Just format -> do
      result <- unwrapArchive format fileBytes path
      case result of
        Left unwrapError -> bailError (ArchiveUnwrapFailed path format unwrapError)
        Right (unwrappedBytes, entryName) -> do
          TextIO.hPutStrLn stderr ("slap: unwrapped " <> pathText path <> spacePaddedRightwardsArrow <> renderEscapingNonPrintable (unEntryName entryName))
          pure unwrappedBytes

readMaybeUnwrap :: FileReadingOptions -> FilePath -> IO ByteString
readMaybeUnwrap fileReadingOptions = case fileReadingArchiveHandling fileReadingOptions of
  AutoUnwrapSingleEntryArchives -> readUnwrap
  ReadBytesVerbatim             -> readInputFile

-- | Resolve @slap create@'s metadata inputs: the 'EmbeddedBlobSource' and 'FileIdDizSource' become the blob and DIZ requests.
resolveCreateMetadata :: FormatLabel -> CreateMetadataInputs -> IO RequestedPatchMetadata
resolveCreateMetadata label inputs = do
  embeddedBlob <- case createEmbeddedBlobSource inputs of
    NoEmbeddedBlob                  -> pure InheritEmbeddedBlob
    EmbeddedBlobFromFile path       -> SetEmbeddedBlob . EmbeddedBlobContents <$> readInputFile path
    EmbeddedBlobFromTypedText typed -> pure (SetEmbeddedTypedText typed)
  fileIdDiz    <- resolveCreateFileIdDiz label (createDizSource inputs)
  pure (createParsedMetadata inputs)
    { requestedEmbeddedBlob = embeddedBlob
    , requestedFileIdDiz    = fileIdDiz
    }

-- | The @--diz@ file and @--diz-text@ string both become UTF-8, because create writes every text field that way.
-- A DIZ file arrives as bytes, so @--diz-encoding@ says how to read them: DOS scene art is usually CP437,
-- and reading that as UTF-8 would replace every high byte. What the chosen encoding still cannot represent is reported.
resolveCreateFileIdDiz :: FormatLabel -> FileIdDizSource -> IO FileIdDizRequest
resolveCreateFileIdDiz _ NoFileIdDiz = pure InheritFileIdDiz
resolveCreateFileIdDiz label (FileIdDizFromFile path encoding) = do
  dizBytes <- readInputFile path
  let (decoded, lossNotices) = decodeTextLenient encoding dizBytes
  emitAdvisories (decodeLossAdvisories label FieldFileIdDiz lossNotices)
  pure (SetFileIdDiz decoded)
resolveCreateFileIdDiz _ (FileIdDizFromText typed) =
  pure (SetFileIdDizFromText (EncodedText EncodingUtf8 typed))

-- | @--metadata-encoding@ decodes bytes, so only the @--diz FILE@ lane consults it; typed text arrives already decoded, and is tagged UTF-8.
resolveConvertMetadata :: FormatLabel -> EncodingName -> ConvertMetadataInputs -> IO RequestedPatchMetadata
resolveConvertMetadata label metadataEncoding inputs = do
  embeddedBlob <- case convertEmbeddedBlobIntent inputs of
    SetBlobFromFile path       -> SetEmbeddedBlob . EmbeddedBlobContents <$> readInputFile path
    SetBlobFromTypedText typed -> pure (SetEmbeddedTypedText typed)
    DropBlob                   -> pure DropEmbeddedBlob
    CarryBlob                  -> pure InheritEmbeddedBlob
  fileIdDiz <- case convertDizIntent inputs of
    SetDizFromFile path       -> do
      dizBytes <- readInputFile path
      let (decoded, lossNotices) = decodeTextLenient metadataEncoding dizBytes
      emitAdvisories (decodeLossAdvisories label FieldFileIdDiz lossNotices)
      pure (SetFileIdDiz decoded)
    SetDizFromTypedText typed -> pure (SetFileIdDizFromText (EncodedText EncodingUtf8 typed))
    DropDiz                   -> pure DropFileIdDiz
    CarryDiz                  -> pure InheritFileIdDiz
  pure (convertParsedMetadata inputs)
    { requestedEmbeddedBlob = embeddedBlob
    , requestedFileIdDiz    = fileIdDiz
    }

----------------------------------------------------------------------------
-- Info & Explain
----------------------------------------------------------------------------

doInfo :: InfoCommand -> IO ()
doInfo parsedCommand = do
  parsed <- readAndParsePatch (infoFileReading parsedCommand) (infoDialects parsedCommand) (infoMetadataEncoding parsedCommand) (infoPatch parsedCommand)
  orBail (rejectIncompatibleDialects
            (acceptedDialects (patchFormat parsed))
            (patchFormat parsed)
            (infoDialects parsedCommand))
  mapM_ TextIO.putStrLn (renderPatchInfo SizeOnly (patchInfo parsed))
  emitAdvisories (patchAdvisories parsed)
  -- Attempt each requested extraction, writing whatever the patch can satisfy;
  -- an extraction that finds nothing is a refused request, reported only after any satisfiable one has been written.
  metadataMiss <- case infoExtractMetadata parsedCommand of
    Nothing -> pure Nothing
    Just outPath -> case patchMetadata parsed of
      Nothing -> pure (Just (NothingToExtract outPath EmbeddedMetadataSubject))
      Just metadataBytes -> do
        refuseOverwrite (infoOverwritePolicy parsedCommand) outPath
        writeOutputFile outPath metadataBytes
        TextIO.putStrLn ("wrote metadata to " <> pathText outPath)
        pure Nothing
  dizMiss <- case infoExtractDiz parsedCommand of
    Nothing -> pure Nothing
    Just outPath -> case patchFileIdDiz parsed of
      Nothing -> pure (Just (NothingToExtract outPath FileIdDizSubject))
      Just dizBytes -> do
        refuseOverwrite (infoOverwritePolicy parsedCommand) outPath
        writeOutputFile outPath dizBytes
        TextIO.putStrLn ("wrote FILE_ID.DIZ to " <> pathText outPath)
        pure Nothing
  mapM_ bailError metadataMiss
  mapM_ bailError dizMiss

doExplain :: ExplainCommand -> IO ()
doExplain parsedCommand = do
  parsed <- readAndParsePatch (explainFileReading parsedCommand) (explainDialects parsedCommand) (explainMetadataEncoding parsedCommand) (explainPatch parsedCommand)
  orBail (rejectIncompatibleDialects
            (acceptedDialects (patchFormat parsed))
            (patchFormat parsed)
            (explainDialects parsedCommand))
  -- The analysis reads "before" bytes at record offsets, and those offsets name positions in the normalized form,
  -- so the explain view normalizes the way apply does. There is no output here, so nothing restores.
  normalizedView <- case explainSource parsedCommand of
    Nothing   -> pure Nothing
    Just path -> do
      handedBytes <- readMaybeUnwrap (explainFileReading parsedCommand) path
      pure (Just (normalizeApplySource (patchSourceNormalization parsed) (InputFileContents handedBytes)))
  let maybeSource = unInputFileContents . normalizedSourceBytes <$> normalizedView
      renderFunction = case explainVerbosity parsedCommand of
        Summary     -> renderAnalysisSummary
        FullRecords -> renderAnalysisFull
  TextIO.putStr (renderFunction (patchInfo parsed) (patchAnalysis parsed) maybeSource)
  emitAdvisories (maybe [] normalizedSourceAdvisories normalizedView)
  emitAdvisories (patchAdvisories parsed)

----------------------------------------------------------------------------
-- Apply
----------------------------------------------------------------------------

doApply :: ApplyCommand -> IO ()
doApply parsedCommand = do
  parsed <- readAndParsePatch (applyFileReading parsedCommand) (applyDialects parsedCommand) EncodingUtf8 (applyPatch parsedCommand)
  orBail (rejectIncompatibleDialects
            (acceptedDialects (patchFormat parsed))
            (patchFormat parsed)
            (applyDialects parsedCommand))
  emitAdvisories (patchAdvisories parsed)
  emitVerboseAnalysis (applyVerbosity parsedCommand) parsed

  let verificationPolicy = applyVerificationPolicy parsedCommand

      applyAndWriteTo outputPath = do
        handedBytes <- readMaybeUnwrap (applyFileReading parsedCommand) (applySource parsedCommand)
        prepared <- orBail (prepareApplySource verificationPolicy parsed (applyHeaderDirective parsedCommand) handedBytes)
        emitAdvisories (preparedAdvisories prepared)
        runOutcome <- runPreparedApply verificationPolicy (applyHeaderDirective parsedCommand) parsed prepared
        emitAdvisories (outcomeAdvisories runOutcome)
        patched <- orBail (outcomeValue runOutcome)
        writeFileAtomicallyOver outputPath (unOutputFileContents (patchedRomBytes patched))
        TextIO.putStrLn (renderActionLine "applied" (patchInfo parsed) outputPath)
        when (patchedRomVerdictStanding patched == VerdictsDescribeTheFiles) $
          mapM_ TextIO.putStrLn
            (renderVerificationReport (patchedRomInputVerdict patched) (patchedRomOutputVerdict patched))

  case applyOutput parsedCommand of
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
  parsed <- readAndParsePatch (undoFileReading parsedCommand) (undoDialects parsedCommand) EncodingUtf8 (undoPatch parsedCommand)
  orBail (rejectIncompatibleDialects
            (acceptedDialects (patchFormat parsed))
            (patchFormat parsed)
            (undoDialects parsedCommand))
  emitAdvisories (patchAdvisories parsed)
  emitVerboseAnalysis (undoVerbosity parsedCommand) parsed
  let verification       = patchVerification parsed
      verificationPolicy = undoVerificationPolicy parsedCommand

      undoAndWriteTo undo outputPath = do
        modified <- readMaybeUnwrap (undoFileReading parsedCommand) (undoSource parsedCommand)
        let patchedWeighing = weighUndoInput parsed modified
        settleVerification (judgeWeighing verificationPolicy patchedWeighing)
        outcome <- orBail (runUndo undo (OutputFileContents modified))
        emitAdvisories (outcomeAdvisories outcome)
        let revertedSource = outcomeValue outcome
            revertedWeighing = flipSpokenSides (weighSource verification revertedSource)
        settleVerification (judgeWeighing verificationPolicy revertedWeighing)
        let InputFileContents result = revertedSource
        writeFileAtomicallyOver outputPath result
        TextIO.putStrLn (renderActionLine "reverted" (patchInfo parsed) outputPath)
        mapM_ TextIO.putStrLn (renderVerificationReport
          (InputSideVerdict (verdictOnWeighing patchedWeighing))
          (OutputSideVerdict (verdictOnWeighing revertedWeighing)))

      undoUsing undo = case undoOutput parsedCommand of
        UndoToExplicitFile outputPath overwritePolicy -> do
          refuseOverwrite overwritePolicy outputPath
          undoAndWriteTo undo outputPath
        UndoToDerivedFile overwritePolicy -> do
          let outputPath = deriveUndoOutput (undoSource parsedCommand)
          refuseOverwrite overwritePolicy outputPath
          undoAndWriteTo undo outputPath

  case patchUndo parsed of
    UndoBySelfInversion undo -> undoUsing undo
    UndoFromCarriedData undo -> undoUsing undo
    UndoAbsentFromPatch      -> bailError (PatchCarriesNoUndoData (patchFormat parsed))
    UndoUnsupportedByFormat  -> bailError (NoUndoForFormat (patchFormat parsed))

----------------------------------------------------------------------------
-- Create
----------------------------------------------------------------------------

doCreate :: CreateCommand -> IO ()
doCreate parsedCommand = do
  orBail (rejectIncompatibleMetadataRequests (createFormat parsedCommand) (createMetadataRequests (createMetadata parsedCommand)))
  createMeta    <- resolveCreateMetadata (createFormatLabel (createFormat parsedCommand)) (createMetadata parsedCommand)
  orBail (rejectUnencodableSecondaryCompressor (createFormat parsedCommand) createMeta)
  orBail (rejectIncompatibleConstraints (createFormat parsedCommand) (createConstraints parsedCommand))
  resolvedXDelta1Names <- orBail (resolveCreateXDelta1Names parsedCommand createMeta)
  refuseOverwrite (createOverwritePolicy parsedCommand) (createOutput parsedCommand)
  originalBytes <- readMaybeUnwrap (createFileReading parsedCommand) (createOriginal parsedCommand)
  modifiedBytes <- readMaybeUnwrap (createFileReading parsedCommand) (createModified parsedCommand)
  emitAdvisories (createDefaultAdvisories (createFormat parsedCommand) createMeta (InputFileContents originalBytes))
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
  writeOutputFile (createOutput parsedCommand) (unPatchFileContents (resultBytes result))
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
  | SourceRequiredToConvert SourceRequiredCause
    -- ^ No source supplied, and the parsed patch carries no 'PatchContents'; the cause says which way.

-- | Decide which convert path runs from the parsed patch and the CLI command.
-- The @--with INPUT@ flag commits to apply-and-recreate outright; without it the parsed 'PatchKind' decides.
chooseConvertDispatch :: ConvertCommand -> SomePatch -> ConvertDispatch
chooseConvertDispatch parsedCommand parsed =
  case convertWithSource parsedCommand of
    Just withSource -> ApplyAndRecreate withSource
    Nothing -> case patchKind parsed of
      Direct (Just contents) -> SourceLessConvert contents
      Direct Nothing         -> SourceRequiredToConvert SourcePatchNotReencodable
      Differential           -> SourceRequiredToConvert SourcePatchIsDifferential

doConvert :: ConvertCommand -> IO ()
doConvert parsedCommand = do
  orBail (rejectIncompatibleMetadataRequests (convertTo parsedCommand) (convertMetadataRequests (convertMetadata parsedCommand)))
  cliMeta <- resolveConvertMetadata (createFormatLabel (convertTo parsedCommand)) (convertMetadataEncoding parsedCommand) (convertMetadata parsedCommand)
  orBail (rejectUnencodableSecondaryCompressor (convertTo parsedCommand) cliMeta)
  orBail (rejectIncompatibleConstraints (convertTo parsedCommand) (convertConstraints parsedCommand))
  parsed <- readAndParsePatch (convertFileReading parsedCommand) (convertDialects parsedCommand) (convertMetadataEncoding parsedCommand) (convertPatch parsedCommand)
  orBail (rejectIncompatibleDialects
            (acceptedDialects (patchFormat parsed))
            (patchFormat parsed)
            (convertDialects parsedCommand))
  orBail (rejectCrossPlatformRomTypeRetag cliMeta (patchExtractedMeta parsed))
  orBail (clearToRun parsed)
  emitAdvisories (patchAdvisories parsed)
  let (outputFile, overwritePolicy) = case convertOutput parsedCommand of
        ConvertToExplicitFile explicit policy -> (explicit, policy)
        ConvertToDerivedFile policy           ->
          ( replaceExtension (convertPatch parsedCommand)
                             (formatExtension (convertTo parsedCommand))
          , policy )
      mergedMeta = mergeRequestedMetadata cliMeta (patchExtractedMeta parsed)
  refuseOverwrite overwritePolicy outputFile
  resolvedXDelta1Names <- orBail (resolveConvertXDelta1Names parsedCommand parsed mergedMeta)
  case chooseConvertDispatch parsedCommand parsed of
    ApplyAndRecreate withSource -> do
      handedSourceBytes <- readMaybeUnwrap (convertFileReading parsedCommand) (convertWithSourcePath withSource)
      -- Apply's own preparation and run, with the write swapped for a re-diff of the framed input against the restored output.
      prepared <- orBail (prepareApplySource (convertWithVerification withSource) parsed (convertWithDirective withSource) handedSourceBytes)
      emitAdvisories (preparedAdvisories prepared)
      runOutcome <- runPreparedApply (convertWithVerification withSource) (convertWithDirective withSource) parsed prepared
      emitAdvisories (outcomeAdvisories runOutcome)
      patched <- orBail (outcomeValue runOutcome)
      let framedInput = InputFileContents (preparedFramedInput prepared)
      createResult <- orBail (createPatch (convertTo parsedCommand) resolvedXDelta1Names framedInput (patchedRomBytes patched)
                                          mergedMeta (patchContentsOf parsed) (convertConstraints parsedCommand) noDialectsRequested)
      emitAdvisories (patchSourceAdvisories parsed
                        ++ createDefaultAdvisories (convertTo parsedCommand) mergedMeta framedInput
                        ++ resultAdvisories createResult)
      writeOutputFile outputFile (unPatchFileContents (resultBytes createResult))
      TextIO.putStrLn ("converted to " <> formatName (convertTo parsedCommand) <> ": " <> pathText outputFile)
      when (patchedRomVerdictStanding patched == VerdictsDescribeTheFiles) $
        mapM_ TextIO.putStrLn
          (renderVerificationReport (patchedRomInputVerdict patched) (patchedRomOutputVerdict patched))
    SourceLessConvert contents -> do
      convertResult <- orBail (convertDirect contents (convertTo parsedCommand) mergedMeta (convertConstraints parsedCommand) noDialectsRequested)
      emitAdvisories (patchSourceAdvisories parsed ++ resultAdvisories convertResult)
      writeOutputFile outputFile (unPatchFileContents (resultBytes convertResult))
      TextIO.putStrLn ("converted to " <> formatName (convertTo parsedCommand) <> ": " <> pathText outputFile)
    SourceRequiredToConvert cause ->
      bailError (ConvertRequiresSource (patchFormat parsed) cause)

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

----------------------------------------------------------------------------
-- Helpers
----------------------------------------------------------------------------

-- | The marker goes before the extension, except where there is none to sit before —
-- an extensionless name, or a dotfile whose leading dot names no extension — and there it goes at the end.
insertBeforeExtension :: String -> FilePath -> FilePath
insertBeforeExtension marker path
  | null (takeBaseName path) = path ++ marker
  | otherwise                = dropExtension path ++ marker ++ takeExtension path

-- | "game.gbc" + "translation.ips" → "game [translation].gbc"
deriveOutput :: FilePath -> FilePath -> FilePath
deriveOutput patchPath sourcePath =
  insertBeforeExtension (" [" ++ takeBaseName patchPath ++ "]") sourcePath

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
deriveUndoOutput modifiedPath = insertBeforeExtension " [reverted]" modifiedPath

-- | Abort if the destination already exists and the user did not pass @--force@.
refuseOverwrite :: OverwritePolicy -> FilePath -> IO ()
refuseOverwrite ForceOverwrite  _          = pure ()
refuseOverwrite RefuseOverwrite outputPath = do
  exists <- doesFileExist outputPath
  when exists (bailError (OutputFileExists outputPath))

----------------------------------------------------------------------------
-- Verification
----------------------------------------------------------------------------

-- | Emit a verification pass's advisories, then bail on its verdict — advisories first, since 'orBail' exits.
settleVerification :: Outcome (Either SlapError ()) -> IO ()
settleVerification verificationOutcome = do
  emitAdvisories (outcomeAdvisories verificationOutcome)
  orBail (outcomeValue verificationOutcome)

-- | Render the full per-record analysis to stderr, gated on 'Verbose'.
emitVerboseAnalysis :: Verbosity -> SomePatch -> IO ()
emitVerboseAnalysis Verbose parsed =
  TextIO.hPutStr stderr (renderAnalysisFull (patchInfo parsed) (patchAnalysis parsed) Nothing)
emitVerboseAnalysis Quiet _ = pure ()

-- | Emits no advisories itself, leaving warning-ordering to each caller:
-- 'doInfo' and 'doExplain' defer until after their stdout renders,
-- while 'doApply', 'doUndo', and 'doConvert' emit immediately (each via 'emitAdvisories').
readAndParsePatch :: FileReadingOptions -> RequestedDialects -> EncodingName -> FilePath -> IO SomePatch
readAndParsePatch fileReading dialects metadataEncoding path = do
  patchBytes <- readMaybeUnwrap fileReading path
  orBail (parseSome dialects metadataEncoding (PatchFileContents patchBytes))

----------------------------------------------------------------------------
-- Stdout and stderr encoding setup
----------------------------------------------------------------------------

-- | Bind 'stdout' and 'stderr' to UTF-8, transliterating on failure so a codepoint the encoder can't represent substitutes a placeholder
-- rather than crashing with an @hPutChar@ invalid-argument error.
-- UTF-8 can only fail on a lone surrogate, and one is unlikely to reach output: 'main' pins the filesystem encoding to UTF-8,
-- so GHC's argv and filepath decoders reject malformed bytes rather than surrogate-escaping them, and slap's lenient decode substitutes U+FFFD.
-- Transliteration is cheap cover for a stray one. Called once at startup, before any I/O.
setStdoutAndStderrToLenientUtf8 :: IO ()
setStdoutAndStderrToLenientUtf8 = do
  hSetEncoding stdout lenientUtf8
  hSetEncoding stderr lenientUtf8
  where
    lenientUtf8 = mkUTF8 TransliterateCodingFailure
