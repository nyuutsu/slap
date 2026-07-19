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
                     createDefaultAdvisories, convertDirect,
                     mergeRequestedMetadata, rejectIncompatibleMetadataRequests,
                     EmbeddedBlobContents(..), EmbeddedBlobRequest(..),
                     formatExtension, formatName)
import Slap.XDelta1.Types (ResolvedXDelta1FileNames,
                           resolveXDelta1FileNames,
                           requireXDelta1FileNames,
                           XDelta1FromName(..), XDelta1ToName(..))
import Slap.Create (createPatch)
import Slap.Text (EncodingName(EncodingUtf8), EncodedText(..), decodeTextLenient)
import qualified Data.Text.IO as TextIO
import Slap.Archive.Types (detectArchive, EntryName(unEntryName))
import Slap.Status (SlapError(..), SourceRequiredCause(..), ExtractionSubject(..),
                   CreateResult(..), Outcome(..),
                   emitAdvisories, bailError, orBail)
import Slap.Normalize (NormalizedSource(..), normalizeApplySource)
import Slap.Display.Glyph (spacePaddedRightwardsArrow)
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
import Control.Monad (when)
import System.Directory (doesFileExist, renameFile, removeFile)
import System.FilePath (dropExtension, replaceExtension, takeBaseName, takeExtension, takeDirectory, takeFileName)
import System.IO (IOMode(ReadMode), hFileSize, hSetEncoding, stderr, stdout, withFile, openBinaryTempFile, hClose)
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
main = do
  -- Source-located backtraces on an uncaught exception, when built with the info-table map (make dev); inert otherwise.
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

-- | Write an output file: the write-side mirror of 'readInputFile'.
writeOutputFile :: FilePath -> ByteString -> IO ()
writeOutputFile path outputBytes = do
  result <- try (ByteString.writeFile path outputBytes)
  case result of
    Right ()   -> pure ()
    Left ioErr -> bailError (UnwritableOutputFile path (ioeGetErrorString ioErr))

-- | Replace @path@'s contents atomically: write a sibling temporary, then 'renameFile' it over @path@.
-- The original is never truncated mid-write — an interrupted or failed write leaves it whole, not half-written —
-- which is what makes a @--force@ overwrite survivable on a file the user cannot re-fetch.
writeFileAtomicallyOver :: FilePath -> ByteString -> IO ()
writeFileAtomicallyOver path outputBytes = do
  result <- try $ bracketOnError
    (openBinaryTempFile (takeDirectory path) (takeFileName path <> ".tmp"))
    (\(tempPath, tempHandle) -> hClose tempHandle >> removeFileIfExists tempPath)
    (\(tempPath, tempHandle) -> do
       ByteString.hPut tempHandle outputBytes
       hClose tempHandle
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

-- | Resolve @slap create@'s metadata inputs: the 'EmbeddedBlobSource' and 'FileIdDizSource' become the blob and DIZ requests.
resolveCreateMetadata :: CreateMetadataInputs -> IO RequestedPatchMetadata
resolveCreateMetadata inputs = do
  embeddedBlob <- case createEmbeddedBlobSource inputs of
    NoEmbeddedBlob                  -> pure InheritEmbeddedBlob
    EmbeddedBlobFromFile path       -> SetEmbeddedBlob . EmbeddedBlobContents <$> readInputFile path
    EmbeddedBlobFromTypedText typed -> pure (SetEmbeddedTypedText typed)
  fileIdDiz    <- resolveCreateFileIdDiz (createDizSource inputs)
  pure (createParsedMetadata inputs)
    { requestedEmbeddedBlob = embeddedBlob
    , requestedFileIdDiz    = fileIdDiz
    }

-- | The @--diz@ file and @--diz-text@ string both become UTF-8: create writes every text field that way,
-- and has no @--metadata-encoding@ knob to say otherwise.
resolveCreateFileIdDiz :: FileIdDizSource -> IO FileIdDizRequest
resolveCreateFileIdDiz NoFileIdDiz              = pure InheritFileIdDiz
resolveCreateFileIdDiz (FileIdDizFromFile path) =
  SetFileIdDiz . fst . decodeTextLenient EncodingUtf8 <$> readInputFile path
resolveCreateFileIdDiz (FileIdDizFromText typed) =
  pure (SetFileIdDizFromText (EncodedText EncodingUtf8 typed))

-- | @--metadata-encoding@ decodes bytes, so only the @--diz FILE@ lane consults it; typed text arrives already decoded, and is tagged UTF-8.
resolveConvertMetadata :: EncodingName -> ConvertMetadataInputs -> IO RequestedPatchMetadata
resolveConvertMetadata metadataEncoding inputs = do
  embeddedBlob <- case convertEmbeddedBlobIntent inputs of
    SetBlobFromFile path       -> SetEmbeddedBlob . EmbeddedBlobContents <$> readInputFile path
    SetBlobFromTypedText typed -> pure (SetEmbeddedTypedText typed)
    DropBlob                   -> pure DropEmbeddedBlob
    CarryBlob                  -> pure InheritEmbeddedBlob
  fileIdDiz <- case convertDizIntent inputs of
    SetDizFromFile path       -> SetFileIdDiz . fst . decodeTextLenient metadataEncoding <$> readInputFile path
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
  parsed <- readAndParsePatch (infoDialects parsedCommand) (infoMetadataEncoding parsedCommand) (infoPatch parsedCommand)
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
  parsed <- readAndParsePatch (explainDialects parsedCommand) (explainMetadataEncoding parsedCommand) (explainPatch parsedCommand)
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
  parsed <- readAndParsePatch (applyDialects parsedCommand) EncodingUtf8 (applyPatch parsedCommand)
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
  parsed <- readAndParsePatch (undoDialects parsedCommand) EncodingUtf8 (undoPatch parsedCommand)
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
  createMeta    <- resolveCreateMetadata (createMetadata parsedCommand)
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
  cliMeta <- resolveConvertMetadata (convertMetadataEncoding parsedCommand) (convertMetadata parsedCommand)
  orBail (rejectUnencodableSecondaryCompressor (convertTo parsedCommand) cliMeta)
  orBail (rejectIncompatibleConstraints (convertTo parsedCommand) (convertConstraints parsedCommand))
  parsed <- readAndParsePatch (convertDialects parsedCommand) (convertMetadataEncoding parsedCommand) (convertPatch parsedCommand)
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
readAndParsePatch :: RequestedDialects -> EncodingName -> FilePath -> IO SomePatch
readAndParsePatch dialects metadataEncoding path = do
  patchBytes <- readUnwrap path
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
