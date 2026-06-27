{-# LANGUAGE OverloadedStrings #-}

-- | The native frontend's archive-unwrap layer: open a single-entry container and hand back the file inside.
-- ZIP is read in-process via "Archive.Zip"; RAR and 7z shell out to @unrar@ and @7z@.
module Archive
  ( unwrapArchive
  ) where

import Data.Bifunctor (first)
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.Char (toLower)
import Data.List (stripPrefix)
import Data.Maybe (mapMaybe)
import qualified Data.Text as Text
import Slap.Archive.Types
  ( ArchiveFormat(..)
  , ToolName(..), ToolDiagnostic(..), EntryName(..), SeenEntryCount(..)
  , UnwrapError(..) )
import Archive.Zip (zipEntryNames, zipExtractEntry)
import System.Directory (findExecutable, createDirectoryIfMissing,
                         removeDirectoryRecursive, removeFile, doesFileExist,
                         getTemporaryDirectory)
import System.Exit (ExitCode(..))
import System.FilePath (takeExtension, (</>), addTrailingPathSeparator)
import System.IO (hClose, openBinaryTempFile)
import System.Process (readProcessWithExitCode)

-- | Unwrap a single-entry archive → (content bytes, entry name).
unwrapArchive :: ArchiveFormat -> FilePath -> IO (Either UnwrapError (ByteString, EntryName))
unwrapArchive ArchiveZIP path = unwrapZip path
unwrapArchive ArchiveRAR path = unwrapViaExternalTool ExternalRAR path
unwrapArchive Archive7z  path = unwrapViaExternalTool External7z  path

----------------------------------------------------------------------------
-- Candidate selection (shared by the in-house and shell-out paths)
----------------------------------------------------------------------------

-- | Filter chaff (readmes, images, docs) and pick the single patch worth
-- extracting, or say why we can't.
selectCandidate :: [EntryName] -> Either UnwrapError EntryName
selectCandidate names = case filter isCandidate names of
  []                 -> Left (ArchiveHasNoCandidate (SeenEntryCount (length names)))
  [name]             -> Right name
  multipleCandidates -> Left (ArchiveHasManyCandidates multipleCandidates)

isCandidate :: EntryName -> Bool
isCandidate (EntryName name)
  | "/" `Text.isSuffixOf` name       = False
  | extension `elem` chaffExtensions = False
  | otherwise                        = True
  where
    extension = map toLower (takeExtension (Text.unpack name))

chaffExtensions :: [String]
chaffExtensions =
  [ ".txt", ".md", ".nfo", ".diz", ".rtf", ".doc", ".pdf"
  , ".html", ".htm", ".jpg", ".jpeg", ".png", ".gif", ".bmp"
  , ".url", ".lnk"
  ]

----------------------------------------------------------------------------
-- In-house ZIP
----------------------------------------------------------------------------

unwrapZip :: FilePath -> IO (Either UnwrapError (ByteString, EntryName))
unwrapZip path = do
  archiveBytes <- ByteString.readFile path
  pure $ do
    names      <- first ArchiveUnreadable (zipEntryNames archiveBytes)
    name       <- selectCandidate (map EntryName names)
    entryBytes <- first ArchiveUnreadable (zipExtractEntry archiveBytes (unEntryName name))
    pure (entryBytes, name)

----------------------------------------------------------------------------
-- Shell-out path (RAR, 7z)
----------------------------------------------------------------------------

-- | The formats unwrapped by shelling out to an external tool.
data ExternalFormat = ExternalRAR | External7z

unwrapViaExternalTool :: ExternalFormat -> FilePath -> IO (Either UnwrapError (ByteString, EntryName))
unwrapViaExternalTool format path = do
  entries <- listEntries format path
  case entries >>= selectCandidate of
    Left unwrapError -> pure (Left unwrapError)
    Right name       -> extractEntry format path name

-- | Capture an external tool's stderr as a 'ToolDiagnostic'.
toolDiagnostic :: String -> ToolDiagnostic
toolDiagnostic = ToolDiagnostic . Text.pack

-- | Wrap a raw entry path from a tool listing as an 'EntryName'.
toEntryName :: String -> EntryName
toEntryName = EntryName . Text.pack

listEntries :: ExternalFormat -> FilePath -> IO (Either UnwrapError [EntryName])
listEntries ExternalRAR path = do
  maybeUnrar <- findExecutable "unrar"
  case maybeUnrar of
    Just _ -> do
      (exitCode, stdout, stderr) <- readProcessWithExitCode "unrar" ["lb", path] ""
      pure $ case exitCode of
        ExitSuccess -> Right (map toEntryName (filter (not . null) (lines stdout)))
        _           -> Left (ArchiveToolFailed (ToolName "unrar") (toolDiagnostic stderr))
    Nothing -> do
      maybe7z <- findExecutable "7z"
      case maybe7z of
        Nothing -> pure (Left NoToolForArchive)
        Just _  -> list7z path

listEntries External7z path = do
  maybe7z <- findExecutable "7z"
  case maybe7z of
    Nothing -> pure (Left NoToolForArchive)
    Just _  -> list7z path

-- | List entries using 7z's machine-readable output.
list7z :: FilePath -> IO (Either UnwrapError [EntryName])
list7z path = do
  (exitCode, stdout, stderr) <- readProcessWithExitCode "7z" ["l", "-ba", "-slt", path] ""
  pure $ case exitCode of
    ExitSuccess -> Right (map toEntryName (parse7zList stdout))
    _           -> Left (ArchiveToolFailed (ToolName "7z") (toolDiagnostic stderr))

-- | Pull the entry paths out of 7z's @-slt@ listing, whose lines read
-- @Path = name@.
parse7zList :: String -> [String]
parse7zList = mapMaybe (stripPrefix "Path = ") . lines

extractEntry :: ExternalFormat -> FilePath -> EntryName -> IO (Either UnwrapError (ByteString, EntryName))
extractEntry format archivePath entryName = do
  systemTemporaryDirectory <- getTemporaryDirectory
  (temporaryFile, handle) <- openBinaryTempFile systemTemporaryDirectory "slap-archive"
  hClose handle
  let temporaryDirectory = temporaryFile ++ ".d"
      entryPath = Text.unpack (unEntryName entryName)
  createDirectoryIfMissing True temporaryDirectory
  result <- doExtract format archivePath entryPath temporaryDirectory
  case result of
    Left unwrapError -> do
      cleanup temporaryFile temporaryDirectory
      pure (Left unwrapError)
    Right () -> do
      extracted <- findExtracted temporaryDirectory entryPath
      case extracted of
        Nothing -> do
          cleanup temporaryFile temporaryDirectory
          pure (Left (ExtractedEntryMissing entryName))
        Just extractedPath -> do
          extractedBytes <- ByteString.readFile extractedPath
          cleanup temporaryFile temporaryDirectory
          pure (Right (extractedBytes, entryName))
  where
    cleanup temporaryFile temporaryDirectory = do
      removeDirectoryRecursive temporaryDirectory
      removeFile temporaryFile

findExtracted :: FilePath -> String -> IO (Maybe FilePath)
findExtracted temporaryDirectory entryName = do
  -- Tools differ: some flatten the entry to its basename, others keep its internal path; probe both.
  let basename = takeFileNamePortable entryName
      flatPath = temporaryDirectory </> basename
      fullPath = temporaryDirectory </> entryName
  flatExists <- doesFileExist flatPath
  if flatExists
    then pure (Just flatPath)
    else do
      fullExists <- doesFileExist fullPath
      pure (if fullExists then Just fullPath else Nothing)

-- | Extract basename from a path (handles both / and \ separators).
takeFileNamePortable :: String -> String
takeFileNamePortable = reverse . takeWhile (\char -> char /= '/' && char /= '\\') . reverse

doExtract :: ExternalFormat -> FilePath -> String -> FilePath -> IO (Either UnwrapError ())
doExtract ExternalRAR archivePath entryName temporaryDirectory = do
  maybeUnrar <- findExecutable "unrar"
  case maybeUnrar of
    Just _ -> do
      (exitCode, _, stderr) <- readProcessWithExitCode "unrar"
        ["e", "-o+", archivePath, entryName, addTrailingPathSeparator temporaryDirectory] ""
      pure $ case exitCode of
        ExitSuccess -> Right ()
        _           -> Left (ArchiveToolFailed (ToolName "unrar") (toolDiagnostic stderr))
    Nothing -> extractWith7z archivePath entryName temporaryDirectory

doExtract External7z archivePath entryName temporaryDirectory =
  extractWith7z archivePath entryName temporaryDirectory

-- | Extract one entry with 7z — for 7z archives, and as the RAR fallback
-- when unrar isn't present. The extraction-side counterpart of 'list7z'.
extractWith7z :: FilePath -> String -> FilePath -> IO (Either UnwrapError ())
extractWith7z archivePath entryName temporaryDirectory = do
  (exitCode, _, stderr) <- readProcessWithExitCode "7z"
    ["e", "-o" ++ temporaryDirectory, "-y", archivePath, entryName] ""
  pure $ case exitCode of
    ExitSuccess -> Right ()
    _           -> Left (ArchiveToolFailed (ToolName "7z") (toolDiagnostic stderr))
