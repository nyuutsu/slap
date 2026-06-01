{-# LANGUAGE OverloadedStrings #-}

-- | Unwrapping single-entry archives by shelling out to the external
-- tool that owns each container format. The pure vocabulary — the
-- formats, detection, the per-format tool list, and the 'UnwrapError'
-- failure space — lives in "Slap.Archive.Types" and is re-exported here
-- for callers who just want "detect and unwrap".
module Slap.Archive
  ( ArchiveFormat(..)
  , detectArchive
  , unwrapArchive
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.Char (toLower)
import Data.List (isPrefixOf, isSuffixOf)
import qualified Data.Text as Text
import Slap.Archive.Types
  ( ArchiveFormat(..), detectArchive, toolsFor
  , ToolName(..), ToolDiagnostic(..), EntryName(..), SeenEntryCount(..)
  , UnwrapError(..) )
import System.Directory (findExecutable, createDirectoryIfMissing,
                         removeDirectoryRecursive, removeFile, doesFileExist)
import System.Exit (ExitCode(..))
import System.FilePath (takeExtension)
import System.IO (hClose, openBinaryTempFile)
import System.Process (readProcessWithExitCode)

-- | Unwrap a single-entry archive → (content bytes, entry name).
-- Filters out chaff (readmes, images, docs), extracts the sole candidate.
unwrapArchive :: ArchiveFormat -> FilePath -> IO (Either UnwrapError (ByteString, String))
unwrapArchive format path = do
  entries <- listEntries format path
  case entries of
    Left unwrapError -> pure (Left unwrapError)
    Right names -> do
      let candidates = filter isCandidate names
      case candidates of
        []     -> pure (Left (ArchiveHasNoCandidate (SeenEntryCount (length names))))
        [name] -> extractEntry format path name
        _      -> pure (Left (ArchiveHasManyCandidates (map (EntryName . Text.pack) candidates)))

isCandidate :: String -> Bool
isCandidate name
  | "/" `isSuffixOf` name = False
  | extension `elem` chaffExtensions = False
  | otherwise            = True
  where
    extension = map toLower (takeExtension name)

chaffExtensions :: [String]
chaffExtensions =
  [ ".txt", ".md", ".nfo", ".diz", ".rtf", ".doc", ".pdf"
  , ".html", ".htm", ".jpg", ".jpeg", ".png", ".gif", ".bmp"
  , ".url", ".lnk"
  ]

----------------------------------------------------------------------------
-- Listing
----------------------------------------------------------------------------

-- | Capture an external tool's stderr as a 'ToolDiagnostic'.
toolDiagnostic :: String -> ToolDiagnostic
toolDiagnostic = ToolDiagnostic . Text.pack

listEntries :: ArchiveFormat -> FilePath -> IO (Either UnwrapError [String])
listEntries ArchiveZIP path = do
  maybeTool <- findExecutable "unzip"
  case maybeTool of
    Nothing -> pure (Left (NoToolForArchive (toolsFor ArchiveZIP)))
    Just _ -> do
      (exitCode, stdout, stderr) <- readProcessWithExitCode "unzip" ["-Z1", path] ""
      pure $ case exitCode of
        ExitSuccess -> Right (filter (not . null) (lines stdout))
        _           -> Left (ArchiveToolFailed (ToolName "unzip") (toolDiagnostic stderr))

listEntries ArchiveRAR path = do
  maybeUnrar <- findExecutable "unrar"
  case maybeUnrar of
    Just _ -> do
      (exitCode, stdout, stderr) <- readProcessWithExitCode "unrar" ["lb", path] ""
      pure $ case exitCode of
        ExitSuccess -> Right (filter (not . null) (lines stdout))
        _           -> Left (ArchiveToolFailed (ToolName "unrar") (toolDiagnostic stderr))
    Nothing -> do
      maybe7z <- findExecutable "7z"
      case maybe7z of
        Nothing -> pure (Left (NoToolForArchive (toolsFor ArchiveRAR)))
        Just _  -> list7z path

listEntries Archive7z path = do
  maybe7z <- findExecutable "7z"
  case maybe7z of
    Nothing -> pure (Left (NoToolForArchive (toolsFor Archive7z)))
    Just _  -> list7z path

-- | List entries using 7z's machine-readable output.
list7z :: FilePath -> IO (Either UnwrapError [String])
list7z path = do
  (exitCode, stdout, stderr) <- readProcessWithExitCode "7z" ["l", "-ba", "-slt", path] ""
  pure $ case exitCode of
    ExitSuccess -> Right (parse7zList stdout)
    _           -> Left (ArchiveToolFailed (ToolName "7z") (toolDiagnostic stderr))

-- | Parse 7z -slt output, extracting Path= lines.
parse7zList :: String -> [String]
parse7zList = map (drop 5) . filter ("Path=" `isPrefixOf`) . lines

----------------------------------------------------------------------------
-- Extraction
----------------------------------------------------------------------------

extractEntry :: ArchiveFormat -> FilePath -> String -> IO (Either UnwrapError (ByteString, String))
extractEntry format archivePath entryName = do
  (temporaryFile, handle) <- openBinaryTempFile "/tmp" "slap-archive"
  hClose handle
  let temporaryDirectory = temporaryFile ++ ".d"
  createDirectoryIfMissing True temporaryDirectory
  result <- doExtract format archivePath entryName temporaryDirectory
  case result of
    Left unwrapError -> do
      cleanup temporaryFile temporaryDirectory
      pure (Left unwrapError)
    Right () -> do
      extracted <- findExtracted temporaryDirectory entryName
      case extracted of
        Nothing -> do
          cleanup temporaryFile temporaryDirectory
          pure (Left (ExtractedEntryMissing (EntryName (Text.pack entryName))))
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
  -- flat extraction puts file directly in temporaryDirectory
  let basename = takeFileNamePortable entryName
      flatPath = temporaryDirectory ++ "/" ++ basename
      fullPath = temporaryDirectory ++ "/" ++ entryName
  flatExists <- doesFileExist flatPath
  if flatExists
    then pure (Just flatPath)
    else do
      fullExists <- doesFileExist fullPath
      pure (if fullExists then Just fullPath else Nothing)

-- | Extract basename from a path (handles both / and \ separators).
takeFileNamePortable :: String -> String
takeFileNamePortable = reverse . takeWhile (\char -> char /= '/' && char /= '\\') . reverse

doExtract :: ArchiveFormat -> FilePath -> String -> FilePath -> IO (Either UnwrapError ())
doExtract ArchiveZIP archivePath entryName temporaryDirectory = do
  (exitCode, _, stderr) <- readProcessWithExitCode "unzip"
    ["-o", "-j", archivePath, entryName, "-d", temporaryDirectory] ""
  pure $ case exitCode of
    ExitSuccess -> Right ()
    _           -> Left (ArchiveToolFailed (ToolName "unzip") (toolDiagnostic stderr))

doExtract ArchiveRAR archivePath entryName temporaryDirectory = do
  maybeUnrar <- findExecutable "unrar"
  case maybeUnrar of
    Just _ -> do
      (exitCode, _, stderr) <- readProcessWithExitCode "unrar"
        ["e", "-o+", archivePath, entryName, temporaryDirectory ++ "/"] ""
      pure $ case exitCode of
        ExitSuccess -> Right ()
        _           -> Left (ArchiveToolFailed (ToolName "unrar") (toolDiagnostic stderr))
    Nothing -> do
      (exitCode, _, stderr) <- readProcessWithExitCode "7z"
        ["e", "-o" ++ temporaryDirectory, "-y", archivePath, entryName] ""
      pure $ case exitCode of
        ExitSuccess -> Right ()
        _           -> Left (ArchiveToolFailed (ToolName "7z") (toolDiagnostic stderr))

doExtract Archive7z archivePath entryName temporaryDirectory = do
  (exitCode, _, stderr) <- readProcessWithExitCode "7z"
    ["e", "-o" ++ temporaryDirectory, "-y", archivePath, entryName] ""
  pure $ case exitCode of
    ExitSuccess -> Right ()
    _           -> Left (ArchiveToolFailed (ToolName "7z") (toolDiagnostic stderr))
