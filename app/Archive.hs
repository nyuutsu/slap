{-# LANGUAGE OverloadedStrings #-}

-- | The native frontend's archive-unwrap layer: open a single-entry container and hand back the file inside.
-- ZIP is read in-process via "Archive.Zip"; 7z shells out to @7z@.
module Archive
  ( unwrapArchive
  ) where

import Data.Bifunctor (first)
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.Char (toLower)
import Data.List (stripPrefix)
import Data.Maybe (mapMaybe, listToMaybe)
import qualified Data.Text as Text
import Control.Exception (try, IOException)
import Slap.Archive.Types
  ( ArchiveFormat(..)
  , ToolName(..), ToolDiagnostic(..), EntryName(..), SeenEntryCount(..)
  , UnreadableReason(..), UnwrapError(..) )
import Archive.Zip (zipEntryNames, zipExtractEntry)
import System.Directory (findExecutable, createDirectoryIfMissing,
                         removeDirectoryRecursive, removeFile, doesFileExist,
                         getTemporaryDirectory)
import System.Exit (ExitCode(..))
import System.FilePath (takeExtension, (</>))
import System.IO (hClose, openBinaryTempFile)
import System.IO.Error (ioeGetErrorString)
import System.Process (readProcessWithExitCode)

-- | ZIP is read from the bytes slap already holds, so a single-entry archive fed through a pipe still unwraps and a regular file isn't read twice.
-- 7z shells out and needs a seekable file, so it takes the path; an archive fed through a pipe fails there with the tool's own diagnostic.
unwrapArchive :: ArchiveFormat -> ByteString -> FilePath -> IO (Either UnwrapError (ByteString, EntryName))
unwrapArchive ArchiveZIP fileBytes _    = pure (unwrapZip fileBytes)
unwrapArchive Archive7z  _        path  = unwrapVia7z path

----------------------------------------------------------------------------
-- Candidate selection (shared by the in-house and shell-out paths)
----------------------------------------------------------------------------

-- | Filter chaff (readmes, images, docs) and pick the single patch worth
-- extracting, or say why we can't.
selectCandidate :: [EntryName] -> Either UnwrapError (Int, EntryName)
selectCandidate names = case filter (isCandidate . snd) (zip [0 ..] names) of
  []                 -> Left (ArchiveHasNoCandidate (SeenEntryCount (length names)))
  [indexedName]      -> Right indexedName
  multipleCandidates -> Left (ArchiveHasManyCandidates (map snd multipleCandidates))

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

unwrapZip :: ByteString -> Either UnwrapError (ByteString, EntryName)
unwrapZip archiveBytes = do
  names         <- first ArchiveUnreadable (zipEntryNames archiveBytes)
  (index, name) <- selectCandidate (map EntryName names)
  entryBytes    <- first ArchiveUnreadable (zipExtractEntry archiveBytes index)
  pure (entryBytes, name)

----------------------------------------------------------------------------
-- Shell-out path (7z)
----------------------------------------------------------------------------

unwrapVia7z :: FilePath -> IO (Either UnwrapError (ByteString, EntryName))
unwrapVia7z path = do
  entries <- listEntries path
  case entries >>= selectCandidate of
    Left unwrapError     -> pure (Left unwrapError)
    Right (_index, name) -> extractEntry path name

-- | Capture an external tool's stderr.
toolDiagnostic :: String -> ToolDiagnostic
toolDiagnostic = ToolDiagnostic . Text.pack

-- | Wrap a raw entry path from a tool listing.
toEntryName :: String -> EntryName
toEntryName = EntryName . Text.pack

listEntries :: FilePath -> IO (Either UnwrapError [EntryName])
listEntries path = do
  maybe7z <- findExecutable "7z"
  case maybe7z of
    Nothing -> pure (Left NoToolForArchive)
    Just _  -> list7z path

-- | List entries using 7z's machine-readable output.
list7z :: FilePath -> IO (Either UnwrapError [EntryName])
list7z path = do
  (exitCode, stdout, stderr) <- readProcessWithExitCode "7z" ["l", "-ba", "-slt", "--", path] ""
  pure $ case exitCode of
    ExitSuccess -> Right (map toEntryName (parse7zList stdout))
    _           -> Left (ArchiveToolFailed (ToolName "7z") (toolDiagnostic stderr))

-- | The file entries in 7z's @-slt@ listing. A directory carries a @D@ in its DOS attributes,
-- not the trailing slash a ZIP central directory would give it, so only the attribute line tells them apart.
parse7zList :: String -> [String]
parse7zList = mapMaybe fileEntryPath . groupIntoEntries . lines
  where
    fileEntryPath entryLines
      | any marksDirectory entryLines = Nothing
      | otherwise = listToMaybe (mapMaybe (stripPrefix "Path = ") entryLines)
    marksDirectory line = case stripPrefix "Attributes = " line of
      Just attributes -> 'D' `elem` takeWhile (/= ' ') attributes
      Nothing         -> False

groupIntoEntries :: [String] -> [[String]]
groupIntoEntries [] = []
groupIntoEntries listingLines =
  let (entry, rest) = break null listingLines
  in entry : groupIntoEntries (drop 1 rest)

extractEntry :: FilePath -> EntryName -> IO (Either UnwrapError (ByteString, EntryName))
extractEntry archivePath entryName = do
  systemTemporaryDirectory <- getTemporaryDirectory
  (temporaryFile, handle) <- openBinaryTempFile systemTemporaryDirectory "slap-archive"
  hClose handle
  let temporaryDirectory = temporaryFile ++ ".d"
      entryPath = Text.unpack (unEntryName entryName)
  createDirectoryIfMissing True temporaryDirectory
  result <- extractWith7z archivePath entryPath temporaryDirectory
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
          readResult <- try (ByteString.readFile extractedPath) :: IO (Either IOException ByteString)
          cleanup temporaryFile temporaryDirectory
          pure $ case readResult of
            Left ioErr -> Left (ExtractedEntryUnreadable entryName
                                  (UnreadableReason (Text.pack (ioeGetErrorString ioErr))))
            Right extractedBytes -> Right (extractedBytes, entryName)
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

-- | Extract one entry with 7z. The extraction-side counterpart of 'list7z'.
extractWith7z :: FilePath -> String -> FilePath -> IO (Either UnwrapError ())
extractWith7z archivePath entryName temporaryDirectory = do
  (exitCode, _, stderr) <- readProcessWithExitCode "7z"
    ["e", "-o" ++ temporaryDirectory, "-y", "--", archivePath, entryName] ""
  pure $ case exitCode of
    ExitSuccess -> Right ()
    _           -> Left (ArchiveToolFailed (ToolName "7z") (toolDiagnostic stderr))
