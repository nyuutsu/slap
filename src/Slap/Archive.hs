{-# LANGUAGE OverloadedStrings #-}

module Slap.Archive
  ( ArchiveFormat(..)
  , detectArchive
  , unwrapArchive
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.Char (toLower)
import Data.List (isPrefixOf, isSuffixOf)
import System.Directory (findExecutable, createDirectoryIfMissing,
                         removeDirectoryRecursive, removeFile, doesFileExist)
import System.Exit (ExitCode(..))
import System.FilePath (takeExtension)
import System.IO (hClose, openBinaryTempFile)
import System.Process (readProcessWithExitCode)

data ArchiveFormat = ArchiveZIP | ArchiveRAR | Archive7z
  deriving (Show, Eq)

-- | Check for archive magic (ZIP: 4 bytes, RAR: 6 bytes, 7z: 6 bytes).
detectArchive :: ByteString -> Maybe ArchiveFormat
detectArchive input
  | ByteString.length input < 4 = Nothing
  | ByteString.take 4 input == "PK\x03\x04"           = Just ArchiveZIP
  | ByteString.length input >= 6
  , ByteString.take 6 input == "Rar!\x1a\x07"         = Just ArchiveRAR
  | ByteString.length input >= 6
  , ByteString.take 6 input == "7z\xbc\xaf\x27\x1c"   = Just Archive7z
  | otherwise                                  = Nothing

-- | Unwrap a single-entry archive → (content bytes, entry name).
-- Filters out chaff (readmes, images, docs), extracts the sole candidate.
unwrapArchive :: ArchiveFormat -> FilePath -> IO (Either String (ByteString, String))
unwrapArchive format path = do
  entries <- listEntries format path
  case entries of
    Left errorMessage -> pure (Left errorMessage)
    Right names -> do
      let candidates = filter isCandidate names
      case candidates of
        []  -> pure (Left ("no usable file found in " ++ formatString format ++ " archive "
                           ++ path ++ " (" ++ show (length names) ++ " entries, all filtered)\n"
                           ++ "If this isn't actually an archive, use --raw."))
        [name] -> extractEntry format path name
        _ -> pure (Left (path ++ " is a " ++ formatString format ++ " archive with "
                         ++ show (length candidates) ++ " candidate files:\n"
                         ++ unlines (map ("  " ++) candidates)
                         ++ "Extract the one you want and pass it directly."))

formatString :: ArchiveFormat -> String
formatString ArchiveZIP = "ZIP"
formatString ArchiveRAR = "RAR"
formatString Archive7z  = "7z"

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

listEntries :: ArchiveFormat -> FilePath -> IO (Either String [String])
listEntries ArchiveZIP path = do
  maybeTool <- findExecutable "unzip"
  case maybeTool of
    Nothing -> pure (Left "ZIP archive detected but unzip not found on PATH")
    Just _ -> do
      (exitCode, stdout, stderr) <- readProcessWithExitCode "unzip" ["-Z1", path] ""
      pure $ case exitCode of
        ExitSuccess -> Right (filter (not . null) (lines stdout))
        _           -> Left ("unzip -Z1 failed: " ++ stderr)

listEntries ArchiveRAR path = do
  maybeUnrar <- findExecutable "unrar"
  case maybeUnrar of
    Just _ -> do
      (exitCode, stdout, stderr) <- readProcessWithExitCode "unrar" ["lb", path] ""
      pure $ case exitCode of
        ExitSuccess -> Right (filter (not . null) (lines stdout))
        _           -> Left ("unrar lb failed: " ++ stderr)
    Nothing -> do
      maybe7z <- findExecutable "7z"
      case maybe7z of
        Nothing -> pure (Left "RAR archive detected but neither unrar nor 7z found on PATH")
        Just _  -> list7z path

listEntries Archive7z path = do
  maybe7z <- findExecutable "7z"
  case maybe7z of
    Nothing -> pure (Left "7z archive detected but 7z not found on PATH")
    Just _  -> list7z path

-- | List entries using 7z's machine-readable output.
list7z :: FilePath -> IO (Either String [String])
list7z path = do
  (exitCode, stdout, stderr) <- readProcessWithExitCode "7z" ["l", "-ba", "-slt", path] ""
  pure $ case exitCode of
    ExitSuccess -> Right (parse7zList stdout)
    _           -> Left ("7z l failed: " ++ stderr)

-- | Parse 7z -slt output, extracting Path= lines.
parse7zList :: String -> [String]
parse7zList = map (drop 5) . filter ("Path=" `isPrefixOf`) . lines

----------------------------------------------------------------------------
-- Extraction
----------------------------------------------------------------------------

extractEntry :: ArchiveFormat -> FilePath -> String -> IO (Either String (ByteString, String))
extractEntry format archivePath entryName = do
  (temporaryFile, handle) <- openBinaryTempFile "/tmp" "slap-archive"
  hClose handle
  let temporaryDirectory = temporaryFile ++ ".d"
  createDirectoryIfMissing True temporaryDirectory
  result <- doExtract format archivePath entryName temporaryDirectory
  case result of
    Left errorMessage -> do
      cleanup temporaryFile temporaryDirectory
      pure (Left errorMessage)
    Right () -> do
      extracted <- findExtracted temporaryDirectory entryName
      case extracted of
        Nothing -> do
          cleanup temporaryFile temporaryDirectory
          pure (Left "extracted file not found in temp dir")
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

doExtract :: ArchiveFormat -> FilePath -> String -> FilePath -> IO (Either String ())
doExtract ArchiveZIP archivePath entryName temporaryDirectory = do
  (exitCode, _, stderr) <- readProcessWithExitCode "unzip"
    ["-o", "-j", archivePath, entryName, "-d", temporaryDirectory] ""
  pure $ case exitCode of
    ExitSuccess -> Right ()
    _           -> Left ("unzip extract failed: " ++ stderr)

doExtract ArchiveRAR archivePath entryName temporaryDirectory = do
  maybeUnrar <- findExecutable "unrar"
  case maybeUnrar of
    Just _ -> do
      (exitCode, _, stderr) <- readProcessWithExitCode "unrar"
        ["e", "-o+", archivePath, entryName, temporaryDirectory ++ "/"] ""
      pure $ case exitCode of
        ExitSuccess -> Right ()
        _           -> Left ("unrar extract failed: " ++ stderr)
    Nothing -> do
      (exitCode, _, stderr) <- readProcessWithExitCode "7z"
        ["e", "-o" ++ temporaryDirectory, "-y", archivePath, entryName] ""
      pure $ case exitCode of
        ExitSuccess -> Right ()
        _           -> Left ("7z extract failed: " ++ stderr)

doExtract Archive7z archivePath entryName temporaryDirectory = do
  (exitCode, _, stderr) <- readProcessWithExitCode "7z"
    ["e", "-o" ++ temporaryDirectory, "-y", archivePath, entryName] ""
  pure $ case exitCode of
    ExitSuccess -> Right ()
    _           -> Left ("7z extract failed: " ++ stderr)
