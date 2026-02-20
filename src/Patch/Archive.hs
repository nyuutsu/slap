{-# LANGUAGE OverloadedStrings #-}

module Patch.Archive
  ( ArchiveFormat(..)
  , detectArchive
  , unwrapArchive
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
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

-- | Check first 8 bytes for archive magic.
detectArchive :: ByteString -> Maybe ArchiveFormat
detectArchive bs
  | BS.length bs < 4 = Nothing
  | BS.take 4 bs == "PK\x03\x04"           = Just ArchiveZIP
  | BS.length bs >= 6
  , BS.take 6 bs == "Rar!\x1a\x07"         = Just ArchiveRAR
  | BS.length bs >= 6
  , BS.take 6 bs == "7z\xbc\xaf\x27\x1c"   = Just Archive7z
  | otherwise                               = Nothing

-- | Unwrap a single-entry archive → (content bytes, entry name).
-- Filters out chaff (readmes, images, docs), extracts the sole candidate.
unwrapArchive :: ArchiveFormat -> FilePath -> IO (Either String (ByteString, String))
unwrapArchive fmt path = do
  entries <- listEntries fmt path
  case entries of
    Left err -> pure (Left err)
    Right names -> do
      let candidates = filter isCandidate names
      case candidates of
        []  -> pure (Left ("no usable file found in " ++ fmtStr fmt ++ " archive "
                           ++ path ++ " (" ++ show (length names) ++ " entries, all filtered)"))
        [name] -> extractEntry fmt path name
        _ -> pure (Left (path ++ " is a " ++ fmtStr fmt ++ " archive with "
                         ++ show (length candidates) ++ " candidate files.\n"
                         ++ unlines (map ("  " ++) candidates)
                         ++ "If the archive itself is the target, use --raw."))

fmtStr :: ArchiveFormat -> String
fmtStr ArchiveZIP = "ZIP"
fmtStr ArchiveRAR = "RAR"
fmtStr Archive7z  = "7z"

isCandidate :: String -> Bool
isCandidate name
  | "/" `isSuffixOf` name = False
  | ext `elem` chaffExts = False
  | otherwise            = True
  where
    ext = map toLower (takeExtension name)

chaffExts :: [String]
chaffExts =
  [ ".txt", ".md", ".nfo", ".diz", ".rtf", ".doc", ".pdf"
  , ".html", ".htm", ".jpg", ".jpeg", ".png", ".gif", ".bmp"
  , ".url", ".lnk"
  ]

----------------------------------------------------------------------------
-- Listing
----------------------------------------------------------------------------

listEntries :: ArchiveFormat -> FilePath -> IO (Either String [String])
listEntries ArchiveZIP path = do
  mTool <- findExecutable "unzip"
  case mTool of
    Nothing -> pure (Left "ZIP archive detected but unzip not found on PATH")
    Just _ -> do
      (ec, out, err) <- readProcessWithExitCode "unzip" ["-Z1", path] ""
      pure $ case ec of
        ExitSuccess -> Right (filter (not . null) (lines out))
        _           -> Left ("unzip -Z1 failed: " ++ err)

listEntries ArchiveRAR path = do
  mUnrar <- findExecutable "unrar"
  case mUnrar of
    Just _ -> do
      (ec, out, err) <- readProcessWithExitCode "unrar" ["lb", path] ""
      pure $ case ec of
        ExitSuccess -> Right (filter (not . null) (lines out))
        _           -> Left ("unrar lb failed: " ++ err)
    Nothing -> do
      m7z <- findExecutable "7z"
      case m7z of
        Nothing -> pure (Left "RAR archive detected but neither unrar nor 7z found on PATH")
        Just _  -> list7z path

listEntries Archive7z path = do
  m7z <- findExecutable "7z"
  case m7z of
    Nothing -> pure (Left "7z archive detected but 7z not found on PATH")
    Just _  -> list7z path

-- | List entries using 7z's machine-readable output.
list7z :: FilePath -> IO (Either String [String])
list7z path = do
  (ec, out, err) <- readProcessWithExitCode "7z" ["l", "-ba", "-slt", path] ""
  pure $ case ec of
    ExitSuccess -> Right (parse7zList out)
    _           -> Left ("7z l failed: " ++ err)

-- | Parse 7z -slt output, extracting Path= lines.
parse7zList :: String -> [String]
parse7zList = map (drop 5) . filter ("Path=" `isPrefixOf`) . lines

----------------------------------------------------------------------------
-- Extraction
----------------------------------------------------------------------------

extractEntry :: ArchiveFormat -> FilePath -> String -> IO (Either String (ByteString, String))
extractEntry fmt archivePath entryName = do
  (tmpFile, h) <- openBinaryTempFile "/tmp" "slap-archive"
  hClose h
  let tmpDir = tmpFile ++ ".d"
  createDirectoryIfMissing True tmpDir
  result <- doExtract fmt archivePath entryName tmpDir
  case result of
    Left err -> do
      cleanup tmpFile tmpDir
      pure (Left err)
    Right () -> do
      extracted <- findExtracted tmpDir entryName
      case extracted of
        Nothing -> do
          cleanup tmpFile tmpDir
          pure (Left "extracted file not found in temp dir")
        Just extractedPath -> do
          bs <- BS.readFile extractedPath
          cleanup tmpFile tmpDir
          pure (Right (bs, entryName))
  where
    cleanup tmpFile tmpDir = do
      removeDirectoryRecursive tmpDir
      removeFile tmpFile

findExtracted :: FilePath -> String -> IO (Maybe FilePath)
findExtracted tmpDir entryName = do
  -- flat extraction puts file directly in tmpDir
  let basename = takeFileName' entryName
      flatPath = tmpDir ++ "/" ++ basename
      fullPath = tmpDir ++ "/" ++ entryName
  flatExists <- doesFileExist flatPath
  if flatExists
    then pure (Just flatPath)
    else do
      fullExists <- doesFileExist fullPath
      pure (if fullExists then Just fullPath else Nothing)

-- | Extract basename from a path (handles both / and \ separators).
takeFileName' :: String -> String
takeFileName' = reverse . takeWhile (\c -> c /= '/' && c /= '\\') . reverse

doExtract :: ArchiveFormat -> FilePath -> String -> FilePath -> IO (Either String ())
doExtract ArchiveZIP archivePath entryName tmpDir = do
  (ec, _, err) <- readProcessWithExitCode "unzip"
    ["-o", "-j", archivePath, entryName, "-d", tmpDir] ""
  pure $ case ec of
    ExitSuccess -> Right ()
    _           -> Left ("unzip extract failed: " ++ err)

doExtract ArchiveRAR archivePath entryName tmpDir = do
  mUnrar <- findExecutable "unrar"
  case mUnrar of
    Just _ -> do
      (ec, _, err) <- readProcessWithExitCode "unrar"
        ["e", "-o+", archivePath, entryName, tmpDir ++ "/"] ""
      pure $ case ec of
        ExitSuccess -> Right ()
        _           -> Left ("unrar extract failed: " ++ err)
    Nothing -> do
      (ec, _, err) <- readProcessWithExitCode "7z"
        ["e", "-o" ++ tmpDir, "-y", archivePath, entryName] ""
      pure $ case ec of
        ExitSuccess -> Right ()
        _           -> Left ("7z extract failed: " ++ err)

doExtract Archive7z archivePath entryName tmpDir = do
  (ec, _, err) <- readProcessWithExitCode "7z"
    ["e", "-o" ++ tmpDir, "-y", archivePath, entryName] ""
  pure $ case ec of
    ExitSuccess -> Right ()
    _           -> Left ("7z extract failed: " ++ err)
