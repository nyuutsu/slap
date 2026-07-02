{-# LANGUAGE OverloadedStrings #-}

-- | The pure vocabulary of archive unwrapping: which container formats
-- slap recognizes, how it detects them, which external tools can open
-- each, and the closed set of ways unwrapping can fail. The IO that acts
-- on these — listing entries, extracting, shelling out — lives in the
-- native frontend, in @Archive@ (@app/Archive.hs@). Keeping the types
-- here lets "Slap.Status" embed an
-- 'UnwrapError' in 'Slap.Status.SlapError' without dragging the process
-- and directory machinery under every module that renders an error.
module Slap.Archive.Types
  ( ArchiveFormat(..)
  , detectArchive
  , archiveFormatName
  , toolsFor
  , ToolName(..)
  , ToolDiagnostic(..)
  , EntryName(..)
  , SeenEntryCount(..)
  , UnreadableReason(..)
  , UnwrapError(..)
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.Text (Text)

-- | A container format slap can unwrap. These are genuine archives — an
-- entry table, chaff to filter, a single file to pick out — not stream
-- compressors.
data ArchiveFormat = ArchiveZIP | ArchiveRAR | Archive7z
  deriving (Show, Eq)

-- | Recognize a container by its magic bytes (ZIP: 4 bytes, RAR and 7z:
-- 6 bytes each).
detectArchive :: ByteString -> Maybe ArchiveFormat
detectArchive input
  | ByteString.length input < 4                     = Nothing
  | ByteString.take 4 input == "PK\x03\x04"         = Just ArchiveZIP
  | ByteString.length input >= 6
  , ByteString.take 6 input == "Rar!\x1a\x07"       = Just ArchiveRAR
  | ByteString.length input >= 6
  , ByteString.take 6 input == "7z\xbc\xaf\x27\x1c" = Just Archive7z
  | otherwise                                       = Nothing

-- | The human name of a container format, for diagnostics.
archiveFormatName :: ArchiveFormat -> Text
archiveFormatName ArchiveZIP = "ZIP"
archiveFormatName ArchiveRAR = "RAR"
archiveFormatName Archive7z  = "7z"

-- | The external tools that can open a format, in the order slap tries
-- them. The single source of truth shared by the IO that dispatches to
-- whichever tool is present and the 'NoToolForArchive' diagnostic that
-- names the alternatives — so the message can never drift from what slap
-- actually attempts.
toolsFor :: ArchiveFormat -> [ToolName]
toolsFor ArchiveZIP = []  -- read via rusty-slap
toolsFor ArchiveRAR = [ToolName "unrar", ToolName "7z"]
toolsFor Archive7z  = [ToolName "7z"]

-- | The name of an external archive tool as looked up on @PATH@.
newtype ToolName = ToolName { unToolName :: Text }
  deriving (Show, Eq)

-- | A tool's own diagnostic output (its stderr), carried verbatim and
-- opaque — peer in spirit to 'Slap.Status.DecompressionCause'.
newtype ToolDiagnostic = ToolDiagnostic { unToolDiagnostic :: Text }
  deriving (Show, Eq)

-- | The path of an entry within an archive.
newtype EntryName = EntryName { unEntryName :: Text }
  deriving (Show, Eq)

-- | How many entries an archive held when none survived chaff filtering.
newtype SeenEntryCount = SeenEntryCount { unSeenEntryCount :: Int }
  deriving (Show, Eq)

-- | Why a container could not be read (corrupt, encrypted, an unsupported
-- codec).
newtype UnreadableReason = UnreadableReason { unUnreadableReason :: Text }
  deriving (Show, Eq)

-- | The closed set of ways unwrapping a recognized archive can fail. The
-- offending file and its format live on the
-- 'Slap.Status.ArchiveUnwrapFailed' wrapper; these variants carry only
-- what distinguishes one failure shape from another.
data UnwrapError
  = -- | The format was recognized but none of the tools that could open
    -- it ('toolsFor') are on @PATH@. The format on the
    -- 'Slap.Status.ArchiveUnwrapFailed' wrapper determines the
    -- alternatives via 'toolsFor' at render time, so this variant
    -- carries nothing.
    NoToolForArchive
  | -- | A tool was invoked and exited nonzero.
    ArchiveToolFailed ToolName ToolDiagnostic
  | -- | The archive opened, but every entry was filtered as chaff
    -- (readme, image, and so on), leaving nothing to treat as the patch.
    ArchiveHasNoCandidate SeenEntryCount
  | -- | Several entries are plausible patches; slap will not guess, so
    -- the user must extract the one they want.
    ArchiveHasManyCandidates [EntryName]
  | -- | A tool reported a successful extraction but the named file was
    -- not found in the temporary directory afterwards.
    ExtractedEntryMissing EntryName
  | -- | slap's reader could not read the container.
    ArchiveUnreadable UnreadableReason
  deriving (Show, Eq)
