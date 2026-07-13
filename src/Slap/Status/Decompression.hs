{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StrictData #-}

-- | The decompression and differ failures, and their voice.
module Slap.Status.Decompression
  ( DecompressionFailure(..)
  , BSDiffSection(..)
  , bsDiffSectionName
  , DecompressionCause(..)
  , XDelta1DiffCause(..)
  , BSDiffDifferCause(..)
  , GDIFFDiffCause(..)
  , decompressionAlgorithm
  , SecondaryStreamGranularity(..)
  , secondaryStreamGranularity
  , secondaryStreamPossessive
  , renderDecompressionFailure
  ) where

import Slap.Status.VCDIFF (VCDIFFSection, vcdiffSectionName)
import Slap.Status.Vocabulary (CompressionAlgorithm(..), compressionAlgorithmName)

import Data.Text (Text)

-- | One constructor per decompression site, each carrying only the axes that vary there.
-- 'VCDIFFSectionFailed' is the one site whose algorithm varies — a secondary stream is decoded
-- by whichever compressor the patch declared — so it alone carries a 'CompressionAlgorithm'.
data DecompressionFailure
  = Yay0WrapperFailed                       DecompressionCause
  | NINJA1Failed                            DecompressionCause
  | XDelta1Failed                           DecompressionCause
  | BSDiffSectionFailed   BSDiffSection     DecompressionCause
  | VCDIFFSectionFailed   VCDIFFSection CompressionAlgorithm DecompressionCause
  deriving (Show, Eq)

-- | BSDiff's three bzip2-compressed sections.
data BSDiffSection = BSDiffControl | BSDiffDiff | BSDiffExtra
  deriving (Show, Eq)

-- | The decompressor's own diagnostic, relayed verbatim (flate2, bzip2-rs, lzma-rs, or slap's Yay0).
-- Decoded as UTF-8 at the FFI seam ('Slap.FFI.readText').
newtype DecompressionCause = DecompressionCause { unDecompressionCause :: Text }
  deriving (Show, Eq)

-- | The xdelta1 differ's failure cause, in the Rust side's own words —
-- an allocation refusal while building the source index, or an internal-invariant violation surfaced rather than panicked.
newtype XDelta1DiffCause = XDelta1DiffCause { unXDelta1DiffCause :: Text }
  deriving (Show, Eq)

-- | The bsdiff differ's counterpart of 'XDelta1DiffCause' — always an invariant violation:
-- bsdiff's 64-bit wire fields outreach any input buffer, so there is no size refusal to relay.
newtype BSDiffDifferCause = BSDiffDifferCause { unBSDiffDifferCause :: Text }
  deriving (Show, Eq)

-- | The GDIFF differ's failure cause — always an invariant violation:
-- GDIFF's 64-bit copy offsets outreach any input buffer, and the differ's index widens with the source rather than refusing one.
newtype GDIFFDiffCause = GDIFFDiffCause { unGDIFFDiffCause :: Text }
  deriving (Show, Eq)

-- | The compression algorithm in flight at a given failure site.
decompressionAlgorithm :: DecompressionFailure -> CompressionAlgorithm
decompressionAlgorithm Yay0WrapperFailed{}                 = Yay0
decompressionAlgorithm NINJA1Failed{}                      = Zlib
decompressionAlgorithm XDelta1Failed{}                     = Gzip
decompressionAlgorithm BSDiffSectionFailed{}               = Bzip2
decompressionAlgorithm (VCDIFFSectionFailed _ algorithm _) = algorithm

bsDiffSectionName :: BSDiffSection -> Text
bsDiffSectionName BSDiffControl = "control"
bsDiffSectionName BSDiffDiff    = "diff"
bsDiffSectionName BSDiffExtra   = "extra"

-- | How a compressor's stream relates to the sections that carry it: one continuous stream whose sections are slices of it
-- ('GatheredAcrossSections'), or a self-contained stream per section ('EachSectionItsOwn').
data SecondaryStreamGranularity
  = GatheredAcrossSections
  | EachSectionItsOwn

secondaryStreamGranularity :: CompressionAlgorithm -> SecondaryStreamGranularity
secondaryStreamGranularity Zlib  = EachSectionItsOwn
secondaryStreamGranularity Gzip  = EachSectionItsOwn
secondaryStreamGranularity Bzip2 = EachSectionItsOwn
secondaryStreamGranularity Yay0  = EachSectionItsOwn
secondaryStreamGranularity DJW   = EachSectionItsOwn
secondaryStreamGranularity LZMA  = GatheredAcrossSections
secondaryStreamGranularity FGK   = GatheredAcrossSections

-- | The possessive subject of a secondary-stream message. The grammatical number follows 'secondaryStreamGranularity':
-- a gathered stream belongs to all sections of its kind, a per-section stream to just one.
secondaryStreamPossessive :: VCDIFFSection -> CompressionAlgorithm -> Text
secondaryStreamPossessive section algorithm =
  vcdiffSectionName section <> ownerSuffix <> " "
  <> compressionAlgorithmName algorithm <> " stream"
  where
    ownerSuffix = case secondaryStreamGranularity algorithm of
      GatheredAcrossSections -> " sections'"
      EachSectionItsOwn      -> " section's"

renderDecompressionFailure :: DecompressionFailure -> Text
renderDecompressionFailure failure = case failure of
  Yay0WrapperFailed       cause -> render "Yay0 wrapper"        cause
  NINJA1Failed            cause -> render "NINJA1 zlib payload" cause
  XDelta1Failed           cause -> render "XDelta1 gzip body"   cause
  BSDiffSectionFailed sec cause -> render
    ("BSDiff " <> bsDiffSectionName sec <> " bzip2 section") cause
  VCDIFFSectionFailed sec algorithm cause -> render
    ("VCDIFF " <> secondaryStreamPossessive sec algorithm) cause
  where
    render siteName (DecompressionCause msg) =
      siteName <> ": decompression failed: " <> msg
