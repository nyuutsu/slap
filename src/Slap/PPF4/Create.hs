{-# LANGUAGE OverloadedStrings #-}

-- | Wire encoder for PPF4 patches. PPF4 is a two-phase format: a run
-- of Replace records (command byte 0) that overwrite bytes within the
-- source's original extent, followed by a run of Append records
-- (command byte 1) that extend the file past the source's end. The
-- one-way transition — no Replace may follow an Append — is honored
-- by emitting all Replaces before any Append.
--
-- Each record is a 1-byte command, a 4-byte LE offset, a 1-byte count,
-- and @count@ payload bytes. The offset is meaningful only for Replace;
-- Append records carry a zero in that field, matching the reference
-- maker, and the applier ignores it.
--
-- The caller ('Slap.Convert.encodeDirect') partitions the diff hunks by
-- the source's length — hunks within @[0, sourceLength)@ become
-- Replaces, hunks at or past @sourceLength@ become Appends — and runs
-- the split/narrow pipeline so each payload is ≤ 255 bytes and each
-- Replace offset fits the 4-byte field before reaching this encoder.
--
-- PPF4's 50-byte description field is always written as zero. The
-- reference maker takes no description and zero-fills the field, and
-- the applier reads past it without using it, so slap does the same —
-- PPF4 create carries no description.
module Slap.PPF4.Create
  ( encodePPF4
  , partitionPPF4Phases
  ) where

import Slap.PPF4.Types (PPF4Append(..), ppf4DescriptionLength)
import Slap.Binary (putWord32LE)
import Slap.Measure (Length(..), Offset(..), FileSize(..), Hunk(..), offsetToInt)
import Slap.Narrow (EncodedHunk, encodedOffset, encodedPayload)
import Slap.Status (CreateResult(..))
import Slap.FileContents (PatchFileContents(..))

import qualified Data.ByteString as ByteString
import Data.ByteString.Builder
import qualified Data.ByteString.Lazy as LazyByteString

-- | Encode a PPF4 patch from pre-split records. Replace records are
-- 'EncodedHunk's — the typed proof that each offset fits the 4-byte
-- field and each payload fits the single-byte count; the convert-layer
-- pipeline narrows them before calling here. Append records are
-- 'PPF4Append's, which carry only a payload: the wire offset field is
-- always zero for an Append, so an offset-bearing type would be a lie.
-- The two phases being different types also means they can't be passed
-- in the wrong order. Append payloads are bounded to the single-byte
-- count by the same @splitHunks@ pass the caller runs, so the
-- @fromIntegral@ casts below are safe-by-construction.
--
-- There is no description parameter: the reference PPF4 maker writes
-- the 50-byte description field as all zeros and takes no description
-- input, so slap matches it rather than populating a field the format's
-- tooling leaves empty.
encodePPF4 :: [EncodedHunk] -> [PPF4Append] -> CreateResult
encodePPF4 replaces appends =
  let body = foldMap encodeReplaceRecord replaces
             <> foldMap encodeAppendRecord appends
  in CreateResult
       (PatchFileContents (LazyByteString.toStrict (toLazyByteString (header <> body))))
       []

-- | The 60-byte PPF4 header: @"PPF40"@ magic+version, the @0xFF@
-- encoding byte, the 50-byte description (always zero — the reference
-- maker takes no description), then four zero bytes (image type,
-- validation flag, undo flag, expansion) — none of which PPF4 uses, all
-- written as zero so the reference applier's combined-zero check on
-- those four bytes passes.
header :: Builder
header =
  byteString "PPF40"                                          -- magic + version (5 bytes)
  <> word8 0xFF                                                -- encoding method
  <> byteString (ByteString.replicate (unLength ppf4DescriptionLength) 0x00)
  <> word8 0x00                                                -- image type
  <> word8 0x00                                                -- validation flag
  <> word8 0x00                                                -- undo flag
  <> word8 0x00                                                -- expansion

encodeReplaceRecord :: EncodedHunk -> Builder
encodeReplaceRecord ehunk =
  word8 0x00                                                   -- command: REPLACE
  <> putWord32LE (fromIntegral (unOffset (encodedOffset ehunk)))
  <> word8 (fromIntegral (ByteString.length (encodedPayload ehunk)))
  <> byteString (encodedPayload ehunk)

encodeAppendRecord :: PPF4Append -> Builder
encodeAppendRecord (PPF4Append payload) =
  word8 0x01                                                   -- command: ADD
  <> putWord32LE 0                                             -- offset unused for ADD
  <> word8 (fromIntegral (ByteString.length payload))
  <> byteString payload

-- | Partition diff hunks into PPF4's two phases by the source's byte
-- length. A hunk entirely within @[0, sourceLength)@ overwrites source
-- bytes (Replace); a hunk entirely at or past @sourceLength@ extends the
-- file (Append); a hunk that straddles the boundary is cut at it — the
-- part within the source becomes a Replace, the part beyond it an
-- Append. The straddle case is the common one: 'Slap.Binary.diffHunks'
-- merges a change ending at the source's last byte with the grown tail
-- into a single hunk, and that hunk must be cut so its Replace half
-- stays within the source bounds the applier enforces. Returns
-- @(replaceHunks, appendHunks)@, each in the input's offset order.
partitionPPF4Phases :: FileSize -> [Hunk] -> ([Hunk], [Hunk])
partitionPPF4Phases sourceSize = foldr classify ([], [])
  where
    sourceLength = unFileSize sourceSize
    classify hunk (replaces, appends)
      | startOffset >= sourceLength = (replaces, hunk : appends)
      | endOffset   <= sourceLength = (hunk : replaces, appends)
      | otherwise =
          let withinSourceCount = sourceLength - startOffset
              replacePart = Hunk (hunkOffset hunk)
                                 (ByteString.take withinSourceCount payload)
              appendPart  = Hunk (Offset sourceLength)
                                 (ByteString.drop withinSourceCount payload)
          in (replacePart : replaces, appendPart : appends)
      where
        startOffset = offsetToInt (hunkOffset hunk)
        payload     = hunkPayload hunk
        endOffset   = startOffset + ByteString.length payload
