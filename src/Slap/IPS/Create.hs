{-# LANGUAGE OverloadedStrings #-}

-- | Wire encoder for the IPS family. This module owns the
-- byte-laying side of patch creation: given a record list and a
-- variant, it produces the patch bytes. The decision side (which
-- records to emit, what shape they should take, how to merge or
-- split runs) lives in 'Slap.IPS.Optimize'.
--
-- The single 'encodeIPSPatch' wire encoder replaces the four
-- near-duplicate top-level encoders of the previous module
-- (@encodeIPS@, @encodeIPS32@, @encodeEBP@, @encodeEBPRaw@). The
-- variant differences — magic bytes, offset width, EOF marker,
-- sentinel offset — are looked up via 'variantSpec' instead of
-- duplicated by hand at four call sites. EBP encoding is a thin
-- wrapper ('encodeEBPPatch') that calls 'encodeIPSPatch' for the
-- standard-IPS body and appends the JSON metadata trailer.
--
-- There is no @createIPS@ / @createIPS32@ / @createEBP@ porcelain
-- — neither here nor in "Slap.Create". End-to-end creation for the
-- IPS family is a coordination-layer concern: the
-- 'Slap.Convert.createPatch' pipeline threads a 'PatchContents'
-- through 'Slap.Convert.buildContents' and 'Slap.Convert.encodeDirect',
-- which is where the live creation path runs. The direct family
-- shares that pipeline, so a per-format typed front door would have
-- nothing format-level to wrap; "Slap.Create" reserves its porcelain
-- for the differential family, which has no shared pipeline.
module Slap.IPS.Create
  ( -- * Wire encoder (used by 'Slap.Convert')
    encodeIPSPatch
  , encodeEBPPatch
    -- * Sentinel-collision resolution (used by 'Slap.Convert')
  , resolveSentinelCollisions
    -- * Wire-emission helpers
  , encodeIPSRecord
  , encodeOffset
  , encodeTruncationMarker
  , buildEBPMetadataJSON
    -- * Optimizer pass-through (re-exported for callers and tests)
  , optimalIPSRecords
  ) where

import Slap.Binary (putWord16BE)
import Slap.Error (SlapError(..))
import Slap.FileContents
  ( PatchFileContents(..)
  , InputFileContents(..)
  , unPatchFileContents
  )
import Slap.Display.Primitives (padHex)
import Slap.FormatLabel (FormatLabel(..))
import Slap.IPS.Optimize (optimalIPSRecords)
import Slap.IPS.Types
  ( IPSVariant(..)
  , OffsetWidth(..)
  , IPSVariantSpec(..)
  , EBPMetadata(..)
  , EBPMetadataFields(..)
  , variantSpec
  )
import Slap.Measure
  ( FileSize(..)
  , Delta(..)
  , Cursor(..)
  , Hunk(..)
  , SentinelOffset(..)
  , offsetToInt
  )
import Slap.Narrow
  ( EncodedHunk
  , encodedOffset
  , encodedPayload
  )

import Data.Bits (shiftR, (.&.))
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.ByteString.Builder
  ( Builder
  , byteString
  , toLazyByteString
  , word8
  )
import qualified Data.ByteString.Lazy as LazyByteString
import qualified Data.Text as Text
import qualified Data.Text.Encoding as TextEncoding

----------------------------------------------------------------------------
-- Parameterized wire encoder
----------------------------------------------------------------------------

-- | Encode a record list as the bytes of an IPS-family patch under
-- the given variant. This is the single wire emitter that replaces
-- the four near-duplicate functions of the previous module; each
-- of those is now either a thin wrapper around this function (the
-- two non-EBP cases) or a thin wrapper around 'encodeEBPPatch' (the
-- two EBP cases).
--
-- The @optionalTruncation@ argument is honored only for the
-- 'StandardIPS' variant. For 'IPS32', the truncation marker has
-- no defined wire shape (no community implementation supports
-- it), so this encoder drops any truncation passed for IPS32.
-- The contract layer in 'Slap.Convert.canConvert' refuses any
-- conversion whose source patch carries a truncation marker and
-- whose target is 'IPS32' or 'EBP' — so the drop branch is
-- defensive, not operational: it will not fire under well-formed
-- callers. 'Slap.Convert.buildContents' on the create path
-- populates 'contentsTruncation' for IPS32/EBP only so
-- 'rejectTruncation' can surface the shrinkage refusal to the
-- user rather than silently produce a non-truncating patch.
--
-- This function does not validate the records and does not resolve
-- sentinel collisions: it assumes each record's offset and length
-- are already within the variant's wire-format range, and that any
-- record sitting on the variant's trailer sentinel has already been
-- shifted or rejected by 'resolveSentinelCollisions'. The optimizer
-- guarantees the range precondition by construction, and the
-- convert-path pipeline in 'Slap.Convert.encodeDirect' runs
-- 'narrowHunks' and 'resolveSentinelCollisions' before calling here.
encodeIPSPatch
  :: IPSVariant
  -> [EncodedHunk]
  -> Maybe FileSize
  -> PatchFileContents
encodeIPSPatch variant records optionalTruncation =
  PatchFileContents
    (LazyByteString.toStrict (toLazyByteString patchBuilder))
  where
    spec        = variantSpec variant
    offsetWidth = ipsVariantOffsetWidth spec

    truncationBuilder = case variant of
      StandardIPS ->
        maybe mempty (encodeTruncationMarker offsetWidth) optionalTruncation
      IPS32 -> mempty

    patchBuilder =
      byteString (ipsVariantMagic spec)
      <> foldMap (encodeIPSRecord offsetWidth) records
      <> byteString (ipsVariantEOFMarker spec)
      <> truncationBuilder

-- | Encode a record list as an EBP patch (a 'StandardIPS' patch
-- with a trailing JSON metadata blob). EBP has no IPS32 analogue,
-- so the variant is fixed.
--
-- The truncation marker is intentionally not supported here. The
-- IPS_AUDIT brief found no reference implementation that emits
-- truncation-then-JSON inside an EBP patch, and 'Slap.IPS.Parse'
-- only accepts EBP trailers that begin with the JSON opening byte
-- @{@. Emitting a truncation marker before the JSON would produce
-- bytes neither this parser nor any third-party EBP parser would
-- round-trip cleanly. The contract layer in
-- 'Slap.Convert.canConvert' refuses conversions that would land
-- truncation here, so the absence of a truncation parameter is
-- enforced upstream rather than silently dropped at this call
-- site.
encodeEBPPatch
  :: [EncodedHunk]
  -> EBPMetadata
  -> PatchFileContents
encodeEBPPatch records (EBPMetadata metadataBytes) =
  let baseStandardIPSBytes =
        unPatchFileContents
          (encodeIPSPatch StandardIPS records Nothing)
  in PatchFileContents (baseStandardIPSBytes <> metadataBytes)

----------------------------------------------------------------------------
-- Wire-emission helpers
----------------------------------------------------------------------------

-- | Encode a single 'EncodedHunk' as one IPS record. The
-- constructor choice (RLE vs. literal) is made here, by the same
-- heuristic the DP optimizer uses internally: a payload of length
-- ≥ 3 whose every byte is identical is emitted as an RLE record
-- (8 bytes for 'StandardIPS', 9 bytes for 'IPS32', regardless of
-- run length); everything else is emitted as a literal copy
-- record.
--
-- The size threshold of 3 is the smallest run for which RLE ties
-- copy on bytes — for runs of length ≥ 4 RLE is strictly cheaper.
-- We accept the tie at length 3 because emitting RLE there
-- preserves byte-identity with patches generated under the same
-- heuristic by the upstream tool ecosystem (Flips, Lunar IPS).
encodeIPSRecord :: OffsetWidth -> EncodedHunk -> Builder
encodeIPSRecord offsetWidth ehunk =
  encodeOffset offsetWidth (offsetToInt recordOffset)
  <> if shouldEncodeAsRLE recordPayload
       then runLengthEncodedBody
       else literalCopyBody
  where
    recordOffset  = encodedOffset ehunk
    recordPayload = encodedPayload ehunk
    payloadLength = ByteString.length recordPayload

    -- RLE record body: zero in the size field acts as the RLE
    -- sentinel, followed by the run length and the fill byte.
    runLengthEncodedBody =
         word8 0x00
      <> word8 0x00
      <> putWord16BE (fromIntegral payloadLength)
      <> word8 (ByteString.index recordPayload 0)

    -- Literal copy record body: the payload length in the size
    -- field followed by the payload bytes verbatim.
    literalCopyBody =
         putWord16BE (fromIntegral payloadLength)
      <> byteString recordPayload

-- | Decide whether a payload should be encoded as an RLE record.
-- True when the payload is at least three bytes long and every
-- byte is identical. See 'encodeIPSRecord' for the cost analysis.
shouldEncodeAsRLE :: ByteString -> Bool
shouldEncodeAsRLE payload =
  ByteString.length payload >= 3
  && ByteString.all (== ByteString.index payload 0) payload

-- | Encode an integer as a big-endian offset field whose width is
-- determined by the variant. 'Offset24' and 'Offset32' are the
-- only two cases — there is no fall-through default branch, so
-- adding a new 'OffsetWidth' constructor in 'Slap.IPS.Types' would
-- force a compile error here, which is exactly what we want.
encodeOffset :: OffsetWidth -> Int -> Builder
encodeOffset Offset24 offsetValue =
     word8 (fromIntegral (offsetValue `shiftR` 16))
  <> word8 (fromIntegral ((offsetValue `shiftR` 8) .&. 0xFF))
  <> word8 (fromIntegral (offsetValue .&. 0xFF))
encodeOffset Offset32 offsetValue =
     word8 (fromIntegral (offsetValue `shiftR` 24))
  <> word8 (fromIntegral ((offsetValue `shiftR` 16) .&. 0xFF))
  <> word8 (fromIntegral ((offsetValue `shiftR` 8) .&. 0xFF))
  <> word8 (fromIntegral (offsetValue .&. 0xFF))

-- | Encode a post-EOF truncation marker: a single big-endian
-- offset value, in the same width as the variant's record offsets.
-- Only emitted for 'StandardIPS'; see 'encodeIPSPatch' for the
-- IPS32 rationale.
encodeTruncationMarker :: OffsetWidth -> FileSize -> Builder
encodeTruncationMarker offsetWidth (FileSize truncatedSizeBytes) =
  encodeOffset offsetWidth truncatedSizeBytes

-- | Resolve every record that sits on the variant's trailer
-- sentinel. Two outcomes per record:
--
-- * "Fixable": the record's offset equals the sentinel, offset \> 0,
--   and the source contains the byte at @sentinel - 1@. The record
--   is rewritten to begin one byte earlier with that preceding byte
--   prepended to its payload — the same shift-and-prepend trick the
--   Archiveteam wiki recommends for IPS's @0x454F46@ collision and
--   that Flips' @libips.cpp@ implements inline.
--
-- * "Unfixable": the record's offset equals the sentinel but the
--   source has no byte to prepend — either because the source is
--   empty (source-less direct conversion), the source is shorter
--   than @sentinel@, or the sentinel sits at offset @0@ so there is
--   no preceding position. The whole call returns
--   'Left' 'SentinelCollisionUnfixable' with the format label and
--   the colliding offset, and the conversion aborts rather than
--   emitting bytes a parser could not faithfully round-trip.
--
-- Records whose offset is not the sentinel pass through unchanged —
-- the explicit "not a collision" branch, not a silent catch-all.
--
-- Both 'Slap.Convert.createPatch' (with real source bytes) and
-- 'Slap.Convert.convertDirect' (with an empty 'InputFileContents')
-- call through this function. The shape of the source bytes decides
-- whether a given collision is fixable; the caller decides whether
-- to invoke sentinel resolution at all based on whether the format
-- has a sentinel (IPS, IPS32, EBP do; nothing else does).
resolveSentinelCollisions
  :: FormatLabel
  -> SentinelOffset
  -> InputFileContents
  -> [Hunk]
  -> Either SlapError [Hunk]
resolveSentinelCollisions label sentinel (InputFileContents source) =
  traverse resolveOne
  where
    SentinelOffset sentinelPosition = sentinel
    sourceLength                    = ByteString.length source

    resolveOne record@(Hunk recordOffset recordPayload)
      | recordOffset /= sentinelPosition = Right record
      | offsetToInt recordOffset > 0
      , offsetToInt recordOffset - 1 < sourceLength =
          let precedingByteIndex = offsetToInt recordOffset - 1
              precedingByte      =
                ByteString.index source precedingByteIndex
              extendedPayload    =
                ByteString.cons precedingByte recordPayload
          in Right Hunk
               { hunkOffset  = displace recordOffset (Delta (-1))
               , hunkPayload = extendedPayload
               }
      | otherwise =
          Left (SentinelCollisionUnfixable label sentinel)

-- | Build the EBP-style JSON metadata blob from CLI-supplied
-- title / author / description fields. The four-key shape
-- (@patcher@, @title@, @author@, @description@) matches what
-- EBPatcher and every long-standing community tool emits. slap
-- fixes @patcher@ to @"slap"@ to identify itself as the source.
--
-- The encoding is a hand-rolled minimal JSON object — only the
-- two characters @"@ and @\\@ get escaped, and control bytes
-- below @0x20@ are emitted as @\\u00XX@ escapes. Pulling in
-- @aeson@ for what is effectively four string interpolations
-- would be wildly disproportionate.
buildEBPMetadataJSON :: EBPMetadataFields -> ByteString
buildEBPMetadataJSON fields =
  TextEncoding.encodeUtf8 (Text.pack jsonText)
  where
    jsonText =
      "{\"patcher\":\"slap\",\"title\":\""
        ++ escapeJSONString (ebpMetadataTitle fields)
        ++ "\",\"author\":\""
        ++ escapeJSONString (ebpMetadataAuthor fields)
        ++ "\",\"description\":\""
        ++ escapeJSONString (ebpMetadataDescription fields)
        ++ "\"}"

    escapeJSONString [] = []
    escapeJSONString ('"'  : rest) = '\\' : '"'  : escapeJSONString rest
    escapeJSONString ('\\' : rest) = '\\' : '\\' : escapeJSONString rest
    escapeJSONString (currentChar : rest)
      | currentChar < ' ' =
          "\\u00"
            ++ padHex 2 (fromEnum currentChar)
            ++ escapeJSONString rest
      | otherwise =
          currentChar : escapeJSONString rest
